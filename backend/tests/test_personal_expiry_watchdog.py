import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "deploy/personal/expiry-watchdog.py"
spec = importlib.util.spec_from_file_location("expiry_watchdog", SOURCE)
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)
KEY = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa"
ROW = {"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "key": KEY, "readyAt": 0, "expiresAt": 1740000}


class ExpiryWatchdogTests(unittest.TestCase):
    def setup_case(self, root):
        artifact = pathlib.Path(root) / "artifact"
        artifact.mkdir()
        file = artifact / KEY
        file.write_bytes(b"synthetic")
        file.chmod(0o600)
        journals = pathlib.Path(root) / "deadlines"
        journals.mkdir()
        (journals / (KEY + ".json")).write_text(json.dumps(ROW))
        return file

    def environment(self, root, run, sql):
        original = watchdog.os.stat

        def lstat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            return types.SimpleNamespace(st_mode=info.st_mode, st_uid=1000)

        return [
            patch.object(watchdog, "STATE", str(pathlib.Path(root) / "root-state.json")),
            patch.object(watchdog.time, "time", return_value=1740),
            patch.object(
                watchdog,
                "read_private",
                side_effect=lambda name, *args: json.loads(pathlib.Path(name).read_text()),
            ),
            patch.object(watchdog.subprocess, "run", side_effect=run),
            patch.object(watchdog, "sql", side_effect=sql),
            patch.object(watchdog.os, "stat", side_effect=lstat),
        ]

    def execute(self, patches):
        import contextlib

        with contextlib.ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            return watchdog.main()

    def test_erases_before_sql_and_persists_fence_during_database_outage(self):
        with tempfile.TemporaryDirectory() as root:
            file = self.setup_case(root)
            events = []

            def run(args, **kwargs):
                events.append(args)
                return types.SimpleNamespace(stdout=root, returncode=0)

            def sql(statement):
                self.assertFalse(file.exists())
                raise RuntimeError("DB_DOWN")

            with self.assertRaisesRegex(RuntimeError, "DB_DOWN"):
                self.execute(self.environment(root, run, sql))
            self.assertFalse(file.exists())
            self.assertTrue(
                json.loads((pathlib.Path(root) / "root-state.json").read_text())["fenced"]
            )
            self.assertTrue(any("stop" in event for event in events))
            self.assertFalse(any("start" in event for event in events))

    def test_failed_start_retried_without_expired_rows_or_journals(self):
        with tempfile.TemporaryDirectory() as root:
            file = self.setup_case(root)
            starts = []

            def run(args, **kwargs):
                if "start" in args:
                    starts.append(args)
                    if len(starts) == 1:
                        raise RuntimeError("START_FAILED")
                return types.SimpleNamespace(stdout=root, returncode=0)

            env = self.environment(root, run, lambda statement: "")
            with self.assertRaisesRegex(RuntimeError, "START_FAILED"):
                self.execute(env)
            self.assertFalse(file.exists())
            self.assertTrue(
                json.loads((pathlib.Path(root) / "root-state.json").read_text())["fenced"]
            )
            result = self.execute(self.environment(root, run, lambda statement: ""))
            self.assertFalse(result["webFenced"])
            self.assertEqual(len(starts), 2)

    def test_invalid_paths_never_reach_unlink_or_sql(self):
        with self.assertRaises(RuntimeError):
            watchdog.deadline_validate({**ROW, "key": "../other.ipa"}, "../other.ipa", 1740000)

    def test_logical_deadline_leaves_full_minute_without_database_delay(self):
        self.assertEqual(ROW["expiresAt"] - ROW["readyAt"], 29 * 60000)
        self.assertEqual(watchdog.deadline_validate(ROW, KEY, ROW["expiresAt"]), ROW)

    def test_normal_descriptor_safe_cleanup_does_not_stop_healthy_web(self):
        with tempfile.TemporaryDirectory() as root:
            (pathlib.Path(root) / "artifact").mkdir()
            (pathlib.Path(root) / "deadlines").mkdir()
            (pathlib.Path(root) / "root-state.json").write_text(
                json.dumps({"deadlines": {KEY: ROW}, "pending": {}, "fenced": False})
            )
            calls = []

            def run(args, **kwargs):
                calls.append(args)
                return types.SimpleNamespace(stdout=root, returncode=0)

            result = self.execute(self.environment(root, run, lambda statement: ""))
            self.assertFalse(result["webFenced"])
            self.assertFalse(any("stop" in call for call in calls))

    def test_all_due_files_erased_before_first_slow_database_request(self):
        with tempfile.TemporaryDirectory() as root:
            first = self.setup_case(root)
            second = pathlib.Path(root) / "artifact" / "cccccccc-cccc-cccc-cccc-cccccccccccc.ipa"
            second.write_bytes(b"synthetic2")
            second.chmod(0o600)
            row = {**ROW, "id": "dddddddd-dddd-dddd-dddd-dddddddddddd", "key": second.name}
            (pathlib.Path(root) / "deadlines" / (second.name + ".json")).write_text(json.dumps(row))

            def run(args, **kwargs):
                return types.SimpleNamespace(stdout=root, returncode=0)

            def sql(statement):
                self.assertFalse(first.exists())
                self.assertFalse(second.exists())
                raise RuntimeError("DB_OUTAGE")

            with self.assertRaises(RuntimeError):
                self.execute(self.environment(root, run, sql))
            self.assertEqual(
                len(json.loads((pathlib.Path(root) / "root-state.json").read_text())["pending"]), 2
            )

    def test_list_read_cleanup_race_does_not_skip_unrelated_due_file(self):
        with tempfile.TemporaryDirectory() as root:
            file = self.setup_case(root)
            missing = "cccccccc-cccc-cccc-cccc-cccccccccccc.ipa.json"
            path = pathlib.Path(root) / "deadlines" / missing
            path.write_text("{}")

            def read(name, *args):
                if str(name).endswith(missing):
                    path.unlink(missing_ok=True)
                    raise FileNotFoundError()
                return json.loads(pathlib.Path(name).read_text())

            def run(args, **kwargs):
                return types.SimpleNamespace(stdout=root, returncode=0)

            patches = self.environment(root, run, lambda statement: "")
            patches.append(patch.object(watchdog, "read_private", side_effect=read))
            self.execute(patches)
            self.assertFalse(file.exists())

    def test_durable_state_reconciles_across_actual_watchdog_process_restart(self):
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as root:
            file = self.setup_case(root)
            code = """import importlib.util,json,pathlib,sys,types,os
spec=importlib.util.spec_from_file_location('watchdog',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=sys.argv[2];m.STATE=root+'/root-state.json';m.time.time=lambda:1740
m.read_private=lambda name,*args:json.loads(pathlib.Path(name).read_text())
m.subprocess.run=lambda args,**kwargs:types.SimpleNamespace(stdout=root,returncode=0)
def remove(directory,key):
 for suffix in ('','.partial'):
  try:os.unlink(directory+'/'+key+suffix)
  except FileNotFoundError:pass
 m.sync_directory(directory)
m.remove_bytes=remove
if sys.argv[3]=='down':
 def sql(statement):raise RuntimeError('DB_DOWN')
 m.sql=sql
else:m.sql=lambda statement:''
try:print(json.dumps(m.main()))
except Exception:print('{"status":"fixture_failure"}');sys.exit(1)
"""
            first = subprocess.run(
                [sys.executable, "-c", code, str(SOURCE), root, "down"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(first.returncode, 1)
            self.assertFalse(file.exists())
            second = subprocess.run(
                [sys.executable, "-c", code, str(SOURCE), root, "up"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(second.returncode, 0)
            self.assertFalse(json.loads(second.stdout)["webFenced"])
            self.assertEqual(
                json.loads((pathlib.Path(root) / "root-state.json").read_text())["pending"], {}
            )
