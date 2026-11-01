"""Single-use guest analysis reuse; archive and staged-byte checks stay real."""

import copy
import hashlib
import io
import os
import pathlib
import tempfile
import time
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

from runner_modules import load
from test_runner_analyzer import archive


class SourceAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.controller = load("guest_controller")
        self.verification = load("verification")
        self.analyzer = self.controller.analyzer
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.raw = archive([("Payload/App.app/resource.txt", b"original")])
        self.source = self.root / "source.ipa"
        self.source.write_bytes(self.raw)
        self.analysis = self.analyzer.analyze_file(self.source)
        self.grant = dict(
            ownerId="owner",
            jobId="job",
            leaseToken="lease",
            connectionId="connection",
            connectionGeneration=1,
            deviceId="device",
            uploadDigest=hashlib.sha256(self.raw).hexdigest(),
            taskNonce="nonce",
            isolationInstanceId="instance",
            expiresAt=int(time.time() * 1000) + 60000,
        )
        self.task = dict(
            identity={"materialPath": "identity.p12"},
            profiles={},
            udid="device",
            components=copy.deepcopy(self.analysis["components"]),
        )
        self.verifier = self.verification.GuestVerifier.__new__(self.verification.GuestVerifier)
        self.verifier.root = self.root
        self.verifier.clock = lambda: int(time.time() * 1000)
        self.verifier.certificate = Mock(return_value=b"CERT")
        self.verifier.openssl_command = self.openssl
        self.plan_check = patch.object(
            self.verification.executor, "validate_plan", return_value=None
        )
        self.plan_check.start()
        self.addCleanup(self.plan_check.stop)

    def openssl(self, args, input_bytes=None):
        if args[0] == "pkcs12":
            if "-nokeys" in args:
                return b"-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
            return b"-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----"
        if args[0] == "pkey":
            return b"SPKI"
        if args[0] == "x509":
            return b"PUBLIC"
        raise AssertionError(args)

    def stage(self):
        with zipfile.ZipFile(io.BytesIO(self.raw)) as source:
            source.extractall(self.root)

    def verify(self, grant=None):
        return self.verifier.verify_materials(
            self.task, self.root, grant or self.grant, pkcs12_password="synthetic"
        )

    def context(self, *, analysis=None, grant=None, size=None):
        return self.verifier.execute_analysis(
            self.analysis if analysis is None else analysis,
            self.grant if grant is None else grant,
            len(self.raw) if size is None else size,
        )

    def test_controller_analyze_then_execute_parses_source_twice_not_three_times(self):
        app = self.controller.GuestController.__new__(self.controller.GuestController)
        app.root = self.root
        app.source = {"sha256": self.grant["uploadDigest"], "size": len(self.raw)}
        app.grant = Mock()
        app.runtime = SimpleNamespace(
            root=self.root,
            verifier=self.verifier,
            signed=lambda value: value,
            validate_source_format=Mock(),
            execute=lambda grant, task, proof: self.verify(grant),
        )
        with patch.object(
            self.analyzer, "analyze_file", wraps=self.analyzer.analyze_file
        ) as analyze:
            app.action("analyze", {"grant": self.grant, "proof": {}})
            result = app.action("execute", {"grant": self.grant, "proof": {}, "task": self.task})
        self.assertTrue(result["inputDigestExact"])
        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(app.runtime.validate_source_format.call_count, 2)
        self.assertIsNone(self.verifier._execute_analysis)

    def optional_source(self):
        from test_runner_optional_extensions import NOTIFICATION, WIDGET, extension

        self.raw = archive(
            extension(NOTIFICATION)
            + extension(WIDGET, point="com.apple.widgetkit-extension", encrypted=False)
            + [("Payload/App.app/resource.txt", b"original")]
        )
        self.source.write_bytes(self.raw)
        self.analysis = self.analyzer.analyze_file(self.source)
        self.grant["uploadDigest"] = hashlib.sha256(self.raw).hexdigest()
        self.task["components"] = copy.deepcopy(self.analysis["components"])
        self.task["removedExtensions"] = copy.deepcopy(self.analysis["removedExtensions"])
        app = self.controller.GuestController.__new__(self.controller.GuestController)
        app.root = self.root
        app.source = {"sha256": self.grant["uploadDigest"], "size": len(self.raw)}
        app.grant = Mock()
        app.runtime = SimpleNamespace(
            verifier=self.verifier, execute=lambda grant, task, proof: self.verify(grant)
        )
        return app, NOTIFICATION, WIDGET

    def test_extraction_omits_only_confirmed_extension_and_proves_remaining_original_bytes(self):
        app, notification, widget = self.optional_source()
        result = app.action("execute", {"grant": self.grant, "proof": {}, "task": self.task})
        self.assertTrue(result["inputDigestExact"])
        self.assertFalse((self.root / notification).exists())
        self.assertTrue((self.root / widget / "Extension").is_file())
        self.assertEqual((self.root / "Payload/App.app/resource.txt").read_bytes(), b"original")
        (self.root / "Payload/App.app/resource.txt").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "STAGED_SOURCE_BYTES_MISMATCH"):
            self.verify()

    def test_task_cannot_add_omit_or_substitute_source_extension_removals(self):
        app, notification, widget = self.optional_source()
        original = copy.deepcopy(self.task["removedExtensions"])
        for removed in ([], [{**original[0], "path": widget}], original + original):
            self.task["removedExtensions"] = removed
            with self.assertRaisesRegex(ValueError, "SOURCE_REMOVALS_MISMATCH"):
                app.action("execute", {"grant": self.grant, "proof": {}, "task": self.task})
            self.assertFalse((self.root / "Payload").exists())
            with self.assertRaisesRegex(ValueError, "SOURCE_REMOVALS_MISMATCH"):
                self.verify()

    def test_removed_extension_cannot_be_reintroduced_into_the_staged_tree(self):
        app, notification, widget = self.optional_source()
        app.action("execute", {"grant": self.grant, "proof": {}, "task": self.task})
        path = self.root / notification / "Extension"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"reintroduced")
        with self.assertRaisesRegex(ValueError, "STAGED_SOURCE_TREE_MISMATCH"):
            self.verify()

    def test_context_reuses_once_and_direct_verifier_falls_back_to_full_analysis(self):
        self.stage()
        with patch.object(
            self.verification.analyzer, "analyze_file", wraps=self.analyzer.analyze_file
        ) as analyze:
            with self.context():
                self.assertTrue(self.verify()["inputDigestExact"])
                with self.assertRaisesRegex(ValueError, "SOURCE_ANALYSIS_ALREADY_USED"):
                    self.verify()
            self.assertEqual(analyze.call_count, 0)
            self.verify()
            self.assertEqual(analyze.call_count, 1)

    def test_digest_and_size_bindings_are_checked_before_reuse(self):
        for change in ({"sha256": "0" * 64},):
            with (
                self.assertRaisesRegex(ValueError, "SOURCE_DIGEST_MISMATCH"),
                self.context(analysis={**self.analysis, **change}),
            ):
                pass
        with (
            self.assertRaisesRegex(ValueError, "SOURCE_SIZE_MISMATCH"),
            self.context(size=len(self.raw) + 1),
        ):
            pass
        self.source.write_bytes(self.raw[:-1] + bytes([self.raw[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "SOURCE_DIGEST_MISMATCH"), self.context():
            pass

    def test_wrong_job_or_upload_grant_cannot_consume_bound_analysis(self):
        self.stage()
        for key, value in (("jobId", "other-job"), ("uploadDigest", "0" * 64)):
            with self.context():
                with self.assertRaisesRegex(ValueError, "SOURCE_ANALYSIS_BINDING_MISMATCH"):
                    self.verify({**self.grant, key: value})

    def test_same_size_source_mutation_and_replacement_are_rejected(self):
        self.stage()
        with self.context():
            previous = self.source.stat()
            self.source.write_bytes(self.raw[:-1] + bytes([self.raw[-1] ^ 1]))
            os.utime(self.source, ns=(previous.st_atime_ns, previous.st_mtime_ns))
            with self.assertRaisesRegex(ValueError, "SOURCE_(CHANGED|DIGEST_MISMATCH)"):
                self.verify()
        self.source.write_bytes(self.raw)
        with self.context():
            self.source.unlink()
            self.source.write_bytes(self.raw)
            with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
                self.verify()

    def test_symlink_source_is_never_reused(self):
        self.stage()
        with self.context():
            original = self.root / "original.ipa"
            self.source.rename(original)
            self.source.symlink_to(original)
            with self.assertRaises((ValueError, OSError)):
                self.verify()
        with self.assertRaises((ValueError, OSError)), self.context():
            pass

    def test_context_clears_on_failure_and_report_is_not_aliased(self):
        with self.assertRaisesRegex(ValueError, "synthetic failure"), self.context():
            raise ValueError("synthetic failure")
        self.assertIsNone(self.verifier._execute_analysis)
        self.stage()
        with self.context():
            self.analysis["components"].clear()
            self.assertTrue(self.verify()["inputDigestExact"])

    def test_staged_bytes_and_source_claims_still_must_match(self):
        self.stage()
        resource = self.root / "Payload/App.app/resource.txt"
        with self.context():
            resource.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "STAGED_SOURCE_BYTES_MISMATCH"):
                self.verify()
        resource.write_bytes(b"original")
        self.task["components"][0]["sourceEntitlements"] = {"unavailable": True}
        with self.context():
            with self.assertRaisesRegex(ValueError, "SOURCE_ENTITLEMENTS_MISMATCH"):
                self.verify()

    def test_analyze_detects_mutation_even_if_file_size_is_unchanged(self):
        original = self.analyzer._analyze

        def mutate(*args, **kwargs):
            result = original(*args, **kwargs)
            self.source.write_bytes(self.raw[:-1] + bytes([self.raw[-1] ^ 1]))
            return result

        with patch.object(self.analyzer, "_analyze", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
                self.analyzer.analyze_file(self.source)

    def test_mutation_during_staged_proof_is_detected(self):
        self.stage()
        original = self.verifier._check_source

        def mutate(*args, **kwargs):
            stamp = original(*args, **kwargs)
            self.source.write_bytes(self.raw)
            return stamp

        with self.context(), patch.object(self.verifier, "_check_source", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
                self.verify()

    def test_missing_staged_member_still_fails(self):
        self.stage()
        (self.root / "Payload/App.app/resource.txt").unlink()
        with self.context(), self.assertRaisesRegex(ValueError, "STAGED_SOURCE_TREE_MISMATCH"):
            self.verify()

    def test_final_archive_analysis_does_not_use_execute_context(self):
        self.verifier.verify_component = Mock(return_value={})
        with (
            self.context(),
            patch.object(
                self.verification.analyzer, "analyze_file", wraps=self.analyzer.analyze_file
            ) as analyze,
        ):
            self.verifier.verify_archive(self.source, self.task, self.grant)
            self.assertEqual(analyze.call_count, 1)
            self.assertIs(analyze.call_args.kwargs["allow_verified_der"], True)
            self.assertEqual(self.verifier.verify_component.call_count, 1)
            self.assertFalse(self.verifier._execute_analysis["used"])

    def test_controller_clears_context_and_closes_source_when_runtime_fails(self):
        app = self.controller.GuestController.__new__(self.controller.GuestController)
        app.root = self.root
        app.source = {"sha256": self.grant["uploadDigest"], "size": len(self.raw)}
        app.grant = Mock()
        opened = []

        def fail(*args):
            opened.append(self.verifier._execute_analysis["source"])
            raise ValueError("synthetic failure")

        app.runtime = SimpleNamespace(root=self.root, verifier=self.verifier, execute=fail)
        with self.assertRaisesRegex(ValueError, "synthetic failure"):
            app.action("execute", {"grant": self.grant, "proof": {}, "task": self.task})
        self.assertIsNone(self.verifier._execute_analysis)
        self.assertTrue(opened[0].closed)

    def test_controller_rejects_upload_size_or_analysis_digest_before_extraction(self):
        app = self.controller.GuestController.__new__(self.controller.GuestController)
        app.root = self.root
        app.source = {"sha256": self.grant["uploadDigest"], "size": len(self.raw) + 1}
        app.grant = Mock()
        app.runtime = SimpleNamespace(root=self.root, verifier=self.verifier, execute=Mock())
        payload = {"grant": self.grant, "proof": {}, "task": self.task}
        with self.assertRaisesRegex(ValueError, "SOURCE_SIZE_MISMATCH"):
            app.action("execute", payload)
        app.source["size"] = len(self.raw)
        with patch.object(
            self.analyzer, "analyze_file", return_value={**self.analysis, "sha256": "0" * 64}
        ):
            with self.assertRaisesRegex(ValueError, "SOURCE_DIGEST_MISMATCH"):
                app.action("execute", payload)
        self.assertFalse((self.root / "Payload").exists())
        app.runtime.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
