"""Controller-only runsc lifecycle. No IPA parsing, host mounts or network."""

import hashlib, hmac, importlib.util, json, pathlib, re, secrets, subprocess, time, threading, os, fcntl, stat


import protocol.proofs as native
import controller.disk_budget as disk_budget

canonical = native.canonical


class DockerCLI:
    def __init__(self, binary, run=None):
        if not pathlib.Path(binary).is_absolute():
            raise ValueError("DOCKER_BINARY_REQUIRED")
        self.binary = binary
        self.transport = run

    def run(self, args, *, timeout=120):
        if (
            args[0] != self.binary
            or args[1] not in ("run", "inspect", "rm", "info", "ps")
            or timeout > 120
        ):
            raise ValueError("DOCKER_COMMAND_REJECTED")
        if self.transport:
            return self.transport(args, timeout=timeout)
        result = subprocess.run(
            args,
            cwd="/tmp",
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if len(result.stdout) > 4 << 20 or len(result.stderr) > 4 << 20:
            raise ValueError("DOCKER_OUTPUT_LIMIT")
        return {"exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


class ContainerBackend:
    def __init__(
        self,
        *,
        docker_path,
        image_digest,
        cli,
        guest_channel,
        proof_key_provider,
        proof_key_id,
        runsc_path,
        runsc_digest,
        state_lock_path,
        disk_allocator=None,
        clock=lambda: int(time.time() * 1000),
    ):
        if (
            not re.fullmatch("sha256:[a-f0-9]{64}", image_digest)
            or not all(callable(f) for f in (proof_key_provider,))
            or not all(
                callable(getattr(guest_channel, n, None))
                for n in ("authenticate", "send_source", "analyze", "execute", "artifact", "revoke")
            )
        ):
            raise ValueError("GVISOR_BACKEND_CONFIGURATION_REQUIRED")
        if disk_allocator is None or any(
            not callable(getattr(disk_allocator, n, None))
            for n in ("allocate", "verify", "destroy", "recover", "pending", "close")
        ):
            raise ValueError("HARD_PRIVATE_DISK_ALLOCATOR_REQUIRED")
        self.disk_allocator = disk_allocator
        self.path = docker_path
        self.image = image_digest
        self.cli = cli
        self.channel = guest_channel
        self.key_provider = proof_key_provider
        self.key_id = proof_key_id
        self.clock = clock
        self.handles = {}
        self.runsc = runsc_path
        self.runsc_digest = runsc_digest
        self.lock = threading.Lock()
        self.label = "isign.runner=" + hashlib.sha256(proof_key_provider()).hexdigest()[:24]
        if not pathlib.Path(runsc_path).is_absolute() or not re.fullmatch(
            "[a-f0-9]{64}", runsc_digest
        ):
            raise ValueError("PINNED_RUNSC_REQUIRED")
        if not pathlib.Path(state_lock_path).is_absolute():
            raise ValueError("GLOBAL_CONTROLLER_LOCK_PATH_REQUIRED")
        self.lock_fd = os.open(state_lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("PRIVATE_CONTROLLER_LOCK_REQUIRED")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise ValueError("SINGLE_CONTROLLER_ALREADY_ACTIVE")

    def close(self):
        if getattr(self, "handles", {}):
            return False
        fd = getattr(self, "lock_fd", None)
        if fd is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            self.lock_fd = None
        self.disk_allocator.close()
        return True

    def inspect(self, handle):
        result = self.cli.run([self.path, "inspect", "--type=container", handle["id"]], timeout=30)
        data = json.loads(result["stdout"])
        item = data[0] if isinstance(data, list) and len(data) == 1 else None
        if not isinstance(item, dict):
            raise ValueError("CONTAINER_INSPECTION_INVALID")
        config = item["HostConfig"]
        user = item["Config"].get("User")
        mounts = item.get("Mounts", [])
        if (
            len(mounts) > 2
            or len({m.get("Destination") for m in mounts}) != len(mounts)
            or config.get("DeviceRequests") not in (None, [])
            or config.get("DeviceCgroupRules") not in (None, [])
        ):
            raise ValueError("PRIVATE_DISK_MOUNTS_AND_NO_DEVICES_REQUIRED")
        if (
            item.get("Image") != self.image
            or item["Config"].get("Image") != self.image
            or config.get("Runtime") != "runsc"
            or config.get("NetworkMode") != "none"
            or config.get("ReadonlyRootfs") is not True
            or user != "65532:65532"
            or config.get("Privileged") is not False
            or config.get("CapAdd") not in (None, [])
            or config.get("CapDrop") != ["ALL"]
            or "no-new-privileges:true" not in config.get("SecurityOpt", [])
            or config.get("PidsLimit") != 128
            or config.get("Memory") != 4 << 30
            or config.get("MemorySwap") != 4 << 30
            or config.get("NanoCpus") != 2000000000
            or config.get("Binds") not in (None, [])
            or any(
                not (
                    (
                        m.get("Type") == "volume"
                        and m.get("Name") == handle["id"]
                        and m.get("Driver") == "local"
                        and m.get("Destination") == "/job"
                        and m.get("RW") is True
                    )
                    or (m.get("Type") == "tmpfs" and m.get("Destination") == "/tmp")
                )
                for m in mounts
            )
            or sum(m.get("Destination") == "/job" for m in mounts) != 1
            or config.get("Tmpfs") != {"/tmp": "rw,nosuid,nodev,noexec,size=268435456,mode=1777"}
            or item.get("State", {}).get("Running") is not True
        ):
            raise ValueError("HARDENED_GVISOR_INSPECTION_REQUIRED")
        if (
            item["Config"].get("Entrypoint") != ["/usr/local/bin/python3"]
            or item["Config"].get("Cmd") != ["/opt/isign/runner/guest_watchdog.py"]
            or "ISIGN_INSTANCE_DEADLINE_MS=" + str(handle["expiresAt"])
            not in item["Config"].get("Env", [])
            or config.get("PidMode", "") not in ("", None)
            or config.get("IpcMode") not in ("private", "")
            or config.get("Devices") not in (None, [])
            or config.get("VolumesFrom") not in (None, [])
        ):
            raise ValueError("CONTAINER_WATCHDOG_OR_NAMESPACE_REQUIRED")
        if self.disk_allocator.verify(handle["disk"]) is not True:
            raise ValueError("HARD_PRIVATE_DISK_REQUIRED")
        return {"type": "gvisor", "runtime": "runsc", **{k: True for k in native.LINUX_ISOLATION}}

    def check_ready(self):
        result = self.cli.run([self.path, "info", "--format", "{{json .Runtimes}}"], timeout=10)
        if result.get("exitCode") != 0:
            raise ValueError("DOCKER_RUNTIME_UNAVAILABLE")
        info = json.loads(result["stdout"])
        if (
            info.get("runsc", {}).get("path") != self.runsc
            or hashlib.sha256(pathlib.Path(self.runsc).read_bytes()).hexdigest()
            != self.runsc_digest
        ):
            raise ValueError("ACTUAL_PINNED_RUNSC_REQUIRED")
        result = self.cli.run([self.path, "inspect", "--type=image", self.image], timeout=10)
        if result.get("exitCode") != 0:
            raise ValueError("PINNED_GUEST_IMAGE_REQUIRED")
        images = json.loads(result["stdout"])
        image = images[0] if isinstance(images, list) and len(images) == 1 else None
        if (
            not isinstance(image, dict)
            or image.get("Id") != self.image
            or image.get("Config", {}).get("User") != "65532:65532"
            or image.get("Config", {}).get("Entrypoint") != ["/usr/local/bin/python3"]
            or image.get("Config", {}).get("Cmd") != ["/opt/isign/runner/guest_watchdog.py"]
        ):
            raise ValueError("PINNED_GUEST_IMAGE_REQUIRED")
        return True

    def launch(self, request):
        self.check_ready()
        name = "isign-" + secrets.token_hex(16)
        handle = {
            "id": name,
            "binding": {"ownerId": request["ownerId"], "jobId": request["jobId"]},
            "expiresAt": self.clock() + request["maxRuntimeMs"],
            "jobKey": secrets.token_bytes(32),
            "dead": False,
            "channel": None,
            "request": dict(request),
            "disk": None,
        }
        with self.lock:
            if self.handles:
                raise ValueError("GLOBAL_EXECUTOR_SLOT_UNAVAILABLE")
            existing = self.cli.run(
                [
                    self.path,
                    "ps",
                    "--all",
                    "--filter",
                    "label=" + self.label,
                    "--format",
                    "{{.Names}}",
                ],
                timeout=30,
            )
            if existing.get("exitCode") != 0 or existing.get("stdout", b"").strip():
                raise ValueError("CONTAINER_RECOVERY_REQUIRED")
            self.handles[name] = handle
        args = [
            self.path,
            "run",
            "--detach",
            "--pull=never",
            "--name",
            name,
            "--label",
            self.label,
            "--runtime=runsc",
            "--network=none",
            "--read-only",
            "--user=65532:65532",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=128",
            "--memory=4g",
            "--memory-swap=4g",
            "--cpus=2",
            "--mount",
            "type=volume,src=" + name + ",dst=/job,volume-nocopy",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=268435456,mode=1777",
            "--env",
            "ISIGN_INSTANCE_DEADLINE_MS=" + str(handle["expiresAt"]),
            "--entrypoint",
            "/usr/local/bin/python3",
            self.image,
            "/opt/isign/runner/guest_watchdog.py",
        ]
        try:
            handle["disk"] = self.disk_allocator.allocate(name)
            if self.cli.run(args).get("exitCode") != 0:
                raise ValueError("GVISOR_LAUNCH_FAILED")
            handle["evidence"] = self.inspect(handle)
            session = self.channel.authenticate(
                name,
                {
                    **request,
                    "identity": {
                        **handle["binding"],
                        "instanceId": name,
                        "expiresAt": handle["expiresAt"],
                    },
                    "evidence": handle["evidence"],
                    "jobKey": handle["jobKey"],
                },
            )
            handle["channel"] = session["channel"]
            self.handles[name] = handle
            return handle
        except Exception:
            self.destroy(handle)
            raise

    def verify_instance(self, handle, request):
        return (
            not handle["dead"]
            and handle["request"] == request
            and self.inspect(handle) == handle["evidence"]
        )

    def proof(self, handle, grant):
        if (
            handle["dead"]
            or grant["expiresAt"] > handle["expiresAt"]
            or grant["isolationInstanceId"] != handle["id"]
            or any(grant[k] != value for k, value in handle["binding"].items())
            or self.inspect(handle) != handle["evidence"]
        ):
            raise ValueError("CONTAINER_GRANT_REJECTED")
        return native.issue_vm_proof(grant, handle["evidence"], handle["jobKey"], self.key_id)

    def upload_source(self, handle, chunks, digest):
        return self.channel.send_source(
            handle["channel"], chunks, digest, max_bytes=handle["request"]["maxInputBytes"]
        )

    def record(self, handle, envelope, grant):
        report = envelope.get("report", {})
        signature = envelope.get("attestation")
        signature = signature.get("signature") if isinstance(signature, dict) else signature
        if (
            any(report.get(k) != value for k, value in grant.items())
            or not isinstance(signature, str)
            or not hmac.compare_digest(
                hmac.new(handle["jobKey"], canonical(report), hashlib.sha256).hexdigest(), signature
            )
        ):
            raise ValueError("JOB_REPORT_UNTRUSTED")
        handle["verifiedReport"] = canonical(report)
        return report

    def analyze(self, handle, grant):
        return self.record(
            handle, self.channel.analyze(handle["channel"], grant, self.proof(handle, grant)), grant
        )

    def execute(self, handle, grant, task):
        envelope = self.channel.execute(handle["channel"], grant, task, self.proof(handle, grant))
        report = self.record(handle, envelope, grant)
        if report.get("planDigest") != hashlib.sha256(canonical(task)).hexdigest():
            raise ValueError("PLAN_DIGEST_MISMATCH")
        return {"report": report, "artifactRef": envelope["artifactRef"]}

    def verify_guest_report(self, report, grant, task):
        handle = self.handles.get(grant["isolationInstanceId"])
        return (
            handle is not None
            and not handle["dead"]
            and handle.get("verifiedReport") == canonical(report)
        )

    def artifact(self, handle, ref):
        return self.channel.artifact(handle["channel"], ref)

    def material_prepare(self, handle, grant, payload):
        result = self.channel.material_prepare(
            handle["channel"], grant, payload, self.proof(handle, grant)
        )
        report = result["report"]
        if (
            report.get("binding") != grant
            or report.get("payloadDigest") != hashlib.sha256(canonical(payload)).hexdigest()
            or not hmac.compare_digest(
                hmac.new(handle["jobKey"], canonical(report), hashlib.sha256).hexdigest(),
                result["attestation"],
            )
        ):
            raise ValueError("JOB_MATERIAL_REPORT_UNTRUSTED")
        return {
            "report": report,
            "attestation": hmac.new(
                self.key_provider(), canonical(report), hashlib.sha256
            ).hexdigest(),
        }

    def control_grant(self, handle, binding, operation):
        prefix = "bootstrap:" if operation == "bootstrap-request" else "device-eligibility:"
        if handle["binding"] != {"ownerId": binding["ownerId"], "jobId": prefix + binding["nonce"]}:
            raise ValueError("CONTROL_INSTANCE_BINDING_MISMATCH")
        grant = {
            "ownerId": binding["ownerId"],
            "connectionOwnerId": binding["ownerId"]
            if operation == "bootstrap-request"
            else binding["connectionOwnerId"],
            "jobId": handle["binding"]["jobId"],
            "leaseToken": binding["nonce"],
            "connectionId": binding["connectionId"],
            "connectionGeneration": binding["generation"],
            "taskNonce": binding["nonce"],
            "isolationInstanceId": handle["id"],
            "expiresAt": min(binding["expiresAt"], handle["expiresAt"]),
            "operation": operation,
            **{k: binding[k] for k in ("accessGrantId", "accessGrantGeneration") if k in binding},
        }
        return grant, self.proof(handle, grant)

    def device_profile_verify(self, handle, binding, payload):
        grant, proof = self.control_grant(handle, binding, "device-profile-verify")
        result = self.channel.device_profile_verify(
            handle["channel"], binding, payload, grant, proof
        )
        report = result["report"]
        if (
            report.get("binding") != binding
            or report.get("instanceId") != handle["id"]
            or report.get("expected") != payload["expected"]
            or not hmac.compare_digest(
                hmac.new(handle["jobKey"], canonical(report), hashlib.sha256).hexdigest(),
                result["attestation"],
            )
        ):
            raise ValueError("DEVICE_PROFILE_JOB_REPORT_UNTRUSTED")
        return {
            "report": report,
            "attestation": hmac.new(
                self.key_provider(), canonical(report), hashlib.sha256
            ).hexdigest(),
        }

    def bootstrap_prepare(self, handle, binding, payload):
        original = payload["sealGrant"]
        unsigned = {k: value for k, value in original.items() if k != "signature"}
        master = self.key_provider()
        signature = hmac.new(
            master, b"isign-bootstrap-grant-v1\0" + canonical(unsigned), hashlib.sha256
        ).hexdigest()
        if (
            original.get("lease") != binding
            or original.get("instanceId") != handle["id"]
            or not hmac.compare_digest(signature, original.get("signature", ""))
        ):
            raise ValueError("CONTROLLER_BOOTSTRAP_SEAL_GRANT_REQUIRED")
        grant, proof = self.control_grant(handle, binding, "bootstrap-request")
        grant["expiresAt"] = min(grant["expiresAt"], original["expiresAt"])
        proof = self.proof(handle, grant)
        delegation = {"binding": binding, "instanceId": handle["id"], "grant": original}
        forward = {
            **payload,
            "sealAttestation": hmac.new(
                handle["jobKey"],
                b"isign-linux-seal-delegation-v1\0" + canonical(delegation),
                hashlib.sha256,
            ).hexdigest(),
        }
        result = self.channel.bootstrap_prepare(handle["channel"], binding, forward, grant, proof)
        report = result["report"]
        domain = b"isign-bootstrap-envelope-v1\0"
        if report.get("grant") != original or not hmac.compare_digest(
            hmac.new(handle["jobKey"], domain + canonical(report), hashlib.sha256).hexdigest(),
            result["attestation"],
        ):
            raise ValueError("BOOTSTRAP_JOB_RECEIPT_UNTRUSTED")
        return {
            "report": report,
            "attestation": hmac.new(master, domain + canonical(report), hashlib.sha256).hexdigest(),
        }

    def retire_launch(self, nonce):
        with self.lock:
            handles = [
                handle
                for handle in self.handles.values()
                if handle.get("request", {}).get("nonce") == nonce
            ]
        for handle in handles:
            if self.destroy(handle) is not True:
                return False
        return True

    def destroy(self, handle):
        handle["dead"] = True
        if handle.get("channel"):
            abort = getattr(self.channel, "abort", None)
            if callable(abort):
                try:
                    abort(handle["channel"])
                except Exception:
                    pass
        try:
            self.cli.run([self.path, "rm", "--force", handle["id"]], timeout=120)
            result = self.cli.run(
                [self.path, "inspect", "--type=container", handle["id"]], timeout=30
            )
            missing = result.get("stderr", b"").strip()
            confirmed = result.get("exitCode") == 1 and (
                (
                    missing
                    == ("Error response from daemon: No such container: " + handle["id"]).encode()
                    and result.get("stdout", b"").strip() == b"[]"
                )
                or (
                    missing == ("Error: No such object: " + handle["id"]).encode()
                    and not result.get("stdout", b"").strip()
                )
            )
            if confirmed:
                disk_clean = (
                    self.disk_allocator.destroy(handle["disk"])
                    if handle.get("disk")
                    else self.disk_allocator.recover(handle["id"])
                )
                if disk_clean is not True:
                    return False
                handle["jobKey"] = b""
                handle["channel"] = None
                with self.lock:
                    self.handles.pop(handle["id"], None)
            return confirmed
        except Exception:
            return False

    def recover_destroy(self, instance_id, metadata):
        if not re.fullmatch("isign-[a-f0-9]{32}", instance_id):
            raise ValueError("CONTAINER_RECOVERY_ID_INVALID")
        return self.destroy({"id": instance_id, "dead": True, "channel": None})

    def recover_orphans(self):
        """Recover the allocation/launch window before broker-state persistence."""
        names = self.cli.run(
            [self.path, "ps", "--all", "--filter", "label=" + self.label, "--format", "{{.Names}}"],
            timeout=30,
        )
        if names.get("exitCode") != 0:
            raise ValueError("CONTAINER_RECOVERY_REQUIRED")
        pending = set(names["stdout"].decode().splitlines()) | set(self.disk_allocator.pending())
        for name in pending:
            if self.recover_destroy(name, {}) is not True:
                raise ValueError("ORPHAN_DESTRUCTION_UNCONFIRMED")
