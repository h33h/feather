"""Prepare a pinned build context; does not build, pull or install by itself."""

import importlib.util, json, pathlib, re, shutil
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import controller.zsign_patch as patcher


def copy_guest_runtime(runner, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for path in runner.rglob("*"):
        relative = path.relative_to(runner)
        if (
            path.is_file()
            and path.suffix in (".py", ".txt")
            and str(relative) not in ("protocol/https_transport.py", "protocol/stdio.py")
            and (
                relative.parts[0] in ("guest", "protocol", "verification_core")
                or str(relative)
                in (
                    "runner_diagnostics.py",
                    "guest_stdio.py",
                    "guest_watchdog.py",
                    "requirements.txt",
                )
            )
        ):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)


def prepare_context(destination, source, *, base_image, trust_directory, public_config):
    if not re.fullmatch(
        r"python:3\.(11|12|13)(\.[0-9]+)?-slim-bookworm@sha256:[a-f0-9]{64}", base_image
    ):
        raise ValueError("APPROVED_BASE_IMAGE_DIGEST_REQUIRED")
    root = pathlib.Path(destination)
    if root.exists():
        raise ValueError("BUILD_CONTEXT_EXISTS")
    allowed = {
        "opensslPath",
        "zsignPath",
        "caFile",
        "intermediateFile",
        "certificateChainDer",
        "cmsSignerSha256",
    }
    if (
        set(public_config) != allowed
        or public_config["zsignPath"] != "/usr/local/bin/zsign"
        or public_config["opensslPath"] != "/usr/bin/openssl"
        or not isinstance(public_config["certificateChainDer"], list)
        or not 1 <= len(public_config["certificateChainDer"]) <= 5
        or not isinstance(public_config["cmsSignerSha256"], list)
        or not public_config["cmsSignerSha256"]
        or any(not re.fullmatch("[a-f0-9]{64}", pin) for pin in public_config["cmsSignerSha256"])
    ):
        raise ValueError("PUBLIC_IMAGE_TRUST_CONFIGURATION_REQUIRED")
    public_paths = [
        public_config["caFile"],
        public_config["intermediateFile"],
        *public_config["certificateChainDer"],
    ]
    certificates = {}
    trust = pathlib.Path(trust_directory).resolve()
    for path in public_paths:
        if (
            not isinstance(path, str)
            or not path.startswith("/opt/isign/trust/")
            or ".." in pathlib.PurePosixPath(path).parts
        ):
            raise ValueError("IMMUTABLE_PUBLIC_TRUST_PATH_REQUIRED")
        relative = path.removeprefix("/opt/isign/trust/")
        source_file = trust / relative
        if (
            source_file.is_symlink()
            or not source_file.is_file()
            or source_file.stat().st_size > 65536
            or source_file.suffix not in (".pem", ".der", ".cer", ".crt")
        ):
            raise ValueError("PUBLIC_CERTIFICATE_FILE_REQUIRED")
        raw = source_file.read_bytes()
        if b"PRIVATE KEY" in raw:
            raise ValueError("PUBLIC_CERTIFICATE_ONLY")
        try:
            if raw.startswith(b"-----BEGIN CERTIFICATE-----"):
                if (
                    raw.count(b"-----BEGIN CERTIFICATE-----") != 1
                    or raw.count(b"-----END CERTIFICATE-----") != 1
                ):
                    raise ValueError("CERTIFICATE_COUNT")
                if not re.fullmatch(
                    rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*",
                    raw,
                ):
                    raise ValueError("CERTIFICATE_TRAILING_DATA")
                certificate = x509.load_pem_x509_certificate(raw)
                raw = certificate.public_bytes(serialization.Encoding.PEM)
            else:
                certificate = x509.load_der_x509_certificate(raw)
                if certificate.public_bytes(serialization.Encoding.DER) != raw:
                    raise ValueError("CERTIFICATE_TRAILING_DATA")
        except ValueError as exc:
            raise ValueError("PUBLIC_CERTIFICATE_ONLY") from exc
        certificates[relative] = raw
    if any(path.is_symlink() for path in trust.rglob("*")) or {
        str(path.relative_to(trust)) for path in trust.rglob("*") if path.is_file()
    } != set(certificates):
        raise ValueError("EXTRA_TRUST_MATERIAL_REJECTED")
    root.mkdir(mode=0o700)
    patcher.patch(source, root / "zsign-source")
    runner = pathlib.Path(__file__).parent
    (root / "runner").mkdir()
    copy_guest_runtime(runner, root / "runner")
    for relative, raw in certificates.items():
        target = root / "trust" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o444)
    (root / "runner-config.json").write_text(json.dumps(public_config, sort_keys=True))
    shutil.copyfile(runner / "Dockerfile.linux", root / "Dockerfile")
    return [
        "docker",
        "build",
        "--pull=false",
        "--build-arg",
        "BASE_IMAGE=" + base_image,
        "--file",
        str(root / "Dockerfile"),
        str(root),
    ]
