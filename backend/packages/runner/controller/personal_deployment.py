"""Explicit personal broker composition. Import performs no provisioning or listening.

Only an approved operator supplies private config/credentials. Every guest uses the
same inspected gVisor backend and 21GiB allocator admission, including bootstrap/profile verification.
"""

import http.client, ipaddress, json, os, pathlib, re, ssl, stat, urllib.parse, socket


def private_bytes(file, maximum):
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > maximum
        ):
            raise ValueError("PRIVATE_DEPLOYMENT_FILE_REQUIRED")
        return os.read(fd, maximum + 1)
    finally:
        os.close(fd)


def validate_config(config):
    required = {
        "origin",
        "authorizerAddress",
        "authorizerPort",
        "authorizerCertificateSha256",
        "authorizerCaFile",
        "tokenFile",
        "proofKeyFile",
        "audience",
        "dockerPath",
        "losetupPath",
        "mkfsPath",
        "runscPath",
        "runscSha256",
        "imageDigest",
        "stateDirectory",
        "scratchDirectory",
    }
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError("PERSONAL_BROKER_CONFIG_INVALID")
    origin = urllib.parse.urlsplit(config["origin"])
    if (
        origin.scheme != "https"
        or origin.path
        or origin.query
        or origin.fragment
        or origin.username
        or origin.password
        or origin.port
        or not origin.hostname
    ):
        raise ValueError("PERSONAL_ORIGIN_INVALID")
    address = ipaddress.ip_address(config["authorizerAddress"])
    if (
        not address.is_loopback
        or type(config["authorizerPort"]) is not int
        or not 1024 <= config["authorizerPort"] <= 65535
    ):
        raise ValueError("PRIVATE_AUTHORIZER_REQUIRED")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", config["imageDigest"]) or any(
        not re.fullmatch("[a-f0-9]{64}", config[k])
        for k in ("runscSha256", "authorizerCertificateSha256")
    ):
        raise ValueError("DEPLOYMENT_PINS_REQUIRED")
    if not re.fullmatch("[a-zA-Z0-9:_-]{1,100}", config["audience"]):
        raise ValueError("DEPLOYMENT_AUDIENCE_INVALID")
    for key in required - {
        "origin",
        "authorizerAddress",
        "authorizerPort",
        "authorizerCertificateSha256",
        "audience",
        "runscSha256",
        "imageDigest",
    }:
        if not isinstance(config[key], str) or not pathlib.Path(config[key]).is_absolute():
            raise ValueError("DEPLOYMENT_ABSOLUTE_PATH_REQUIRED")
    return config


class LoopbackHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        # Socket address is loopback, while SNI/hostname verification remains canonical.
        sock = self._create_connection(
            (self.private_address, self.port), self.timeout, self.source_address
        )
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def authorizer_transport(config, token):
    import protocol.https_transport as transport

    origin = urllib.parse.urlsplit(config["origin"])
    context = ssl.create_default_context(cafile=config["authorizerCaFile"])

    def connection(host, port, **kwargs):
        result = LoopbackHTTPSConnection(host, port, **kwargs)
        result.private_address = config["authorizerAddress"]
        return result

    class CanonicalHostPinnedHTTPS(transport.PinnedHTTPS):
        def request(self, path, body, **kwargs):
            kwargs["headers"] = {**kwargs.get("headers", {}), "Host": origin.netloc}
            return super().request(path, body, **kwargs)

    return CanonicalHostPinnedHTTPS(
        config["origin"] + ":" + str(config["authorizerPort"]),
        token=token,
        audience=config["audience"],
        certificate_sha256=config["authorizerCertificateSha256"],
        ssl_context=context,
        connection_factory=connection,
        reuse_connections=True,
    )


def recovered_broker(config_file=None):
    config = validate_config(
        json.loads(
            private_bytes(
                config_file
                or os.environ.get(
                    "ISIGN_PERSONAL_BROKER_CONFIG", "/etc/isign/personal-broker.json"
                ),
                16384,
            )
        )
    )
    token = private_bytes(config["tokenFile"], 128).decode().strip()
    key = private_bytes(config["proofKeyFile"], 32)
    if len(token) < 32 or len(key) != 32:
        raise ValueError("BROKER_CREDENTIALS_INVALID")
    for directory in (config["stateDirectory"], config["scratchDirectory"]):
        info = pathlib.Path(directory).lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or pathlib.Path(directory).resolve() != pathlib.Path(directory)
        ):
            raise ValueError("PRIVATE_BROKER_DIRECTORY_REQUIRED")
    import controller.container_backend as backend_module
    import controller.disk_budget as disk_module
    import controller.stdio_backend as channel_module
    import controller.broker as broker_module
    import protocol.https_transport as transport_module

    disk = disk_module.LoopbackJobDisk(
        config["scratchDirectory"],
        docker_path=config["dockerPath"],
        losetup_path=config["losetupPath"],
        mkfs_path=config["mkfsPath"],
        host_free_required=21 << 30,
    )
    backend = backend_module.ContainerBackend(
        docker_path=config["dockerPath"],
        image_digest=config["imageDigest"],
        cli=backend_module.DockerCLI(config["dockerPath"]),
        guest_channel=channel_module.DockerStdioGuestChannel(config["dockerPath"]),
        proof_key_provider=lambda: key,
        proof_key_id="personal-controller",
        runsc_path=config["runscPath"],
        runsc_digest=config["runscSha256"],
        state_lock_path=str(pathlib.Path(config["stateDirectory"]) / "controller.lock"),
        disk_allocator=disk,
    )
    state = broker_module.SQLiteBrokerState(
        str(pathlib.Path(config["stateDirectory"]) / "broker.sqlite")
    )
    authorizer = transport_module.HttpBindingAuthorizer(authorizer_transport(config, token), key)
    # Apple planning and certificate lookup/creation remain in the lease-scoped web
    # provisioner; these flags enable only the authenticated sealed guest bridges.
    broker = broker_module.BrokerController(
        token=token,
        audience=config["audience"],
        proof_key=key,
        state=state,
        backend=backend,
        authorize_binding=authorizer,
        sealed_materials_bridge=True,
        bootstrap_bridge=True,
    )
    broker.recover()
    return broker
