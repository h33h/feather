"""Trusted Linux controller allocator for fresh fixed-size ext4 job volumes.

Requires separately approved privileged host setup. No commands run on import.
The loop device exposes at most JOB_DISK_BYTES regardless of backing-host quota.
No host directory or device is passed into the guest.
"""

import fcntl, json, os, pathlib, re, stat, struct, subprocess

JOB_DISK_BYTES = 12 << 30
HOST_FREE_REQUIRED = 16 << 30
VOLUME_OPTIONS = "rw,nosuid,nodev,noexec"


class LoopbackJobDisk:
    def __init__(
        self,
        directory,
        *,
        docker_path,
        losetup_path,
        mkfs_path,
        run=None,
        host_free_required=HOST_FREE_REQUIRED,
    ):
        if type(host_free_required) is not int or host_free_required < HOST_FREE_REQUIRED:
            raise ValueError("HOST_BUDGET_POLICY_INVALID")
        self.host_free_required = host_free_required
        self.root = pathlib.Path(directory).absolute()
        self.docker = docker_path
        self.losetup = losetup_path
        self.mkfs = mkfs_path
        self.run = run or self._run
        self.tools = (self.docker, self.losetup, self.mkfs)
        if any(not pathlib.Path(p).is_absolute() for p in self.tools):
            raise ValueError("TRUSTED_DISK_TOOLS_REQUIRED")
        info = self.root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or self.root.resolve() != self.root
        ):
            raise ValueError("PRIVATE_DISK_ALLOCATOR_DIRECTORY_REQUIRED")
        if run is None:
            if os.geteuid() != 0 or os.uname().sysname != "Linux":
                raise ValueError("APPROVED_PRIVILEGED_LINUX_ALLOCATOR_REQUIRED")
            for path in self.tools:
                tool = pathlib.Path(path).stat()
                if not stat.S_ISREG(tool.st_mode) or tool.st_uid != 0 or tool.st_mode & 0o022:
                    raise ValueError("TRUSTED_DISK_TOOLS_REQUIRED")
            loop_control = pathlib.Path("/dev/loop-control").stat()
            if not stat.S_ISCHR(loop_control.st_mode):
                raise ValueError("LOOP_FILESYSTEM_PREREQUISITE_REQUIRED")
            capabilities = int(
                next(
                    line.split()[1]
                    for line in pathlib.Path("/proc/self/status").read_text().splitlines()
                    if line.startswith("CapEff:")
                ),
                16,
            )
            if not capabilities & (1 << 21):
                raise ValueError("APPROVED_SYS_ADMIN_ALLOCATOR_REQUIRED")
            # An existing allocation must be recoverable even when it consumes
            # the free-space reserve. allocate() always checks the budget again.
            if not self.pending():
                self._host_budget()
        self.lock_fd = os.open(
            self.root / "allocator.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("PRIVATE_ALLOCATOR_LOCK_REQUIRED")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise

    def close(self):
        if self.lock_fd is not None:
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            os.close(self.lock_fd)
            self.lock_fd = None

    def pending(self):
        return [path.stem for path in self.root.glob("isign-*.ext4")]

    def _host_budget(self):
        info = os.statvfs(self.root)
        if info.f_bavail * info.f_frsize < self.host_free_required:
            raise ValueError("JOB_DISK_HOST_BUDGET_REQUIRED")

    @staticmethod
    def _run(args):
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            shell=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        )
        if len(result.stdout) > 1 << 20 or len(result.stderr) > 1 << 20:
            raise ValueError("DISK_COMMAND_OUTPUT_LIMIT")
        if result.returncode:
            raise ValueError("DISK_COMMAND_FAILED")
        return result.stdout

    def _path(self, name):
        if not re.fullmatch("isign-[a-f0-9]{32}", name):
            raise ValueError("DISK_INSTANCE_ID_INVALID")
        return self.root / (name + ".ext4")

    def allocate(self, name):
        path = self._path(name)
        disk = {"name": name, "path": str(path), "device": None}
        self._host_budget()
        if self.pending():
            raise ValueError("PRIVATE_DISK_RECOVERY_REQUIRED")
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            # Reserve actual host extents, rather than overcommit a sparse file.
            os.posix_fallocate(fd, 0, JOB_DISK_BYTES)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            path.unlink(missing_ok=True)
            raise
        else:
            os.close(fd)
        try:
            device = self.run([self.losetup, "--find", "--show", str(path)]).decode().strip()
            if not re.fullmatch("/dev/loop[0-9]+", device):
                raise ValueError("PRIVATE_LOOP_DEVICE_REQUIRED")
            disk["device"] = device
            self.run(
                [
                    self.mkfs,
                    "-q",
                    "-t",
                    "ext4",
                    "-m",
                    "0",
                    "-E",
                    "nodiscard,lazy_itable_init=0,lazy_journal_init=0,root_owner=65532:65532",
                    device,
                ]
            )
            # Formatting/zeroout may punch holes through a loop device. Complete
            # all initialization first, then reserve those extents again without
            # changing filesystem bytes; no background lazy zeroout remains.
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                os.posix_fallocate(fd, 0, JOB_DISK_BYTES)
                os.fsync(fd)
            finally:
                os.close(fd)
            self.run(
                [
                    self.docker,
                    "volume",
                    "create",
                    "--driver",
                    "local",
                    "--label",
                    "isign.job=" + name,
                    "--opt",
                    "type=ext4",
                    "--opt",
                    "device=" + device,
                    "--opt",
                    "o=" + VOLUME_OPTIONS,
                    name,
                ]
            )
            if self.verify(disk) is not True:
                raise ValueError("HARD_JOB_DISK_REQUIRED")
            return disk
        except BaseException:
            # Preserve allocator metadata if cleanup cannot be confirmed.
            self.destroy(disk)
            raise

    def verify(self, disk):
        path = self._path(disk["name"])
        info = path.lstat()
        if (
            str(path) != disk["path"]
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size != JOB_DISK_BYTES
            or info.st_blocks * 512 < JOB_DISK_BYTES
        ):
            raise ValueError("PREALLOCATED_FIXED_DISK_REQUIRED")
        loops = json.loads(self.run([self.losetup, "--json", "--list", disk["device"]]))[
            "loopdevices"
        ]
        if (
            len(loops) != 1
            or loops[0].get("name") != disk["device"]
            or loops[0].get("back-file") != str(path)
            or loops[0].get("offset") != 0
            or loops[0].get("sizelimit") not in (0, JOB_DISK_BYTES)
            or loops[0].get("ro") not in (False, 0)
        ):
            raise ValueError("EXACT_LOOP_BACKING_REQUIRED")
        with open(disk["device"], "rb", buffering=0) as block:
            if not stat.S_ISBLK(os.fstat(block.fileno()).st_mode):
                raise ValueError("LOOP_BLOCK_DEVICE_REQUIRED")
            capacity = struct.unpack("Q", fcntl.ioctl(block, 0x80081272, b"\0" * 8))[0]
            if capacity != JOB_DISK_BYTES:
                raise ValueError("LOOP_CAPACITY_REQUIRED")
            block.seek(1024)
            superblock = block.read(1024)
            if len(superblock) != 1024 or superblock[56:58] != b"\x53\xef":
                raise ValueError("EXT4_JOB_FILESYSTEM_REQUIRED")
            blocks = struct.unpack_from("<I", superblock, 4)[0]
            if struct.unpack_from("<I", superblock, 96)[0] & 128:
                blocks |= struct.unpack_from("<I", superblock, 336)[0] << 32
            exponent = struct.unpack_from("<I", superblock, 24)[0]
            if exponent > 6:
                raise ValueError("EXT4_BLOCK_SIZE_INVALID")
            blocksize = 1024 << exponent
            if blocks * blocksize != JOB_DISK_BYTES:
                raise ValueError("EXT4_CAPACITY_REQUIRED")
        volume = json.loads(self.run([self.docker, "volume", "inspect", disk["name"]]))
        if (
            len(volume) != 1
            or volume[0].get("Name") != disk["name"]
            or volume[0].get("Driver") != "local"
            or volume[0].get("Labels") != {"isign.job": disk["name"]}
            or volume[0].get("Options")
            != {"type": "ext4", "device": disk["device"], "o": VOLUME_OPTIONS}
        ):
            raise ValueError("EXACT_PRIVATE_VOLUME_REQUIRED")
        return True

    def recover(self, name):
        path = self._path(name)
        disk = {"name": name, "path": str(path), "device": None}
        loops = json.loads(self.run([self.losetup, "--json", "--list"]))["loopdevices"]
        matching = [loop for loop in loops if loop.get("back-file") == str(path)]
        if len(matching) > 1:
            raise ValueError("DISK_RECOVERY_AMBIGUOUS")
        if matching:
            disk["device"] = matching[0]["name"]
        return self.destroy(disk)

    def destroy(self, disk):
        try:
            # Removal must succeed while no container references the volume.
            volumes = (
                self.run([self.docker, "volume", "ls", "--format", "{{.Name}}"])
                .decode()
                .splitlines()
            )
            if disk["name"] in volumes:
                self.run([self.docker, "volume", "rm", disk["name"]])
            if (
                disk["name"]
                in self.run([self.docker, "volume", "ls", "--format", "{{.Name}}"])
                .decode()
                .splitlines()
            ):
                return False
            loops = json.loads(self.run([self.losetup, "--json", "--list"]))["loopdevices"]
            matching = [loop for loop in loops if loop.get("back-file") == disk["path"]]
            if len(matching) > 1:
                return False
            if matching:
                device = matching[0].get("name")
                if not re.fullmatch("/dev/loop[0-9]+", device or "") or (
                    disk.get("device") and device != disk["device"]
                ):
                    return False
                self.run([self.losetup, "--detach", device])
            loops = json.loads(self.run([self.losetup, "--json", "--list"]))["loopdevices"]
            if any(loop.get("back-file") == disk["path"] for loop in loops):
                return False
            self._path(disk["name"]).unlink(missing_ok=True)
            return not self._path(disk["name"]).exists()
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return False
