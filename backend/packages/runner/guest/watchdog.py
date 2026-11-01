"""Pinned container PID1 expiry guard; deadline is independent of broker lifetime."""

import os, pathlib, shutil, time


def run(
    deadline, *, clock=lambda: int(time.time() * 1000), pause=time.sleep, cleanup=shutil.rmtree
):
    if type(deadline) is not int or not clock() < deadline <= clock() + 3600000:
        raise ValueError("BOUNDED_INSTANCE_DEADLINE_REQUIRED")
    try:
        while clock() < deadline:
            pause(min(1, (deadline - clock()) / 1000))
    finally:
        cleanup("/job", ignore_errors=True)


if __name__ == "__main__":
    run(int(os.environ["ISIGN_INSTANCE_DEADLINE_MS"]))
