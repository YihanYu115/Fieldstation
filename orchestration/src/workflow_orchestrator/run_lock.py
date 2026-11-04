"""OS-owned locks survive stale files but release when their owner exits."""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def exclusive(path: Path, *, wait_seconds: float = 0):
    if not 0 <= wait_seconds <= 5:
        raise ValueError("lock wait must be bounded to five seconds")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    getattr(fcntl, "flock")(stream, getattr(fcntl, "LOCK_EX") | getattr(fcntl, "LOCK_NB"))
                break
            except OSError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Execution is still owned by another process") from None
                time.sleep(min(.01, remaining))
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                getattr(fcntl, "flock")(stream, getattr(fcntl, "LOCK_UN"))
