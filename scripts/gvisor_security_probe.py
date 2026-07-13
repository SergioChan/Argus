#!/usr/bin/env python3
"""Exercise dangerous syscalls and read-only Argus trust mounts inside a sandbox."""

from __future__ import annotations

import ctypes
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import platform


SYSCALLS = {
    "x86_64": {
        "ptrace": 101,
        "mount": 165,
        "kexec_load": 246,
        "keyctl": 250,
        "bpf": 321,
    },
    "aarch64": {
        "mount": 40,
        "kexec_load": 104,
        "ptrace": 117,
        "keyctl": 219,
        "bpf": 280,
    },
}
TRUST_PATHS = (
    Path("/opt/argus/trust/verifier/verify.py"),
    Path("/opt/argus/trust/ledger/ledger.jsonl"),
)


def main() -> int:
    architecture = platform.machine().lower()
    syscall_numbers = SYSCALLS.get(architecture)
    if syscall_numbers is None:
        raise RuntimeError(f"unsupported probe architecture: {architecture}")

    libc = ctypes.CDLL(None, use_errno=True)
    syscall_results = {
        name: _invoke_syscall(libc, number)
        for name, number in sorted(syscall_numbers.items())
    }
    trust_results = {
        str(path): _attempt_trust_write(path)
        for path in TRUST_PATHS
    }
    print(
        json.dumps(
            {
                "architecture": architecture,
                "syscalls": syscall_results,
                "trust_mounts": trust_results,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
    return 0


def _invoke_syscall(libc: ctypes.CDLL, number: int) -> dict[str, int]:
    ctypes.set_errno(0)
    result = int(
        libc.syscall(
            ctypes.c_long(number),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
        )
    )
    return {"return_code": result, "errno": ctypes.get_errno()}


def _attempt_trust_write(path: Path) -> dict[str, object]:
    before = path.read_bytes()
    write_errno = 0
    write_succeeded = False
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    except OSError as exc:
        write_errno = int(exc.errno or 0)
    else:
        try:
            os.write(descriptor, b"ARGUS_TRUST_WRITE_PROBE")
            write_succeeded = True
        finally:
            os.close(descriptor)
    after = path.read_bytes()
    return {
        "write_succeeded": write_succeeded,
        "errno": write_errno,
        "errno_name": errno.errorcode.get(write_errno, "UNKNOWN"),
        "before_sha256": sha256(before).hexdigest(),
        "after_sha256": sha256(after).hexdigest(),
        "unchanged": before == after,
    }


if __name__ == "__main__":
    raise SystemExit(main())
