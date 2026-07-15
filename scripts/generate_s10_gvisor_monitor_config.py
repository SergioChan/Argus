#!/usr/bin/env python3
"""Generate the architecture-bound gVisor runtime-monitor pod-init config."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from typing import Any


CONTEXT_FIELDS = ["time", "container_id", "thread_id", "group_id", "cwd", "process_name"]
ARCHITECTURES: dict[str, dict[str, Any]] = {
    "x86_64": {
        "aliases": {"x86_64", "amd64"},
        "open_points": (
            ("syscall/open/exit", ()),
            ("syscall/creat/exit", ("fd_path",)),
            ("syscall/openat/exit", ("fd_path",)),
        ),
        "write_points": (
            "syscall/write/exit",
            "syscall/pwrite64/exit",
            "syscall/writev/exit",
            "syscall/pwritev/exit",
            "syscall/pwritev2/exit",
        ),
        "dangerous_syscalls": (101, 165, 166, 246, 250, 272, 308, 321),
    },
    "aarch64": {
        "aliases": {"aarch64", "arm64"},
        "open_points": (("syscall/openat/exit", ("fd_path",)),),
        "write_points": (
            "syscall/write/exit",
            "syscall/writev/exit",
            "syscall/pwrite64/exit",
            "syscall/pwritev/exit",
            "syscall/pwritev2/exit",
        ),
        "dangerous_syscalls": (39, 40, 97, 104, 117, 219, 268, 280),
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    architecture = _normalize_architecture(args.architecture)
    endpoint = _validate_endpoint(args.endpoint)
    output = Path(args.output).resolve()
    payload = build_config(architecture=architecture, endpoint=endpoint)
    _write_atomic(output, payload)
    return 0


def build_config(*, architecture: str, endpoint: str) -> dict[str, Any]:
    spec = ARCHITECTURES[architecture]
    points: list[dict[str, Any]] = []
    for name, optional_fields in spec["open_points"]:
        point: dict[str, Any] = {"name": name, "context_fields": CONTEXT_FIELDS}
        if optional_fields:
            point["optional_fields"] = list(optional_fields)
        points.append(point)
    for name in spec["write_points"]:
        points.append(
            {
                "name": name,
                "optional_fields": ["fd_path"],
                "context_fields": CONTEXT_FIELDS,
            }
        )
    points.extend(
        {
            "name": f"syscall/sysno/{sysno}/exit",
            "context_fields": CONTEXT_FIELDS,
        }
        for sysno in spec["dangerous_syscalls"]
    )
    names = [point["name"] for point in points]
    if len(names) != len(set(names)):
        raise RuntimeError("gVisor monitor config contains duplicate tracepoints")
    return {
        "trace_session": {
            "name": "Default",
            "ignore_missing": False,
            "points": points,
            "sinks": [
                {
                    "name": "remote",
                    "config": {
                        "endpoint": endpoint,
                        "retries": 3,
                        "backoff": "25us",
                        "backoff_max": "10ms",
                    },
                    "ignore_setup_error": False,
                }
            ],
        }
    }


def _normalize_architecture(raw: str) -> str:
    normalized = raw.strip().lower()
    for architecture, spec in ARCHITECTURES.items():
        if normalized in spec["aliases"]:
            return architecture
    raise ValueError(f"unsupported gVisor monitor architecture: {raw!r}")


def _validate_endpoint(raw: str) -> str:
    if not raw or "\x00" in raw:
        raise ValueError("gVisor monitor endpoint is invalid")
    path = Path(raw)
    normalized = os.path.normpath(raw)
    if not path.is_absolute() or normalized != raw or normalized == "/":
        raise ValueError("gVisor monitor endpoint must be a normalized absolute non-root path")
    return normalized


def _write_atomic(output: Path, payload: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=f".{output.name}.",
        delete=False,
    ) as temporary:
        temporary.write(encoded)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    os.chmod(temporary_path, 0o644)
    os.replace(temporary_path, output)


if __name__ == "__main__":
    raise SystemExit(main())
