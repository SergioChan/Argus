"""Thin script wrapper for the argus-s2 command line interface."""

from __future__ import annotations

from argus_runtime.s2_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
