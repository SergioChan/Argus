#!/usr/bin/env python3
"""Render a self-contained Argus Observatory v0 verified-run report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from argus_core import C3ReportVerifier, InMemoryVerifierTrustStore  # noqa: E402
from argus_core.s11 import observatory_lineage_bundle_from_json, render_observatory_v0_html  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path, help="Signed C3 v1.1 ValidationReport JSON")
    parser.add_argument("--lineage", required=True, type=Path, help="C4 lineage bundle JSON")
    parser.add_argument("--trust-store", required=True, type=Path, help="Verifier trust-store JSON")
    parser.add_argument("--out", required=True, type=Path, help="Destination self-contained HTML file")
    args = parser.parse_args(argv)

    report_payload = _load_object(args.report)
    lineage_payload = _load_object(args.lineage)
    trust_store = _load_trust_store(args.trust_store)
    result = render_observatory_v0_html(
        report_payload=report_payload,
        lineage=observatory_lineage_bundle_from_json(lineage_payload),
        report_verifier=C3ReportVerifier(trust_store),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(result.html, encoding="utf-8")
    if result.verification.trusted:
        print(f"VERIFIED {args.out}")
        return 0
    print(f"FAIL {args.out}: " + "; ".join(result.verification.failures), file=sys.stderr)
    return 1


def _load_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return payload


def _load_trust_store(path: Path) -> InMemoryVerifierTrustStore:
    payload = _load_object(path)
    keys = payload.get("keys")
    if not isinstance(keys, list):
        raise SystemExit(f"{path} must contain a keys array")
    trust_store = InMemoryVerifierTrustStore()
    for key in keys:
        if not isinstance(key, dict):
            raise SystemExit("trust-store key entries must be objects")
        key_id = key.get("key_id")
        secret = key.get("secret")
        if not isinstance(key_id, str) or not isinstance(secret, str):
            raise SystemExit("trust-store keys require string key_id and secret")
        trust_store.register_key(key_id, secret.encode("utf-8"))
        if key.get("revoked") is True:
            trust_store.revoke_key(key_id)
    return trust_store


if __name__ == "__main__":
    raise SystemExit(main())
