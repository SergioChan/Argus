#!/usr/bin/env python3
"""Create ephemeral cosign image trust material for deployed S10 tests."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus_core import cosign_signature_store_path
from argus_core.s10 import COSIGN_CONTAINER_SIGNATURE_TYPE, DIGEST_PINNED_IMAGE


COSIGN_VERSION = "v2.6.3"
COSIGN_IMAGE = (
    "ghcr.io/sigstore/cosign/cosign:v2.6.3@"
    "sha256:4bedb8de1c5c1abd8dea60de704ba449402d238623fa8bb33d2ccaa9beffcbf5"
)


def create_cosign_image_trust(
    *,
    docker_bin: str,
    output_dir: str | os.PathLike[str],
    images: Iterable[str],
) -> dict[str, Any]:
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise RuntimeError("cosign image trust output directory must be empty")
    root.chmod(0o700)
    signer_dir = root / ".signer"
    signature_store = root / "signatures"
    signer_dir.mkdir(mode=0o700)
    signature_store.mkdir(mode=0o755)
    password = secrets.token_urlsafe(32)
    env = {**os.environ, "COSIGN_PASSWORD": password}
    try:
        _run_cosign(
            docker_bin=docker_bin,
            root=root,
            args=("generate-key-pair", "--output-key-prefix", "/work/.signer/cosign"),
            env=env,
        )
        public_key = signer_dir / "cosign.pub"
        private_key = signer_dir / "cosign.key"
        if not public_key.is_file() or not private_key.is_file():
            raise RuntimeError("cosign did not generate the expected key pair")
        trusted_public_key = root / "cosign.pub"
        shutil.copyfile(public_key, trusted_public_key)
        entries: list[dict[str, str]] = []
        for image in sorted(set(images)):
            identity, digest = _parse_image(image)
            entry_dir = cosign_signature_store_path(signature_store, image)
            entry_dir.mkdir(parents=True, exist_ok=False)
            payload_path = entry_dir / "payload.json"
            signature_path = entry_dir / "signature.sig"
            payload = {
                "critical": {
                    "identity": {"docker-reference": identity},
                    "image": {"Docker-manifest-digest": digest},
                    "type": COSIGN_CONTAINER_SIGNATURE_TYPE,
                },
                "optional": {"creator": "project-argus-s10-tc30"},
            }
            payload_path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            _run_cosign(
                docker_bin=docker_bin,
                root=root,
                args=(
                    "sign-blob",
                    "--tlog-upload=false",
                    "--key",
                    "/work/.signer/cosign.key",
                    "--output-signature",
                    _container_path(root, signature_path),
                    "--yes",
                    _container_path(root, payload_path),
                ),
                env=env,
            )
            _run_cosign(
                docker_bin=docker_bin,
                root=root,
                args=(
                    "verify-blob",
                    "--private-infrastructure",
                    "--key",
                    "/work/cosign.pub",
                    "--signature",
                    _container_path(root, signature_path),
                    _container_path(root, payload_path),
                ),
                env=os.environ,
                expected_output="Verified OK",
            )
            payload_path.chmod(0o444)
            signature_path.chmod(0o444)
            entries.append(
                {
                    "image": image,
                    "image_identity": identity,
                    "manifest_digest": digest,
                    "payload_sha256": "sha256:" + sha256(payload_path.read_bytes()).hexdigest(),
                    "signature_sha256": "sha256:" + sha256(signature_path.read_bytes()).hexdigest(),
                }
            )
        trusted_public_key.chmod(0o444)
    finally:
        env.pop("COSIGN_PASSWORD", None)
        password = ""
        shutil.rmtree(signer_dir, ignore_errors=False)
    private_material = tuple(root.rglob("*.key"))
    if private_material:
        raise RuntimeError("private cosign key material remained in the S10 trust root")
    manifest = {
        "cosign_image": COSIGN_IMAGE,
        "cosign_version": COSIGN_VERSION,
        "signer_key_id": "sha256:" + sha256((root / "cosign.pub").read_bytes()).hexdigest(),
        "entries": entries,
        "private_key_present": False,
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "manifest.json").chmod(0o444)
    root.chmod(0o755)
    return manifest


def _parse_image(image: str) -> tuple[str, str]:
    if DIGEST_PINNED_IMAGE.fullmatch(image) is None:
        raise ValueError(f"image must be digest pinned: {image!r}")
    if "@" in image:
        identity, digest = image.rsplit("@", 1)
        return identity, digest
    return image, image


def _container_path(root: Path, path: Path) -> str:
    return "/work/" + path.resolve().relative_to(root).as_posix()


def _run_cosign(
    *,
    docker_bin: str,
    root: Path,
    args: tuple[str, ...],
    env: Mapping[str, str],
    expected_output: str | None = None,
) -> None:
    command = [
        docker_bin,
        "run",
        "--rm",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--env",
        "COSIGN_PASSWORD",
        "--volume",
        f"{root}:/work",
        "--workdir",
        "/work",
        COSIGN_IMAGE,
        *args,
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=dict(env),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"cosign fixture command failed with exit {completed.returncode}: {args[0]}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    if expected_output is not None:
        output_lines = {
            line.strip()
            for line in (completed.stdout + "\n" + completed.stderr).splitlines()
            if line.strip()
        }
        if expected_output not in output_lines:
            raise RuntimeError(f"cosign fixture command omitted expected proof: {expected_output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--image", action="append", required=True)
    parser.add_argument("--docker-bin", default=shutil.which("docker") or "docker")
    args = parser.parse_args()
    manifest = create_cosign_image_trust(
        docker_bin=args.docker_bin,
        output_dir=args.output_dir,
        images=args.image,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
