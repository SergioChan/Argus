# S10 Image Trust Mount

The deployed S10 supervisor mounts this directory read-only. Runtime or CI
deployment tooling must replace it with a generated trust root containing only:

- `cosign.pub`
- `signatures/<manifest-digest>/<identity-hash>/payload.json`
- `signatures/<manifest-digest>/<identity-hash>/signature.sig`
- `manifest.json`

Private signing keys must never be written to this committed directory or
mounted into the S10 supervisor.
