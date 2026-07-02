# Generated Contract Bindings

This directory contains generated binding metadata for C1-C6 and generated C4
ArtifactRecord bindings for Python, TypeScript, and Rust.

Do not edit generated files directly. Run:

```bash
python3 scripts/generate_bindings.py --write
```

`python3 scripts/generate_bindings.py --check` is part of the repository check suite and fails when generated bindings drift from `schemas/contracts/manifest.json`.

The TypeScript binding has its own locked package in `bindings/typescript`.
Run `npm ci --prefix bindings/typescript` before `npm test --prefix bindings/typescript`
when starting from a clean checkout.
