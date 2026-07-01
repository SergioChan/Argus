# Argus Contract Schemas

This directory contains the canonical source JSON Schemas for contracts C1-C6.

The schemas are intentionally source-first:

- `manifest.json` records ownership, versions, schema paths, and consumers.
- Each `c*.schema.json` file is draft-2020-12 and carries `x-argus-contract`.
- C3 starts at version `1.1.0`, including the adversarial red-blue debate fields required by the roadmap.
- `examples/` contains one minimal validating example per contract.

Run `python3 scripts/validate_schemas.py` after editing this directory.
