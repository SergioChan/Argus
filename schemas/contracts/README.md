# Argus Contract Schemas

This directory contains the canonical source JSON Schemas for contracts C1-C6.

The schemas are intentionally source-first:

- `manifest.json` records ownership, versions, schema paths, and consumers.
- Each `c*.schema.json` file is draft-2020-12 and carries `x-argus-contract`.
- C3 starts at version `1.1.0`, including the adversarial red-blue debate fields required by the roadmap.
- C4 is the provenance spine. Its v1 schema is frozen through `compatibility/c4.artifact-record.v1.0.0.schema.json`; immutable registry publication is gated on S8-T05 because that task owns the write-once object-store facade.
- `examples/` contains one minimal validating example per contract.

Compatibility rules:

- Patch changes may only alter annotations or examples.
- Minor changes must be additive: new fields are optional or have defaults, and no existing type, enum, required field, hash rule, or lineage/tier invariant is narrowed.
- Major changes are required for removed fields, newly required fields without defaults, stricter `additionalProperties`, narrowed enums/types, changed canonical hash inputs, or changed C4 tier/report coupling.
- Every published baseline listed in `compatibility.json` is checked by `scripts/schema_compatibility.py --check-manifest`.

Run `python3 scripts/validate_schemas.py` after editing this directory.
