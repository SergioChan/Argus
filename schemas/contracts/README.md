# Argus Contract Schemas

This directory contains the canonical source JSON Schemas for contracts C1-C6 and
the S10 runtime wire contract C10.

The schemas are intentionally source-first:

- `manifest.json` records ownership, versions, schema paths, and consumers.
- Each `c*.schema.json` file is draft-2020-12 and carries `x-argus-contract`.
- C3 starts at version `1.1.0`, including the adversarial red-blue debate fields required by the roadmap.
- C4 is the provenance spine. Its v1 schema is frozen through `compatibility/c4.artifact-record.v1.0.0.schema.json`; S8-T01 publishes that frozen version immutably through the S8 write-once object-store facade, while the service/API dual-serve registry remains S8-T27 scope.
- C10 is the S10 runtime wire surface for tokens, policy, quota, launch,
  sandbox, audit, and checkpoint-signing payloads. C10 v2 tightens the
  `PolicyBundle.risk_to_runtime` map keys to the canonical `RiskClass` enum.
- `examples/` contains one minimal validating example per contract.

Compatibility rules:

- Patch changes may only alter annotations or examples.
- Minor changes must be additive: new fields are optional or have defaults, and no existing type, enum, required field, hash rule, or lineage/tier invariant is narrowed.
- Major changes are required for removed fields, newly required fields without defaults, stricter `additionalProperties`, narrowed enums/types, changed canonical hash inputs, or changed C4 tier/report coupling.
- Every published baseline listed in `compatibility.json` is checked by `scripts/schema_compatibility.py --check-manifest`.

Run `python3 scripts/validate_schemas.py` after editing this directory.
