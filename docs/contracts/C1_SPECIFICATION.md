# C1 Specification and Migration Policy

This document is the human-readable companion to
`schemas/contracts/c1.subagent.schema.json`. The schema remains the source of
truth. This specification records the public C1 surface that S1 exposes to
subagents and the compatibility rules that S5, S3, and S12 rely on.

## Contract Metadata

| Field | Value |
|---|---|
| Contract id | `C1` |
| Owner | `S1` |
| Version | `1.0.0` |
| Schema | `schemas/contracts/c1.subagent.schema.json` |
| Draft | JSON Schema draft 2020-12 |

## Public Definitions

C1 exposes these public definitions. Implementations may add private helpers, but
wire payloads must remain schema-compatible with this set:

| Definition | Purpose |
|---|---|
| `Acceptance` | Result of the accept/refuse gate. |
| `ArtifactRef` | C4 artifact reference used by C1 payloads. |
| `BuildResult` | Result payload from the build step. |
| `ClaimTier` | Trust tier label relayed from external verification. |
| `CostEstimate` | Common cost estimate shape. |
| `ExecContext` | Capability-handle payload exposed to subagent code. |
| `HashRef` | Stable hash reference shape. |
| `Heartbeat` | Liveness/progress event emitted by a running job. |
| `LifecycleEvent` | Event-sourced lifecycle transition record. |
| `LifecycleMethod` | Public lifecycle method enum. |
| `LifecycleState` | Public lifecycle state enum. |
| `NonEmptyString` | Common non-empty string type. |
| `Plan` | Planning output before build. |
| `PlanStep` | Single step inside `Plan`. |
| `SelfCheck` | Advisory self-check entry. |
| `SubagentEnvelope` | Method envelope wrapping C1 calls. |
| `SubagentReport` | Final report payload. |
| `TypedError` | Shared typed error envelope. |
| `UncertaintySummary` | Uncertainty summary required by higher conformance. |
| `Uuid` | UUID string type. |
| `ValidationRequest` | Request handed to validation. |

## Lifecycle States

`LifecycleState` is exactly:

`REGISTERED`, `ACCEPTED`, `PLANNING`, `BUILDING`, `VALIDATING`, `REPORTED`,
`FAILED`, `REJECTED`, `CANCELLED`, `QUARANTINED`.

Refusal is represented as `Acceptance.accepted=false` with state `REJECTED`.
There is no public lifecycle state named `REFUSED`.

## Lifecycle Methods

`LifecycleMethod` is exactly:

`register`, `accept`, `refuse`, `plan`, `build`, `validate`, `report`,
`heartbeat`, `cancel`, `fail`, `quarantine`.

## Typed Errors

`TypedError.category` is exactly:

`RETRYABLE`, `PERMANENT`, `BUDGET`, `POLICY`, `VERIFIER_UNAVAILABLE`,
`SANDBOX`, `VALIDATION`, `VERSION_UNSUPPORTED`, `QUARANTINE`, `NOT_FOUND`.

Policy, sandbox, budget, and quarantine errors are non-retryable and may place a
job into quarantine. Version incompatibility is a refusal path and must surface
as `VERSION_UNSUPPORTED`.

## Accept Refusal Reasons

The `Acceptance.reason` enum is:

`OUT_OF_SCOPE`, `MISSING_ADAPTER`, `BUDGET_TOO_SMALL`, `NO_VERIFIER`,
`VERSION_UNSUPPORTED`, `POLICY`, `null`.

When `accepted=true`, `reason` must be `null` and `state` must be `ACCEPTED`.
When `accepted=false`, `reason` is required and `state` must be `REJECTED`.

## Compatibility and Migration Policy

C1 uses semver on `contract_version` or the C1-side envelope version:

- Patch changes are documentation or clarification changes only.
- Minor changes may add optional fields. Consumers must ignore unknown additive
  fields and continue using the known schema-defined fields.
- Breaking wire changes require a major version bump.
- Major versions may be dual-served only inside an explicit migration window.
  Outside that window, consumers must reject the request with
  `VERSION_UNSUPPORTED`.
- A schema diff that removes a required field, narrows an enum, or changes a
  field type is a breaking change and cannot be published as a minor bump.

The compatibility gate for this policy is `scripts/schema_compatibility.py`, and
the C1 runtime acceptance gate must preserve S1-TC-09, S1-TC-10, and S1-TC-11.

## Cross-Owner Review Matrix

| Owner | Review focus |
|---|---|
| `S5` | C2 job routing and `Acceptance` refusal semantics remain compatible. |
| `S3` | `ValidationRequest`, `SubagentReport`, and claim-tier relay remain externally verifiable. |
| `S12` | Standard release packaging, semver classification, and dual-serve migration notes remain publishable. |

Any C1 change that affects one of these rows must update this document, the
schema, the compatibility manifest, and the corresponding tests in one commit.
