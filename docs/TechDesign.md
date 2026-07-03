# Project Argus — Technical Design

> Part of the Project Argus design set. Start at README.md for the doc map and reading order. Related docs: Architecture.md, PRD.md, TechDesign.md, Backlog-and-Interfaces.md, TestPlan.md, Roadmap.md.

> **Product.** *Argus* is a verifier-gated, agent-built ML foundry for fragmented theoretical-particle-physics / particle-cosmology research (e.g. electroweak phase transition → stochastic gravitational-wave background → Higgs-sector observables).
>
> **Core thesis.** ML extracts information humans cannot see; an agent by itself only automates human labor. Argus's agents are therefore **automated ML researchers** that build, train, validate, and iterate ML models for each physics subtopic. Each subtopic is served by a domain **subagent** conforming to a standardized contract ("SLHA-for-agents"); a central **Control Tower (总台)** orchestrates a federation of subagents. Every ML artifact is gated by a **physics verifier** (injection tests, held-out/null tests, cross-code consistency, physical-consistency checks, leakage/contamination screens). Recursion (self-improvement of an ML pipeline) is allowed **only** under a cheap external verifier. Nothing is trusted without validation; every claim is tiered (**ran-toy / recapitulated-known / novel-needs-human**), and human sign-off is mandatory before any external artifact.
>
> **Design principles.** Oracle-gated autonomy; verify-before-trust; claim-tiering; full provenance & reproducibility; strict sandboxing of agent-executed code; breadth-over-depth near-term; human-in-the-loop mandatory; decoupled subsystems communicating only through published contracts.

## About this document

This is the **Technical Design** for Project Argus — a complete implementation design, not an MVP. It contains one section per subsystem (architecture, components, algorithms, data models, public APIs), followed by a consolidated cross-subsystem interface section built from every subsystem's produced/consumed interfaces.

### Subsystem index

| ID | Subsystem | Owns contract(s) |
|----|-----------|------------------|
| [S1](#s1--subagent-framework--contract-slha-for-agents) | Subagent Framework & Contract (SLHA-for-agents) | C1 |
| [S2](#s2--ml-builder-engine) | ML Builder Engine | — |
| [S3](#s3--physics-validation--verifier-framework) | Physics Validation & Verifier Framework | C3 |
| [S4](#s4--recursive-improvement-loop-evolver) | Recursive Improvement Loop (Evolver) | — |
| [S5](#s5--control-tower--orchestration-总台) | Control Tower / Orchestration (总台) | C2 |
| [S6](#s6--knowledge--ingestion) | Knowledge & Ingestion | C5 (co-owned) |
| [S7](#s7--physics-compute-adapters) | Physics Compute Adapters | C6 |
| [S8](#s8--data-artifact--provenance) | Data, Artifact & Provenance | C4 |
| [S9](#s9--human-in-the-loop-review--governance) | Human-in-the-loop Review & Governance | — |
| [S10](#s10--security-sandbox--runtime) | Security, Sandbox & Runtime | — |
| [S11](#s11--observability--evaluation) | Observability & Evaluation | — |
| [S12](#s12--interop-standard--federation) | Interop Standard & Federation | C5 (co-owned) |

### Contract legend

Argus's subsystems couple **only** through six published contracts:

| Contract | Name | Owner |
|----------|------|-------|
| **C1** | Subagent Contract (SLHA-for-agents) | S1 |
| **C2** | Task/Job Envelope | S5 |
| **C3** | Verifier Interface + Validation Report | S3 |
| **C4** | Artifact + Provenance Record | S8 |
| **C5** | Registry / Capability Descriptor | S6 / S12 (co-owned) |
| **C6** | Compute-Adapter Tool Interface | S7 |

Shared stack conventions referenced throughout: **JSON Schema draft 2020-12** as canonical IDL with generated pydantic v2 / TypeScript / Rust serde bindings; **mTLS + least-privilege capability scopes** on every call; **BLAKE3** content addressing; **gVisor/Firecracker (S10)** sandboxing; **NATS JetStream** eventing; **OpenTelemetry → Prometheus/Tempo (S11)** observability; **Postgres 16** systems of record; **Rust** at trust boundaries / hot paths; **Python 3.11+** for orchestration/SDKs; **Claude via the Agent SDK** for agent reasoning with tool-use restricted to contract surfaces and full prompt/response provenance.

---

## S1 — Subagent Framework & Contract (SLHA-for-agents)

**Owns contract:** **C1**. **Consumes:** C2 (S5), C3 (S3), C4 (S8), C5 (S6), C6 (S7), S10.

### S1.1 Architectural overview

S1 ships four cooperating artifacts:

1. **`argus-contracts`** — the canonical JSON-Schema (draft 2020-12) definitions of C1 (owned here) plus generated language bindings (pydantic v2, TypeScript, Rust serde). Single source of truth; all other subsystems import the *generated* types, never each other's.
2. **`argus-subagent` (Python SDK)** — the developer-facing framework: `Subagent` base class, lifecycle engine, provenance emitter, sandbox client, uncertainty helpers, error envelopes, CLI.
3. **`argus-subagent-runtime` (host process)** — the long-lived service that terminates the C1 wire API (gRPC + HTTP/JSON), owns the event-sourced lifecycle store, propagates traces, and mediates calls into S10 and S8. This is the *trusted* half; the subagent's domain code runs in the *untrusted* S10 sandbox.
4. **`argus-conformance` (reference harness)** — executable Bronze/Silver/Gold checks; consumed by S12.

**Critical split — trusted runtime vs. untrusted domain code.** The runtime process (holds the lifecycle store, provenance credentials via brokered tokens, S10 client) is separate from where `plan()`/`build()` domain logic executes. Domain code and any model-generated/training code execute in the S10 sandbox; the runtime marshals inputs in and provenance/results out. The subagent's domain hooks receive a restricted `ExecContext` handle whose only capabilities are: submit-work-to-sandbox, emit-artifact-through-C4, call-declared-adapter (C6, brokered), read-declared-dataset, log/trace. It has **NO** handle to the tier-assignment path, the verifier, or raw credentials.

```
        ┌─────────────────────────── S1 (trusted runtime) ─────────────────────────┐
S5 ───► │  C1 wire API (gRPC/HTTP, mTLS)                                            │
(C2)    │      │                                                                    │
        │      ▼                                                                    │
        │  Lifecycle Engine (event-sourced FSM) ──► Event Log (Postgres) ──► NATS   │
        │      │                          ▲                                         │
        │      ▼                          │ (transition events -> S11 traces)       │
        │  Method Dispatcher ── register / accept / plan / build / validate / report│
        │      │        │                                                           │
        │      │        └── Descriptor Builder (C5) ──► S6 registry (publish)       │
        │      ▼                                                                    │
        │  Sandbox Marshaler ──► S10 (gVisor/Firecracker) ◄── domain plan()/build() │
        │      │                        │ egress-deny; allowlist = required_adapters│
        │      ▼                        ▼                                           │
        │  Provenance Emitter ──► S8 (C4 ArtifactRecord, BLAKE3, lineage DAG)       │
        │      │                                                                    │
        │      └── Frozen-Pipeline Packager ──► content-addressed store ──► S3 (C3) │
        └───────────────────────────────────────────────────────────────────────────┘
```

### S1.2 Components

#### S1.2.1 Contract & codegen (`argus-contracts`)
- Canonical schemas: `c1.subagent.schema.json` and the C1-side view of the shared envelopes. S1 co-consumes C2/C3/C4/C5/C6 schemas (owned elsewhere) and pins their versions.
- **Codegen pipeline:** `datamodel-code-generator` → pydantic v2 models; `json-schema-to-typescript` → TS; `typify`/`schemars` → Rust serde. Runs in CI; drift between schema and generated bindings fails the build.
- **Compatibility checker:** a `schema-diff` gate classifies a change as additive-minor vs breaking-major (removing a field, tightening a type, changing required-set = major). Enforces semver on publish.

#### S1.2.2 Lifecycle engine
- **FSM** with states `REGISTERED, ACCEPTED, PLANNING, BUILDING, VALIDATING, REPORTED` and terminals `FAILED, REJECTED, QUARANTINED`. Legal transitions are a static table; illegal transition attempts raise `POLICY` errors (non-retryable, quarantine-eligible).
- **Event sourcing:** every transition writes an immutable `LifecycleEvent` to Postgres and mirrors an entry to the S8 provenance ledger (append-only). State = fold over events. Replay is a pure reducer.
- **Idempotency:** each mutating method carries an idempotency key `(job_id, method, attempt_nonce?)`; duplicate keys return the stored prior result rather than re-executing.
- **Cancellation:** `cancel()` sets a cooperative cancel flag; the sandbox marshaler propagates SIGTERM-equivalent to the sandbox and awaits a grace window (default 30s), then hard-kills, captures partial provenance, and transitions to `FAILED(category=CANCELLED)`.
- **Heartbeat:** the sandbox job posts progress/spend heartbeats; the runtime exposes them via `heartbeat()` and forwards budget spend so S5 can enforce caps.

#### S1.2.3 SDK base class & inversion of control
```python
class Subagent(ABC):
    contract_version = "1.0.0"
    def describe(self) -> CapabilityDescriptor: ...          # author-declared (C5)
    def accept(self, job: JobEnvelope) -> Acceptance:        # default impl does gate checks; author may extend
    @abstractmethod
    def plan(self, job: JobEnvelope, ctx: ExecContext) -> Plan: ...
    @abstractmethod
    def build(self, plan: Plan, ctx: ExecContext) -> BuildResult: ...
    # validate/report/heartbeat/cancel are framework-provided (author does not grade)
```
The framework wraps each hook with: trace span, budget-token check, provenance context injection, sandbox marshaling, error-envelope normalization, and event emission. `validate()` is **not** overridable — it always hands off to S3.

#### S1.2.4 Default `accept()` gate algorithm
```
accept(job):
  if contract_version incompatible(job.envelope_version): return REFUSED(VERSION_UNSUPPORTED)
  if job.problem_spec.subtopic ∉ descriptor.subtopics: return REFUSED(OUT_OF_SCOPE)
  for a in required_adapters(job): if a ∉ descriptor.required_adapters ∪ job.allowed_adapters: return REFUSED(MISSING_ADAPTER)
  if job.verifier_profile_ref is null OR profile unresolvable: return REFUSED(NO_VERIFIER)   # "no verifier, no run"
  if estimate_cost(job) > job.budget.*: return REFUSED(BUDGET_TOO_SMALL)
  emit ACCEPTED event; return Acceptance(accepted=true, estimated_cost, plan_eta)
```
Refusal is idempotent and event-sourced; it is a normal outcome that S5 routes on.

#### S1.2.5 Sandbox marshaler (S10 bridge)
- Builds an **egress allowlist** = {content-addressed store, declared adapter endpoints from `required_adapters` ∩ `allowed_adapters`}. Default-deny everything else.
- Packages the domain `build()` closure + inputs into an OCI container (pinned by digest), requests execution from S10 with the job's `budget_token`, `capability_scopes`, seeds, and resource caps.
- Receives back a metered result (stdout/stderr captured to provenance, cost, exit status). `SANDBOX`-category errors (escape attempt, quota breach caught by supervisor, write-to-trust-path) → immediate `QUARANTINED`.
- **No-secret guarantee:** the marshaler never places secrets in the container; adapters needing credentials are invoked through the S10-brokered adapter proxy outside the sandbox.

#### S1.2.6 Provenance emitter (S8/C4 bridge)
- Wraps every artifact write: computes BLAKE3, assembles the `lineage` block (inputs, derived_from, code repo+commit+dirty, environment_digest, adapters_used+versions, seeds, config_hash, params_hash), and calls S8's C4 writer.
- **Fail-closed:** if any required lineage field is missing, the write is refused (`INCOMPLETE_LINEAGE`) and no artifact is committed — the author literally cannot ship an unprovenanced artifact.
- **Tier coupling guard:** if the record's `claim_tier > ran-toy`, the emitter requires a `validation_report_ref` to a signature-valid C3 report whose tier matches; otherwise `ILLEGAL_TIER`.

#### S1.2.7 Frozen-pipeline packager (S3 handoff)
- On `validate()`, the runtime freezes the exact pipeline: container digest, code commit, config, adapter versions, seeds, input hashes → a content-addressed `frozen_pipeline_ref` (a C4 artifact of `kind=container`+manifest). Hands S3 the ref + artifact refs + `profile_ref` + `blind_dataset_handle` (opaque). The subagent never receives blind labels; S3 fetches and re-runs the frozen pipeline itself.

#### S1.2.8 Descriptor builder & conformance attestation
- Emits the C5 `CapabilityDescriptor` from author declarations + framework-derived fields (contract version range, resource envelope defaults, `uncertainty_support`, `independence_tags`). Signs with the subagent identity key; publishes a new immutable revision to S6.
- Includes the `conformance` block (level, suite_version, passed_at, evidence_ref, expires_at) produced by the conformance harness.

### S1.3 Key algorithms
- **Tier monotonicity guard (structural):** `report()` computes `claim_tier` ONLY by reading the S3 `ValidationReport.claim_tier`; there is no code path by which a subagent-supplied tier reaches the report. Attempting to pass a tier via the domain hooks is dropped and logged. `novel-needs-human` additionally requires S9 sign-off downstream — S1 never emits it as final-external.
- **Deterministic replay reducer:** `state = fold(reduce, INITIAL, events)`; `reduce(state, event)` is total and side-effect-free; used for recovery after runtime restart and for auditor replay.
- **Bounded auto-repair loop (Silver+):** on `build()` failure, run ≤ `max_repair_attempts` (default 2) repair cycles; each attempt: capture failing diagnostics → invoke S2 auto-repair hook inside sandbox → re-run → record provenance per attempt. Hard-stop on budget breach or attempt cap; then `FAILED`.
- **Idempotency resolution:** hash `(job_id, method, canonical_request)`; on collision return stored response; on same-method-different-request → `POLICY` conflict.
- **Egress allowlist derivation:** intersection of declared adapters and job-permitted adapters; empty-intersection with a plan that needs an adapter → refuse at `plan()`.

### S1.4 Sequence flows

**F1 — Happy path (S5 drives a job):**
```
S5 → register()                → runtime publishes C5 descriptor to S6, state REGISTERED
S5 → accept(JobEnvelope C2)    → gate algorithm → ACCEPTED (or REFUSED)
S5 → plan(JobEnvelope)         → domain plan() in sandbox → Plan (adapters, datasets, verifier_profile, budget breakdown) → PLANNING
S5 → build(Plan)               → S2 build in S10 sandbox → artifacts + provenance (C4) → BUILDING
    → validate(BuildResult)    → freeze pipeline → S3.verify() → signed ValidationReport (C3) → VALIDATING
S5 → report()                  → SubagentReport{artifact_refs, validation_report_ref, claim_tier(from S3), ...} → REPORTED
```

**F2 — Refusal:** `accept()` returns `accepted:false, reason:MISSING_ADAPTER` → state `REJECTED` → S5 reroutes. No error, no retry.

**F3 — Sandbox escape / trust-path write:** S10 supervisor flags a write to a read-only trust mount → runtime receives `SANDBOX` error → `QUARANTINED`, sandbox image frozen for forensics, Sev-1 event.

**F4 — Verifier unavailable:** `validate()` gets `VERIFIER_UNAVAILABLE` (or `INDEPENDENCE_UNAVAILABLE`) → no tier promotion; result stays `ran-toy` (or the loop, for S4, aborts). Surfaced, not hidden.

**F5 — Cancel mid-build:** `cancel(job_id)` → cooperative flag → sandbox SIGTERM → grace 30s → partial provenance captured → `FAILED(CANCELLED)`.

**F6 — Runtime restart during BUILDING:** on restart, reducer replays events → state restored to BUILDING; marshaler reattaches to (or reissues) the durable sandbox job via S10 handle; no lost lineage.

### S1.5 Tech choices (consistent with shared stack)
- **Python 3.11+** for SDK/runtime; **pydantic v2** models generated from schemas. **Rust** for the provenance-write client shim only if latency/safety demands (default: call S8's Rust ledger writer over its API). **gRPC** (primary) + **HTTP/JSON** (interop) for the C1 wire API; **mTLS** everywhere; least-privilege capability scopes on every call.
- **JSON Schema draft 2020-12** canonical IDL; **CBOR** optional compact wire; JSON default.
- **Postgres 16** for the lifecycle event log (append-only table, partitioned by `root_request_id`). **NATS JetStream** for lifecycle/registry-change events. **OpenTelemetry** for traces; exported to Tempo/Prometheus (S11 consumes).
- **S10** for isolation (gVisor/Firecracker, seccomp, read-only rootfs, egress-deny); **OCI** containers pinned by digest. **BLAKE3** content addressing (via S8/C4). **Claude via Agent SDK** drives the domain reasoning inside `plan()`/`build()`, with tool-use restricted to the C1/C6 surface; prompt/response provenance captured (S8).

### S1.6 Failure & degradation handling
- **Contract version mismatch:** typed `VERSION_UNSUPPORTED`; if only minor-newer, accept and ignore unknown fields (forward-compat).
- **S8 unavailable (cannot write provenance):** fail-closed — do NOT proceed to emit an unprovenanced artifact; retry with backoff; if persistent, `FAILED(RETRYABLE→PERMANENT)`. Never degrade to "run without provenance."
- **S10 unavailable:** cannot execute domain code; `accept()`/`plan()` may still run metadata-only steps, but `build()` returns `SANDBOX`-category retryable error; no direct-exec fallback (ever).
- **S6 registry unavailable at register():** buffer descriptor, retry publish; job may still `accept` if descriptor cached; if descriptor cannot be resolved by S5, S5 routes elsewhere.
- **S3 verifier down:** `VERIFIER_UNAVAILABLE`; block tier promotion; surface to S5/S4.
- **Partial build then crash:** durable sandbox handle + event replay recover state; captured partial artifacts retain lineage.
- **Budget breach mid-build:** S10 meter halts execution; runtime captures partial result and emits `BUDGET` error; `FAILED`.
- **Quarantine discipline:** `POLICY` and `SANDBOX` errors are terminal-quarantine, fully logged, never auto-retried.

### S1.7 Data models

All models are generated from JSON Schema (draft 2020-12) into pydantic v2 / TS / Rust. C1 is owned by S1; C2/C3/C4/C5/C6 shapes below are the *views* S1 consumes/produces (owned elsewhere but referenced exactly).

**1. CapabilityDescriptor (C5 — emitted by S1)**
```jsonc
{
  "entity_id": "uuid",
  "entity_type": "subagent",
  "name": "ewpt-gw-spectrum",
  "owner": "argus-internal | ext:orcid:...",
  "maintainer_contact": "string",
  "contract_versions": { "c1": "1.0.0", "c6": "1.0.0", "min": "1.0.0", "max": "1.x" },
  "subtopics": [ { "taxonomy_id": "cosmo.ewpt.gw", "description": "EWPT → SGWB spectrum" } ],
  "capabilities": [ { "verb": "model", "target_observable": "Omega_GW(f)", "io_schema_ref": "ref" } ],
  "required_adapters": [ "adapter:bounce-solver@1", "adapter:gw-spectrum@2" ],
  "required_datasets": [ "dataset_ref" ],
  "resource_envelope": { "cpu": 8, "gpu": 1, "mem": "32Gi", "typical_wallclock": "PT20M", "cost_class": "small" },
  "uncertainty_support": true,
  "conformance": { "level": "silver", "suite_version": "1.2.0", "passed_at": "ts", "evidence_ref": "C4", "expires_at": "ts" },
  "independence_tags": [ "impl:argus-jax-bounce", "family:coleman-weinberg" ],
  "trust_class": "internal | federated",
  "provenance_ref": "C4-ref",
  "signature": "…", "signer_key_id": "…",
  "status": "active"
}
```

**2. JobEnvelope (C2 — consumed by S1).** Consumed as-is per C2. S1 reads `job_id, parent_job_id, root_request_id, dag_node_id, problem_spec{subtopic,objective,target_observable,inputs_schema,success_criteria,required_claim_tier_max}, verifier_profile_ref, budget{...}, constraints{physics_priors[],units_contract,allowed_adapters[],allowed_datasets[],disallowed_actions[]}, provenance_context{root_lineage_ref,contamination_index_version}, scheduling, routing, capability_scopes[]`.

**3. Acceptance (C1 — produced)**
```jsonc
{
  "job_id": "uuid",
  "accepted": true,
  "reason": null,                 // enum when accepted=false: OUT_OF_SCOPE|MISSING_ADAPTER|BUDGET_TOO_SMALL|NO_VERIFIER|VERSION_UNSUPPORTED|POLICY
  "estimated_cost": { "compute_units": 0, "gpu_seconds": 0, "model_tokens": 0, "cost_usd": 0.0 },
  "plan_eta_seconds": 12,
  "idempotency_key": "hash(job_id,'accept')"
}
```

**4. Plan (C1 — produced)**
```jsonc
{
  "job_id": "uuid",
  "steps": [ { "step_id": "s1", "kind": "feature|train|eval|selfcheck", "description": "…", "est_cost": {} } ],
  "adapters_required": [ "adapter:bounce-solver@1" ],
  "datasets_required": [ "dataset_ref" ],
  "verifier_profile_ref": "C3-profile-ref",
  "budget_breakdown": { "per_step": [ ], "total": {} },
  "risk_notes": [ "extrapolation possible near T_c" ],
  "plan_hash": "blake3"
}
```

**5. BuildResult (C1 — produced)**
```jsonc
{
  "job_id": "uuid",
  "artifact_refs": [ "C4-ref (model)", "C4-ref (dataset)" ],
  "training_log_ref": "C4-ref (log)",
  "diagnostics": { "converged": true, "repair_attempts": 0, "warnings": [] },
  "self_checks": [ { "type": "PHYSICAL_CONSISTENCY", "status": "PASS", "advisory": true } ],  // Silver+, advisory only
  "uncertainty_summary": { "representation": "covariance|interval|samples", "value": {} }      // Silver+ mandatory
}
```

**6. ValidationRequest (C1 → C3 — produced/handed off)**
```jsonc
{
  "job_id": "uuid",
  "frozen_pipeline_ref": "C4-ref (container+manifest)",
  "artifact_refs": [ "C4-ref" ],
  "profile_ref": "C3-profile-ref",
  "blind_dataset_handle": "opaque-handle",   // S1 never dereferences labels
  "budget_token": "…", "trace_id": "…"
}
```

**7. SubagentReport (C1 — final deliverable)**
```jsonc
{
  "job_id": "uuid",
  "subagent_id": "uuid",
  "artifact_refs": [ "C4-ref" ],
  "validation_report_ref": "C3-ref",         // required if claim_tier > ran-toy
  "claim_tier": "ran-toy | recapitulated-known | novel-needs-human",  // SOURCED ONLY FROM C3
  "uncertainty_summary": {},
  "cost_actual": { "compute_units": 0, "gpu_seconds": 0, "model_tokens": 0, "cost_usd": 0.0 },
  "reproducibility_manifest": { /* mirror of C4 lineage block, sufficient to re-derive */ },
  "state": "REPORTED"
}
```

**8. LifecycleEvent (S1-internal, mirrored to S8 ledger)**
```jsonc
{
  "event_id": "uuid", "job_id": "uuid", "root_request_id": "uuid",
  "seq": 7,                              // monotonic per job
  "from_state": "BUILDING", "to_state": "VALIDATING",
  "method": "validate", "trigger": "S5|S4|internal|cancel",
  "payload_hash": "blake3", "spend_delta": { "cost_usd": 0.12 },
  "trace_id": "…", "ts": "ISO-8601", "idempotency_key": "…"
}
```

**9. Health / Heartbeat (C1 — produced)**
```jsonc
{ "job_id": "uuid", "status": "PLANNING|BUILDING|...", "progress": 0.42, "spend_so_far": {}, "last_heartbeat_at": "ts" }
```

**10. Typed error envelope (shared with C1/C2)**
```jsonc
{
  "code": "string",
  "category": "RETRYABLE|PERMANENT|BUDGET|POLICY|VERIFIER_UNAVAILABLE|SANDBOX",
  "message": "string",
  "retry_after_seconds": 30,             // optional, RETRYABLE only
  "provenance_ref": "C4-ref"             // links to captured diagnostics
}
```

**11. ExecContext (SDK-internal capability handle passed to plan/build)**
```jsonc
{
  "job_id": "uuid",
  "submit_sandbox_job(spec) -> SandboxResult",     // only path to execute code (S10)
  "emit_artifact(bytes, kind, lineage_inputs) -> C4-ref",   // fail-closed provenance
  "call_adapter(adapter_ref, EvalRequest) -> EvalResult",   // brokered via S10, allowlisted (C6)
  "read_dataset(dataset_ref) -> handle",           // allowlisted only
  "log(...)", "span(...)"
  // NOTE: NO tier-set, NO verifier handle, NO credential access
}
```

**12. Lifecycle store schema (Postgres)**
- `lifecycle_events(event_id pk, job_id, root_request_id, seq, from_state, to_state, method, trigger, payload_hash, spend_delta jsonb, trace_id, ts, idempotency_key unique(job_id,idempotency_key))` — append-only.
- `job_current(job_id pk, subagent_id, state, last_seq, updated_at)` — materialized view for fast reads; rebuildable from events.
- `idempotency(job_id, method, request_hash, response_blob, created_at, unique(job_id,method,request_hash))`.

### S1.8 Public APIs

**1. C1 wire API (gRPC + HTTP/JSON, mTLS, least-privilege scopes).** Every method envelope carries: `job_id (uuid)`, `subagent_id`, `trace_id (OTel)`, `budget_token`, `provenance_context`, `capability_scopes[]`.

| RPC | HTTP | Semantics |
|-----|------|-----------|
| `Register(RegisterRequest) → CapabilityDescriptor` | `POST /v1/subagents/{subagent_id}/register` | Advertise identity/subtopics/adapters/resource envelope/conformance/contract range. Idempotent per `subagent_id`. Publishes a C5 revision to S6. |
| `Accept(JobEnvelope) → Acceptance` | `POST /v1/jobs/{job_id}/accept` | Potentially-refusing, idempotent per `job_id`. `accepted:false` is a normal outcome. |
| `Plan(JobEnvelope) → Plan` | `POST /v1/jobs/{job_id}/plan` | Inspectable plan BEFORE execution; no heavy compute. |
| `Build(Plan) → BuildResult` | `POST /v1/jobs/{job_id}/build` | Runs in S10 sandbox via S2; emits C4 provenance per artifact; bounded auto-repair. |
| `Validate(BuildResult) → ValidationRequest` | `POST /v1/jobs/{job_id}/validate` | Freezes pipeline, hands off to S3; NEVER self-grades. |
| `Report(ReportRequest) → SubagentReport` | `GET /v1/jobs/{job_id}/report` | Final deliverable; `claim_tier` sourced ONLY from the C3 report. Idempotent. |
| `Cancel(CancelRequest) → CancelAck` | `POST /v1/jobs/{job_id}/cancel` | Cooperative cancellation; idempotent. |
| `Heartbeat(HeartbeatRequest) → Health` | `GET /v1/jobs/{job_id}/heartbeat` | Liveness + progress + spend. |

**2. Python SDK (`argus-subagent`)**
```python
from argus_subagent import Subagent, CapabilityDescriptor, JobEnvelope, Plan, BuildResult, ExecContext

class MySubagent(Subagent):
    contract_version = "1.0.0"
    def describe(self) -> CapabilityDescriptor: ...
    def accept(self, job: JobEnvelope) -> Acceptance: ...     # optional override; default gate provided
    def plan(self, job: JobEnvelope, ctx: ExecContext) -> Plan: ...   # required
    def build(self, plan: Plan, ctx: ExecContext) -> BuildResult: ... # required
    # validate(), report(), heartbeat(), cancel() are framework-final (not overridable)

# ExecContext (only execution/provenance path):
ctx.submit_sandbox_job(spec) -> SandboxResult
ctx.emit_artifact(bytes, kind, lineage_inputs=[...]) -> ArtifactRef   # fail-closed on incomplete lineage
ctx.call_adapter(adapter_ref, eval_request) -> EvalResult             # C6, brokered, allowlisted
ctx.read_dataset(dataset_ref) -> DatasetHandle
ctx.tag_uncertainty(representation, value)                            # Silver+ helper
# There is deliberately NO ctx.set_claim_tier(...)
```

**3. CLI (`argus-subagent`, shipped for P1/P2; reused by S12)**
- `argus-subagent init <name>` — scaffold a subagent project (base class, descriptor stub, tests).
- `argus-subagent validate-descriptor` — check the C5 descriptor against schema and completeness.
- `argus-subagent run --job <job.json>` — run a job end-to-end locally against sandbox + mock S3/S8 for development.
- `argus-subagent conformance --level {bronze|silver|gold}` — run the reference conformance suite; prints pass/fail per behavior; emits an evidence artifact (C4).
- `argus-subagent replay --job <id>` — replay lifecycle events from the store and show the state trajectory.
- `argus-subagent codegen` — regenerate pydantic/TS/Rust bindings from schemas; fail on drift.
- `argus-subagent freeze --build <result>` — produce and inspect the frozen_pipeline_ref manifest.

**4. Events emitted (NATS JetStream)**
- `s1.lifecycle.transition` — `{job_id, from_state, to_state, method, trace_id, ts}` (consumed by S11, S5).
- `s1.subagent.registered` — `{subagent_id, descriptor_revision_ref}` (consumed by S6 registry cache, S11).
- `s1.job.refused` — `{job_id, reason}` (consumed by S5 for rerouting).
- `s1.job.quarantined` — `{job_id, category, provenance_ref}` (Sev-1; consumed by S9/S11).
- `s1.artifact.emitted` — `{job_id, artifact_ref, kind}` (consumed by S8/S11).

**5. Interfaces consumed (exact contracts)**
- **C4 (S8):** `write_artifact_record(ArtifactRecord) -> ref` (fail-closed), `get_lineage(ref)`.
- **S10 runtime API:** `submit_sandbox_job(oci_digest, inputs, budget_token, scopes, seeds, caps) -> metered SandboxResult`; brokered adapter proxy for C6 calls needing credentials.
- **C3 (S3):** `verify(VerificationRequest) -> ValidationReport` (S1 calls on `validate()`).
- **C5 registry (S6):** `publish(descriptor) -> revision_ref`, `resolve(query)`.
- **C6 (S7):** `describe()`, `evaluate(EvalRequest) -> EvalResult`, `grad(...)`, `batch_evaluate(...)` — invoked via `ctx.call_adapter`.
- **C2 (S5):** receives `JobEnvelope`, returns `JobResult`/`SubagentReport`.

---

## S2 — ML Builder Engine

**Owns contract:** none (coupling is contract-only). **Consumes:** C2/Plan (S5), C4 (S8), C6 (S7), C5 (S6), C3 `list_profiles` presence-only (S3), S6 curated priors, S10, S11.

### S2.1 Architecture overview
S2 is a library + in-sandbox service embedded in a subagent process (S1 runtime). It is invoked by S1's `build(Plan)` and, for recursion, by S4 through S1. It runs entirely in the S10 untrusted zone. It talks to the outside world ONLY through contracts: reads/writes artifacts via C4/S8, calls forward models via C6/S7 (brokered), pulls curated priors/docs via S6 (read-only), and receives budget tokens via C2/S10. It emits OTel to S11. It does not import S3/S4/S5 internal types.

```
             ┌──────────────────────────── S1 Subagent (C1 build step) ────────────────────────────┐
 C2 Plan ───►│  BuildOrchestrator (Temporal-activity-driven, checkpointed)                          │
             │    ├─►(1) SpecCompiler ── validates units contract, resolves datasets(C4)/adapters(C6)│
             │    ├─►(2) DataManager ── deterministic splits, folds, blind-input handling            │
             │    ├─►(3) FeatureEngine ── UnitsAlgebra + PriorInjectors + FeatureGraph               │
             │    ├─►(4) ModelSynthesizer ── zoo + complexity-escalation policy → search space       │
             │    ├─►(5) HPOEngine ── Optuna/Ray Tune, multi-objective, warm-start                   │
             │    ├─►(6) TrainingRuntime ── JAX/PyTorch/sklearn backends, checkpoint, meter          │
             │    ├─►(7) UQCalibrator ── uncertainty repr + coverage calibration                     │
             │    ├─►(8) FailureDoctor ── diagnose + bounded auto-repair playbooks                   │
             │    ├─►(9) AdvisorySelfCheck ── non-authoritative physics/leakage pre-screen           │
             │    ├─►(10) PipelineFreezer ── serialize deterministic inference pipeline for S3       │
             │    └─►(11) ProvenanceEmitter ── C4 records for every artifact                         │
             └───────────────────────────────────────────────────────────────────────────────────────┘
     C6 adapters (S7) ↑ forward models      C4/S8 store ↕ artifacts     S6 priors ↑     S11 OTel ↓
```

### S2.2 Components

**(1) SpecCompiler.** Parses C2 `problem_spec` + `constraints` into an internal `BuildSpec`. Validates the `units_contract` (every input/target field carries a dimension), resolves `allowed_datasets` and `allowed_adapters` to concrete C4/C6 descriptors, and selects a task-type (regression / classification / density-estimation / surrogate-emulation / generative). Fails closed with `POLICY` if a required adapter/verifier profile is absent (S2 does not run without the verifier profile being resolvable, mirroring "no verifier, no run").

**(2) DataManager.** Materializes datasets by C4 ref (content-hash verified). Produces deterministic, seed-pinned train/val/test splits and k-fold indices; supports *blind inputs* (opaque handles the optimizer must not see labels for) by routing them through a "features-only" path. Enforces temporal / group-aware splitting when the spec declares grouping keys (prevents naive leakage). Emits a `DatasetSplit` C4 artifact.

**(3) FeatureEngine.** The physics core. Three sub-parts:
- *UnitsAlgebra*: a dimension-vector engine (SI base dimensions + natural-unit extensions ℏ=c=1 with an explicit energy dimension) attached to every column. Every constructed feature carries a derived dimension; combinations that are dimensionally invalid are rejected at graph-build time.
- *PriorInjectors*: pluggable constructors that emit physically-motivated features and constraints: dimensionless-group builder (Buckingham-π style), symmetry-invariant features (e.g. |p|, invariant masses, permutation-invariant pooling), positivity/log transforms, known-limit anchors (features that vanish/saturate in asymptotic regimes), and forward-model-derived features via C6 `evaluate` (with propagated uncertainty).
- *FeatureGraph*: a content-addressed DAG of transforms; deterministic, serializable, replayable at inference time inside the frozen pipeline.

**(4) ModelSynthesizer.** Maintains a pluggable **model zoo** with descriptors declaring family, capability (task types), cost class, differentiability, uncertainty-native support, and physics-constraint hooks. Applies a **complexity-escalation policy**: start from strong classical baselines (linear/GLM, XGBoost/LightGBM, random forest, GP for small-N with native UQ), escalate to shallow MLP, then JAX physics-informed nets / normalizing flows / deep ensembles only if a held-out gain threshold over the incumbent is exceeded and budget remains. Produces a candidate search space for HPO. Physics constraints are attached as (a) architecture constraints (e.g. monotonicity, non-negativity output layer), (b) loss terms (e.g. symmetry-consistency, unitarity-penalty via differentiable C6 surrogate), (c) post-hoc gates.

**(5) HPOEngine.** Optuna study (TPE/CMA-ES/multivariate) with Ray Tune distributed trials, ASHA/Hyperband pruning, and a **multi-objective** scalarization or Pareto front over {held-out predictive score, calibration error, cost/latency}. Supports **warm-start** from a prior generation's trials (for S4). Trial budget derived from C2 budget minus reserve for training/packaging. Never optimizes against any authoritative verifier signal directly — only against held-out advisory metrics computed on data S2 is allowed to see.

**(6) TrainingRuntime.** Backend-abstracted trainer (JAX/Flax/Optax default for differentiable/physics-informed; PyTorch for imported community models; sklearn/XGBoost/LightGBM for classical). Provides: seeded determinism, gradient-clipping, mixed precision, checkpointing to the object store, early stopping, live spend metering (GPU-seconds/wallclock/model-tokens via a `BudgetMeter`), and cooperative cancellation + heartbeat integration. Emits `TrainingLog` and `ModelCheckpoint` C4 artifacts.

**(7) UQCalibrator.** Attaches a calibrated uncertainty representation appropriate to the model: native (GP posterior, quantile regression, deep ensemble, MC-dropout, conformal prediction wrapper for point predictors). Runs a **coverage/calibration** procedure on a held-out calibration split (reliability diagram / PIT / empirical coverage of nominal intervals) and stores the calibration mapping in the frozen pipeline. A model whose stated uncertainty fails an internal coverage threshold is flagged for repair; if unrepairable, the build fails-loud (mirrors the platform's calibration NFR, though the *authoritative* CALIBRATION gate is S3's).

**(8) FailureDoctor.** Rule + heuristic engine mapping symptoms to bounded repairs: NaN/Inf loss → lower LR / grad-clip / re-init; divergence → LR schedule change / normalization; OOM → reduce batch / grad-accum / smaller model; degenerate constant predictor → class-weighting / feature check; suspicious-perfect metric → leakage smell → halt & flag; adapter `UNDERLYING_CODE_ERROR` → retry with narrowed validity domain or drop the adapter feature. Repairs are **bounded** (max N attempts, budget-charged) and **logged** to provenance. Exhaustion → `QUARANTINED`.

**(9) AdvisorySelfCheck.** Runs *cheap, non-authoritative* pre-screens that mirror (but never replace) S3: quick injection-recovery sanity on a synthetic signal, a null/label-shuffle sanity, a dimensional-consistency assertion, and a leakage smell detector. Results are stamped `advisory=true` and can only *lower* confidence / trigger repair — never raise a claim tier. This reduces S3 round-trips and reward-hacking surface.

**(10) PipelineFreezer.** Serializes the full inference path (FeatureGraph + fitted transforms + model weights + UQ calibration map + declared nondeterminism tolerance) into a **self-contained, deterministic, S3-executable** artifact with a manifest: entrypoint signature `predict(inputs_units_tagged) -> {outputs_units_tagged, uncertainty}`, pinned container digest, adapter refs+versions, seeds, config/params hashes. This is the `frozen_pipeline_ref(C4)` that S3's `verify()` fetches and runs itself (S3 never runs it in-process with S2).

**(11) ProvenanceEmitter.** Wraps every artifact write through the S8 C4 writer (Rust ledger), guaranteeing complete lineage (inputs, derived_from, code commit, environment_digest, adapters_used+versions, seeds, config_hash, params_hash) and fail-closed on incomplete lineage.

### S2.3 Key algorithms

**A1 — Dimensional Feature Validation (Buckingham-π guard).** Represent each quantity's dimension as an integer vector over base dimensions. A constructed feature f = Πxᵢ^aᵢ is admissible iff its target dimension matches the declared feature dimension (or is dimensionless when required). The π-builder searches integer null-space combinations of the input dimension matrix to enumerate dimensionless groups; only these enter as "dimensionless features". Complexity bounded by capping the exponent search range and group count. Oracle: reject any feature whose dimension vector ≠ declared.

**A2 — Complexity-Escalation Selection.** Maintain incumbent best held-out score `S*`. Fit next-tier family; escalate only if `S_new - S* > δ·se(S*)` (statistically significant gain, `se` = held-out standard error, `δ` a policy margin) AND remaining budget ≥ family's cost class. Otherwise stop and keep incumbent. Guarantees breadth-first, avoids over-fitting compute to deep nets.

**A3 — Multi-Objective HPO.** Objective vector `(−score, calib_error, normalized_cost)`. Use Optuna multi-objective (NSGA-II) to build a Pareto front; final selection by a policy weighting from C2 `success_criteria` (default: lexicographic — score first, then calibration, then cost). ASHA prunes dominated trials early. Warm-start seeds the sampler with prior-generation completed trials.

**A4 — Conformal / Coverage Calibration.** For point predictors, wrap with split-conformal to produce prediction intervals with nominal coverage 1−α; validate empirical coverage on a held-out fold; if |empirical − nominal| > tol, widen via the calibration multiplier or switch UQ method. For native-UQ models, run a PIT-histogram uniformity test.

**A5 — Auto-Repair Policy Search.** Bounded best-first over a symptom→repair graph with a cost budget; each repair re-trains a short probe (reduced epochs) to confirm symptom resolution before committing full budget; loop-detection prevents oscillating repairs.

**A6 — Deterministic Freeze & Replay.** Canonicalize the FeatureGraph + model into a byte-stable serialization; record all seeds and nondeterminism sources; on freeze, run a self-replay: execute the frozen pipeline twice on a fixed probe input and assert output equality within declared tolerance before emitting the artifact (guarantees S3 can reproduce).

### S2.4 Sequence flow (build)
1. S1 calls `build(Plan, C2)` → BuildOrchestrator starts a checkpointed workflow, mints `BudgetMeter` from `budget_token`.
2. SpecCompiler validates units + resolves datasets(C4)/adapters(C6)/verifier-profile presence → `BuildSpec` (fail-closed on missing).
3. DataManager materializes + splits data (C4 artifact).
4. FeatureEngine builds FeatureGraph (dimensional guard) → candidate feature sets (C4).
5. ModelSynthesizer proposes tiered search space.
6. HPOEngine runs distributed trials (each: fit subset + advisory held-out score + calib); FailureDoctor intercepts trial failures; BudgetMeter enforces caps; heartbeats to S1.
7. Best config → TrainingRuntime full train with checkpointing → ModelCheckpoint (C4).
8. UQCalibrator fits + validates calibration.
9. AdvisorySelfCheck runs non-authoritative screens (advisory flags).
10. PipelineFreezer serializes + self-replays → `frozen_pipeline_ref` (C4, write-once).
11. ProvenanceEmitter finalizes lineage; BuildOrchestrator returns `BuildResult{artifact_refs, training_log_ref, frozen_pipeline_ref, diagnostics}` to S1, which proceeds to `validate()` (S3).

### S2.5 Sequence flow (Evolver variant, S4)
S4 → S1 → S2 `build_variant(base_pipeline_ref, mutation_spec, warm_start_ref?)`: SpecCompiler diffs mutation against base (family/feature/HPO changes), reuses cached splits/features where hashes match, warm-starts HPO, trains deterministically, freezes. S2 returns the built pipeline; **scoring happens only via S3's signed report**, read back by S4. S2 exposes no score channel to S4 other than advisory metrics clearly stamped non-authoritative.

### S2.6 Tech choices (consistent with shared stack)
Python 3.11 + pydantic v2 models generated from C1/C2/C4/C6 schemas. JAX/Flax/Optax default; PyTorch for imported models; scikit-learn/XGBoost/LightGBM classical; Optuna (HPO) + Ray Tune (distributed trials). Artifacts to S8 object store keyed by BLAKE3. Durable orchestration as Temporal activities (long training survives restarts). OTel → Prometheus/Tempo. Runs inside gVisor/Firecracker (S10); egress via allowlist proxy to C6 adapter endpoints + content store only. No secrets in-process; adapters brokered.

### S2.7 Failure & degradation handling
- **Missing verifier profile / adapter / dataset:** `POLICY`/`PERMANENT` fail-closed at SpecCompiler; no execution.
- **Budget breach:** BudgetMeter halts within a bounded grace, checkpoints best-so-far as a partial artifact, returns `BUDGET` typed error (non-retryable auto).
- **Adapter errors:** `OUT_OF_DOMAIN`/`UNITS_MISMATCH` → drop feature or fail-closed per policy; `UNDERLYING_CODE_ERROR`/`TIMEOUT` → FailureDoctor bounded retry, else drop with provenance note.
- **Training instability:** FailureDoctor bounded auto-repair; exhaustion → `QUARANTINED` with full diagnostics.
- **Calibration failure:** attempt UQ-method switch/widen; if unrepairable → fail-loud.
- **Non-reproducible freeze (self-replay mismatch beyond tolerance):** hard fail; artifact not emitted (fail-closed).
- **Sandbox/policy violation attempt (egress, self-grade, ledger write bypass):** Sev-1, halt + quarantine sandbox image.
- **Leakage smell:** never auto-resolved by hiding; surfaced as advisory, may halt, always defers authority to S3.

### S2.8 Data models (pydantic v2; JSON-Schema-generated where they cross contracts)

**BuildSpec (internal, compiled from C2)**
```
BuildSpec {
  job_id: uuid; subagent_id: str; trace_id: str
  task_type: enum{regression, classification, density_estimation, surrogate_emulation, generative}
  target_observable: { name: str; units: DimVector }
  inputs_schema: [ FieldSpec ]                # each with units: DimVector, role
  units_contract_ref: ref                     # C2 constraints.units_contract
  success_criteria: { primary_metric: str; direction: enum{max,min};
                      calibration_tol: float; secondary: [ {metric, weight} ] }
  required_claim_tier_max: enum{ran-toy, recapitulated-known}   # S2 never emits > recapitulated-known
  datasets: [ DatasetRef(C4) ]
  adapters: [ AdapterRef(C6) ]
  verifier_profile_ref: ref(C3)               # must be present (resolvable) or fail-closed
  physics_priors: [ PriorSpec ]
  budget: BudgetCaps                           # from C2.budget
  determinism: enum{deterministic, seeded, best_effort}
  grouping_keys: [str]                         # for group/temporal splits
}
FieldSpec { name; dtype; units: DimVector; role: enum{feature, target, group, id, blind_input} }
DimVector { base: {mass,length,time,charge,temperature,amount,luminous, energy_natural}: int[8]; scale?: str }
PriorSpec { kind: enum{dimensionless_group, symmetry_invariant, positivity, monotonicity,
                       unitarity_bound, asymptotic_limit, forward_model_feature};
            params: json; enforcement: enum{feature, constraint, loss, gate} }
BudgetCaps { max_compute_units; max_gpu_seconds; max_model_tokens; max_wallclock_s; max_cost_usd; repair_attempts_max: int }
```

**FeatureGraph & FeatureSet**
```
FeatureGraph { graph_id; nodes: [FeatureNode]; content_hash }
FeatureNode { node_id; op: enum{source, arithmetic, pi_group, invariant, transform, adapter_eval, aggregate};
              inputs: [node_id]; params: json; out_dim: DimVector; deterministic: bool;
              adapter_ref?(C6); uncertainty_propagated: bool }
FeatureSet { feature_set_id; graph_ref; selected_nodes: [node_id]; content_hash }
```

**ModelDescriptor (zoo entry) & Candidate**
```
ModelDescriptor { family_id; family: str; backend: enum{sklearn,xgboost,lightgbm,jax,torch,gp,flow,ensemble};
                  task_types: [enum]; cost_class: enum{XS,S,M,L,XL}; differentiable: bool;
                  native_uq: enum{none,gp,quantile,ensemble,mc_dropout,conformal_required};
                  constraint_hooks: [enum{arch,loss,posthoc}]; search_space_schema: json;
                  descriptor_version: semver }
Candidate { candidate_id; family_id; hyperparams: json; feature_set_ref; complexity_tier: int }
```

**HPO artifacts**
```
HPOStudy { study_id; sampler: str; pruner: str; objectives: [ObjectiveSpec];
           warm_start_ref?; trials: [HPOTrial]; pareto_front: [trial_id]; content_hash }
ObjectiveSpec { name: enum{score, calibration_error, cost}; direction: enum{max,min}; weight?: float }
HPOTrial { trial_id; candidate_ref; metrics: {score,calibration_error,cost, ...};
           status: enum{COMPLETE,PRUNED,FAILED}; duration_s; spend: SpendRecord }
```

**Training / Model / UQ**
```
TrainingLog { log_id; candidate_ref; epochs; curves: {train_loss[],val_loss[],metric[]};
              checkpoints: [ckpt_ref]; repairs: [RepairAction]; final_metrics; spend: SpendRecord }
ModelArtifact { model_id; family_id; weights_ref(C4); backend; feature_set_ref;
                uq: UQSpec; determinism: enum; nondeterminism_tolerance?: float }
UQSpec { representation: enum{interval, covariance, samples, quantiles, gp_posterior};
         method: enum{gp,quantile,ensemble,mc_dropout,conformal}; nominal_coverage: float;
         empirical_coverage: float; calibration_map_ref; passed_internal_coverage: bool }
```

**Repair / Diagnostics / Self-check**
```
RepairAction { symptom: enum{nan_loss,divergence,oom,degenerate,leakage_smell,adapter_error,
                             calibration_fail,slow_convergence};
               action: str; params_before/after: json; probe_result: enum{resolved,unresolved};
               spend: SpendRecord; timestamp }
Diagnostics { build_id; phase_metrics: json; repairs: [RepairAction];
              advisory_self_checks: [AdvisoryCheck]; warnings: [str]; quarantine_reason?: str }
AdvisoryCheck { type: enum{injection_sanity,null_sanity,dimensional,leakage_smell,calibration};
                status: enum{PASS,FAIL,INCONCLUSIVE}; metric; note; advisory: bool=true }  # never sets tier
```

**FrozenPipeline (S3-executable) & BuildResult (C1 build return)**
```
FrozenPipeline { pipeline_id; entrypoint: "predict";
                 io_signature: { inputs: [FieldSpec]; outputs: [FieldSpec]; uncertainty: UQSpec };
                 feature_graph_ref; model_ref; calibration_map_ref;
                 container_digest; adapters_used: [{adapter_ref, adapter_version}];
                 seeds: {global, per_library}; config_hash; params_hash;
                 nondeterminism_tolerance; self_replay_passed: bool; content_hash }   # write-once C4
BuildResult {   # returned to S1, per C1
  job_id; artifact_refs: [C4]; training_log_ref; frozen_pipeline_ref(C4);
  diagnostics: Diagnostics; claim_tier: "ran-toy";           # S2 caps at ran-toy pre-verification
  uncertainty_summary: UQSpec; cost_actual: SpendRecord; reproducibility_manifest_ref }
SpendRecord { compute_units; gpu_seconds; model_tokens; wallclock_s; cost_usd }
```

**Events (NATS).** `s2.build.started/phase/heartbeat/repair/completed/failed/quarantined` — `{ job_id, trace_id, phase, progress, spend_so_far, ... }`. All C4 ArtifactRecords produced by S2 conform to the C4 schema (content_hash, kind, producer, lineage{...}, uncertainty_tag, claim_tier<=ran-toy).

### S2.9 Public APIs

S2 is embedded behind the C1 `build`/`validate` step; its own surface is consumed by the S1 runtime and (through S1) by S4. All calls carry the C1 required envelope (`job_id, subagent_id, trace_id, budget_token, provenance_context, capability_scopes[]`). Transport: in-process library + optional gRPC for the in-sandbox service. All cross-subsystem I/O goes only through C4 (S8), C6 (S7), C5/S6 read, C3-profile presence check.

**Core build API (Python / gRPC)**
```
build(plan: Plan, envelope: C2.JobEnvelope) -> BuildResult
    # Executes phases 1-11; returns BuildResult (claim_tier fixed at "ran-toy").
    # Raises typed error {code, category(RETRYABLE|PERMANENT|BUDGET|POLICY|SANDBOX|VERIFIER_UNAVAILABLE)}.

build_variant(base_pipeline_ref: C4ref, mutation: MutationSpec,
              envelope: C2.JobEnvelope, warm_start_ref: C4ref | None) -> BuildResult
    # Evolver path (S4). Deterministic; reuses cached splits/features by hash; warm-starts HPO.
    # Returns a built FrozenPipeline; NO score is returned (score comes only from S3 signed report).

heartbeat() -> Health{status, phase, progress, spend_so_far}     # liveness for S1/S5
cancel(job_id, reason) -> Ack                                     # cooperative; checkpoints partial
```

**Introspection / plugin registration**
```
list_model_families() -> [ModelDescriptor]
list_prior_injectors() -> [PriorInjectorDescriptor]
register_model_family(descriptor: ModelDescriptor, entrypoint) -> revision_ref   # plugin, S2-internal
register_prior_injector(descriptor, entrypoint) -> revision_ref
list_repair_playbooks() -> [RepairPlaybookDescriptor]
```

**MutationSpec (Evolver)**
```
MutationSpec {
  change_model_family?: family_id
  feature_subset?: [node_id]           # add/remove feature nodes
  hpo: { budget_trials?, sampler?, warm_start: bool }
  hyperparam_overrides?: json
  constraint_overrides?: [PriorSpec]
}
```

**CLI (developer / debugging; runs inside sandbox harness)**
```
argus-s2 build --plan plan.json --envelope job.json --out result.json
argus-s2 build-variant --base <pipeline_hash> --mutation mut.json --envelope job.json [--warm-start <hash>]
argus-s2 replay --pipeline <hash> --input probe.json          # runs frozen pipeline self-replay
argus-s2 explain --build <build_id>                           # renders model/feature/HPO/repair report
argus-s2 zoo list | zoo add <descriptor.json>
argus-s2 priors list
argus-s2 diagnose --build <build_id>                          # dumps Diagnostics + advisory checks
```

**Events emitted (NATS JetStream, consumed by S11/S5)**
```
s2.build.started      { job_id, trace_id, budget }
s2.build.phase        { job_id, phase, progress }
s2.build.heartbeat    { job_id, spend_so_far, progress }
s2.build.repair       { job_id, RepairAction }
s2.build.completed    { job_id, build_result_ref, cost_actual }
s2.build.failed       { job_id, category, provenance_ref }
s2.build.quarantined  { job_id, reason, diagnostics_ref }
```

**Interfaces consumed (contract calls)**
```
C4/S8:  put_artifact(record) -> content_hash ; get_artifact(ref) -> bytes+record
C6/S7:  adapter.describe() ; adapter.evaluate(EvalRequest) -> EvalResult(units+uncertainty) ;
        adapter.grad(EvalRequest) -> Jacobian ; adapter.batch_evaluate([...])
C5/S6:  registry.resolve(query) -> [descriptor]   # resolve datasets/adapters, read curated priors (RAG, read-only)
C3/S3:  list_profiles() -> [VerifierProfile]      # PRESENCE/resolvability check only; S2 never calls verify()
C2/S5:  receives JobEnvelope; honors budget_token via S10 BudgetMeter
S11:    OTel spans + NATS events
```

---

## S3 — Physics Validation & Verifier Framework

**Owns contract:** **C3**. **Consumes:** C4 (S8), C5 (S6), C6 (S7), S6 frozen index, S10 nested sandbox, Vault/KMS, C2 (S5), C1 validate-handoff (S1), S11.

### S3.1 Architecture overview
S3 runs entirely in the **Verifier Zone** — a trust zone separate from the agent (S10) sandbox, with its own service identity, its own signing key (vault/KMS), read-only access to content-addressed storage (S8), and blind-data storage no other zone can read. S3 never runs subagent code in-process; it treats a "frozen pipeline" as an opaque, content-addressed artifact executed inside a *nested, disposable* S10 sandbox that S3 controls (so the pipeline runs under isolation, but the grading logic, thresholds, blind labels, and signing key live outside that sandbox).

```
                 ┌──────────────────────────────────────────────────────┐
                 │                VERIFIER ZONE (S3)                     │
 C2 job ───────► │  Verifier API (gRPC/HTTP, mTLS)                        │
 (S1/S4/S5)      │    list_profiles / verify / challenge                 │
                 │        ▼                                              │
                 │  Verify Orchestrator (Temporal child workflow)        │
                 │    ├─ Profile Resolver (loads VerifierProfile rev)    │
                 │    ├─ Independence Resolver ──► C5 registry (S6)       │
                 │    ├─ Blind-Data Manager  ──► Blind Vault (zone-only)  │
                 │    ├─ Frozen-Pipeline Runner ─► nested S10 sandbox     │
                 │    ├─ Check Executor pool (6 families, plugin API)     │
                 │    │      INJECTION NULL CROSS_CODE PHYS LEAK CALIB    │
                 │    │            └─► S7/C6 adapters                     │
                 │    ├─ Tiering Rule Engine (deterministic)             │
                 │    ├─ Report Builder + Canonicalizer                  │
                 │    └─ Signer (Rust) ──► vault/KMS key                 │
                 │        ▼ write-once bucket (S8) + provenance (C4)     │
                 └──────────────────────────────────────────────────────┘
   reads: C4 artifacts (S8), C5 registry (S6), frozen index (S6), C6 adapters (S7)
   emits: signed ValidationReport (C3), evidence artifacts (C4), OTel traces (S11)
```

### S3.2 Components
1. **Verifier API service** (Python 3.11, gRPC + HTTP/JSON, pydantic v2 models generated from the C3 JSON Schema). Stateless front door; authorizes each call by least-privilege capability scope + mTLS; validates the `budget_token`.
2. **Verify Orchestrator** — a Temporal workflow (durable, restart-surviving). Steps: resolve profile → resolve independence → stage blind data → run frozen pipeline on each dataset variant → dispatch checks → aggregate → tier → build/sign report → commit. Human-wait states are NOT here (that's S9); S3 is fully automated but its output *feeds* the S9 gate.
3. **Profile Resolver** — loads an immutable `VerifierProfile` revision from the profile registry (Postgres, append-only). Compiles it: resolves each check plugin version, threshold set, and independence requirement; re-checks the C6 cost ceiling; produces a `CompiledProfile`.
4. **Independence Resolver** — queries C5 `resolve(query{observable, independence_needed})` to select a cross-code adapter with `independence_tags` disjoint from the code-under-test's lineage (`code.repo`, `derived_from`). Emits an `IndependenceAttestation` or `INDEPENDENCE_UNAVAILABLE`.
5. **Blind-Data Manager** — owns the Blind Vault (write-once, verifier-zone-only object store buckets, mTLS-scoped to S3 identity). Manages injection templates, null/negative-control sets, held-out recapitulation benchmarks, and blind test partitions. Delivers data to the frozen pipeline ONLY as opaque inputs (never labels); computes labels/answers server-side for scoring.
6. **Frozen-Pipeline Runner** — takes `frozen_pipeline_ref` (a container digest + entrypoint contract from C4), spins up a *nested* disposable S10 sandbox (egress-denied, read-only rootfs, resource-capped), feeds opaque inputs, captures outputs + uncertainty tags. The pipeline is a pure function input→(prediction, uncertainty); no network, no blind labels inside.
7. **Check Executor** — plugin host. Each check family is a versioned plugin implementing `CheckPlugin{describe(), run(ctx)->CheckResult}`. Plugins are pure w.r.t. their declared inputs; determinism class declared. Runs in the verifier zone (not the agent sandbox) except the frozen-pipeline invocation which is delegated to the Runner.
8. **Cross-code engine** — a specialization used by CROSS_CODE: calls one or more independent S7/C6 adapters via `evaluate`/`grad`, propagates units + uncertainty, applies the agreement statistic.
9. **Statistics library** — shared: tolerance tests, χ²/z agreement, coverage/PIT calibration tests, false-positive-rate estimation, multiple-comparison correction (Benjamini–Hochberg), bootstrap CIs. Pure JAX/NumPy, seeded.
10. **Tiering Rule Engine** — deterministic finite decision function `f(check_results, independence, degradations) -> (tier, justification, rule_id)`. Encoded as declarative rules with a compiled evaluation order; monotone by construction.
11. **Report Builder + Canonicalizer** — assembles the `ValidationReport`, produces a canonical serialization (RFC 8785 JCS / deterministic CBOR), computes content hash.
12. **Signer** (Rust) — signs the canonical bytes with the verifier key (cosign/Sigstore-style) fetched from vault; the private key never leaves the signer process. Emits `signature`, `signer_key_id`.
13. **Signature-verification library** — shipped as a small vendored lib (Python + Rust + TS) to all C3 consumers (S1/S2/S4/S5/S8/S9/S11) so verification is identical everywhere; rejects unsigned/tampered.
14. **Profile-author tooling** — DSL/schema for profiles, `dry_run` mode, and a profile conformance harness (does the profile's thresholds behave sanely on gold/known-bad fixtures?).

### S3.3 Key algorithms

**3.1 Injection recovery (INJECTION) — the MUST-REACT half of a bidirectional pair.** For a subtopic with known forward model M and injectable signal parameter θ (e.g. GW amplitude Ω): sample a set of ground-truth θ_i from the profile's injection grid; synthesize inputs x_i = M(θ_i) + noise (noise model from profile). Run frozen pipeline → θ̂_i, σ̂_i. Recovery metric = fraction of i with |θ̂_i − θ_i| ≤ tol(θ_i) AND z_i=(θ̂_i−θ_i)/σ̂_i within calibration band. PASS iff recovery_rate ≥ profile threshold. Deterministic given seeds. Guards against a model that learns nothing real. As a **must_react** probe this check also asserts **amplitude-linearity**: the recovered signal must scale proportionally with the planted signal; a KNOWN-REAL signal that does not appear → FAIL (model is blind/insensitive).

**3.2 Null / negative control (NULL_CONTROL) — the MUST-NOT-REACT half of a bidirectional pair.** Three variants: (a) signal-free input (θ=0 or pure-noise realizations), (b) label-shuffled inputs, (c) fake-contamination / data-contamination injections. Run pipeline; estimate empirical false-positive rate FPR at the pipeline's own reported decision threshold. PASS iff FPR ≤ profile α with a one-sided binomial upper bound below the ceiling. As a **must_not_react** probe the claim MUST NOT manufacture a signal and MUST degrade appropriately: if a strong result survives UNCHANGED under noise/shuffle/contamination it should have reacted to, that invariance is the **INSENSITIVITY** failure (result is not data-driven: memorized / constant / spurious-feature) → FAIL. Guards against hallucinated signal / leakage.

**3.2b Bidirectional perturbation pairing (BIDIRECTIONAL, must_react + must_not_react).** The INJECTION and NULL_CONTROL families are run as **bidirectional perturbation pairs**, not in isolation. Each pair `{must_react, must_not_react}` shares a `perturbation_id` and is adjudicated jointly: `run_perturbation_pair(model_ref, perturbation_spec)` plants a KNOWN-REAL signal (must_react) AND injects noise/shuffle/contamination (must_not_react), records `expected` vs `observed` for each direction, and emits a per-direction verdict. A perturbation pair only passes when the must_react direction recovers the planted signal proportionally AND the must_not_react direction does not manufacture a signal AND no insensitivity is detected. Both directions plus the no-insensitivity condition are recorded in the report's `perturbation_pairs[]`.

**3.2c Insensitivity detector (INSENSITIVITY → FAIL).** `detect_insensitivity(model_ref, perturbation_set)` looks for **invariance to a perturbation the claim should have reacted to**. For each must_not_react perturbation, it compares the claim's headline result/statistic before and after the perturbation; if a strong result survives essentially UNCHANGED (delta below a sensitivity floor) when it should have degraded — e.g. the result persists under label-shuffle or data-contamination — the perturbation is flagged as an insensitivity: the result is not actually data-driven (memorized / constant / spurious-feature). Any insensitivity flag → the affected check FAILs and populates the report's `insensitivity_flags[]` (`{perturbation_id, reason}`). This is the hard detector behind the planted-spurious-model KPI.

**3.2d Challenger-independence attestation (lineage-disjoint cross-code).** `attest_challenger_independence(challenger_ids[])` verifies that the panel of challenger agents attacking a claim is genuinely INDEPENDENT: it resolves each challenger's `code_lineage_hash` and `independence_class` via C5, requires the panel to be **lineage-disjoint** (no shared code lineage), computes a cross-challenger correlation estimate, and emits an `IndependenceAttestation` extended with `{ min_independent_challengers, lineage_disjoint, correlation_warning }`. Correlated / collusion-prone panels raise `correlation_warning=true` and are refreshed. This is the S3-side check consumed by S4's debate loop (S4-TDB2/S4-TDB4).

**3.2e Non-gameable referee separation (referee != proponent).** The REFEREE that adjudicates a debate is the S3 verifier itself: oracle-backed, NON-GAMEABLE, and NEVER the same agent as the PROPONENT (the Builder subagent that produced the candidate). Every report carries a `referee` block `{ referee_id, non_gameable, signed_by, distinct_from_proponent }`; S3 refuses to emit (fail-closed, `POLICY`) if `distinct_from_proponent` is false — i.e. a builder cannot self-attest / self-sign its own claim. Emission of the affected artifact is blocked downstream at S9 (see X-16).

**3.3 Cross-code consistency (CROSS_CODE).** Choose validation points p_k in the validity domain (from profile / intersection of adapter validity domains). Compute y_test,k = pipeline/forward-under-test at p_k with uncertainty; y_ref,k = independent adapter(s) at p_k with uncertainty. Agreement statistic: χ² = Σ (y_test,k − y_ref,k)² / (σ_test,k² + σ_ref,k²). PASS iff χ²/dof within [profile low, high] AND max pointwise |z_k| ≤ z_max. Requires independence attestation; if none → INDEPENDENCE_UNAVAILABLE → tier cap. Out-of-validity-domain points from any adapter → those points INCONCLUSIVE, excluded, and if too many excluded the whole check is INCONCLUSIVE.

**3.4 Physical-consistency gate (PHYSICAL_CONSISTENCY).** Static + runtime checks: (i) dimensional analysis over the pipeline's declared I/O units contract (from C2 `units_contract`) using a units algebra; (ii) positivity of quantities declared non-negative (probabilities, cross-sections, spectral densities) sampled across the domain; (iii) unitarity/normalization bounds (e.g. Σ probabilities ≤ 1 + ε, S-matrix bounds where applicable); (iv) symmetry invariance: transform inputs by declared symmetry group elements g, require outputs invariant/covariant within tol; (v) asymptotic-limit checks: at declared limits (θ→0, high-energy), require known analytic behavior within tol. Each sub-gate independently PASS/FAIL; family PASS iff all mandatory sub-gates PASS.

**3.5 Leakage / contamination screen (LEAKAGE).** (a) Train/test overlap: hash-based near-duplicate detection (BLAKE3 shingling + MinHash/LSH) between the pipeline's declared training inputs (from C4 lineage) and the blind test set. (b) Target leakage: mutual-information / permutation-importance probe that flags features carrying the label deterministically. (c) Frozen-index overlap: embed the candidate result/claim and query the frozen contamination index (S6) via OpenSearch vector+lexical; overlap above threshold ⇒ result is likely memorized/recapitulated, not novel. FAIL blocks novelty; borderline ⇒ downgrade.

**3.6 Calibration (CALIBRATION).** Using injection/held-out points with known truth, compute coverage of stated intervals (e.g. does the 68% interval contain truth ~68% of the time?) and PIT (probability-integral-transform) histogram uniformity (KS test). PASS iff coverage within tolerance band AND PIT KS p-value ≥ α. Rejects overconfident/underconfident uncertainty tags (backs NFR6).

**3.7 Tiering rule (monotone).**
```
tier = ran-toy                      # default: pipeline executed & PHYS self-consistent on a toy
if INJECTION.pass and NULL.pass and PHYS.pass and CALIB.pass:
    tier = recapitulated-known      # additionally requires match to a held-out known benchmark
    if RECAP_BENCHMARK.pass ...     #   (benchmark check, part of profile for known subtopics)
if tier == recapitulated-known and CROSS_CODE.pass and LEAKAGE.all_pass
   and independence_attested and no INCONCLUSIVE on mandatory checks:
    tier = novel-needs-human (CANDIDATE)   # never final; requires S9
```
Any INDEPENDENCE_UNAVAILABLE caps tier at `recapitulated-known`. Any mandatory INCONCLUSIVE caps at the tier below the one it gates. The engine records `claim_tier_justification` = ordered list of rules fired + failing/inconclusive checks.

**3.8 Canonicalization + signing.** Serialize report minus `signature` field via RFC 8785 JSON Canonicalization (or deterministic CBOR); hash with BLAKE3; sign hash with verifier key; embed `signature` + `signer_key_id` + `issued_at`. Consumers recompute the canonical form and verify.

**3.9 Challenge / re-audit (canary).** `challenge(report_ref)` re-loads the pinned inputs, check_suite_version, contamination_index_version, seeds, environment_digest; re-runs; compares to stored report. Deterministic checks must match bit-for-bit; stochastic checks must agree within declared statistical tolerance. Mismatch ⇒ raise a canary alarm (S11) and quarantine the original report as suspect.

### S3.4 Sequence flow (verify)
1. S1 (or S4) calls `verify(VerificationRequest)` with mTLS + budget_token + scopes.
2. API authorizes, validates schema, checks profile exists → starts Verify Orchestrator (Temporal).
3. Profile Resolver loads immutable profile revision → CompiledProfile; re-checks cost ceiling & determinism classes.
4. Independence Resolver queries C5; on success emits IndependenceAttestation; on failure sets degradation=INDEPENDENCE_UNAVAILABLE (tier cap) and continues (CROSS_CODE becomes INCONCLUSIVE).
5. Blind-Data Manager stages injection/null/held-out/blind partitions (opaque inputs) into a runner-scratch mount; retains truth server-side.
6. Frozen-Pipeline Runner spins nested S10 sandbox, runs pipeline on each dataset variant, captures (prediction, uncertainty) with per-call provenance (C4). Budget metered; breach ⇒ halt + partial capture.
7. Check Executor runs the six families concurrently (respecting data deps); each emits CheckResult + evidence artifact (C4).
8. Tiering Rule Engine computes tier + justification.
9. Report Builder assembles + canonicalizes; Signer signs; written to write-once bucket; ArtifactRecord (C4) committed with `validation_report_ref` coupling.
10. API returns the signed report (or its ref). S1 attaches ref to `report()`; S4 reads `aggregate.score`.

### S3.5 Tech choices (consistent with shared stack)
- Python 3.11 + pydantic v2 (models generated from C3 JSON Schema draft 2020-12).
- Temporal for durable verify/challenge workflows (long-running, restart-surviving, budget-metered).
- JAX/NumPy for statistics; SciPy for hypothesis tests; scikit-learn for LSH/MinHash utilities.
- Rust for the Signer and canonical-hash path (trust boundary; matches S8 ledger writer rationale).
- Postgres 16 for the profile registry + report index (append-only tables, recursive-CTE lineage joins).
- Object store (S3-compatible, write-once buckets) for reports, evidence, blind vault; BLAKE3 content addressing.
- OpenSearch (read-only, via S6) for frozen-index leakage vector/lexical queries.
- S7/C6 adapters for cross-code and forward models; S10 for nested sandbox; S6 for frozen index; S8 for artifacts.
- cosign/Sigstore-style signing; keys in HashiCorp Vault / cloud KMS, minted to the Signer identity only.
- OpenTelemetry traces/metrics to S11; NATS JetStream for report-issued / canary-alarm events.

### S3.6 Failure & degradation handling
- **No independent cross-code** → `INDEPENDENCE_UNAVAILABLE`; CROSS_CODE = INCONCLUSIVE; tier capped at `recapitulated-known`; surfaced in report, not hidden.
- **Adapter out-of-domain** → those points excluded; if >profile-max-fraction excluded, CROSS_CODE/INJECTION = INCONCLUSIVE.
- **Frozen-pipeline crash / nondeterminism beyond tolerance** → check INCONCLUSIVE; job may `FAILED` if the crash is total; provenance captures stderr.
- **Budget breach** → immediate halt, partial-result capture, report marked `aggregate.passed=false`, `INCONCLUSIVE` on unrun checks; C2 BUDGET error.
- **Signing failure / vault unavailable** → job does NOT emit a report (fail-closed); returns RETRYABLE; no unsigned report ever leaves.
- **Profile missing/unsupported** → `PROFILE_UNSUPPORTED` (C3 error), non-retryable; subagent must refuse upstream.
- **Blind-data integrity mismatch (hash)** → quarantine + Sev; refuse to run.
- **Independence attestation cannot be produced but profile requires it strictly** → job REFUSED for that tier target; downgraded profile offered.
- **Consumer receives unsigned/tampered report** → verification lib rejects → treated as failure + quarantine (NFR2).
- **Sandbox write-attempt to verifier mounts** → Sev-1, halt, quarantine sandbox image (structural safety).
- All degradations are recorded as first-class fields (`degradations[]`) so downstream tiering and S9 review see them explicitly.

### S3.7 Data models
All models are JSON-Schema-canonical (draft 2020-12), pydantic v2 in Python. C3-owned models are authoritative; S3 also defines internal models.

**C3 contract version:** the Verifier Interface + Validation Report contract keeps **C3 v1.1** as the M0 additive compatibility baseline. C3 v1.1 added six `ValidationReport` fields — `perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate` (debate extension), `referee`, and `debate_ref` — supporting bidirectional perturbation pairing, insensitivity detection, challenger-independence, non-gameable referee separation, and a pointer into the C4 provenance DebateLedger. The current C3 schema is **v2.0**, which makes the trust-surface fields that Observatory renders schema-required and fail-closed in VERIFIED gating.

**VerifierProfile (registry, immutable revision)**
```
VerifierProfile {
  profile_ref: string           # e.g. "ewpt-gw-spectrum@2.1.0#rev7"
  profile_id, revision: int
  verifier_contract_version: semver
  applicable_subtopics: [taxonomy_id]
  checks: [ CheckSpec ]          # ordered; each pins plugin + version + thresholds
  independence_guarantees: {
      cross_code_required: bool, min_independent_codes: int,
      independence_policy: strict | best_effort }
  cost_estimate: { max_compute_units, max_gpu_seconds, max_wallclock_s, cost_class }
  determinism_profile: { deterministic_checks:[check_id], stochastic_checks:[{check_id, tolerance}] }
  recap_benchmark_ref?: ref(C4)  # held-out known result for recapitulated-known gate
  units_contract_ref: ref        # for PHYSICAL_CONSISTENCY
  contamination_index_min_version: string
  author, reviewed_by, signature, signer_key_id, status: active|deprecated|revoked
}
```

**CheckSpec**
```
CheckSpec {
  check_id: string, type: INJECTION|NULL_CONTROL|CROSS_CODE|PHYSICAL_CONSISTENCY|LEAKAGE|CALIBRATION,
  plugin_ref: string, plugin_version: semver,
  mandatory: bool,               # mandatory checks gate tiering
  thresholds: object,            # family-specific (e.g. {recovery_rate_min:0.9, tol_rel:0.1})
  determinism: deterministic|seeded|stochastic,
  tolerance?: object,            # for stochastic determinism (used by challenge)
  requires_independence: bool,
  budget: { max_wallclock_s, max_compute_units }
}
```

**VerificationRequest (C3 input)**
```
VerificationRequest {
  job_id: uuid, trace_id, budget_token,
  frozen_pipeline_ref: ref(C4),          # container digest + entrypoint contract
  artifact_refs: [ref(C4)],              # model, config, training-lineage handles
  profile_ref: string,
  blind_dataset_handle?: opaque,         # optional pre-provisioned handle; else profile default
  capability_scopes: [scope],
  provenance_context: { root_lineage_ref, contamination_index_version }
}
```

**CheckResult**
```
CheckResult {
  check_id, type,
  status: PASS | FAIL | INCONCLUSIVE,
  metric: { name, value }, threshold: { op, value },
  statistic?: { name, value, dof?, p_value? },
  points_evaluated?: int, points_excluded?: int, exclusion_reason?: string,
  uncertainty?: { representation, value },
  evidence_ref: ref(C4),                 # plots, tables, raw metric arrays
  determinism_class, seed_used?,
  degradations?: [string]
}
```

**ValidationReport (C3 output, signed, write-once)**
```
ValidationReport {
  report_id: uuid, job_id, verifier_id, verifier_contract_version,
  profile_ref, check_suite_version, contamination_index_version,
  checks: [CheckResult],
  aggregate: { passed: bool, score: float, score_definition: string },
  claim_tier: ran-toy | recapitulated-known | novel-needs-human,   # top tier = CANDIDATE only
  claim_tier_is_candidate: bool,         # true when novel; requires S9
  claim_tier_justification: [ { rule_id, effect, evidence:[check_id] } ],
  uncertainty_summary: object,
  frozen_pipeline_ref, artifact_refs:[ref], input_hashes: [blake3], environment_digest,
  independence_attestation?: IndependenceAttestation,
  degradations: [ { code, detail, tier_effect } ],
  cost_actual: { compute_units, gpu_seconds, wallclock_s, cost_usd },
  # --- C3 debate fields (introduced in v1.1; required subset in current v2.0) ---
  perturbation_pairs: [ { perturbation_id, kind: "must_react"|"must_not_react",
                          expected, observed, verdict } ],
  insensitivity_flags: [ { perturbation_id, reason } ],
  challenger_panel: [ { challenger_id, code_lineage_hash, independence_class } ],
  independence_attestation_debate?: {           # challenger-panel independence (distinct from cross-code attestation above)
      min_independent_challengers: int, lineage_disjoint: bool, correlation_warning: bool },
  referee: { referee_id, non_gameable: bool, signed_by, distinct_from_proponent: bool },
  debate_ref?: ref(C4),                         # pointer into the C4 provenance DebateLedger
  issued_at, signature, signer_key_id,
  canonicalization: "JCS-RFC8785" | "CBOR-DETERMINISTIC"
}
```

**IndependenceAttestation**
```
IndependenceAttestation {
  observable, code_under_test: { adapter_ref?, repo, commit, derived_from:[artifact_ref] },
  cross_codes: [ { adapter_ref, repo, commit, independence_tags:[string] } ],
  disjointness_proof: { shared_lineage: [], shared_repos: [], verdict: INDEPENDENT|NOT_INDEPENDENT },
  resolver_query, registry_revision_pinned, attested_at, attester_id
}
```

**BlindDatasetDescriptor (verifier-zone-only)**
```
BlindDatasetDescriptor {
  blind_id, subtopic, kind: injection|null_control|held_out|recap_benchmark|shuffled,
  opaque_input_ref: ref,          # what the pipeline sees
  truth_ref: ref,                 # verifier-zone-only; NEVER delivered to pipeline
  noise_model_ref?, injection_grid_ref?,
  content_hash, access_scope: verifier-only, contamination_index_version
}
```

**ChallengeResult**
```
ChallengeResult {
  report_ref, rerun_report_id, match: EXACT | WITHIN_TOLERANCE | MISMATCH,
  per_check: [ { check_id, delta, within_tolerance: bool } ],
  determinism_verdict, alarm_raised: bool, evidence_ref
}
```

**Postgres tables (append-only unless noted)**
- `verifier_profiles(profile_id, revision, spec_json, status, signature, created_at)` — append-only revisions; `current` pointer view.
- `check_plugins(plugin_ref, version, type, digest, determinism, registered_at)`.
- `validation_reports(report_id, job_id, profile_ref, claim_tier, aggregate_passed, content_hash, storage_uri, signer_key_id, issued_at)` — index; body in write-once bucket.
- `independence_attestations(report_id, verdict, cross_codes_json, registry_revision)`.
- `challenge_runs(rerun_id, report_ref, match, alarm, created_at)`.
- `blind_dataset_index(blind_id, subtopic, kind, content_hash, access_scope)` — restricted schema, verifier-zone creds only.

**Events (NATS JetStream)**
- `s3.report.issued { report_id, job_id, claim_tier, passed }`
- `s3.report.candidate_novel { report_id, job_id }` → S9 queue
- `s3.canary.alarm { report_ref, match, detail }` → S11
- `s3.independence.unavailable { job_id, observable }`
- `s3.quarantine { job_id, reason, sev }`

### S3.8 Public APIs (C3 interface + service endpoints, CLI, events)

**gRPC / HTTP (mTLS, capability-scoped) — owner of contract C3**

**1. list_profiles**
```
rpc ListProfiles(ListProfilesRequest{ subtopic?, observable?, min_conformance?, require_independence? })
  returns (ListProfilesResponse{ profiles: [VerifierProfileSummary{
      profile_ref, applicable_subtopics, checks:[check_id,type,mandatory],
      cost_estimate, independence_guarantees, determinism_profile }] })
HTTP: GET /v1/profiles?subtopic=...&observable=...&require_independence=true
```

**2. verify** (the core method)
```
rpc Verify(VerificationRequest) returns (ValidationReport)   # signed
HTTP: POST /v1/verify   body=VerificationRequest → 200 ValidationReport
                                                 | 409 {PROFILE_UNSUPPORTED}
                                                 | 424 {INDEPENDENCE_UNAVAILABLE}  (degraded report still returned)
                                                 | 402 {BUDGET}
                                                 | 422 {INPUT_MISSING}
Async variant: POST /v1/verify:submit → {verify_job_id}; GET /v1/verify/{verify_job_id} → status|report
```
Semantics: verifier fetches inputs itself from S8 by ref; never runs subagent code in-process; report is written to write-once storage before return; response includes signature.

**3. challenge** (re-audit for S11 canary)
```
rpc Challenge(ChallengeRequest{ report_ref, mode: full|checks_subset[] }) returns (ChallengeResult)
HTTP: POST /v1/challenge  body={report_ref, mode}
```

**3b. Bidirectional perturbation + debate APIs (current C3)**
```
rpc RunPerturbationPair(model_ref, perturbation_spec) returns (PerturbationResult)
  # runs a {must_react, must_not_react} pair sharing a perturbation_id; returns per-direction
  # expected/observed/verdict for the report's perturbation_pairs[].
  HTTP: POST /v1/perturbation-pair  body={model_ref, perturbation_spec}

rpc DetectInsensitivity(model_ref, perturbation_set) returns (InsensitivityReport)
  # flags invariance to a should-react perturbation (memorized/constant/spurious) -> FAIL;
  # populates insensitivity_flags[]{perturbation_id, reason}.
  HTTP: POST /v1/detect-insensitivity  body={model_ref, perturbation_set}

rpc AttestChallengerIndependence(challenger_ids[]) returns (IndependenceAttestation)
  # verifies lineage-disjoint, cross-code-independent challenger panel;
  # returns {min_independent_challengers, lineage_disjoint, correlation_warning}.
  HTTP: POST /v1/attest-challenger-independence  body={challenger_ids}
```

**4. Profile management (author/admin, elevated scope)**
```
POST   /v1/profiles                      body=VerifierProfile  → {profile_ref, revision}   (append-only; requires review sig)
POST   /v1/profiles/{id}/dry-run         body={fixture_refs}   → {per_check outcomes, no signature}
POST   /v1/profiles/{id}:deprecate  |  :revoke
GET    /v1/profiles/{profile_ref}
```

**5. Signature verification (library, all consumers)**
```
verify_report_signature(report_bytes, trust_store) -> {valid: bool, signer_key_id, canonical_hash}
# shipped as: python argusverify.verify_report(...), rust argusverify::verify_report(...), ts verifyReport(...)
```

**6. Blind-data admin (verifier-zone identity only)**
```
POST /v1/blind/datasets    body=BlindDatasetDescriptor      # stores opaque_input + truth (truth zone-only)
GET  /v1/blind/datasets/{blind_id}   # returns descriptor WITHOUT truth_ref payload
```

**CLI (`argusverify`)**
```
argusverify profiles list [--subtopic S] [--observable O] [--require-independence]
argusverify verify --pipeline <c4ref> --artifacts <c4ref...> --profile <ref> [--async] --budget-token <t>
argusverify report show <report_id>            # renders checks, tier, justification, degradations
argusverify report verify-signature <report_id|file>   # local signature check via lib
argusverify challenge <report_ref> [--mode full|--checks INJECTION,NULL_CONTROL]
argusverify profile author <spec.yaml> [--dry-run --fixtures <refs>]
argusverify independence resolve --observable O --code-under-test <ref>   # preview cross-code selection
argusverify explain-tier <report_id>           # prints exact rules fired
```

**Error envelope (shared with C1/C2 typed errors, C3-specific categories)**
```
{ code, category( RETRYABLE | BUDGET | PROFILE_UNSUPPORTED | INDEPENDENCE_UNAVAILABLE
                 | INPUT_MISSING | INCONCLUSIVE | SIGNING_UNAVAILABLE | POLICY | SANDBOX ),
  message, retry_after?, provenance_ref }
```
- INDEPENDENCE_UNAVAILABLE: not fatal — returns a degraded but signed report with tier cap.
- SIGNING_UNAVAILABLE: fatal for that attempt, RETRYABLE, NO report emitted (fail-closed).
- POLICY / SANDBOX: non-retryable, quarantine.

**Interfaces consumed**
- C4 (S8): `get_artifact(ref)`, `put_artifact(record)` for reports+evidence; lineage coupling of `validation_report_ref`.
- C5 (S6 registry): `resolve(query{observable, independence_needed, min_conformance})` for cross-code selection.
- C6 (S7 adapters): `describe()`, `evaluate(EvalRequest)`, `grad()`, `batch_evaluate()` for cross-code & forward models. **Extrapolation reciprocity:** S3 MUST consume S7's extrapolation / out-of-validity flag (`in_validity_domain`/`extrapolation_flag`) in each C6 tool result and set the affected check to INCONCLUSIVE unless the profile explicitly permits (reciprocal to S7's obligation to emit the flag).
- S6 frozen contamination index: read-only vector+lexical query (pinned version).
- S10: nested sandbox lifecycle for the Frozen-Pipeline Runner; budget/egress enforcement.
- Vault/KMS: signer key issuance to the Signer identity only.
- S11: OTel spans; NATS events.

**Events produced (NATS):** `s3.report.issued`, `s3.report.candidate_novel`, `s3.canary.alarm`, `s3.independence.unavailable`, `s3.quarantine`.

---

## S4 — Recursive Improvement Loop (Evolver)

**Owns contract:** none. **Consumes:** C1 build/validate (S1), C3 (S3), C4 (S8), C5 (S6), C6 descriptors read-only via C5 (S7), C2 (S5), S10.

### S4.1 Architecture overview
S4 is a **durable, verifier-gated evolutionary optimizer**. It sits above S2 (trainer) and S3 (verifier) and below S5 (orchestrator). It is implemented as a Temporal workflow (`EvolutionWorkflow`) driving a set of activities; the workflow holds the deterministic decision logic (selection, mutation choice, acceptance, budget accounting), while non-deterministic / long-running / sandboxed work is pushed into activities. All variant code runs in S10; all scores come from S3; all artifacts persist to S8.

```
                          ┌────────────── S5 Control Tower ──────────────┐
                          │  dispatch C2 EvolutionJob  ◄── JobResult      │
                          └───────────────────┬──────────────────────────┘
                                              │ C2
                    ┌─────────────────────────▼───────────────────────────┐
                    │                 S4 EVOLVER                            │
                    │  ┌───────────────┐   ┌──────────────────────────┐    │
                    │  │ Precondition  │   │  EvolutionWorkflow        │    │
                    │  │ Gate (verifier│──►│  (Temporal, durable)      │    │
                    │  │ + independence│   │   ├─ Population Mgr        │    │
                    │  │ + cheapness)  │   │   ├─ Archive (MAP-Elites)  │    │
                    │  └───────────────┘   │   ├─ Proposer (LLM+ops)    │    │
                    │                       │   ├─ Selector/Diversity   │    │
                    │                       │   ├─ Budget Ledger        │    │
                    │                       │   ├─ Reward-Hack Screens  │    │
                    │                       │   └─ Checkpointer         │    │
                    │                       └──────┬─────────┬──────────┘    │
                    └──────────────┬───────────────┼─────────┼──────────────┘
                       C1 build    │        C3 verify│   C4 persist│
                            ┌──────▼──────┐   ┌──────▼─────┐ ┌────▼─────┐
                            │ S2 Builder  │   │ S3 Verifier│ │ S8 Prov. │
                            │ (in S10)    │   │ (oracle)   │ │ ledger   │
                            └─────────────┘   └────────────┘ └──────────┘
                            (S2 calls C6/S7 adapters; S4 never calls adapters directly)
```

### S4.2 Components

**2.1 Precondition Gate (Rust + Python).** Before the workflow enters its loop it MUST pass:
- **Verifier existence & validity**: resolve the `verifier_profile_ref` via C3 `list_profiles()` and C5 `resolve()`; confirm it applies to the subtopic and returns `independence_guarantees`.
- **Independence check**: confirm at least one INDEPENDENT cross-code S7 adapter exists for the target observable (C5 `resolve(independence_needed=true)`), so `CROSS_CODE` checks are possible; if none, cap max achievable tier and record `INDEPENDENCE_UNAVAILABLE`.
- **Cheapness check**: verifier profile `cost_estimate` × `max_generations` × `population_size` must fit within the job budget; if a single verify call cannot complete within its declared budget, refuse (the "cheap-verifier precondition"). This is the structural defeat of unguarded loops.
- **Signature-trust check**: the verifier's `signer_key_id` must be registered in the trust store. On any failure → `REFUSED` with `VERIFIER_UNAVAILABLE`/`INDEPENDENCE_UNAVAILABLE`; the loop is never entered.

**2.2 Population Manager.** Maintains the current generation's population of `Variant` records (genotype = pipeline spec + hyperparameters + feature-engineering choices + architecture genes; phenotype = trained model artifact + signed score). Fixed `population_size`; supports elitism carry-over.

**2.3 Archive (MAP-Elites / novelty).** A behavior-descriptor grid archive keyed by physics-meaningful behavior descriptors (e.g. model class, feature-set signature, uncertainty-calibration bucket, injection-recovery-shape). Retains the best-scoring elite per cell. Provides diversity pressure and an anti-collapse guarantee: selection samples from the archive, not just the top-k, so the loop cannot collapse onto one lineage.

**2.4 Proposer (variant generation).** Two complementary mechanisms, both producing a new genotype:
- **Operator-based** — typed mutation operators over the gene schema (hyperparameter perturbation, feature add/drop, model-class swap, architecture edit, ensemble combine) and crossover between two parents. Fully deterministic given RNG state.
- **LLM-guided (Claude via Agent SDK, AlphaEvolve-style)** — the Proposer prompts Claude with the current population, their signed scores, diffs, and the gene schema, asking for a targeted mutation *diff*. The LLM proposal is treated as **untrusted**: it is schema-validated, must lie within the declared search space, and its generated code runs only in S10. The LLM never sees held-out data and never sees the reward function; it sees only signed scores that S4 already holds. LLM proposals are logged with full prompt/response provenance (S8).

**2.5 Selector / Diversity Controller.** Implements the selection strategy (default: tournament + MAP-Elites archive sampling + novelty bonus). "Fitness" = signed `aggregate.score` ONLY; novelty = behavior-descriptor distance. Enforces `diversity_target`: if population entropy drops below threshold, injects archive-sampled or freshly-mutated diverse variants.

**2.6 Budget Ledger (Rust).** Append-only, per-generation spend accounting across compute units, GPU-seconds, model tokens, wall-clock, USD; decrements the minted `budget_token`; halts the workflow the instant a cap is breached (checked before dispatching each variant's train+verify). Emits cost-per-verified-improvement.

**2.7 Reward-Hacking Screens (pre-admission gate).** Before any scored variant enters the population/archive, S4 runs *admission screens* (S4-side defenses, complementary to S3's own leakage checks):
- **Signature verification** of the C3 report against the trust store (reject unsigned/tampered → Sev-1).
- **Report-binding check**: `frozen_pipeline_ref`, `input_hashes`, `environment_digest`, `contamination_index_version`, and `profile_ref` in the report MUST match exactly what S4 submitted (defeats report replay / swapped-input attacks).
- **Leakage-flag honoring**: if the report's `LEAKAGE` or `CALIBRATION` check is FAIL, or `CROSS_CODE` disagrees, the variant is inadmissible regardless of score.
- **Profile-invariance probe** (anti-overfit-to-verifier): periodically re-score the current best under a *held-out sibling profile* / rotated injection amplitude (requested from S3); a variant whose score collapses under profile rotation is flagged as a suspected verifier-overfit and demoted.
- **Independence attestation check**: the report's `independence_attestation` must be present for any tier > `recapitulated-known`.
- **INCONCLUSIVE handling**: counts as non-improvement, never reward.
Any screen failure → variant rejected, event tagged `reward_hack_suspected` and counted in the KPI; repeated systemic failure → QUARANTINE the job.

**2.8 Checkpointer.** Serializes the full evolution state (population, archive, RNG streams, budget ledger, best-so-far, generation index, pending evaluations) as a content-addressed C4 checkpoint artifact each generation. Enables durable resume and per-generation re-derivation (re-run canary).

**2.9 API/Event Surface (Python + gRPC/HTTP, Rust hot paths).** Start/pause/resume/cancel/status/checkpoint endpoints; NATS JetStream events for generation-complete, best-improved, refused, quarantined; OTel spans throughout.

### S4.3 Key algorithms

**3.1 Precondition gate (pseudocode).**
```
def precondition_gate(job):
    prof = C3.list_profiles(); p = resolve(job.verifier_profile_ref, prof)
    if p is None: refuse(VERIFIER_UNAVAILABLE)
    if job.problem_spec.subtopic not in p.applicable_subtopics: refuse(PROFILE_UNSUPPORTED)
    indep = C5.resolve(subtopic, independence_needed=True)
    max_tier = full if indep else capped_at_recapitulated
    est = p.cost_estimate * job.max_generations * job.population_size
    if est > job.budget.max_cost_usd or p.single_call_cost > p.single_call_budget:
        refuse(VERIFIER_UNAVAILABLE)  # cheap-verifier precondition fails
    if p.signer_key_id not in trust_store: refuse(POLICY)
    return RunContext(max_tier, p, indep)
```

**3.2 Main evolution loop (deterministic decision core).**
```
seed = load(job.seed_pipeline_ref)
pop  = init_population(seed, gene_schema, master_seed)   # gen 0
archive = MapElites(descriptor_fn)
best = None
for gen in range(max_generations):
    if budget.breached(): halt_quarantine("BUDGET"); break
    # 1. evaluate any unscored variants (train + verify) — parallel activities
    for v in pop.unscored():
        art = S2.build(freeze(v))                 # C1 build in S10
        rep = S3.verify(VerificationRequest(frozen_pipeline_ref=art, profile))  # C3
        if not admit(v, rep): mark_rejected(v); continue   # reward-hack screens
        v.score = rep.aggregate.score; v.report = rep; v.tier = rep.claim_tier
        archive.insert(v)
        best = argmax_signed(best, v)
        checkpoint_incremental(gen, v)
    # 2. diversity guard
    if population_entropy(pop) < diversity_target:
        pop += diverse_injection(archive, master_seed, gen)
    # 3. select parents (fitness = signed score, + novelty bonus)
    parents = select(pop, archive, strategy, rng(gen))
    # 4. propose children (operators + LLM-guided), schema-validated, in-domain
    children = propose(parents, gene_schema, proposer_cfg, rng(gen))
    # 5. next generation with elitism
    pop = elitism(pop, k) + children
    checkpoint_generation(gen, pop, archive, budget, best, rng)
    emit_event("generation_complete", metrics(gen))
    if convergence_or_no_improvement(best, patience): break   # early stop (still bounded)
if best and best.tier == novel_needs_human:
    route_to_S9_via_S5(best)     # never self-promote
return JobResult(best, best.report, cost_actual, tier=best.tier)
```

**3.3 Admission (reward-hacking gate).**
```
def admit(v, rep):
    if not verify_signature(rep, trust_store): sev1("signature"); quarantine(); return False
    if rep.frozen_pipeline_ref != v.frozen_ref \
       or rep.input_hashes != v.expected_input_hashes \
       or rep.profile_ref != active_profile \
       or rep.contamination_index_version != pinned_index:
        flag_reward_hack("report_binding"); return False
    if any(c.type in {LEAKAGE} and c.status==FAIL for c in rep.checks):
        flag_reward_hack("leakage"); return False
    if calibration_failed(rep) or cross_code_disagrees(rep): return False
    if rep.aggregate.passed is False or rep.aggregate.score is INCONCLUSIVE: return False
    if v.tier > recapitulated and rep.independence_attestation is None: return False
    return True
```

**3.4 Diversity / MAP-Elites.** Behavior descriptor `b(v)` derived from phenotype (model family id, feature-set hash bucket, calibration-coverage bucket, injection-recovery slope bucket). Archive cell keeps the highest signed-score elite. Selection mixes (a) top-k population, (b) uniform archive samples, (c) novelty-ranked (k-NN distance in descriptor space) to maintain exploration. Prevents premature collapse.

**3.5 Profile-invariance / verifier-overfit probe.** Every `probe_interval` generations, request S3 to re-score the current best under a rotated injection amplitude / sibling held-out profile. Compute score-delta; if delta exceeds `overfit_tolerance`, demote and record `verifier_overfit_suspected`. This structurally punishes optimizing to a fixed verifier quirk.

**3.6 Adversarial Red-Blue Debate Evolution (recursion under oracle).** The self-improvement loop is a multi-agent adversarial peer-review embedded in evolution. Roles: **PROPONENT** = the Builder subagent (produces candidate model + claim); **CHALLENGERS** = a panel of ≥K INDEPENDENT red-team agents that attack the claim with evidence; **REFEREE** = the S3 verifier, oracle-backed, NON-GAMEABLE, and NEVER the same agent as the proponent. Eight steps:
```
1. Precondition gate: REFUSE to run unless a CHEAP VALID S3 verifier + oracle exists for this
   subtopic (recursion only under oracle).
2. Proponent produces candidate (model + claim).
3. select_challenger_panel(subtopic, k, diversity_policy): >=K challengers, lineage-disjoint,
   diverse across attack types AND code lineages.
4. Each challenger runs attacks:
     - must-react probes  (plant KNOWN-REAL signals; claim MUST recover them, proportionally)
     - must-not-react probes (noise / label-shuffle / data-contamination; claim MUST NOT
       manufacture a signal and MUST degrade)
     - plus alt-analysis (independent re-analysis of the same claim)
5. Referee (S3; != proponent; signed) adjudicates via ChallengeVerdict:
     require must_react_pass AND must_not_react_pass AND NOT insensitivity_detected.
6. FAIL -> structured feedback -> proponent revises/retrains -> next round.
7. Reward-hacking & collusion screens: detect proponent overfitting to a fixed challenger set;
   detect challenger correlation/collusion; detect referee tampering; hard bound on rounds;
   refresh challenger diversity each round.
8. Emit signed current C3 ValidationReport with debate_ref; set claim tier by survival.
```
The referee's must_react / must_not_react adjudication maps 1:1 onto S3 `run_perturbation_pair` + `detect_insensitivity`; challenger independence maps onto S3 `attest_challenger_independence`. Every ChallengeRound is appended to the C4 `DebateLedger`; the emitted report's `debate_ref` points at it.

**3.7 Debate-round orchestration (pseudocode).**
```
def evolve_under_debate(seed_candidate, budget, stop_criteria):
    assert precondition_gate(...).ok            # step 1: cheap valid S3 verifier + oracle
    cand = seed_candidate
    for rnd in range(bounds.max_debate_rounds):        # hard bound on rounds
        challengers = S4.select_challenger_panel(subtopic, k, diversity_policy)  # step 3
        att = S3.attest_challenger_independence(challengers)
        if not att.lineage_disjoint or att.correlation_warning:
            challengers = refresh_diversity(challengers); continue          # collusion screen
        round = run_debate_round(cand, challengers, referee=S3_verifier)     # steps 2,4,5
        record_debate_ledger(round)                                          # C4 DebateLedger
        if round.referee_verdict.overall == "PASS" and round.survived:
            return emit_report_with_debate_ref(cand, round)                  # step 8
        if reward_hack_or_collusion_screen(cand, round): quarantine(); break # step 7
        cand = proponent_revise(cand, round.feedback)                        # step 6
    return best_surviving(cand)

def run_debate_round(candidate_ref, challenger_pool, referee):
    attacks = [c.attack(candidate_ref) for c in challenger_pool]     # signal_injection /
                                                                     # null_noise / label_shuffle /
                                                                     # data_contamination / alt_analysis
    mr = referee.run_perturbation_pair(candidate_ref, must_react_spec(attacks))
    mn = referee.run_perturbation_pair(candidate_ref, must_not_react_spec(attacks))
    ins = referee.detect_insensitivity(candidate_ref, perturbation_set(attacks))
    verdict = ChallengeVerdict(must_react_pass=mr.pass, must_not_react_pass=mn.pass,
                               insensitivity_detected=bool(ins.flags),
                               overall = "PASS" if (mr.pass and mn.pass and not ins.flags)
                                         else ("FAIL" if mr.decisive or mn.decisive else "INCONCLUSIVE"))
    survived = (verdict.overall == "PASS")
    return ChallengeRound(round_id, proponent_ref=candidate_ref, challenger_ids=[c.id for c in challenger_pool],
                          attacks=attacks, referee_verdict=verdict, survived=survived,
                          feedback=build_feedback(attacks, verdict))
```

**3.8 Reward-hacking + challenger-collusion screens (debate-specific, extends 3.3).** In addition to the admission screens in §3.3, the debate loop runs: **proponent-overfit-to-fixed-challenger-set** detection (if the proponent's survival is stable only against a frozen challenger panel but collapses when the panel is refreshed → reward-hack suspected); **challenger correlation/collusion** detection (via S3 `attest_challenger_independence` correlation_warning + cross-attack agreement statistics → refresh diversity); **referee-tampering** detection (referee must be S3, signed, `distinct_from_proponent`; any self-attestation attempt → QUARANTINE); a **hard bound on debate rounds** (`max_debate_rounds`); and **challenger-diversity refresh each round** (re-draw a lineage-disjoint panel so the proponent cannot memorize a fixed adversary).

### S4.4 Sequence flows
- **4.1 Nominal evolution.** S5 → (C2 dispatch) → S4 Precondition Gate PASS → EvolutionWorkflow starts → per generation: [Proposer → S2.build (C1, in S10) → S3.verify (C3) → admit-screens → archive/select → checkpoint (C4→S8)] → early-stop or max-gen → best variant with signed report → JobResult to S5. If best tier == `novel-needs-human`: S5 inserts S9 wait-state.
- **4.2 Refusal.** S5 dispatches with a profile that fails cheapness/independence/existence → Precondition Gate returns `REFUSED{VERIFIER_UNAVAILABLE|INDEPENDENCE_UNAVAILABLE}` → JobResult REFUSED (a first-class, non-error outcome; S5 may escalate to human).
- **4.3 Reward-hack caught.** Variant's report fails signature / binding / leakage screen → admit() returns False → event `reward_hack_suspected` (KPI++), variant discarded; if systemic (rate over threshold) → QUARANTINE job, Sev evaluation.
- **4.4 Budget breach.** Ledger detects cap breach before dispatching next variant → workflow halts → partial-result capture (best-so-far with its signed report if admitted) → JobResult with `cost_actual`, status reflecting halt; no double-spend.
- **4.5 Restart/resume.** Host dies mid-generation → Temporal replays workflow from last durable checkpoint (C4) → in-flight S2/S3 activities are idempotent (keyed by frozen_pipeline_ref content hash) → no re-training of already-scored variants, no lost provenance.

### S4.5 Tech choices (consistent with shared stack)
- **Temporal** — durable `EvolutionWorkflow`; survives restarts, models long async train+verify steps and the S9 human wait-state; deterministic workflow code (RNG seeded from durable state) makes the decision path replayable.
- **Python 3.11 + pydantic v2** — evolver orchestration, proposer, selector; models generated from contract JSON Schemas.
- **Rust** — Budget Ledger writer and signature-verification hot path at the trust boundary; provenance-write path reuses S8's Rust ledger writer via C4.
- **JAX/PyTorch** — only inside S2 (S4 does not train); S4 stays numerics-light.
- **Claude via Agent SDK** — LLM-guided proposer, tool-use restricted to the gene-schema mutation surface; prompt/response provenance captured (S8); model swappable (acts only through S4's internal mutation contract).
- **PostgreSQL 16** — run/generation/variant metadata, budget ledger rows, selection decisions (queryable lineage/genealogy).
- **Object store (S8, BLAKE3-keyed)** — checkpoints, variant genotypes, LLM prompts, signed reports referenced by ref.
- **NATS JetStream** — generation/best-improved/refused/quarantined events.
- **OpenTelemetry** — spans S4→S2→S3; Prometheus/Grafana KPIs.
- **gVisor/Firecracker (S10)** — all variant code + LLM-generated mutations execute here; S4 orchestrator runs in the control zone, egress-denied except to S8/S3/S5/S2 brokered endpoints.

### S4.6 Failure & degradation handling
- **Verifier stalls/timeouts** → the verify activity times out → treated as `INCONCLUSIVE` → variant non-improvement; retried under `retry_categories` only if RETRYABLE.
- **S2 build fails** → captured in provenance; the variant is marked failed (fitness = −∞); auto-repair is S2's responsibility, bounded; S4 does not retrain endlessly.
- **INDEPENDENCE_UNAVAILABLE mid-run** (adapter revoked via C5 revocation propagation) → cap max tier, surface, continue at reduced tier ceiling.
- **Signature/trust failure** → Sev-1, halt, quarantine sandbox image for forensics.
- **Diversity collapse** → diversity guard injects archive/novel variants; if entropy cannot be restored within N generations → flag and early-stop (bounded).
- **Budget breach** → immediate halt + partial capture, fail-loud.
- **Checkpoint corruption / hash mismatch** → fail-closed (C4 HASH_MISMATCH), resume from prior good checkpoint; if none → QUARANTINE.
- **Runaway/plateau** → early-stop on `no_improvement patience`, always subordinate to hard `max_generations`.

### S4.7 Security notes (S4-specific)
S4 is a prime reward-hacking adversary target because it *is* the optimizer. Mitigations are structural: (a) reward only from signed oracle; (b) report-binding prevents input-swap/replay; (c) profile-rotation probe prevents verifier-overfit; (d) all variant/LLM code in S10, egress-denied; (e) S4 holds no verifier key, no held-out data; (f) budget/RNG/trust-store on read-only mounts unreachable from variant code; (g) every abort/quarantine fully logged & tamper-evident.

### S4.8 Data models
All models are pydantic v2 (generated from JSON Schema), content-addressed as C4 artifacts where noted. Cross-subsystem references are C4 `artifact_ref`s or contract refs; S4 never embeds another subsystem's internal types.

**EvolutionJobSpec (payload inside C2 `problem_spec` / S4 extension block)**
```
EvolutionJobSpec {
  evolution_job_id: uuid
  job_id: uuid                      # C2 job_id
  root_request_id: uuid
  subtopic: string
  seed_pipeline_ref: artifact_ref(C4)     # starting pipeline (from subagent, C1)
  gene_schema_ref: artifact_ref(C4)       # declares mutable genes + valid ranges/domains
  mutation_operator_set: [operator_id]    # allowed operators (subset of registered ops)
  verifier_profile_ref: ref(C3 profile)   # REQUIRED; null => refuse
  objective: { score_definition, direction: maximize|minimize }
  strategy: EvolverStrategy
  bounds: EvolverBounds                    # hard caps
  diversity: DiversityConfig
  proposer: ProposerConfig
  reward_defense: RewardDefenseConfig
  provenance_context: { root_lineage_ref, contamination_index_version }
  required_claim_tier_max: ran-toy|recapitulated-known|novel-needs-human
}
```

**EvolverStrategy**
```
EvolverStrategy {
  kind: map_elites | tournament_ga | novelty_search | hybrid   # default hybrid
  population_size: int; elitism_k: int; tournament_size: int
  selection_pressure: float; crossover_rate: float; mutation_rate: float
  early_stop: { patience_generations: int, min_relative_improvement: float }
}
```

**EvolverBounds (hard, runtime-enforced)**
```
EvolverBounds {
  max_generations: int; max_variants_total: int; max_wallclock_s: int
  max_compute_units: float; max_gpu_seconds: float; max_model_tokens: int; max_cost_usd: float
  per_variant_train_budget: BudgetSlice; per_variant_verify_budget: BudgetSlice
}
```

**DiversityConfig**
```
DiversityConfig {
  behavior_descriptors: [descriptor_id]    # e.g. model_family, featureset_hash_bucket, calibration_bucket, injection_slope_bucket
  archive_kind: map_elites_grid
  grid_resolution: { descriptor_id: bins }
  diversity_target_entropy: float; novelty_knn_k: int; min_novelty_distance: float; diverse_injection_size: int
}
```

**ProposerConfig**
```
ProposerConfig {
  use_llm_proposer: bool; llm_model_id: string
  llm_proposal_fraction: float      # fraction of children from LLM vs operators
  operator_weights: { operator_id: float }
  max_llm_tokens_per_generation: int
  proposal_validation: strict       # must pass gene-schema + in-domain validation
}
```

**RewardDefenseConfig**
```
RewardDefenseConfig {
  require_signed_report: true        # non-overridable
  report_binding_check: true         # non-overridable
  honor_leakage_flags: true          # non-overridable
  profile_rotation: { enabled: bool, probe_interval_generations: int,
                      overfit_score_tolerance: float, rotation_profile_refs: [ref] }
  quarantine_on_hack_rate: float     # systemic-hack threshold
}
```

**Variant (genotype+phenotype; content-addressed C4)**
```
Variant {
  variant_id: uuid; content_hash: string (BLAKE3); evolution_job_id: uuid; generation: int
  genotype: {
     pipeline_spec_ref: artifact_ref(C4)
     genes: { gene_id: value }             # concrete instantiation over gene_schema
     lineage: { parent_variant_ids: [uuid], operator_id, crossover_partner?: uuid,
                llm_prompt_ref?: artifact_ref(C4), diff_ref?: artifact_ref(C4) }
  }
  phenotype?: {
     built_model_ref?: artifact_ref(C4)     # from S2 build
     frozen_pipeline_ref?: artifact_ref(C4) # what was submitted to S3
     validation_report_ref?: ref(C3)        # signed report
     score?: float                          # from report.aggregate.score ONLY
     claim_tier?: ran-toy|recapitulated-known|novel-needs-human
     uncertainty_summary?: {...}
     behavior_descriptor?: { descriptor_id: value }
  }
  status: proposed | building | verifying | admitted | rejected | failed
  rejection_reason?: enum(REWARD_HACK|LEAKAGE|CALIBRATION|CROSS_CODE|INCONCLUSIVE|
                          SIGNATURE|REPORT_BINDING|BUILD_FAILED|OUT_OF_DOMAIN)
  cost_actual?: BudgetSlice; created_at, trace_id
}
```

**GeneSchema (content-addressed C4; supplied by subagent)**
```
GeneSchema {
  gene_schema_id, content_hash
  genes: [ { gene_id, type: categorical|int|float|bool|struct,
             domain: {enum|range|distribution}, mutable: bool, physics_constraint?: string } ]
  operators_supported: [operator_id]
  invariants: [ constraint_expr ]     # e.g. units/positivity that any variant must satisfy
}
```

**GenerationRecord (content-addressed C4; the genealogy unit)**
```
GenerationRecord {
  generation_record_id, content_hash; evolution_job_id, generation: int
  population: [variant_ref]
  admitted: [variant_ref], rejected: [{variant_ref, reason}]
  best_so_far: variant_ref; best_score: float, population_entropy: float, archive_coverage: float
  selection_decisions: [ { child_ref, parents: [variant_ref], operator_id, rng_stream_pos } ]
  budget_spent_cumulative: BudgetSlice; rng_state_ref: artifact_ref(C4)
  reward_hack_events: [ { variant_ref, kind, evidence_ref } ]; emitted_at
}
```

**EvolutionCheckpoint (content-addressed C4; durable resume)**
```
EvolutionCheckpoint {
  checkpoint_id, content_hash, evolution_job_id, generation: int
  population_state_ref, archive_state_ref, rng_state_ref
  budget_ledger_ref, best_variant_ref
  pending_evaluations: [ { variant_ref, stage: building|verifying } ]; created_at
}
```

**BudgetLedgerEntry (Postgres row + append-only C4 snapshot)**
```
BudgetLedgerEntry {
  entry_id, evolution_job_id, generation, variant_id?
  phase: build|verify|llm_proposal|overhead
  compute_units, gpu_seconds, model_tokens, wallclock_s, cost_usd
  cumulative_cost_usd, remaining_budget_token_ref; breached: bool, recorded_at
}
```

**EvolutionResult (payload into C2 JobResult)**
```
EvolutionResult {
  evolution_job_id, job_id
  status: SUCCEEDED | REFUSED | QUARANTINED | CANCELLED | BUDGET_HALTED
  best_variant_ref?: artifact_ref(C4)
  best_validation_report_ref?: ref(C3)      # signed
  best_claim_tier: ran-toy|recapitulated-known|novel-needs-human
  seed_score: float, best_score: float, relative_improvement: float
  generations_run: int, variants_evaluated: int
  cost_actual: BudgetSlice; cost_per_verified_improvement: float
  reward_hack_events_count: int
  human_review_required: bool                # true iff best tier == novel-needs-human
  genealogy_ref: artifact_ref(C4)            # full lineage for S9
  refusal_reason?: enum(VERIFIER_UNAVAILABLE|INDEPENDENCE_UNAVAILABLE|PROFILE_UNSUPPORTED|POLICY)
  trace_id
}
```

**ChallengeRound (content-addressed C4; owned by S4, referenced by S3 and C4 provenance)**
```
ChallengeRound {
  round_id: uuid
  proponent_ref: artifact_ref(C4)          # the candidate model + claim under debate
  challenger_ids: [challenger_id]
  attacks: [Attack]
  referee_verdict: ChallengeVerdict
  survived: bool
  feedback: object                         # structured feedback -> proponent revise/retrain
}
```

**Attack (content-addressed C4; produced by a challenger)**
```
Attack {
  attack_id: uuid
  challenger_id
  type: "signal_injection"|"null_noise"|"label_shuffle"|"data_contamination"|"alt_analysis",
  payload_ref: artifact_ref(C4)            # the perturbation / alt-analysis inputs
  evidence_ref: artifact_ref(C4)           # the challenger's supporting evidence
  target_claim                             # which claim this attack targets
}
```

**ChallengeVerdict (referee adjudication)**
```
ChallengeVerdict {
  round_id: uuid
  must_react_pass: bool
  must_not_react_pass: bool
  insensitivity_detected: bool
  overall: "PASS"|"FAIL"|"INCONCLUSIVE"    # PASS iff must_react_pass AND must_not_react_pass
}                                          #         AND NOT insensitivity_detected
```

**DebateLedger (append-only C4 provenance record)**
```
DebateLedger {
  debate_ledger_id, content_hash, evolution_job_id, artifact_ref(C4)   # the artifact under debate
  rounds: [ChallengeRound]                 # append-only, ordered; all ChallengeRounds for the artifact
  # emitted via C4; the current C3 ValidationReport.debate_ref points here.
}
```

**Postgres schema (system-of-record, abbreviated)**
- `evolution_jobs(evolution_job_id PK, job_id, subtopic, status, verifier_profile_ref, bounds_json, created_at, ...)`
- `variants(variant_id PK, evolution_job_id FK, generation, content_hash, status, score, claim_tier, validation_report_ref, rejection_reason, ...)`
- `generations(generation_record_id PK, evolution_job_id FK, generation, best_score, population_entropy, archive_coverage, content_hash, ...)`
- `budget_ledger(entry_id PK, evolution_job_id FK, generation, phase, cost_usd, cumulative_cost_usd, breached, recorded_at)`
- `reward_hack_events(event_id PK, evolution_job_id FK, variant_id, kind, evidence_ref, detected_at)`
- `lineage_edges(child_variant_id, parent_variant_id, operator_id, evolution_job_id)` — genealogy DAG.
- `debate_rounds(round_id PK, evolution_job_id FK, proponent_ref, survived, overall_verdict, debate_ledger_id, created_at)` — one row per ChallengeRound.
- `challenger_panels(round_id FK, challenger_id, code_lineage_hash, independence_class, correlation_warning)` — per-round independent challenger panel.

### S4.9 Public interfaces
Transport: gRPC + HTTP/JSON, mTLS, least-privilege capability scopes. All methods carry the C1/C2 common envelope fields (`job_id`, `trace_id`, `budget_token`, `provenance_context`, `capability_scopes[]`).

**A. Control API (consumed by S5 / Control Tower)**
```
POST /v1/evolver/jobs
  req:  EvolutionJobSpec (embedded in C2 JobEnvelope)
  res:  { evolution_job_id, workflow_id, status: ACCEPTED|REFUSED, refusal_reason?, estimated_cost, plan_eta }
  # REFUSED (no valid/cheap/independent verifier) is a first-class non-error outcome.
GET  /v1/evolver/jobs/{evolution_job_id}
  res:  { status, generation, best_score, seed_score, population_entropy,
          archive_coverage, spend_so_far, spend_remaining, human_review_required }
POST /v1/evolver/jobs/{evolution_job_id}/pause    -> { status: PAUSED }
POST /v1/evolver/jobs/{evolution_job_id}/resume   -> { status: RUNNING, resumed_from_checkpoint }
POST /v1/evolver/jobs/{evolution_job_id}/cancel   req: { reason }  -> { status: CANCELLED }
POST /v1/evolver/jobs/{evolution_job_id}/checkpoint -> { checkpoint_ref(C4), generation }
GET  /v1/evolver/jobs/{evolution_job_id}/result   -> EvolutionResult   # terminal
GET  /v1/evolver/jobs/{evolution_job_id}/genealogy -> { genealogy_ref(C4) }
GET  /v1/evolver/jobs/{evolution_job_id}/generations/{n} -> GenerationRecord
GET  /v1/evolver/jobs/{evolution_job_id}/heartbeat -> Health{status, progress, spend_so_far}
```

**B. Preflight API (dry-run precondition gate; consumed by S5 before committing budget)**
```
POST /v1/evolver/preflight
  req:  { verifier_profile_ref, subtopic, bounds, population_size, max_generations }
  res:  { admissible: bool, verifier_valid: bool, independence_available: bool, cheap_enough: bool,
          max_achievable_tier: enum, estimated_cost, reasons[] }
```

**B2. Adversarial Red-Blue Debate API (S4-owned; drives the debate loop)**
```
select_challenger_panel(subtopic, k, diversity_policy) -> challenger_ids[]
  # picks >=K lineage-disjoint challengers, diverse across attack types AND code lineages.
run_debate_round(candidate_ref, challenger_pool, referee) -> ChallengeRound
  # one round: challengers attack; referee (S3, != proponent, signed) adjudicates -> ChallengeVerdict.
evolve_under_debate(seed_candidate, budget, stop_criteria) -> EvolutionResult
  # the full red-blue evolution loop under the precondition gate (recursion only under oracle);
  # FAIL -> feedback -> proponent revise/retrain -> next round; hard-bounded rounds.
HTTP: POST /v1/evolver/debate/panel | /v1/evolver/debate/round | /v1/evolver/debate/run
```

**C. Internal method contracts S4 CONSUMES (named exactly for coherence audit)**
```
# C1 (from the target subagent / S1 framework) — drive build/validate lifecycle:
C1.build(Plan) -> BuildResult{artifact_refs[](C4), training_log_ref, diagnostics}   # in S10, invokes S2
C1.validate(BuildResult) -> ValidationRequest                                       # hands frozen pipeline to S3
# C3 (from S3 Verifier) — the ONLY reward source:
C3.list_profiles() -> [VerifierProfile]
C3.verify(VerificationRequest{...}) -> ValidationReport(signed current C3)
C3.challenge(report_ref) -> ChallengeResult     # used for profile-rotation / re-run probe
# C3 debate/referee methods (referee = S3, != proponent, signed):
C3.run_perturbation_pair(model_ref, perturbation_spec) -> PerturbationResult
C3.detect_insensitivity(model_ref, perturbation_set) -> InsensitivityReport
C3.attest_challenger_independence(challenger_ids[]) -> IndependenceAttestation
# C4 (from S8) — artifacts + lineage; DebateLedger emission:
C4.put_artifact(ArtifactRecord) -> {content_hash}   # incl. ChallengeRound / DebateLedger records
C4.get_artifact(ref) / C4.query_lineage(query) -> lineage DAG
# C5 (from S6/S12 registry) — verifier & independence resolution:
C5.resolve(query{subtopic, required_verifier, min_conformance, independence_needed}) -> [descriptor_revision]
# C6 is invoked by S2 (adapters), NOT by S4 directly. S4 only reads adapter descriptors via C5
# to confirm an INDEPENDENT cross-code exists for the precondition gate.
```

**D. Events (NATS JetStream; consumed by S11 observability, S5)**
```
evolver.job.accepted        { evolution_job_id, job_id, subtopic, bounds }
evolver.job.refused         { evolution_job_id, reason }
evolver.generation.complete { evolution_job_id, generation, best_score, population_entropy,
                              archive_coverage, spend_cumulative, admitted, rejected }
evolver.best.improved       { evolution_job_id, generation, old_best, new_best, variant_ref }
evolver.reward_hack.detected{ evolution_job_id, variant_ref, kind, evidence_ref }
evolver.budget.breached     { evolution_job_id, phase, cumulative_cost_usd }
evolver.job.quarantined     { evolution_job_id, reason, forensic_ref }
evolver.job.completed       { evolution_job_id, status, best_claim_tier, human_review_required }
evolver.human_review.requested { evolution_job_id, genealogy_ref, best_validation_report_ref }
```

**E. CLI (argusctl evolver — for P4 platform engineer / P6 red-team)**
```
argusctl evolver start   --spec spec.json [--dry-run]
argusctl evolver preflight --profile <ref> --subtopic <s> --bounds bounds.json
argusctl evolver status  <evolution_job_id>
argusctl evolver pause|resume|cancel <evolution_job_id> [--reason ...]
argusctl evolver genealogy <evolution_job_id> [--gen N] [--format dot|json]
argusctl evolver replay  <evolution_job_id> --from-checkpoint <ref>   # re-derive (canary)
argusctl evolver quarantine list|inspect <evolution_job_id>
argusctl evolver redteam inject-hackable-verifier <scenario_id>       # security harness
```

**F. Typed error envelope (shared with C1/C2)**
```
{ code, category(RETRYABLE|PERMANENT|BUDGET|POLICY|VERIFIER_UNAVAILABLE|SANDBOX|
                 INDEPENDENCE_UNAVAILABLE|SIGNATURE|REPORT_BINDING),
  message, retry_after?, provenance_ref }
# POLICY, SANDBOX, SIGNATURE, REPORT_BINDING, VERIFIER_UNAVAILABLE are non-retryable
# and either refuse (pre-loop) or quarantine (mid-loop).
```

---

## S5 — Control Tower / Orchestration (总台)

**Owns contract:** **C2**. **Consumes:** C1 (S1), C3 list_profiles (S3), C4 (S8), C5 (S6/S12), C6 descriptors/errors (S7), S9 review coupling, S10 tokens, S11 back-pressure, S4 recursion requests.

### S5.1 Architecture overview
S5 is a control-plane service cluster in the **Control/Provenance trust zone** (never runs agent code). It is composed of stateless API/planner services fronting a **durable workflow engine (Temporal)**, with **PostgreSQL 16** as the system of record for job state, DAG topology, routing decisions, and the budget ledger, and **Redis** for ephemeral queues/rate-limits/leases only. It publishes/consumes events on **NATS JetStream**, reads the registry (C5) and lineage (C4/S8), and coordinates human waits with S9. Written primarily in **Python 3.11+** (pydantic v2 models generated from the C2 JSON Schema); the budget-metering hot path and idempotency broker may use Rust where latency/safety matter, but default is Python calling the Rust ledger writer (S8) for provenance.

**Components**
1. **Intake & Request API (`ctl-intake`)** — accepts research requests (HTTP/JSON + gRPC), validates against schema and guardrail policy, creates a `root_request`, returns a request handle. Applies admission back-pressure.
2. **Decomposer / Planner (`ctl-planner`)** — turns a request into a **job DAG**. Uses a Claude-driven planning agent (Agent SDK, tool-restricted) + deterministic template library + registry lookups to propose nodes, edges, verifier profiles, and budget breakdown. Produces an **inspectable DecompositionPreview**; never executes.
3. **Envelope Factory (`ctl-envelope`)** — mints immutable C2 envelopes from approved DAG nodes, assigns `job_id`/`parent_job_id`/`root_request_id`/`dag_node_id`, attaches `verifier_profile_ref`, `budget`, `constraints`, `provenance_context` (pins contamination index version), `capability_scopes`, and mints the metered `budget_token`.
4. **Router (`ctl-router`)** — resolves candidate subagents via C5 `resolve()`, scores them (conformance, independence, verifier availability, cost class, historical reliability), selects, and records a signed **RoutingDecision** to the ledger. Handles refusal-driven re-routing and escalation.
5. **DAG Executor (`ctl-exec`)** — Temporal workflows/activities that drive each node through the C1 lifecycle (accept→plan→build→validate→report), gate downstream nodes on provenance commit, and manage retries/timeouts/cancellation.
6. **Scheduler & Concurrency Governor (`ctl-sched`)** — admission control across concurrency classes, priorities, deadlines, and global caps; enforces back-pressure sized to S9 review throughput.
7. **Budget Governor (`ctl-budget`)** — real-time spend meter per job/DAG/pool; consumes cost signals from heartbeats + C4 actuals; halts on breach; exposes cost-per-verified-artifact KPI.
8. **Human-Gate Coordinator (`ctl-hgate`)** — inserts S9 review wait states, translates approvals/rejections into DAG continuation/prune/quarantine, enforces external-artifact rate limits and non-goal guardrails.
9. **Recursion Governor (`ctl-recur`)** — the S4-facing scheduling surface; enforces verifier precondition, max-generations, max-spend, and diversity/budget bounds at the orchestration level.
10. **State Store & Query API (`ctl-state`)** — Postgres-backed DAG/job/routing/budget models + read APIs for UI/audit; lineage writes delegated to S8.

### S5.2 Data-dependency & durability model
- Each DAG node = one C2 envelope executed as a **Temporal child workflow**. Node lifecycle mirrors C1's state machine (`REGISTERED→ACCEPTED→PLANNING→BUILDING→VALIDATING→REPORTED`, terminals `FAILED/REFUSED/QUARANTINED/CANCELLED`). Every transition is event-sourced to the C4 ledger via S8.
- An edge declares **data dependency** (produces/consumes `artifact_ref`) or **ordering**. A downstream node is admitted **only after** all upstream `artifact_ref`s are provenance-committed (S8 confirms `content_hash` present and, for tier > ran-toy, a signature-valid C3 report is coupled). This is the gate that makes "a node's outputs are addressable only after provenance-committed" true.
- Durability via Temporal: workflow state, timers, human-wait signals, and retries survive restarts. **Idempotency keys** (`job_id` + `attempt` + `step_id`) on every side-effecting activity (dispatch, budget debit, ledger write) guarantee exactly-once effect on replay.

### S5.3 Key algorithms
**A. Decomposition (NL → DAG).**
1. Parse request; resolve `subtopic` against S6 taxonomy (C5) — if ambiguous, emit clarification item.
2. Retrieve candidate **workflow templates** (e.g. EWPT→bounce→GW-spectrum→observable chain) from a versioned template library; the planner agent proposes a DAG by composing/adapting templates, restricted to tool calls that only *read* the registry and *simulate* cost (no execution).
3. For each proposed node: bind a `verifier_profile_ref` via S3 `list_profiles()`; if none applicable, mark node `verifier_unavailable` (blocks tier promotion; may still run as ran-toy or be pruned).
4. Compute budget breakdown by summing adapter/train/verify cost classes; check against request budget → feasibility.
5. Emit **DecompositionPreview** (DAG, plans, cost, verifier availability, risk notes) for human edit/approval. Decomposition is deterministic given (request, template-lib revision, registry revision, planner-model version) — all pinned for replay.

**B. Routing / scoring.** `resolve(subtopic, required_verifier, min_conformance, independence_needed)` → candidate descriptor revisions. Score = weighted( conformance level, verifier-profile support, independence match (for cross-code parents), cost class fit, resource-envelope fit within budget, historical reliability/refusal rate, load ). Deterministic tie-break by descriptor revision hash. Pin the chosen `descriptor_revision` into the envelope for reproducible routing.

**C. Budget governance.** Two-phase: **reserve** at dispatch (debit projected max from job+pool budget), **reconcile** on heartbeat/report against C4 actuals; release unused reservation. Near-real-time meter compares cumulative spend to caps every metering tick; on breach → emit `BUDGET` halt signal, capture partial result, quarantine. Global pools use a leaky-bucket + hierarchical debit (job ⊂ DAG ⊂ pool ⊂ platform).

**D. Retry & refusal.** On typed error: RETRYABLE → honor `retry_policy` (max_attempts, backoff, `retry_categories`); PERMANENT/POLICY/SANDBOX/VERIFIER_UNAVAILABLE → never retry; POLICY/SANDBOX → quarantine; VERIFIER_UNAVAILABLE → block promotion, and for S4 abort the loop; BUDGET → halt + partial capture. REFUSED (not an error) → re-route to next candidate; if candidates exhausted → escalate to human via S9.

**E. Human-gate & guardrails.** Before any node whose output is externally-visible or tier candidate is `novel-needs-human`, insert an S9 wait state (Temporal signal). A **guardrail policy engine** blocks by construction: autonomous-new-theory claims, autonomous paper submission, flagship-HPC config, empirical-validation claims → hard `POLICY` block regardless of agent output. External-emission rate limiter sits in front of S9 to size intake to review throughput.

**F. Back-pressure.** Admission controller monitors S9 queue depth (via S11/NATS) and global concurrency; when review queue nears its cap, intake returns `THROTTLED` with retry-after and the planner defers dispatch of nodes that would generate review items.

### S5.4 Sequence flows (representative)
- **F1 Request→run:** P1 submits → `ctl-intake` validates + guardrail-screens → `ctl-planner` decomposes → DecompositionPreview to P1 → P1 approves → `ctl-envelope` mints C2 envelopes → `ctl-exec` starts root Temporal workflow → per node: `ctl-router` selects subagent → C1 `accept` (may REFUSE→re-route) → `plan`→`build`(S10)→`validate`(S3)→`report` → S8 commit → gate downstream → on external candidate: `ctl-hgate` S9 wait → sign-off → continue → JobResult(s) aggregated → `root_request` COMPLETE.
- **F2 Budget breach:** heartbeat spend > cap → `ctl-budget` emits halt → `ctl-exec` cancels node cooperatively (C1 `cancel`) → partial artifacts captured to S8 → node QUARANTINED → DAG paused/pruned per policy → operator notified.
- **F3 Recursion:** S4 requests loop → `ctl-recur` checks S3 verifier profile exists (else refuse) → schedules bounded generations, each a child job (S2 train → S3 score) → stops at max-gen/max-spend or no-improvement → best variant reported.

### S5.5 Tech choices & rationale (consistent with shared stack)
- **Temporal** for durable DAG execution, timers, human-wait signals, retries — research jobs are long-running and mix automated + human-approval steps.
- **PostgreSQL 16** system of record; DAG topology + lineage-index queries via recursive CTEs; budget ledger as append-only rows.
- **Redis** ephemeral only (leases, rate-limit buckets, dispatch queues) — never system of record.
- **NATS JetStream** for job-state/registry-change/budget/back-pressure events.
- **OpenTelemetry**→Prometheus/Grafana/Tempo for traces/metrics; every job carries `trace_id`.
- **Claude via Agent SDK** for the planner, tool-restricted to read-only registry/cost-sim tools; planner never executes physics or agent code; prompt/response provenance captured (S8).
- **JSON Schema (2020-12)** canonical for C2; pydantic models generated; **mTLS** + capability scopes on all calls.

### S5.6 Failure & degradation handling
- **Verifier unavailable:** node cannot promote; run as ran-toy or prune; S4 loop aborts. Surfaced, never hidden.
- **Registry revocation mid-flight:** subscribe to C5 revocation events; halt in-flight jobs referencing revoked entity; re-route or quarantine.
- **Subagent timeout/crash:** heartbeat gap → mark stalled → retry (if RETRYABLE) or quarantine; budget reservation released.
- **S8/S9 outage:** S8 write failure = fail-closed (cannot commit → cannot gate downstream → node blocks, DAG pauses durably, no silent progress). S9 outage = human waits accumulate; back-pressure engages; no external emission.
- **Control-plane restart:** Temporal replays; idempotency keys prevent double effects; budget ledger reconciled on resume.
- **Partial DAG failure:** independent branches continue; failed branch quarantined; DAG marked PARTIAL with a complete failure report.
- **Cost meter drift:** periodic reconciliation vs C4 actuals; drift beyond threshold alarms and pauses new dispatch in the affected pool.

### S5.7 Data models (Postgres system of record; pydantic/JSON Schema wire types)

**RootRequest**
```
RootRequest {
  root_request_id: uuid (pk), requester_id: string, submitted_at: timestamptz,
  objective_nl: text, subtopic_hint?: taxonomy_id,
  required_claim_tier_max: enum(ran-toy|recapitulated-known|novel-needs-human),
  budget_ceiling: BudgetSpec,            // global cap for the whole request
  policy_flags: { allow_external_artifact: bool, ... },
  status: enum(SUBMITTED|PLANNING|AWAITING_APPROVAL|RUNNING|PARTIAL|COMPLETED|FAILED|CANCELLED|QUARANTINED),
  guardrail_screen: { passed: bool, blocked_reasons[] },
  contamination_index_version: string,   // pinned at intake
  registry_revision_pin: string,         // pinned registry snapshot for reproducible routing
  template_lib_revision: string, planner_model_version: string, trace_id: string
}
```

**JobDag / DagNode / DagEdge**
```
JobDag { dag_id: uuid, root_request_id: fk, version: int, decomposition_preview_ref(C4),
         created_at, status, node_count, is_replay_of?: dag_id }
DagNode { dag_node_id: uuid (pk), dag_id: fk, job_id?: uuid,   // job_id set at envelope mint
          subtopic: taxonomy_id, objective: text,
          verifier_profile_ref?: ref(C3 profile), verifier_available: bool,
          plan_ref?(C1 Plan), budget_alloc: BudgetSpec,
          state: enum(mirrors C1 lifecycle + terminals),
          is_external_candidate: bool, requires_human_gate: bool, routing_decision_id?: fk }
DagEdge { edge_id, dag_id: fk, from_node: fk, to_node: fk,
          kind: enum(DATA|ORDER), artifact_role?: string, consumes_artifact_ref?: ref(C4) }
```

**JobEnvelope (C2 — owned, immutable once dispatched)**
```
JobEnvelope {
  job_id: uuid, parent_job_id?: uuid, root_request_id: uuid, dag_node_id: uuid,
  envelope_version: semver,
  problem_spec: { subtopic, objective, target_observable, inputs_schema,
                  success_criteria, required_claim_tier_max },
  verifier_profile_ref: ref(C3 profile),          // REQUIRED (null => subagent must refuse)
  budget: { max_compute_units, max_gpu_seconds, max_model_tokens, max_wallclock_s, max_cost_usd },
  budget_token: opaque,                            // minted, metered credential
  constraints: { physics_priors[], units_contract, allowed_adapters[](C6),
                 allowed_datasets[](C4), disallowed_actions[] },
  provenance_context: { root_lineage_ref, contamination_index_version },
  scheduling: { priority, deadline?, concurrency_class,
                retry_policy{ max_attempts, backoff, retry_categories[] } },
  routing: { candidate_subagents?[], routing_strategy },
  capability_scopes[], created_at, dispatched_at?, immutable_hash: content_hash
}
```

**JobResult (C2 result envelope)**
```
JobResult { job_id, status: enum(SUCCEEDED|FAILED|REFUSED|QUARANTINED|CANCELLED),
            subagent_report_ref(C1), validation_report_ref?(C3), artifacts[](C4),
            cost_actual: BudgetSpec, claim_tier, trace_id }
```

**RoutingDecision (append-only, signed)**
```
RoutingDecision { routing_decision_id, job_id, dag_node_id,
  candidates_considered: [{ descriptor_revision(C5), score, rejected_reason? }],
  selected_descriptor_revision(C5), strategy, independence_satisfied: bool,
  verifier_profile_ref, decided_at, signature, signer_key_id }
```

**BudgetSpec / BudgetLedgerEntry / BudgetPool**
```
BudgetSpec { max_compute_units, max_gpu_seconds, max_model_tokens, max_wallclock_s, max_cost_usd }
BudgetPool { pool_id, scope: enum(PLATFORM|SUBTOPIC|REQUEST|DAG|JOB), parent_pool?, caps: BudgetSpec,
             reserved: BudgetSpec, spent: BudgetSpec }
BudgetLedgerEntry { entry_id (pk), job_id, pool_id, kind: enum(RESERVE|RECONCILE|RELEASE|HALT),
                    delta: BudgetSpec, source: enum(HEARTBEAT|REPORT|C4_ACTUAL|MANUAL),
                    at, idempotency_key, running_total: BudgetSpec }
```

**ReviewWaitState (S9 coupling)**
```
ReviewWaitState { wait_id, job_id, dag_node_id, review_item_ref(S9),
  reason: enum(EXTERNAL_ARTIFACT|NOVEL_CANDIDATE|GUARDRAIL_ESCALATION|REFUSAL_ESCALATION),
  status: enum(PENDING|APPROVED|REJECTED|EXPIRED), decided_by?, decided_at?, resume_signal_sent: bool }
```

**GuardrailEvent (audit)**
```
GuardrailEvent { event_id, root_request_id, job_id?, rule_id:
  enum(NO_AUTONOMOUS_THEORY|NO_AUTO_PAPER_SUBMIT|NO_FLAGSHIP_HPC|NO_EMPIRICAL_CLAIM|RATE_LIMIT|NOVEL_SELF_ASSIGN),
  action: enum(BLOCK|ESCALATE|QUARANTINE), detail, at }
```

**RecursionGovernance (S4 coupling)**
```
RecursionGovernance { recur_id, root_request_id, target_node,
  verifier_profile_ref, verifier_precondition_ok: bool,
  max_generations, max_spend: BudgetSpec, generations_run, spend_so_far,
  diversity_policy, stop_reason?: enum(MAX_GEN|MAX_SPEND|NO_IMPROVEMENT|VERIFIER_UNAVAILABLE|POLICY),
  best_variant_ref?(C4) }
```

**ConcurrencyClass / SchedulerLease (Redis + Postgres)**
```
ConcurrencyClass { class_id, max_concurrent, priority_weight, subtopic_scope? }
SchedulerLease { lease_id, job_id, class_id, acquired_at, ttl, heartbeat_at } // Redis, ephemeral
```

All persisted mutations that cross a trust boundary or produce an artifact also emit a **C4 ArtifactRecord/provenance edge** via S8 (event-sourced lifecycle). Envelopes, routing decisions, decomposition previews, and budget ledgers are content-addressed and lineage-linked.

### S5.8 Public interfaces

**A. Intake & Request API (HTTP/JSON + gRPC, mTLS)**
```
POST /v1/requests
  body: { objective_nl, subtopic_hint?, required_claim_tier_max, budget_ceiling: BudgetSpec, policy_flags?, deadline? }
  -> 202 { root_request_id, status:SUBMITTED, trace_id }
  -> 429 { code:THROTTLED, retry_after }        // back-pressure
GET  /v1/requests/{root_request_id}   -> { RootRequest, dag_summary, spend, review_waits[] }
POST /v1/requests/{id}/cancel  { reason } -> { status:CANCELLED }
```

**B. Decomposition / Planning API**
```
POST /v1/requests/{id}/plan            // (re)run decomposition
  -> { dag_id, decomposition_preview_ref(C4), feasible: bool, cost_estimate: BudgetSpec,
       verifier_coverage: {node_id: bool}, clarifications[]? }
GET  /v1/dags/{dag_id}                  -> { JobDag, nodes[], edges[] }
PATCH /v1/dags/{dag_id}                 // human edits before approval
  body: { add_nodes[]?, remove_nodes[]?, edit_edges[]?, budget_overrides? }  -> { dag_id, version, feasible }
POST /v1/dags/{dag_id}/approve          { approved_by } -> { status:RUNNING, dispatched_nodes[] }
```

**C. Execution / Job API (C2)**
```
POST /v1/jobs                           // internal: mint + dispatch a single envelope
  body: JobEnvelope(C2 without job_id/token)  -> { job_id, immutable_hash, dispatched_at }
GET  /v1/jobs/{job_id}                  -> { JobEnvelope, DagNode.state, JobResult?, spend }
POST /v1/jobs/{job_id}/cancel           { reason } -> { status }
GET  /v1/jobs/{job_id}/result           -> JobResult(C2)
```

**D. Subagent-facing dispatch (S5 -> S1 over C1; S5 is caller).** S5 invokes C1 methods on the routed subagent: `accept(JobEnvelope C2) -> Acceptance{accepted, reason?, estimated_cost, plan_eta}`, `plan`, `build`, `validate`, `report`, `heartbeat() -> Health`, `cancel(job_id, reason)`. Every call carries `{job_id, subagent_id, trace_id, budget_token, provenance_context, capability_scopes[]}`.

**E. Registry consumption (S5 -> C5).** `resolve(query{subtopic, required_verifier, min_conformance, independence_needed}) -> [descriptor_revision]`; `subscribe(filter) -> stream` for revocation/deprecation events.

**F. Verifier-profile consumption (S5 -> C3).** `list_profiles() -> [VerifierProfile]` (used at plan time to bind `verifier_profile_ref` and compute verifier coverage).

**G. Provenance (S5 -> C4/S8).** `commit_record(ArtifactRecord)`, `get_record(content_hash)`, `is_committed(artifact_ref)`, `query_lineage(root_request_id)` — used for gating and audit; lineage writes go through the S8 Rust ledger writer.

**H. Human-gate (S5 <-> S9).** `open_review(ReviewWaitState) -> review_item_ref`; consumes S9 decision events `ReviewDecided{review_item_ref, decision:APPROVED|REJECTED, decided_by}`.

**I. Recursion governance (S4 -> S5)**
```
POST /v1/recursion   body: { root_request_id, target_node, max_generations, max_spend, diversity_policy }
  -> { recur_id, verifier_precondition_ok, accepted: bool, reason? }   // refuses if no S3 verifier
GET  /v1/recursion/{recur_id} -> RecursionGovernance
```

**J. Operator API**
```
POST /v1/admin/concurrency-classes    { class_id, max_concurrent, priority_weight, subtopic_scope? }
POST /v1/admin/budget-pools           { scope, parent_pool?, caps }
POST /v1/admin/drain                  { mode: GRACEFUL|IMMEDIATE } -> { draining: true }
POST /v1/admin/pause | /resume        { scope }
GET  /v1/admin/health                 -> { queue_depths, active_jobs, pool_utilization, backpressure }
```

**K. Query / Audit API**
```
GET /v1/audit/requests/{id}/routing   -> [RoutingDecision]
GET /v1/audit/requests/{id}/budget    -> [BudgetLedgerEntry]
GET /v1/audit/requests/{id}/guardrails-> [GuardrailEvent]
GET /v1/audit/dags/{dag_id}/replay    -> { replayable: bool, pins:{registry,template_lib,index,model} }
```

**L. Events (NATS JetStream, published by S5)**
```
argus.s5.request.status        { root_request_id, status, at }
argus.s5.job.state             { job_id, dag_node_id, state, spend, at, trace_id }
argus.s5.routing.decided       { job_id, selected_descriptor_revision }
argus.s5.budget.event          { pool_id, job_id?, kind, running_total }
argus.s5.budget.breach         { job_id, pool_id, cap, spent }
argus.s5.review.opened         { review_item_ref, job_id, reason }
argus.s5.guardrail.blocked     { rule_id, root_request_id, job_id?, action }
argus.s5.backpressure          { active: bool, review_queue_depth, threshold }
```

**M. CLI (`argusctl`)**
```
argusctl request submit --objective "..." --subtopic ewpt --tier recapitulated-known --budget-usd 200
argusctl request status <id>            argusctl dag show <dag_id>
argusctl dag approve <dag_id>           argusctl dag edit <dag_id> --remove-node <n>
argusctl job show <job_id>              argusctl job cancel <job_id> --reason "..."
argusctl budget pool create --scope subtopic --caps ...   argusctl admin drain --mode graceful
argusctl audit routing <id>             argusctl audit replay <dag_id>
argusctl recursion start --request <id> --node <n> --max-gen 20 --max-spend-usd 50
```

**Events consumed by S5.** S1 `Health`/lifecycle events; C5 registry change/revocation stream; S3 `list_profiles`; S8 provenance-commit confirmations; S9 `ReviewDecided`; S11 back-pressure/queue-depth metrics; S4 recursion requests.

---

## S6 — Knowledge & Ingestion

**Co-owns contract:** **C5** (with S12). **Consumes:** C4 (S8), S10 sandbox/egress proxy, C6 units contract (S7 descriptors), S12 conformance evidence, NATS, S11.

### S6.1 Architecture overview
S6 is a set of decoupled services around a shared data plane (S8) and isolation substrate (S10):

```
                        ┌──────────────────────────────────────────────┐
   external internet →  │  INGESTION PLANE (S10-sandboxed, egress-allowlisted) │
   (arXiv/GitHub/HEP)   │  Connector Framework → Fetchers → Raw Landing │
                        └───────────────┬──────────────────────────────┘
                                        │ raw artifacts (C4 via S8)
                        ┌───────────────▼──────────────────────────────┐
                        │  NORMALIZATION PLANE                          │
                        │  LaTeX/PDF/HTML→struct text+math+tables,      │
                        │  code parse, citation-graph, unit-annotation  │
                        └───────────────┬──────────────────────────────┘
                                        │ normalized docs (C4)
                        ┌───────────────▼──────────────────────────────┐
                        │  INDEXING PLANE                               │
                        │  Chunker → Embedder → OpenSearch (lexical+vec)│
                        │  Dedup/near-dup (simhash/minhash) tables (PG) │
                        └───────────────┬──────────────────────────────┘
     ┌──────────────────────────────────┼──────────────────────────────┐
     ▼                                  ▼                              ▼
 ┌─────────────┐             ┌───────────────────────┐      ┌────────────────────────┐
 │ RETRIEVAL   │             │ FROZEN CONTAMINATION  │      │ REGISTRY SERVICE (C5)  │
 │ /RAG API    │             │ INDEX SVC (snapshots, │      │ publish/resolve/       │
 │ hybrid+rerank│            │ novelty/overlap query)│      │ deprecate/revoke/sub   │
 └─────────────┘             └───────────────────────┘      └────────────────────────┘
     (all serving APIs: mTLS, capability-scoped, read-mostly; events → NATS JetStream)
```

Stores: **PostgreSQL 16** (registry, ingest state/cursors, dedup tables, snapshot manifests metadata, curation flags, citation graph edges); **OpenSearch** (full-text + vector, per-version index aliases); **Object store via S8** (raw + normalized artifacts, embedding shards, immutable snapshot manifests); **Redis** (rate-limit tokens, ephemeral connector cursors, dedup bloom cache); **NATS JetStream** (registry-change + ingest events). Language: Python 3.11 for connectors/normalization/retrieval/registry; Rust only where it touches the S8 hashing path indirectly (S6 delegates hashing to S8's Rust writer).

### S6.2 Components

**2.1 Connector Framework (SPI).** A driver interface `SourceConnector` with methods `list_since(cursor)`, `fetch(record_ref)`, `describe_source()`. Concrete drivers:
- **arXiv**: OAI-PMH for incremental listings (`ListRecords` with `from`/`resumptionToken`), plus the arXiv API/bulk source for full-text (LaTeX source tarballs preferred over PDF). Respects rate limits and robots. Cursor = OAI resumptionToken + last datestamp.
- **GitHub**: REST/GraphQL for repos matching curated org/topic allowlists + releases; clones pinned commits into sandbox; extracts code, README, docs, `CITATION.cff`. Cursor = per-repo last-seen commit SHA / release tag.
- **HEPData**: record + table API; tables normalized into typed columns with units + uncertainty; links to originating arXiv id. Cursor = record id / last-modified.
- Driver SPI is pluggable; each driver declares its egress allowlist (enforced by S10 proxy).

**2.2 Ingest Orchestrator.** A Temporal-driven (via S5's engine, but S6 owns its own workflow definitions) or standalone durable scheduler that runs incremental syncs on a cron cadence, resumable via persisted cursors in PG. Idempotency: a record is keyed by `(source, source_id, source_version)`; if the S8 content_hash of the raw bytes matches an existing artifact, it's a no-op (dedup). Backpressure and rate-limit via Redis token buckets per source.

**2.3 Normalization Pipeline.**
- **PDF/LaTeX/HTML → structured doc:** prefer LaTeX source; parse with a math-aware pipeline (LaTeX AST for equations, GROBID/science-parse-style extraction for PDF fallback). Output: sections, paragraphs, equations (with symbol table), tables, figures-captions, references.
- **Citation graph:** resolve `\cite`/bibitems/HEPData cross-refs → edges `cites(doc_a, doc_b)` stored in PG; enables lineage-aware retrieval and "downstream of contaminated source" queries.
- **Unit annotation:** a physics-units tagger (rule + model hybrid) annotates quantities with dimensions using a controlled units vocabulary (aligned with C6 units contract), producing per-chunk `units_present[]` metadata. Backstops S2/S3 dimensional checks.
- **Code repo normalization:** language detection, symbol/API extraction, docstrings, README → doc units; `CITATION.cff`/license parsed.

**2.4 Chunker + Embedder.**
- Structure-aware chunking (respect section/equation/table boundaries; never split an equation). Chunk carries `{doc_id, section_path, char_span, units_present, has_math, has_table, source_ref}`.
- Embedding via an internally-served domain-appropriate model (default config; pinned model version recorded per chunk for reproducibility). Embeddings stored as shards (C4) + indexed in OpenSearch kNN. Model version is part of the index alias name so a model swap = a new index, never a silent mix.

**2.5 Indexing Plane.**
- OpenSearch indices named `docs-v{schema}-{embed_model_ver}`; **alias `docs-live`** points to the current live index; frozen snapshots get **alias `docs-frozen-{index_version}`**. Lexical BM25 + dense kNN fields co-located.
- Dedup/near-dup: SimHash (64-bit) + MinHash LSH (for near-duplicate document detection) stored in PG; used at ingest (skip re-embed) and by leakage primitives.

**2.6 Retrieval / RAG API.**
- **Hybrid retrieval:** BM25 + dense kNN → **Reciprocal Rank Fusion (RRF)** → cross-encoder reranker (pinned model) → top-k.
- **Filters:** subtopic taxonomy, source, license/access-scope, `contamination_index_version` (query the frozen vs. live index), `units_present`, curated-only flag, date ceiling (for reproducing a historical retrieval).
- **Output:** ranked chunks each with a full **CitationProvenance** (`external_source_ref`, doc_id, section_path, snapshot_hash, license) so downstream artifacts (C4) can record exactly what grounded them.
- **Curated-doc mode:** restrict to human-vetted set; returns priors/unit-conventions for a subtopic.

**2.7 Registry Service (C5).**
- Append-only per-entity revisions in PG; `current` pointer; signature verification on publish (signer key in trust store). `publish()` refuses without valid conformance evidence for the claimed level (`CONFORMANCE_MISSING/EXPIRED`). `resolve()` filters by subtopic, required verifier, min conformance, independence.
- **Independence resolution (critical):** given "independent implementation of observable O relative to code X", the service uses `independence_tags` + `code.repo`/`derived_from` (from C4 lineage) to exclude any code sharing a repo/fork lineage/tag with X, returning genuinely independent candidates for S3 cross-code checks.
- `revoke()` propagates a NATS event; in-flight consumers must halt (S5 honors it). Descriptor revisions are immutable & content-addressed.

**2.8 Frozen Contamination Index Service.**
- **Snapshot creation:** `freeze(spec) → index_version` copies the live index state (doc set + embeddings + dedup tables) into an immutable, aliased OpenSearch snapshot + writes an immutable **SnapshotManifest** (C4, write-once bucket) listing every included doc's content_hash, source_ref, and the embedding model version, plus the freeze timestamp = the novelty cutoff date.
- **Novelty/overlap query:** `novelty_query(text|artifact_ref, index_version) → {max_overlap_score, matches[], calibrated_novelty_prob}` combining lexical n-gram overlap, SimHash/MinHash near-dup, and embedding cosine max-sim, calibrated so S3's threshold is meaningful. Also `recall_query` for the recapitulation-benchmark path (is a *known* result present, held out or not).
- **Immutability guarantee:** once frozen, an index_version's doc set never changes; corrections create a *new* version with a `supersedes` link, never a mutation.

### S6.3 Key algorithms
- **Incremental dedup ingest:** for each source record → compute raw content_hash (via S8) → if present, skip; else normalize → SimHash → MinHash-LSH near-dup lookup; if near-dup above threshold, link `near_dup_of` and optionally skip re-embed; else embed + index. O(1) exact dedup, sublinear near-dup via LSH bands.
- **Hybrid retrieval RRF:** `score(d) = Σ_r 1/(k + rank_r(d))` over lexical & dense rankers, then cross-encoder rerank of top-N. k=60 default.
- **Novelty scoring (calibrated):** `s = f(ngram_jaccard, simhash_hamming, minhash_est, max_embed_cos)`; f is a logistic model calibrated on a labeled memorized/novel set (isotonic/Platt) → `calibrated_novelty_prob`. Coverage-tested so P(novel | reported novel) matches nominal.
- **Independence exclusion:** build the fork/lineage closure of code X from C4 `derived_from` + `code.repo`; candidate is independent iff its closure ∩ X's closure = ∅ AND `independence_tags` disjoint on shared-implementation markers.

### S6.4 Sequence flows
- **4.1 Daily arXiv incremental ingest.** S6 scheduler → arXiv driver `list_since(cursor)` (sandbox, egress-allowlisted) → for each new id: fetch LaTeX source → normalize → dedup check (S8 hash) → if new: chunk+embed → index into `docs-live` → write C4 records (raw, normalized, embedding shard) with `external_source_ref` → advance cursor in PG → emit `s6.ingest.doc_indexed` (NATS).
- **4.2 RAG grounding call from S2.** S2 (inside subagent lifecycle) → `retrieve(query, filters{subtopic, curated_only, contamination_index_version})` via mTLS+scope → hybrid+rerank → returns chunks + CitationProvenance → S2 records the used citations into its artifact lineage (C4). No secrets, read-only.
- **4.3 Leakage/novelty screen for S3.** S3 → `novelty_query(candidate_result, index_version=job.contamination_index_version)` → S6 returns calibrated overlap + matches → S3 applies its LEAKAGE gate threshold and sets/limits claim tier. S6 does not decide tier.
- **4.4 Routing resolve from S5.** S5 → registry `resolve({subtopic, required_verifier, min_conformance, independence_needed})` → S6 returns conformance-valid, non-revoked descriptor revisions (pinned revision refs) → S5 routes C2 job.
- **4.5 Freeze a contamination index.** Curator/orchestrated `freeze(spec)` → snapshot live index → write immutable SnapshotManifest (C4) → register `contamination_index` entity revision in C5 → emit `s6.index.frozen` → S5 may now pin the new `contamination_index_version` in future C2 envelopes.

### S6.5 Tech choices (consistent with shared stack)
Python 3.11 (pydantic v2 models generated from C4/C5 JSON Schemas); OpenSearch (lexical+vector+snapshots); PostgreSQL 16 (registry, cursors, dedup, citation graph via recursive CTEs); Redis (rate-limit/cursor cache only, never system of record); object store via S8 (BLAKE3 content-addressed, immutable buckets for snapshots); NATS JetStream (events); OpenTelemetry traces to S11; gVisor/Firecracker sandbox + egress-allowlist proxy (S10) for all ingestion; mTLS + capability scopes on every API. JSON Schema draft 2020-12 as canonical IDL for C5/C4 bindings.

### S6.6 Failure & degradation handling
- **Source unavailable / rate-limited:** exponential backoff; cursor not advanced; partial batch committed idempotently; `s6.ingest.source_degraded` event; retrieval keeps serving from existing index (freshness SLA breach alarmed, not an outage).
- **Normalization failure:** doc quarantined with reason, raw artifact retained (C4), excluded from index; never partially indexed. Quarantine queue reviewable by curator.
- **Embedding model unavailable:** ingest pauses embedding stage (lexical-only fallback flagged on chunks); retrieval degrades to BM25-only with a `degraded:true` flag on results so callers know vector recall is reduced.
- **OpenSearch shard loss:** index rebuildable from C4 normalized artifacts + pinned embed model (reindex job); frozen snapshots are separately durable in immutable bucket.
- **Registry write conflict:** append-only optimistic concurrency on `(entity_id, revision_seq)`; conflicting publish retried with new seq; `current` pointer moved atomically.
- **Snapshot integrity:** every read of a frozen index validates the SnapshotManifest hash; mismatch → fail-closed, artifact flagged, S3 novelty queries against that version blocked (fail loud) rather than returning wrong novelty.
- **License/egress violation attempt:** blocked at proxy; job quarantined (POLICY error); audit event.

### S6.7 Data models
All externally-visible produced objects are C4 ArtifactRecords (content-addressed via S8) and/or C5 descriptors. Below are S6-internal + wire models (pydantic/JSON-Schema shape).

**IngestCursor (PG)**
```
{ source: enum(arxiv|github|hepdata|<driver>), cursor_token: string,
  last_datestamp: timestamptz, last_source_id?: string,
  status: enum(active|paused|degraded), updated_at, error_streak: int }
```

**SourceRecordRef**
```
{ source, source_id, source_version?, source_url, retrieved_at, license, raw_artifact_ref(C4) }
```

**NormalizedDoc (C4 kind=dataset/notebook; body in object store)**
```
{ doc_id: uuid, content_hash(BLAKE3),
  external_source_ref: { source, id, url, snapshot_hash, ingested_at, license },
  title, authors[], date, subtopics:[taxonomy_id],
  sections:[{ path, text, equations:[{latex, symbols[]}], tables:[table_ref] }],
  references:[doc_id|external_source_ref],   // citation edges
  units_present:[unit_dim], quality_flags:{ has_latex_source, parse_confidence, vetted:bool },
  simhash: uint64, minhash_sig: bytes, embed_model_version?, indexed_at? }
```

**Chunk (OpenSearch doc)**
```
{ chunk_id, doc_id, section_path, char_span:[start,end], text,
  bm25_field(text), vector: float[dim], embed_model_version,
  units_present:[unit_dim], has_math:bool, has_table:bool,
  subtopics:[taxonomy_id], source_ref(SourceRecordRef),
  license, access_scope, curated:bool, index_version|live }
```

**CitationProvenance (returned with each retrieval hit)**
```
{ chunk_id, doc_id, section_path, external_source_ref, snapshot_hash,
  license, score, retrieved_from_index_version|live }
```

**HEPDataTable**
```
{ table_id, hepdata_record_id, origin_arxiv_id?,
  columns:[{ name, dimension/units, kind: independent|dependent,
             values:[num], uncertainties:[{type, plus, minus}] }],
  observable_hint?, provenance_ref(C4) }
```

**CapabilityDescriptor (C5 — authoritative shape, owner-shared)**
```
{ entity_id, entity_type: subagent|physics_code|adapter|dataset|verifier|contamination_index,
  revision_seq, name, owner, maintainer_contact,
  contract_versions:{ c1?, c6?, min, max },
  subtopics:[{ taxonomy_id, description }],
  capabilities:[{ verb, target_observable, io_schema_ref }],
  required_adapters:[adapter_ref(C6)], required_datasets:[dataset_ref],
  resource_envelope:{ cpu, gpu, mem, typical_wallclock, cost_class },
  uncertainty_support: bool,
  conformance:{ level:bronze|silver|gold, suite_version, passed_at, evidence_ref(C4), expires_at },
  independence_tags:[string], trust_class: internal|federated,
  provenance_ref(C4), signature, signer_key_id, status: active|deprecated|revoked }
```

**RegistryEntity (PG)**
```
{ entity_id, entity_type, current_revision_seq, created_at,
  revisions:[ CapabilityDescriptor (immutable) ] }   // append-only
```

**SnapshotManifest (C4 kind=report, immutable/write-once)**
```
{ index_version: string (semver+date), created_at (=novelty_cutoff_date),
  embed_model_version, schema_version,
  included_docs:[{ doc_id, content_hash, external_source_ref }],
  doc_count, chunk_count, opensearch_alias, dedup_table_hash,
  supersedes?: index_version, manifest_hash(self, BLAKE3), signature, signer_key_id }
```

**NoveltyResult (returned to S3)**
```
{ query_ref, index_version, max_overlap_score: float, calibrated_novelty_prob: float,
  matches:[{ doc_id, external_source_ref, overlap_kind:[ngram|simhash|minhash|embed],
             overlap_score, matched_span? }],
  calibration_ref(C4), degraded:bool }
```

**CurationRecord (PG)**
```
{ doc_id|source, action: vet|block|deprecate|add_to_curated_set,
  curated_set_id?, curator, reason, at, audit_ref(C4) }
```

**Taxonomy (PG)**
```
{ taxonomy_id, parent_id?, label, description, aliases[], version }
```

**Events (NATS JetStream subjects)**
```
s6.ingest.doc_indexed { doc_id, source, index=live, content_hash, trace_id }
s6.ingest.source_degraded { source, reason, since }
s6.ingest.doc_quarantined { doc_id, reason }
s6.index.frozen { index_version, doc_count, cutoff_date, manifest_ref }
s6.registry.published { entity_id, revision_seq, entity_type }
s6.registry.deprecated { entity_id, revision_seq }
s6.registry.revoked { entity_id, reason }        // consumers MUST halt in-flight refs
s6.curation.changed { doc_id|set_id, action }
```

### S6.8 Public APIs (gRPC/HTTP+JSON, mTLS, capability-scoped)

**Retrieval / RAG (`s6.retrieval.*`)**
```
retrieve(RetrieveRequest) -> RetrieveResponse
  RetrieveRequest = { query: string|embedding, top_k:int=20,
     filters:{ subtopics?[], sources?[], curated_only?:bool,
               contamination_index_version?: string|"live",
               units_present?[], date_ceiling?, license_scope? },
     rerank:bool=true, trace_id, capability_scopes[] }
  RetrieveResponse = { hits:[{ chunk, CitationProvenance, score }],
     degraded:bool, index_version_used, retrieval_manifest_hash }
get_curated_docs(subtopic, version?="live") -> [NormalizedDoc summary + CitationProvenance]
get_unit_conventions(subtopic) -> { units_contract_fragment, sources:[CitationProvenance] }
```

**Frozen Contamination Index (`s6.contamination.*`) — consumed by S3**
```
list_index_versions() -> [{ index_version, cutoff_date, doc_count, status }]
novelty_query(NoveltyRequest) -> NoveltyResult
  NoveltyRequest = { text?|artifact_ref?(C4), index_version, kinds?:[ngram|simhash|minhash|embed], trace_id }
recall_query(text|artifact_ref, index_version, target_known_result_id?) -> NoveltyResult
freeze(FreezeSpec) -> { index_version, manifest_ref(C4) }        // audited, curator/orchestrated
  FreezeSpec = { source_filter?, date_ceiling?, label, supersedes? }
get_manifest(index_version) -> SnapshotManifest(C4)
```

**Registry (`s6.registry.*`) — C5, consumed by S5/S3/S12/S1**
```
publish(CapabilityDescriptor) -> { entity_id, revision_ref }     // requires valid conformance
resolve(ResolveQuery) -> [descriptor_revision]
  ResolveQuery = { subtopic?, required_verifier?, min_conformance?:bronze|silver|gold,
     independence_needed?:{ relative_to_code: entity_id, observable }, entity_type?, trust_class? }
get_descriptor(entity_id, revision_seq?="current") -> CapabilityDescriptor
deprecate(entity_id, revision_seq) -> ok
revoke(entity_id, reason) -> ok                                  // emits s6.registry.revoked
subscribe(filter) -> stream<RegistryChangeEvent>                 // NATS-backed
resolve_independent_code(observable, relative_to_code) -> [descriptor_revision]
```

**Admin / Ingestion (`s6.admin.*`) — SRE/Curator, elevated scope**
```
trigger_sync(source, mode:incremental|backfill, range?) -> job_id
reindex(target_index, embed_model_version) -> job_id
requeue_quarantined(doc_id|all) -> job_id
add_source_connector(driver_descriptor) -> ok
curate(CurationRecord) -> audit_ref(C4)
manage_taxonomy(op:add|rename|merge|deprecate, node) -> taxonomy_version
```

**CLI (`argusctl s6 ...`)**
```
argusctl s6 ingest run --source arxiv --mode incremental
argusctl s6 ingest backfill --source hepdata --from 2020-01-01
argusctl s6 index freeze --label "cutoff-2026Q2" --date-ceiling 2026-06-30
argusctl s6 index list
argusctl s6 novelty check --index v3 --file result.json
argusctl s6 registry publish --file descriptor.json
argusctl s6 registry resolve --subtopic ewpt --min-conformance silver --independence-of code:cosmoTransitions
argusctl s6 registry revoke --entity adapter:foo --reason "cve"
argusctl s6 retrieve --subtopic ewpt --curated-only --q "sphaleron rate"
argusctl s6 curate vet --doc <doc_id> --reason "peer-reviewed"
argusctl s6 reindex --embed-model v2
```

**Events produced (NATS):** `s6.ingest.doc_indexed`, `s6.ingest.source_degraded`, `s6.ingest.doc_quarantined`, `s6.index.frozen`, `s6.registry.published|deprecated|revoked`, `s6.curation.changed` (schemas in Data Models).

---

## S7 — Physics Compute Adapters

**Owns contract:** **C6**. **Consumes:** C4 (S8), C5 (S6/S12), C2 budget_token (S5), S10 sandbox/egress substrate, S11 OTel, C3 extrapolation-flag coupling (S3).

### S7.1 Architecture overview
S7 is a **brokered tool plane** sitting in the control/provenance-adjacent zone (NOT inside the agent sandbox). Callers (S2 inside the sandbox, S3 in the verifier zone, S4) issue C6 calls to the **Adapter Broker** over mTLS/gRPC through the mediating egress proxy. The broker dispatches to a **Backend Worker** that hosts the specific adapter implementation, which may itself shell out to a pinned container running a physics binary. Every call is metered, seeded, unit-checked, uncertainty-checked, validity-checked, cached, and provenance-emitted.

```
            ┌────────────────────────────────────────────────────────────┐
 S2 (sandbox)│                                                            │
 S3 (verifier)─C6/gRPC/mTLS─► Egress Proxy ─► ADAPTER BROKER (Rust/Py)    │
 S4 (evolver) │                                   │ dispatch (adapter_ref, ver pin) │
            └───────────────────────────────────┼────────────────────────┘
                            ┌────────────────────┼─────────────────────────┐
                            ▼                    ▼                          ▼
                    Backend Worker         Backend Worker            Backend Worker
                    (JAX surrogate)        (subprocess: C++ bounce   (GP emulator)
                            │               solver in OCI container)        │
                            ▼                    ▼ stdin/stdout/files        ▼
                    Units Engine │ Uncertainty Engine │ Validity Guard │ Seed Mgr
                            ▼
                    Provenance Emitter ──C4──► S8 ledger + object store
                    Metrics/Trace ──OTel──► S11 ;  Cost meter ──► budget_token
```

### S7.2 Components
1. **C6 Schema & Bindings (`s7-contract`)** — canonical JSON Schemas for `AdapterDescriptor`, `EvalRequest`, `EvalResult`, `Jacobian`, error envelope; generated pydantic v2 / TS / Rust serde bindings. Single source of truth; semver'd in the schema registry.
2. **Adapter SDK (`argus-adapter-sdk`, Python)** — base class `Adapter` with `describe/evaluate/grad/batch_evaluate`; decorators `@units_in(schema)`, `@units_out(schema)`, `@validity_domain(...)`, `@uncertainty(kind=...)`; auto-generation of the descriptor and a conformance test stub. Provides `EvalContext` giving seed, budget handle, trace ctx, provenance writer.
3. **Units Engine (`s7-units`)** — Pint-based with a **frozen physics unit registry** (natural units, GeV/TeV, Hz, mHz, cross-sections in pb/fb, energy densities Ω h², dimensionless couplings) and canonical normalization. Enforces dimensional analysis on every field; rejects mismatches with `UNITS_MISMATCH`; supports derived/compound units and log-space fields.
4. **Uncertainty Engine (`s7-uncertainty`)** — representations `Interval | Covariance | Samples | Analytic`; utilities: linear error propagation (via `grad`), Monte-Carlo propagation, GP posterior variance extraction, deep-ensemble variance, conformal intervals; a **coverage/calibration harness** that produces the calibration metadata S3's CALIBRATION check reads.
5. **Validity-Domain Guard (`s7-domain`)** — per-adapter declared box/polytope/learned-density domain; classifies each input as in/out of domain; policy modes `flag | refuse | clamp-with-flag`; emits `in_validity_domain` + `extrapolation_flag`.
6. **Backend Plugin System (`s7-backends`)** — plugin kinds: `native_python`, `jax`, `pytorch`, `subprocess_binary` (OCI, digest-pinned), `emulator_gp`, `emulator_nn`, `surrogate_diff`. Each backend implements a `Backend` protocol (`load`, `invoke`, `invoke_grad?`, `invoke_batch`, `warm/teardown`). Subprocess backend marshals units-normalized inputs to the binary's native format (e.g. CosmoTransitions/BubbleProfiler-style config, SLHA-like param cards, HDF5) and parses stdout/files back.
7. **Adapter Broker (`s7-broker`, Rust core + Python worker host)** — front door. Responsibilities: authn/authz (mTLS, capability scopes), request validation against pinned C6 version, adapter resolution via registry (C5), version pinning, dispatch to worker pool, **budget metering & halt**, timeout enforcement, seed injection, caching, degradation handling, provenance emission trigger, OTel + cost metrics. Bulkheaded worker pools per adapter (a bad backend never starves others).
8. **Seed Manager (`s7-seed`)** — deterministic per-call seed derivation `seed = KDF(job_seed, dag_node_id, call_index, adapter_id)`; records seeds into provenance so any call is replayable.
9. **Cache (`s7-cache`)** — content-addressed by `cache_key = BLAKE3(adapter_id ‖ adapter_version ‖ underlying_code_version ‖ canonical(inputs) ‖ fidelity ‖ seed?)`; only caches `deterministic`/`seeded` results (never `stochastic` unless seeded). Backed by Redis (hot) + object store (large outputs, via S8).
10. **Provenance Emitter (`s7-prov`)** — builds the C4 `ArtifactRecord` for each call (`kind: log` or `dataset` for large outputs), pins adapter/underlying versions, seeds, config_hash, input hashes, environment_digest; hands to the S8 Rust ledger writer. Fail-closed: if provenance can't be written, the result is not returned as trusted (`PROVENANCE_UNAVAILABLE`).
11. **Registration Service (`s7-register`)** — validates a descriptor, runs the conformance stub (units present, uncertainty present, validity domain declared, determinism honored, grad present iff differentiable), enforces the **cost-class ceiling gate**, and publishes to the registry (C5) via `publish(descriptor)`.
12. **Reference Adapter Suite (`s7-refadapters`)** — concrete adapters (below).

### S7.3 Reference adapter suite (flagship physics thread + independence pairs)
- **A1 `eff_potential_bounce`** — effective potential + bounce action / nucleation (T_n, α, β/H) solver (CosmoTransitions-style Python or BubbleProfiler-style C++ in container). `deterministic`.
- **A1' `eff_potential_bounce_alt`** — *independent* re-implementation (different code base/algorithm, distinct `code.repo` + `independence_tags`) for CROSS_CODE.
- **A2 `gw_spectrum`** — stochastic GW background Ω_GW(f) h² from (α, β/H, T_n, v_w) via sound-shell/analytic templates. `deterministic`.
- **A2' `gw_spectrum_alt`** — independent GW template (different fit/model) for cross-code.
- **A3 `gw_spectrum_surrogate`** — **differentiable JAX surrogate** of A2 (emulator with GP/ensemble uncertainty) exposing `grad`; validity domain declared over (α, β/H, T_n, v_w). For S4 cheap scoring.
- **A4 `collider_fastsim`** — collider fast-sim/emulator chain (Delphes-style fast detector sim or an NN emulator) producing cross-sections/observables with uncertainty.
- **A5 `boltzmann_transport_toy`** — lightweight Boltzmann/transport toy solver (e.g. baryon asymmetry or relic-density toy) with analytic uncertainty.
- **A6 `higgs_observables`** — Higgs-sector observables mapper (couplings → signal strengths) with propagated uncertainty; independent pair `A6'` for cross-code.
Each ships: descriptor, validity domain, uncertainty model, calibration test set, conformance evidence, and (where applicable) an independent twin.

### S7.4 Key algorithms
- **Units normalization**: parse each field's declared unit → convert to a canonical base (natural units where physics-appropriate) → dimensional-consistency check across the declared `input_schema`/`output_schema` → carry canonical value + original unit tag. Compound/log fields handled by a small expression evaluator over the Pint registry. Mismatch → hard `UNITS_MISMATCH`.
- **Uncertainty propagation (analytic path)**: for differentiable adapters, output covariance `Σ_out = J Σ_in Jᵀ` using `grad`; for emulators, posterior variance (GP) or ensemble variance; for stochastic, sample-based intervals with declared n_samples. Coverage validated by the calibration harness (empirical coverage vs nominal on a held-out set) → calibration_ref.
- **Validity-domain classification**: box check for simple ranges; convex-hull/polytope membership for correlated ranges; for emulators, a learned in-distribution density threshold (e.g. Mahalanobis distance or a normalizing-flow density) → `extrapolation_flag` when density below threshold.
- **Deterministic seeding**: `seed_i = BLAKE3-KDF(job_seed, dag_node_id, call_index, adapter_id)[:k]`; injected into all RNGs (NumPy, JAX PRNGKey, framework seeds, subprocess env `PYTHONHASHSEED`/binary seed flag). Recorded to provenance.
- **Budget metering**: broker tracks cumulative CPU-seconds/GPU-seconds/wallclock/cost against `budget_token`'s remaining allowance (atomic decrement in Redis); pre-flight reservation + post-call reconciliation; on breach → `BUDGET` error + halt + partial provenance.
- **Cache lookup**: compute `cache_key`; hit → return cached EvalResult with a fresh provenance edge (`derived_from: cache_key`) marking a cache hit; miss → compute, store (if cacheable), emit.
- **Batch execution**: `batch_evaluate` groups by fidelity/backend; vectorizes native/JAX backends via `vmap`; for subprocess backends, parallelizes bounded worker pool; partial failure returns per-element results with per-element error envelopes.
- **Cross-code independence resolution**: registry query `resolve(observable, independence_needed=exclude(code.repo=X, underlying_code_version=Y, independence_tags∩...))` → returns adapters with disjoint independence tags. S7 supplies the tags; the query is answered by C5.

### S7.5 Sequence flows
**F1 — evaluate (S2, differentiable surrogate)**
1. S2 (sandbox) → egress proxy → broker: `evaluate(EvalRequest{inputs(units), fidelity, seed?, budget_token, trace_id})`.
2. Broker authn/authz (mTLS, scopes) → validate C6 version → resolve adapter revision from C5 (pinned).
3. Units engine normalizes/validates inputs (mismatch → `UNITS_MISMATCH`, abort).
4. Validity guard classifies (out-of-domain → set flags, apply policy).
5. Cache lookup (hit → step 9).
6. Seed manager derives seed; budget pre-reserve.
7. Backend worker invokes (JAX surrogate `jit`+forward); uncertainty engine attaches posterior variance.
8. Budget reconcile; cache store.
9. Provenance emitter writes C4 (adapter+underlying versions, seed, input hashes, env digest) → S8; OTel span + cost metric → S11.
10. Return `EvalResult{outputs(units), uncertainty, in_validity_domain, extrapolation_flag, cost, provenance_ref}`.

**F2 — grad (S4 gradient fit)**: as F1 but calls `grad`; returns `Jacobian{d out_i / d in_j}` with units on each entry; `NOT_DIFFERENTIABLE` if adapter is not differentiable.

**F3 — cross-code (S3)**: S3 → registry `resolve(observable O, independence)` → two independent adapter refs → S3 calls `evaluate` on each with identical canonicalized inputs → compares outputs within combined uncertainty. Extrapolated outputs → INCONCLUSIVE.

**F4 — subprocess binary (bounce solver)**: broker → subprocess backend → writes normalized param card to scratch → runs pinned OCI binary under S10 limits (timeout, mem cap, no egress) → parses stdout/HDF5 → uncertainty (numerical-tolerance analytic) → provenance pins binary digest + version. Binary nonzero exit → `UNDERLYING_CODE_ERROR` with stderr captured to provenance.

**F5 — registration**: author → `s7-register.register(descriptor)` → schema validate → run conformance stub → **cost-class ≤ ceiling gate** (else reject) → `publish` to C5 → registry emits change event (NATS) consumed by S5/S11 caches.

### S7.6 Tech choices (consistent with shared stack)
- Python 3.11 for SDK/backends/adapters; **Pint** for units; **JAX** for surrogates/grad/vmap/jit; **PyTorch** for imported emulators; **scikit-learn/GPy/GPflow** for GP emulators.
- **Rust** for the broker's hot trust-boundary path (authn, budget metering, dispatch) and for provenance-write hand-off to S8's Rust ledger writer; Python worker host for adapter execution.
- **gRPC (mTLS)** primary transport; HTTP/JSON fallback; **CBOR** optional compact encoding for large numeric payloads, JSON default.
- **OCI containers** digest-pinned for subprocess binaries; **gVisor/Firecracker** isolation via S10; **Kubernetes** for broker + worker pool scaling with `ResourceQuota`.
- **Redis** for budget counters + hot cache + rate limits (ephemeral only). **Object store (S8)** for large outputs + descriptors. (Registry is S6/C5; provenance graph is S8/C4.)
- **OpenTelemetry** spans/metrics → S11; **NATS JetStream** for registration/health events.
- **cosign** signing for adapter container images.

### S7.7 Failure & degradation handling
- **Units mismatch / out-of-domain**: non-retryable hard errors (`UNITS_MISMATCH`, `OUT_OF_DOMAIN`); OUT_OF_DOMAIN may instead be a flagged success if adapter policy is `flag` (verifier decides admissibility).
- **Underlying binary error**: `UNDERLYING_CODE_ERROR`, stderr → provenance, non-fatal to broker; S2 auto-repair can inspect.
- **Timeout**: `TIMEOUT`; partial provenance; retryable if declared idempotent + `seeded/deterministic`.
- **Budget breach**: `BUDGET`; immediate halt; partial-result capture with provenance.
- **Not differentiable**: `NOT_DIFFERENTIABLE` on `grad` for non-diff adapters.
- **Provenance write failure**: `PROVENANCE_UNAVAILABLE` — result NOT returned as trusted (fail-closed); caller must not promote it.
- **Backend crash / OOM**: bulkheaded — only that adapter's worker pool affected; broker circuit-breaks the adapter and emits a health event; other adapters unaffected.
- **Emulator extrapolation**: never silently trusted — `extrapolation_flag:true`, verifier treats as INCONCLUSIVE unless profile allows.
- **Determinism violation**: a `deterministic` adapter that yields differing output on identical input trips a conformance/health alarm and is quarantined from `resolve` results.

### S7.8 Interactions with contracts
- **Produces**: C6 (the interface itself), C6 `AdapterDescriptor` published into C5, and one C4 provenance record per call.
- **Consumes**: C4 (provenance write API, S8), C5 (registry publish/resolve, S6/S12), S10 (sandbox/resource-limit/egress substrate), budget_token semantics from C2 (S5), OTel from S11.
- Never imports S2/S3/S4 internal types; coupling is contract-only.

### S7.9 Data models (canonical JSON Schema draft 2020-12; pydantic/TS/Rust generated)

**AdapterDescriptor (registered via C5)**
```jsonc
{
  "adapter_id": "uuid",
  "adapter_contract_version": "semver",      // C6 version
  "adapter_version": "semver",               // this adapter build
  "underlying_code_version": "string",       // wrapped solver/binary/emulator version
  "underlying_code": { "repo": "string", "commit": "string", "algorithm_family": "string" },  // for independence
  "name": "string", "owner": "string", "maintainer_contact": "string",
  "exposes": "physics_code | emulator | surrogate",
  "backend_kind": "native_python|jax|pytorch|subprocess_binary|emulator_gp|emulator_nn|surrogate_diff",
  "container_digest": "string|null",         // OCI digest if subprocess/binary
  "observable": { "taxonomy_id": "string", "symbol": "string", "description": "string" },
  "differentiable": "bool",
  "input_schema": { "fields": [ { "name","dtype":"f64|i64|f64[]|...","unit",
                                  "log_space":"bool","required":"bool","default":"any|null" } ] },
  "output_schema": { "fields": [ { "name","dtype","unit","log_space" } ] },
  "validity_domain": {
    "kind": "box|polytope|density",
    "box": { "field": { "min":"num","max":"num","unit":"string" } },
    "polytope_ref": "artifact_ref|null", "density_model_ref": "artifact_ref|null",
    "policy": "flag|refuse|clamp_with_flag", "applicability_notes": "string" },
  "uncertainty_model": {
    "kind": "analytic|emulator_gp|ensemble|conformal|declared",
    "representation": "interval|covariance|samples",
    "calibration_ref": "artifact_ref(C4)|null", "n_samples": "int|null" },
  "determinism": "deterministic|seeded|stochastic",
  "independence_tags": [ "string" ],          // e.g. code family, method, author-group
  "resource_envelope": { "cpu":"num","gpu":"num","mem_mb":"num",
                         "typical_wallclock_s":"num","max_wallclock_s":"num" },
  "cost_class": "trivial|light|medium|heavy",  // heavy > ceiling => REJECTED at registration
  "cost_estimate_usd_per_call": "num",
  "batch_supported": "bool", "fidelity_levels": [ "string" ],
  "provenance_ref": "ref(C4)", "signature": "string", "signer_key_id": "string",
  "status": "active|deprecated|revoked", "trust_class": "internal|federated"
}
```

**EvalRequest**
```jsonc
{
  "adapter_ref": "descriptor_revision_ref",
  "inputs": { "<field>": { "value":"num|array", "unit":"string" } },  // units MANDATORY
  "fidelity": "string|null",
  "seed": "int|null",                 // if null, broker derives deterministic seed
  "return_provenance": "bool",        // default true
  "budget_token": "opaque",           // minted, metered (C2)
  "trace_id": "otel-trace-id",
  "job_id": "uuid", "dag_node_id": "string", "call_index": "int",
  "policy_overrides": { "domain_policy":"flag|refuse|clamp_with_flag|null" }
}
```

**EvalResult**
```jsonc
{
  "outputs": { "<field>": { "value":"num|array", "unit":"string" } },  // units MANDATORY
  "uncertainty": {                    // MANDATORY, non-null
    "representation": "interval|covariance|samples",
    "interval": { "<field>": { "lo":"num","hi":"num","unit":"string","level":"num" } },
    "covariance": { "matrix":"num[][]","field_order":["string"],"units":["string"] },
    "samples": { "n":"int","array_ref":"artifact_ref|inline","units":["string"] },
    "source": "analytic|emulator_gp|ensemble|conformal" },
  "in_validity_domain": "bool", "extrapolation_flag": "bool",
  "domain_diagnostics": { "distance":"num|null","violated_fields":["string"] },
  "fidelity_used": "string", "seed_used": "int", "cache_hit": "bool",
  "cost": { "cpu_s":"num","gpu_s":"num","wallclock_s":"num","usd":"num","budget_remaining":"num" },
  "provenance_ref": "ref(C4)", "adapter_version": "semver", "underlying_code_version": "string"
}
```

**Jacobian (grad)**
```jsonc
{
  "matrix": "num[][]",                 // d(output_i)/d(input_j)
  "output_order": ["string"], "input_order": ["string"],
  "output_units": ["string"], "input_units": ["string"],
  "entry_units": "string[][]",         // derived unit per entry (out_unit / in_unit)
  "evaluated_at_inputs": { "<field>": {"value","unit"} },
  "seed_used": "int", "cost": { }, "provenance_ref": "ref(C4)"
}
```

**BatchResult**
```jsonc
{ "results": [ "EvalResult | ErrorEnvelope" ],   // per-element, order-preserving
  "batch_cost": { }, "n_ok":"int","n_err":"int" }
```

**CalibrationEvidence (artifact, feeds S3 CALIBRATION)**
```jsonc
{ "adapter_id","adapter_version","representation",
  "test_set_ref":"artifact_ref","nominal_level":"num",
  "empirical_coverage":"num","coverage_by_field":{"<f>":"num"},
  "n_points":"int","method":"coverage|pit|reliability",
  "passed":"bool","generated_at","provenance_ref" }
```

**Error Envelope (C6-aligned)**
```jsonc
{ "code":"string",
  "category":"OUT_OF_DOMAIN|UNITS_MISMATCH|NOT_DIFFERENTIABLE|BUDGET|
              UNDERLYING_CODE_ERROR|TIMEOUT|PROVENANCE_UNAVAILABLE|
              VERSION_UNSUPPORTED|BACKEND_UNAVAILABLE",
  "message":"string","retry_after":"int|null",
  "provenance_ref":"ref(C4)|null","stderr_ref":"artifact_ref|null" }
```

**Registration events (NATS)**
```jsonc
{ "event":"adapter.registered|adapter.deprecated|adapter.revoked|adapter.health",
  "adapter_id","adapter_version","revision_ref","cost_class",
  "status","health":{ "circuit":"closed|open|half_open","error_rate":"num" }, "ts" }
```

**Unit Registry (frozen).** Versioned Pint registry file (`argus_units@<ver>`) content-addressed in S8; every EvalResult pins the registry version used. Extensions: `GeV,TeV,MeV`, natural-unit conversions, `Hz,mHz`, cross-sections `pb,fb`, dimensionless `Omega_h2`, `dimensionless`, log-space markers.

### S7.10 Public APIs

**C6 Adapter Interface (gRPC/mTLS + HTTP/JSON), served by the Adapter Broker**
```
rpc Describe(DescribeRequest{adapter_ref}) returns (AdapterDescriptor)
rpc Evaluate(EvalRequest) returns (EvalResult)          // errors: OUT_OF_DOMAIN, UNITS_MISMATCH, BUDGET, UNDERLYING_CODE_ERROR, TIMEOUT, PROVENANCE_UNAVAILABLE, VERSION_UNSUPPORTED, BACKEND_UNAVAILABLE
rpc Grad(EvalRequest) returns (Jacobian)                // errors: + NOT_DIFFERENTIABLE
rpc BatchEvaluate(BatchRequest{items:[EvalRequest]}) returns (BatchResult)
rpc HealthCheck(adapter_ref) returns (AdapterHealth{circuit,error_rate,p50,p99})
```

**Adapter SDK (Python) — authoring surface**
```python
class Adapter:
    descriptor: AdapterDescriptor
    def describe(self) -> AdapterDescriptor: ...
    def evaluate(self, req: EvalRequest, ctx: EvalContext) -> EvalResult: ...
    def grad(self, req: EvalRequest, ctx: EvalContext) -> Jacobian: ...        # iff differentiable
    def batch_evaluate(self, reqs: list[EvalRequest], ctx) -> BatchResult: ...

# decorators / helpers
@units_in(schema: dict) @units_out(schema: dict)
@validity_domain(kind="box"|"polytope"|"density", spec=..., policy=...)
@uncertainty(kind="analytic"|"emulator_gp"|"ensemble"|"conformal", representation=...)
@differentiable(backend="jax")
class EffPotentialBounceAdapter(Adapter): ...

# EvalContext gives: ctx.seed, ctx.budget, ctx.trace, ctx.prov_writer, ctx.units_registry
uncertainty_from_ensemble(preds) -> Uncertainty
propagate_linear(jacobian, input_cov) -> Covariance      # Σ = J Σ Jᵀ
declare_domain_box({field:(min,max,unit)}) -> ValidityDomain
```

**Registration Service (HTTP/gRPC, internal)**
```
POST /adapters/register        body: AdapterDescriptor      -> {revision_ref} | 4xx{ErrorEnvelope: CONFORMANCE_FAILED|COST_CLASS_EXCEEDED|SCHEMA_INVALID}
POST /adapters/{id}/deprecate  body:{revision}              -> 200
POST /adapters/{id}/revoke     body:{reason}                -> 200 (propagates: halts in-flight refs)
GET  /adapters/{id}/conformance -> ConformanceReport
```
(Publishes to registry via C5 `publish(descriptor)`; `resolve/deprecate/revoke/subscribe` are C5-owned and consumed by S7.)

**CLI (`argus-adapter`)**
```
argus-adapter new <name> --backend jax|subprocess|emulator_gp     # scaffold SDK adapter
argus-adapter validate <path>            # local schema + conformance stub check
argus-adapter describe <adapter_ref>     # print descriptor
argus-adapter eval <adapter_ref> --inputs inputs.json [--seed N] [--fidelity F]
argus-adapter grad <adapter_ref> --inputs inputs.json
argus-adapter register <path> [--dry-run]   # runs cost-ceiling + conformance gate
argus-adapter calibrate <adapter_ref> --test-set ref   # produce CalibrationEvidence
argus-adapter independence <observable>     # list registered independent implementations
argus-adapter cache-stats <adapter_ref>
```

**Events (NATS JetStream, subject `argus.s7.*`)**
```
argus.s7.adapter.registered   {adapter_id,revision_ref,cost_class,ts}
argus.s7.adapter.deprecated   {adapter_id,revision,ts}
argus.s7.adapter.revoked      {adapter_id,reason,ts}
argus.s7.adapter.health       {adapter_id,circuit,error_rate,p50,p99,ts}
argus.s7.call.metered         {adapter_id,job_id,cost,cache_hit,ts}   // observability (S11)
```

**Consumed contracts (exact)**
- **C4** `ArtifactRecord` write (S8 ledger writer) — one per call.
- **C5** `publish(descriptor)`, `resolve(query{observable,required_verifier,independence_needed})`, `deprecate`, `revoke`, `subscribe`.
- **C2** `budget_token` semantics (minted by S5) — metered/halted by S7.
- **S10** sandbox/resource-limit/egress-proxy substrate for subprocess backends.
- **S11** OTel spans + metrics.

**Produced contracts (exact)**
- **C6** interface (owner) — `Describe/Evaluate/Grad/BatchEvaluate`.
- **C6 AdapterDescriptor** published into the C5 registry.
- **C4 provenance record** per `evaluate`/`grad` call.
- **CalibrationEvidence** artifact (C4) consumed by S3 CALIBRATION check.

---

## S8 — Data, Artifact & Provenance

**Owns contract:** **C4**. **Consumes:** C3 signed reports (S3), S10 KMS/trust store & sandbox, S6 frozen index/external snapshots, S11 re-derivation callback, base infra (Postgres 16, S3/MinIO Object-Lock, NATS JetStream).

### S8.1 Architecture overview
S8 is a set of decoupled services fronted by a stable API gateway, all inside the **control/provenance trust zone**. Trust-boundary and hot-path components are **Rust**; orchestration-adjacent helpers and the SDK client are **Python**.

```
                +-----------------------------------------------------+
                |                 S8 API Gateway (mTLS)                |
                |   gRPC + HTTP/JSON, least-privilege scope check      |
                +----+-------------------+------------------+---------+
                     |                   |                  |
          +----------v-----+   +---------v--------+  +------v-----------+
          | Hashing &      |   | Provenance Ledger|  | Artifact Store   |
          | Canonicalizer  |   | Writer (RUST)    |  | Facade           |
          | (RUST lib)     |   | append-only,     |  | content-addressed|
          | BLAKE3         |   | Merkle-anchored  |  | S3/MinIO         |
          +----------------+   +---------+--------+  +------+-----------+
                                         |                  |
                              +----------v-------+   +------v-----------+
                              | PostgreSQL 16    |   | Object Store     |
                              | records+lineage  |   | (write-once      |
                              | (recursive CTE)  |   |  buckets +        |
                              | append-only tabs |   |  Object-Lock)    |
                              +------------------+   +------------------+
          +----------v--------------------+   +-----------------------+
          | Tiering-Coupling Enforcer     |   | Dataset Registry svc  |
          | (verifies C3 sig via S10 KMS  |   | versions/splits/blind |
          |  trust store)                 |   +-----------------------+
          +-------------------------------+
          +----------v--------+   +--------------------+  +------------------+
          | Retention/GC +    |   | Schema Registry &  |  | Event Emitter    |
          | Holds engine      |   | Binding Generator  |  | (NATS JetStream) |
          +-------------------+   +--------------------+  +------------------+
```

### S8.2 Components

**2.1 Hashing & Canonicalizer (Rust lib + service).** BLAKE3 over bytes for blobs; for structured records, a **canonical serialization** (JCS-style deterministic JSON: sorted keys, normalized numbers/unicode, no insignificant whitespace) versioned as `canon_version`. Hash inputs to the record hash: canonical bytes of the record minus the `content_hash`/`signature` fields. Streaming hashing for large objects (chunked, multipart-upload compatible); returns `content_hash` before commit so the store key is known. Deterministic across Python/TS/Rust because canonicalization is a pinned spec, not per-language default serialization.

**2.2 Artifact Store Facade (Rust).** Wraps S3-compatible store. Key = `blake3/<hex>` (immutable). Two bucket classes:
- **write-once (Object-Lock/compliance mode)** for: signed Validation Reports, frozen contamination index, any artifact with `claim_tier > ran-toy`.
- **mutable-until-referenced scratch** for intermediate blobs (still content-addressed; promoted to write-once on first lineage reference or tier assignment).
Content-addressed dedup: identical bytes → single object; multiple ArtifactRecords may reference it (records are the mutable-identity layer, blobs are immutable). **Verify-on-read**: recompute (or verify via stored integrity tag) hash on serve; mismatch → refuse + emit `ARTIFACT_TAMPER` Sev-1 event + quarantine record.

**2.3 Provenance Ledger Writer (Rust, single-writer discipline).** The ONLY component with write credentials to the append-only record + lineage tables. Agents/other subsystems call it through the gateway with scoped tokens; they never hold DB write creds. Append-only: records and lineage edges are INSERT-only. A "change" = new record with new `content_hash` + `derived_from` edge to prior. No UPDATE/DELETE on record/edge tables (enforced by DB grants + triggers). **Merkle-chained audit log**: each committed record appends a leaf `H(prev_root || record_hash || seq)`; periodic signed checkpoints (signer = S8 ledger key from S10 KMS) give tamper-evidence and cheap audit export. Transactional commit couples: (a) validate schema, (b) validate lineage completeness, (c) validate tier-coupling, (d) write blob reference, (e) insert record + edges + Merkle leaf — all-or-nothing (fail-closed).

**2.4 Lineage Graph Model & Query engine.** Stored in PostgreSQL 16: `artifact_record` (nodes), `lineage_edge` (typed edges: `input`, `derived_from`, `code`, `adapter_used`, `validation_report`). External sources are nodes too (`external_source` kind). Queries via **recursive CTEs** with edge-type filters and cycle guards (DAG-enforced at write: reject an edge that would create a cycle). Materialized closure table (`lineage_closure`, incrementally maintained on insert) for O(1)-ish descendant/ancestor and impact-set at 10^5+ nodes; recursive CTE is the fallback/verification path. Covering indexes on `(kind)`, `(producer.job_id)`, `(contamination_index_version)`, `(claim_tier)`, GIN on lineage JSON where needed.

**2.5 Tiering-Coupling Enforcer.** On any record with `claim_tier > ran-toy`: require `validation_report_ref`; fetch the referenced C3 report; verify its signature against the S3 verifier key in the S10-backed trust store; assert report `claim_tier == record claim_tier` and report `aggregate.passed == true`; assert `contamination_index_version` consistency. Any failure → `ILLEGAL_TIER`, no commit. Independence for `novel-needs-human`: additionally assert the report's leakage checks all PASS and a cross-code check is present (mirrors C3 monotonicity; S8 is a second, independent gate on the data-plane side).

**2.6 Dataset Registry service.** Dataset = a versioned family of ArtifactRecords with `kind=dataset`. Tracks `dataset_id`, `version`, `splits[]` each with `role: train|val|test|blind|null_control|injection`, `content_hash`, `row_count`, `schema_ref`, `contamination_index_version`. **Blind segregation invariant**: splits with `role in {blind, test-held-out, null_control, injection}` are marked `access_scope=verifier-only`; their **labels** are stored only in the verifier zone (S8 stores a label-less feature blob + a sealed label reference resolvable only with a verifier-scope token). The gateway denies label materialization to non-verifier scopes. This is the data-plane half of "blind test data."

**2.7 External-Source Ingestion records.** `external_source_ref = {source: arxiv|github|hepdata|other, id, url, snapshot_hash, ingested_at, license}` stored as `external_source` nodes; any dataset built from them carries `inputs[].external_source_ref` edges and `contamination_index_version`.

**2.8 Retention / GC + Holds engine.** Mark-and-sweep GC over unreferenced scratch blobs only; write-once objects and anything reachable from a promoted/held artifact are never collected. `retention_policy` per record; `holds` (legal/audit) block deletion regardless of policy. GC is dry-run-first, quorum-gated, fully audited; never deletes ledger rows or Merkle leaves.

**2.9 Schema Registry & Binding Generator.** Canonical C4 JSON Schema (draft 2020-12) is the source of truth; CI generates pydantic v2, TypeScript types, Rust serde. Semver; minor = additive (consumers ignore unknown fields), major = breaking + dual-serve window. Publishes schema artifacts as immutable C4 records (self-describing).

**2.10 Event Emitter (NATS JetStream).** Emits `artifact.created`, `artifact.promoted`, `artifact.tamper_detected`, `lineage.edge_added`, `hold.placed/released`, `gc.swept`, `ledger.checkpoint` for S5/S11/observability. At-least-once; consumers idempotent via `content_hash`.

### S8.3 Key algorithms

**3.1 Canonical content hashing.** 1. If blob: BLAKE3(bytes) streaming. 2. If record: strip volatile fields (`content_hash`, `signature`, `created_at` if excluded by canon spec), canonicalize (sorted keys, normalized numbers/strings), BLAKE3(canonical_bytes). `canon_version` pinned in record.

**3.2 Fail-closed commit (transaction).** `begin → schema_validate → lineage_complete_check → tier_couple_check → blob_present_and_hash_match → cycle_check(new edges) → insert record+edges → append Merkle leaf → commit`. Any step raises typed C4 error and rolls back.

**3.3 Impact-set / contamination-trace query.** Given seed node(s) (e.g. a retracted external source or contaminated dataset), compute transitive descendants over `input`/`derived_from` edges using the maintained closure table; return the set with each member's `claim_tier` and `validation_report_ref` so S9 can invalidate/re-review. Cross-checked against recursive CTE in audit mode.

**3.4 Re-derivation comparison (for S11 canary).** Given `artifact_id`, S8 returns the full reproducibility manifest. S11 re-runs (in S10) producing `content_hash'`. S8 compares: exact match → PASS; else apply the artifact's declared nondeterminism tolerance (statistical comparator registered per `kind`/`media_type`) → PASS/FAIL. Result recorded as a `reproducibility_check` provenance annotation (never mutates the original record).

**3.5 Merkle audit checkpointing.** Rolling hash chain over committed record hashes; every N commits or T seconds, sign a checkpoint `{seq, root, ts}` with the S8 ledger key. Audit export = checkpoint + inclusion proofs for requested records.

### S8.4 Sequence flows
- **4.1 Subagent writes a trained model (happy path).** S1 → gateway `create_artifact(record draft + blob stream)` → Hashing (content_hash) → Store Facade (put write-once) → Ledger Writer (fail-closed commit incl. lineage + tier check) → Merkle leaf → Event `artifact.created` → returns `ArtifactRef{artifact_id, content_hash}`.
- **4.2 Illegal tier attempt.** S2 → `create_artifact(claim_tier=novel-needs-human, no report_ref)` → Tier Enforcer: missing report → `{category: ILLEGAL_TIER}` → no commit → typed error to caller + audit event.
- **4.3 Verifier writes signed report.** S3 → `create_artifact(kind=report, signature, signer_key_id)` to write-once bucket → S8 verifies signer_key_id ∈ trust store and signature over canonical form → commit immutable → Event `artifact.created(kind=report)`. (S8 does NOT sign; it stores + verifies.)
- **4.4 Impact-set on retraction.** S9/S6 → `query_impact_set(seed=external_source X)` → closure lookup → return descendants + tiers + report refs → S9 initiates re-review; S8 emits `artifact.flagged` on each.
- **4.5 Consumption with tamper.** Any consumer → `get_artifact(content_hash)` → Store Facade verify-on-read → mismatch → refuse (`HASH_MISMATCH`) + `ARTIFACT_TAMPER` Sev-1 + quarantine record + halt reachable jobs (via event to S5).

### S8.5 Tech choices (consistent with shared stack)
- **Rust** for hashing, store facade, ledger writer, egress-free trust-boundary logic. **Python (pydantic v2)** for the S8 SDK client and orchestration helpers. **PostgreSQL 16** system of record (recursive CTE + closure table; dedicated graph DB deferred). **MinIO/S3** with **Object-Lock (compliance mode)** for write-once. **BLAKE3** hashing. **NATS JetStream** events. **JSON Schema draft 2020-12** canonical IDL; CBOR optional compact wire. **Sigstore/cosign-style** verification for report signatures using keys in **Vault/KMS** trust store (S10-provided). **OpenTelemetry** tracing on every API call.

### S8.6 Failure & degradation handling
- **Object store unavailable**: reads degrade to cached metadata + `503 RETRYABLE`; writes fail-closed (no partial commit). Ledger never commits a record whose blob isn't durably stored.
- **DB unavailable**: gateway returns `RETRYABLE`; no writes accepted; object puts allowed to a staging area but records not committed until DB back (idempotent replay by content_hash).
- **Hash mismatch on read**: fail-closed refuse + Sev-1 + quarantine + event.
- **Tamper on ledger (Merkle checkpoint mismatch)**: freeze writes, page SRE, produce inclusion-proof diff, treat as Sev-1.
- **Signature verify failure on report**: reject at write (never store an unverifiable report as trusted) and at read (refuse to serve as tier-bearing).
- **Partial upload / crash mid-commit**: transaction rollback; orphan blobs collected by GC (unreferenced); commit is idempotent keyed by content_hash so retries are safe.
- **Schema version skew**: minor-compatible accepted; incompatible major rejected with `VERSION_UNSUPPORTED` during non-migration windows.
- **Closure table drift**: periodic reconciliation job recomputes closure via recursive CTE and diffs; discrepancy → alarm + rebuild.
- **Hold vs GC race**: holds checked inside the GC transaction; any hold aborts deletion of the whole reachable set.

### S8.7 Data models

**C4 ArtifactRecord (owned by S8; canonical JSON Schema draft 2020-12)**
```jsonc
ArtifactRecord {
  record_version: string,          // semver of C4
  canon_version: string,           // pinned canonicalization spec version
  artifact_id: uuid,               // stable identity across re-reads
  content_hash: string,            // BLAKE3 hex; also storage key
  kind: "dataset"|"model"|"report"|"figure"|"config"|"log"|"container"|"notebook"|"external_source"|"schema",
  media_type: string, size_bytes: int,
  storage_uri: string,             // blake3/<hex> resolved against a bucket class
  producer: {
    job_id: uuid, actor_id: string,              // subagent_id | verifier_id | adapter_id | ingest_id
    actor_kind: "subagent"|"verifier"|"adapter"|"ingest"|"control_tower"|"evolver", step_id: string },
  lineage: {
    inputs: [ { role: string, artifact_ref?: {artifact_id, content_hash},
                external_source_ref?: ExternalSourceRef } ],
    derived_from: [ {artifact_id, content_hash} ],
    code: { repo: string, commit: string, dirty: bool },
    environment_digest: string,    // container image digest (pinned)
    adapters_used: [ { adapter_ref: string, adapter_version: string, underlying_code_version: string } ],
    seeds: { global: int, per_library: { [lib: string]: int } },
    config_hash: string, params_hash: string },
  claim_tier?: "ran-toy"|"recapitulated-known"|"novel-needs-human",
  validation_report_ref?: {artifact_id, content_hash},   // C3 report as an artifact
  uncertainty_tag?: { representation: "interval"|"covariance"|"samples"|"declared", value: object },
  contamination_index_version?: string,
  nondeterminism_tolerance?: { comparator_id: string, params: object },
  created_at: string (RFC3339),
  retention_policy: { class: "ephemeral"|"standard"|"write_once", ttl_days?: int },
  access_scope: "internal"|"verifier-only"|"external-approved"
  // signature/signer_key_id present ONLY for signed artifacts (e.g. reports); NOT hashed into content_hash
}
```

**ExternalSourceRef**
```jsonc
ExternalSourceRef {
  source: "arxiv"|"github"|"hepdata"|"other", id: string, url: string,
  snapshot_hash: string,    // BLAKE3 of the frozen snapshot bytes
  ingested_at: string, license: string
}
```

**DatasetRecord (registry projection over ArtifactRecords)**
```jsonc
DatasetRecord {
  dataset_id: uuid, version: string,
  splits: [ { split_id, role: "train"|"val"|"test"|"blind"|"null_control"|"injection",
              content_hash, row_count, schema_ref, access_scope,
              label_seal_ref?: string } ],  // label_seal_ref resolvable only with verifier scope
  contamination_index_version: string,
  provenance_ref: {artifact_id, content_hash}, created_at
}
```

**Lineage storage (PostgreSQL, append-only)**
```
artifact_record(artifact_id PK, content_hash UNIQUE, kind, ... , merkle_seq, created_at)   -- INSERT only
lineage_edge(edge_id PK, src_artifact_id, dst_artifact_id, edge_type
             ["input"|"derived_from"|"code"|"adapter_used"|"validation_report"],
             role?, created_at)                                                            -- INSERT only, DAG-checked
external_source(source_id PK, source, ext_id, url, snapshot_hash, license, ingested_at)     -- INSERT only
lineage_closure(ancestor_id, descendant_id, depth)                                          -- maintained on insert
holds(hold_id PK, artifact_id, reason, placed_by, placed_at, released_at?)
merkle_checkpoint(seq PK, root, ts, signature, signer_key_id)
reproducibility_check(check_id PK, artifact_id, rerun_content_hash, verdict, tolerance_id, checked_at)
```
DB grants: only the Rust ledger-writer role may INSERT into record/edge/checkpoint tables; no role may UPDATE/DELETE (enforced by REVOKE + rules/triggers). Read role is separate and least-privilege.

**Trust-store / signature model.** Report signatures verified against S3 verifier keys registered in the S10-backed trust store; S8 caches key material read-only. `signer_key_id` must resolve to an active, non-revoked verifier key.

**Bucket classes.** `write-once` (Object-Lock compliance, retention >= governance minimum) for reports, frozen index, promoted artifacts, ledger checkpoints; `scratch` (lifecycle-managed, GC-eligible) for unreferenced intermediates.

### S8.8 Public APIs (gRPC + HTTP/JSON, mTLS, scope-checked). Also CLI + events.

**Artifact & Provenance (C4 owner)**
- `CreateArtifact(record_draft: ArtifactRecord, blob: stream<bytes> | blob_ref) -> ArtifactRef{artifact_id, content_hash}` — fail-closed commit (schema+lineage+tier+hash+cycle checks). Idempotent by content_hash.
- `GetArtifact(ref: {artifact_id | content_hash}, materialize?: bool) -> {record: ArtifactRecord, bytes?: stream}` — verify-on-read; refuses on hash mismatch.
- `GetArtifactRecord(ref) -> ArtifactRecord` — metadata only.
- `QueryArtifacts(filter: {kind?, actor_id?, job_id?, claim_tier?, contamination_index_version?, created_range?}, page) -> [ArtifactRecord]`.
- `HashBlob(blob: stream<bytes>) -> {content_hash, size_bytes, canon_version}` — pre-commit hashing.
- `VerifySignature(report_ref) -> {valid: bool, signer_key_id, tier}` — for consumption-point checks.

**Lineage / audit**
- `GetLineage(ref, direction: ANCESTORS|DESCENDANTS|BOTH, edge_types?[], max_depth?) -> LineageGraph{nodes[], edges[]}`.
- `GetReproducibilityManifest(ref) -> Manifest{lineage, environment_digest, seeds, code, adapters, config_hash, params_hash, nondeterminism_tolerance}`.
- `QueryImpactSet(seed_refs[], edge_types?[]) -> [{artifact_ref, claim_tier, validation_report_ref}]` — contamination-trace/retraction.
- `AssertLineageComplete(ref) -> {complete: bool, missing_fields[]}` — used by promotion gates.
- `RecordReproducibilityCheck(ref, rerun_content_hash, verdict, tolerance_id) -> check_id` — S11 canary callback (annotation, never mutates original).
- `ExportAuditSlice(range | refs[]) -> {records[], merkle_checkpoints[], inclusion_proofs[]}`.

**Dataset registry**
- `RegisterDataset(DatasetRecord) -> {dataset_id, version}` — enforces blind-split access_scope.
- `GetDataset(dataset_id, version?) -> DatasetRecord`.
- `ResolveSplit(dataset_id, version, split_id, scope_token) -> blob_ref` — denies label materialization for verifier-only splits unless verifier scope.
- `ListDatasetVersions(dataset_id) -> [version]`.

**External-source ingestion**
- `RegisterExternalSource(ExternalSourceRef) -> source_id` — immutable.
- `GetExternalSource(source_id) -> ExternalSourceRef`.

**Retention / holds / GC**
- `PlaceHold(artifact_ref | family, reason) -> hold_id`; `ReleaseHold(hold_id, reason)`.
- `RunGC(dry_run: bool) -> {candidates[], swept[], blocked_by_hold[]}` — quorum-gated when not dry-run.
- `SetRetentionPolicy(ref, policy)` — only tightens for write-once; cannot weaken immutability.

**Schema registry**
- `PublishSchema(schema_bytes, semver) -> schema_artifact_ref`; `GetSchema(name, version) -> bytes`; `GenerateBindings(version, targets[python,ts,rust]) -> artifact_refs[]`.

**Events (NATS JetStream, at-least-once, idempotent by content_hash).** `artifact.created`, `artifact.promoted`, `artifact.flagged`, `artifact.tamper_detected`, `lineage.edge_added`, `hold.placed`, `hold.released`, `gc.swept`, `ledger.checkpoint`, `dataset.registered`.

**CLI (`argusctl s8 ...`).** `argusctl s8 put --record r.json --blob model.bin` ; `argusctl s8 get <hash> [--materialize]` ; `argusctl s8 lineage <ref> --direction descendants` ; `argusctl s8 impact-set --seed <ref>` ; `argusctl s8 verify-sig <report_ref>` ; `argusctl s8 hold place|release` ; `argusctl s8 gc --dry-run` ; `argusctl s8 audit-export --range ...` ; `argusctl s8 schema gen --target python`.

**Typed error envelope (C4-aligned).** `{code, category: HASH_MISMATCH|INCOMPLETE_LINEAGE|ILLEGAL_TIER|IMMUTABLE_VIOLATION|SCHEMA_INVALID|VERSION_UNSUPPORTED|SIGNATURE_INVALID|SCOPE_DENIED|CYCLE_DETECTED|NOT_FOUND|RETRYABLE|HELD, message, provenance_ref?}` — HASH_MISMATCH/INCOMPLETE_LINEAGE/ILLEGAL_TIER/IMMUTABLE_VIOLATION are non-retryable and fail-closed.

---

## S9 — Human-in-the-loop Review & Governance

**Owns contract:** none. **Consumes:** C3 (S3), C4 (S8), C2 (S5), C5 (S6/S12), S6 frozen index, S11 calibration/telemetry, S10 secrets/HSM/mTLS.

### S9.1 Architecture overview
S9 sits entirely in the **control/provenance & human-governance zones** — never in the agent sandbox. It is a set of stateless services fronting a PostgreSQL system-of-record and a hash-chained append-only governance ledger, plus a TypeScript/React+Next.js review UI. It integrates with the durable Control Tower workflow (Temporal, S5) via *human-review wait states*: S5 signals a wait, S9 creates a review task, and S5 blocks until S9 emits a decision signal.

```
                 ┌─────────────────────────────────────────────────────────┐
                 │              Human Governance Zone (S9)                    │
   S5 (C2 wait)  │  ┌───────────────┐   ┌───────────────┐  ┌──────────────┐ │
  ───────────────┼─▶│ Intake &      │──▶│ Review Queue  │─▶│ Review UI    │◀┼── Reviewers
   (Temporal     │  │ Signature/    │   │ & Prioritizer │  │ (Next.js)    │ │   (mTLS+SSO)
    signal)      │  │ Guardrail     │   └───────┬───────┘  └──────┬───────┘ │
                 │  │ Pre-screen    │           │                 │         │
                 │  └──────┬────────┘           ▼                 ▼         │
                 │         │            ┌────────────────┐  ┌──────────────┐│
                 │         │            │ Decision &     │  │ Governance   ││
                 │         │            │ Sign-off Engine│─▶│ Policy Engine ││
   S3 (C3) ──────┼─────────┘            │ (state machine)│  │ (guardrails, ││
   S8 (C4) ──────┼──read only──────────▶│                │  │ quorum, COI, ││
   S6 (C5/index) │                      └───────┬────────┘  │ rate-limit)  ││
                 │                              │           └──────┬───────┘│
                 │   ┌───────────────┐   ┌──────▼────────┐  ┌──────▼───────┐│
                 │   │ Reviewer/Role/│   │ Emission      │  │ Governance   ││
                 │   │ COI Registry  │   │ Authorization │─▶│ Ledger       ││
                 │   │               │   │ Minter (HSM)  │  │ (hash-chain) ││
                 │   └───────────────┘   └──────┬────────┘  └──────────────┘│
                 └─────────────────────────────┼──────────────────────────┘
                                               │ EmissionAuthorization token+event (NATS)
                                               ▼
                              External-emission actor (out-of-band human action);
                                     S5 decision signal; S11 KPIs
```

### S9.2 Components
1. **Intake & Pre-screen Service (Rust for the signature/hash-verify hot path + provenance write; Python for orchestration).** Receives a `CreateReviewTask` (from S5 via C2 wait-state hook, or directly from S3 emitting a `novel` candidate event on NATS). Verifies the C3 Validation Report signature against the trust store (cosign/sigstore-style verification of `signer_key_id`), verifies referenced C4 artifact `content_hash`es match bytes (fail-closed on mismatch → QUARANTINED, never queued). Runs the **guardrail pre-screen** (cheap static checks: is this an out-of-scope claim class? is the claim tier legal for the requested emission?). Assigns priority and required review policy (single vs dual vs quorum) based on claim tier and emission class.
2. **Review Queue & Prioritizer (Python + PostgreSQL + Redis for ephemeral locks).** Durable queue of `ReviewTask` rows; priority = f(claim_tier, deadline, aging, emission_class, budget_pressure). Uses a deterministic priority score for reproducible ordering. **Rate limiter / admission controller**: token-bucket over queue-admission and over external-emission budgets; emits the **back-pressure gauge** consumed by S5. Task locking/assignment with lease TTL (Redis) to prevent double-review; auto-release on reviewer timeout.
3. **Decision & Sign-off Engine (Python).** Owns the `ReviewTask` state machine (below) and the sign-off collection logic (single/dual/quorum), enforcing distinct principals and eligibility. On terminal decision, writes an immutable `ReviewDecision` (as a C4 artifact via S8) and appends a signed entry to the governance ledger.
4. **Governance Policy Engine (Python; policies as versioned, declarative rules — OPA/Rego-style or a pinned in-house rule DSL).** Guardrail rules (non-goals), quorum/dual-sign-off policies, COI rules, rate-limit budgets, novelty-review requirements (leakage PASS + cross-code agreement mandatory before `novel` acceptance). Policies are versioned artifacts; every evaluation records `policy_version` for reproducibility.
5. **Emission Authorization Minter (Rust; HSM/Vault-backed signing key).** After all required sign-offs + guardrail PASS + budget available, mints a short-lived, scope-bound `EmissionAuthorization` (signed, single-use, tied to specific artifact `content_hash`es and emission_class). This token is the *structural* gate: no external-emission actor proceeds without verifying it.
6. **Reviewer / Role / COI Registry (Python + PostgreSQL).** Reviewer identities, roles (domain/ml/governance/federation-admissions/auditor/admin), eligible subtopics (from C5 taxonomy), COI declarations, delegation, recusal.
7. **Governance Ledger (Rust writer; PostgreSQL append-only table + write-once object mirror).** Hash-chained (`entry_hash = BLAKE3(prev_hash || canonical(entry))`), each entry signed by acting principal; periodic checkpoint anchors mirrored to write-once bucket (S8).
8. **Review UI (TypeScript, React + Next.js).** Queue view, claim-tier review detail (renders C3 checks + C4 lineage graph + S6 novelty context + S11 calibration view), decision capture, guardrail panel, emission-authorization flow, admin/COI consoles, auditor console.
9. **Notification & Escalation Service (Python + NATS + email/push adapters).** SLA aging alerts, reassignment, escalation to Governance Officer, quorum-timeout handling.

### S9.3 Review task state machine
```
PENDING_INTAKE → QUARANTINED(terminal, on signature/hash/guardrail-hard-fail)
PENDING_INTAKE → QUEUED → ASSIGNED → IN_REVIEW
IN_REVIEW → NEEDS_MORE_INFO (→ requests C3.challenge / more lineage) → IN_REVIEW
IN_REVIEW → AWAITING_SECOND_SIGNOFF (dual/quorum) → IN_REVIEW
IN_REVIEW → APPROVED_INTERNAL (claim accepted, no external emission)
AWAITING_SECOND_SIGNOFF → APPROVED_FOR_EMISSION → EMISSION_AUTHORIZED (token minted)
IN_REVIEW → REJECTED (terminal) | ESCALATED → (Governance disposition)
ANY → EXPIRED (SLA breach → reassign or escalate)
```
All transitions are event-sourced to the governance ledger; state is authoritative in PostgreSQL and mirrored as ledger events.

### S9.4 Key algorithms
- **Signature & hash verification (fail-closed).** At intake and again immediately before minting an emission authorization: verify report signature (`signer_key_id` in trust store, canonical serialization matches), verify each `artifact_ref.content_hash` equals BLAKE3 of fetched bytes. Any mismatch ⇒ QUARANTINED + Sev-alert; never proceeds. Re-verify at emission time defeats TOCTOU.
- **Guardrail evaluation.** Declarative rule set mapping (claim_class, emission_class, claim_tier, checks) → ALLOW/BLOCK/REQUIRE(policy). Hard blocks: emission_class ∈ {new-fundamental-theory-confirmation, autonomous-paper-submission, flagship-HPC-execution, empirical-validation-claim} ⇒ BLOCK always (these are enforced non-goals, cannot be overridden by any role). Novelty gate: `claim_tier == novel-needs-human` REQUIRES all LEAKAGE checks PASS and ≥1 CROSS_CODE PASS in the C3 report, else auto-downgrade recommendation + block emission.
- **Quorum / dual sign-off.** For `novel` acceptance and for any external emission: require ≥ policy.min_signoffs distinct, eligible, non-conflicted principals with role coverage (≥1 domain AND ≥1 ml for novel; ≥1 governance for emission). A single principal can never satisfy two required roles. Delegated sign-offs record the delegation chain.
- **COI detection.** For a candidate touching subtopic S and citing/deriving from sources in lineage, cross-reference reviewer COI declarations (co-authorship, institution, self-review of own subagent) → auto-recuse and exclude from eligible pool; record recusals.
- **Priority scoring.** `priority = w_tier·tier_rank + w_age·age_norm + w_deadline·deadline_pressure + w_emit·emission_class_rank − w_backpressure·budget_scarcity`. Deterministic given inputs (reproducible ordering); ties broken by `created_at` then `task_id`.
- **Rate limiting / back-pressure.** Two token buckets: (a) queue-admission rate (items/window), (b) external-emission budget (emissions/window, per emission_class). Back-pressure gauge = min(remaining ratios); published to S5 and S11. When admission bucket empty, new `CreateReviewTask` calls are deferred (S5 back-pressured, not dropped) — deferral is audited.
- **Ledger integrity check.** Continuous canary recomputes the hash chain from the last checkpoint; mismatch ⇒ Sev-1, freeze emissions.

### S9.5 Sequence flows
**A. Novel-candidate review → external emission**
1. S3 produces signed C3 report tagging a candidate `novel-needs-human`; S5 hits human-review wait state and calls S9 `CreateReviewTask` (C2 wait) OR S3 emits `novel.candidate` NATS event.
2. Intake verifies report signature + C4 hashes + guardrail pre-screen. Legal ⇒ QUEUED with policy = dual sign-off + governance emission approval.
3. Prioritizer assigns to eligible, non-conflicted Domain Reviewer.
4. Reviewer opens UI: sees checks, lineage graph, novelty context vs frozen index, calibration. Records decision + rationale (first sign-off, role=domain).
5. Engine transitions AWAITING_SECOND_SIGNOFF; ML Reviewer signs (role=ml). Novelty gate re-checked (leakage PASS, cross-code PASS).
6. Governance Officer opens emission review; guardrail engine evaluates emission_class; budget checked. Officer authorizes (governance sign-off).
7. Emission Minter verifies signatures again (TOCTOU guard), mints single-use `EmissionAuthorization` bound to artifact hashes + emission_class; appends ledger entry; emits `emission.authorized` event; returns to S5 as C2 JobResult decision signal.
8. Out-of-band human performs the actual external submission using the authorization; S9 records `emission.completed` when confirmed. (S9 never auto-submits.)

**B. Guardrail hard-block.** Intake/policy detects emission_class = autonomous-paper-submission ⇒ BLOCK; task → REJECTED with guardrail reason; ledger records block; S5 notified REFUSED; no token ever minted.

**C. Reviewer requests re-verification.** Reviewer sets NEEDS_MORE_INFO ⇒ S9 calls C3 `challenge(report_ref)` (re-run canary path); on ChallengeResult, task returns IN_REVIEW with the new evidence linked.

**D. Back-pressure.** S5 requests admission; admission bucket empty ⇒ S9 returns `deferred=true` + back-pressure gauge; S5 pauses admitting new jobs into the review-bound path.

### S9.6 Tech choices (consistent with shared stack)
- **Python 3.11 + pydantic v2** (generated from C2/C3/C4/C5 JSON Schemas) for services.
- **Rust** for the ledger writer, signature/hash verify hot path, and emission-authorization minter (trust-boundary + performance).
- **PostgreSQL 16** system of record (tasks, reviewers, COI, policies, ledger table with recursive-CTE lineage queries).
- **Object store (S3/MinIO), write-once buckets** for immutable decision records, ledger checkpoints, and emission authorizations.
- **Redis** for ephemeral task leases/locks and rate-limit token buckets (never system of record).
- **Temporal** integration for S5 human-review wait states (S9 exposes activities/signals; the durable wait lives in S5's workflow).
- **NATS JetStream** for `review.*`, `emission.*`, `guardrail.*`, back-pressure and change events.
- **TypeScript + React + Next.js** UI; **OpenTelemetry** tracing; **Prometheus/Grafana** dashboards; KPIs to S11.
- **Vault/KMS + HSM** for the emission-authorization signing key and principal signing keys; **mTLS** for all inter-subsystem calls; **OIDC/SSO** for reviewer authentication with WebAuthn step-up for emission authorization.
- **Policy engine:** OPA/Rego (or pinned in-house DSL) with versioned, content-addressed policy bundles.

### S9.7 Failure / degradation handling
- **Signature/hash mismatch** ⇒ fail-closed QUARANTINE; never surfaced as approvable; Sev alert.
- **Trust store / S3 unreachable at intake** ⇒ cannot verify ⇒ task held in PENDING_INTAKE (not queued), S5 informed VERIFIER_UNAVAILABLE-style; no fallback that trusts unverified reports.
- **Ledger append failure** ⇒ decision does NOT commit (2-phase: ledger append must succeed before state transition is durable); operation retried; if persistently failing, emissions frozen (fail-closed).
- **Emission-minter/HSM unavailable** ⇒ approvals may proceed to APPROVED_FOR_EMISSION but token mint blocks; no external emission possible ⇒ safe degradation (blocks, never bypasses).
- **Reviewer unavailability / SLA breach** ⇒ auto-escalate/reassign; aging surfaced in KPIs; queue back-pressures S5 rather than auto-approving.
- **Redis loss** ⇒ leases rebuilt from PostgreSQL task state; at-most-one review guaranteed by DB-level optimistic lock (version column) even without Redis.
- **UI outage** ⇒ API remains available (CLI + programmatic sign-off for governance officers with WebAuthn); no auto-approval.
- **Policy engine unavailable** ⇒ fail-closed: emissions blocked (cannot prove guardrail compliance), internal review may continue read-only.
- **Duplicate `CreateReviewTask`** ⇒ idempotent on `(root_request_id, artifact_content_hash_set)`; returns existing task.
- **Quarantine disposition** ⇒ Governance Officer can only route to re-verification or permanent-reject; never to emission.

### S9.8 Data models
All timestamps RFC3339 UTC. All hashes BLAKE3. Records referencing external subsystem artifacts store `content_hash` (C4) or `report_id`+signature handle (C3), never inlined mutable copies. Decision/audit records are themselves persisted as C4 ArtifactRecords (kind=`report`/`log`) for lineage.

**ReviewTask (PostgreSQL `review_tasks`)**
```
{
  task_id: uuid (PK), root_request_id: uuid, job_id: uuid, parent_job_id?: uuid, dag_node_id?: string,
  source: enum{S5_WAIT_STATE, S3_CANDIDATE_EVENT, FEDERATION_ADMISSION, QUARANTINE_DISPOSITION},
  validation_report_ref: string,    // C3 report_id / content-addressed handle
  validation_report_signature_verified: bool,
  artifact_refs: [ {artifact_id, content_hash, kind} ],   // C4
  claim_tier_claimed: enum{ran-toy, recapitulated-known, novel-needs-human},
  emission_class?: enum{ none, internal-claim, dataset-release, figure-release,
                        result-summary, novel-claim-external, federation-admission,
                        new-fundamental-theory-confirmation, autonomous-paper-submission,
                        flagship-HPC-execution, empirical-validation-claim },   // last four = enforced-blocked
  contamination_index_version: string,   // pinned from C4/C6
  required_policy_ref: string,           // Policy version applied
  required_signoffs: int, required_roles: [enum],   // e.g. [domain, ml] for novel; [governance] for emission
  state: enum{PENDING_INTAKE, QUEUED, ASSIGNED, IN_REVIEW, NEEDS_MORE_INFO,
              AWAITING_SECOND_SIGNOFF, APPROVED_INTERNAL, APPROVED_FOR_EMISSION,
              EMISSION_AUTHORIZED, REJECTED, ESCALATED, QUARANTINED, EXPIRED},
  priority_score: float, assignee_id?: uuid, lease_expires_at?: timestamp, deadline?: timestamp,
  version: int,                     // optimistic lock (at-most-one review)
  created_at, updated_at, quarantine_reason?: string,
  idempotency_key: string           // hash of (root_request_id, sorted artifact content_hashes)
}
```

**SignOff (PostgreSQL `signoffs`; immutable)**
```
{
  signoff_id: uuid (PK), task_id: uuid (FK), principal_id: uuid,   // reviewer
  role_asserted: enum{domain, ml, governance, federation-admissions},
  decision: enum{APPROVE, REJECT, ABSTAIN, REQUEST_INFO},
  rationale: text (required for APPROVE/REJECT),
  evidence_reviewed: { report_id, artifact_content_hashes[], contamination_index_version },
  policy_version: string, coi_attestation: bool,            // "I have no undeclared conflict"
  delegation_chain?: [principal_id],
  step_up_auth: { method: webauthn, assertion_ref },   // for emission-grade
  signature: string,                // principal key over canonical signoff
  signer_key_id: string, created_at: timestamp             // immutable; corrections via new superseding signoff
}
```

**ReviewDecision (terminal; persisted also as C4 artifact)**
```
{
  decision_id: uuid, task_id: uuid,
  outcome: enum{APPROVED_INTERNAL, APPROVED_FOR_EMISSION, REJECTED, ESCALATED, QUARANTINED},
  final_claim_tier: enum{ran-toy, recapitulated-known, novel-needs-human},
  claim_tier_promoted: bool,        // true only when S9 accepts a novel candidate
  signoffs: [signoff_id], guardrail_result_ref: uuid, emission_authorization_id?: uuid,
  ledger_entry_hash: string, decided_at: timestamp,
  supersedes?: decision_id          // corrections only, never edits
}
```

**EmissionAuthorization (write-once; signed by HSM key)**
```
{
  authorization_id: uuid, task_id: uuid, decision_id: uuid, emission_class: enum,
  bound_artifact_content_hashes: [string],   // exact artifacts authorized
  bound_report_id: string,
  scope: { destination_class, single_use: true },
  budget_charge: { bucket_id, cost: 1 },
  issued_at, expires_at,            // short-lived
  consumed: bool, consumed_at?,
  signature: string, signer_key_id: string   // HSM/vault key, governance zone only
}
```

**GuardrailResult**
```
{
  guardrail_result_id: uuid, task_id: uuid, policy_version: string,
  evaluations: [ { rule_id, subject, verdict: enum{ALLOW, BLOCK, REQUIRE}, requirement?, reason } ],
  aggregate: enum{ALLOW, BLOCK, REQUIRE},
  hard_block: bool,                 // non-overridable non-goal hit
  evaluated_at: timestamp
}
```

**GovernanceLedgerEntry (append-only, hash-chained)**
```
{
  seq: bigint (monotonic), entry_id: uuid,
  prev_hash: string,                // BLAKE3 chain
  entry_hash: string,               // BLAKE3(prev_hash || canonical(payload))
  event_type: enum{TASK_CREATED, STATE_TRANSITION, SIGNOFF_RECORDED, GUARDRAIL_EVALUATED,
                   EMISSION_AUTHORIZED, EMISSION_COMPLETED, REJECTED, QUARANTINED,
                   COI_RECUSAL, POLICY_CHANGED, REVIEWER_CHANGED, CHALLENGE_REQUESTED,
                   BACKPRESSURE_APPLIED, LEDGER_CHECKPOINT},
  actor: { principal_id | service_id, role }, payload: json,   // event-specific, includes referenced hashes
  actor_signature: string, signer_key_id: string, recorded_at: timestamp,
  checkpoint_anchor?: string        // periodic write-once mirror reference
}
```

**Reviewer (PostgreSQL `reviewers`)**
```
{
  principal_id: uuid, display_name, email, oidc_subject,
  roles: [enum{domain, ml, governance, federation-admissions, auditor, admin}],
  eligible_subtopics: [taxonomy_id],       // from C5
  independence_tags: [string],             // for self-review avoidance vs C5
  credentials: { webauthn_registered: bool, signing_key_id },
  status: enum{active, suspended, retired}, created_at, updated_at
}
```

**COIDeclaration**
```
{
  coi_id: uuid, principal_id: uuid,
  scope: enum{subtopic, artifact, subagent, institution, coauthor},
  subject_ref: string,             // taxonomy_id | artifact_id | subagent_id | org | source_ref
  reason: text, declared_by: uuid, active: bool, created_at, expires_at?
}
```

**Policy (versioned, content-addressed)**
```
{
  policy_id, policy_version: semver, content_hash,
  kind: enum{guardrail, quorum, rate_limit, coi, novelty_gate},
  rules_bundle_ref: string,        // Rego/DSL bundle in write-once store
  effective_from, effective_to?, author, signature
}
```

**RateBudget / TokenBucket**
```
{ bucket_id, kind: enum{queue_admission, external_emission}, emission_class?: enum,
  window: duration, capacity: int, refill_rate: float, current_tokens: float, updated_at }
```

**BackPressureGauge (published to S5/S11)**
```
{ gauge_id, admission_remaining_ratio: float, emission_remaining_ratio: float,
  effective_backpressure: float,   // 0..1, 1 = fully open
  queue_depth: int, oldest_task_age_s: int, computed_at }
```

**Notification / Escalation**
```
{ notification_id, task_id, kind: enum{ASSIGNED, SLA_WARNING, SLA_BREACH, ESCALATED,
   QUORUM_TIMEOUT, GUARDRAIL_BLOCK, QUARANTINE}, recipient_id, channel: enum{ui, email, push},
   sent_at, acknowledged_at? }
```

**Indexing / integrity.** `review_tasks`: idx on (state, priority_score desc), (assignee_id, state), unique(idempotency_key). `governance_ledger`: unique(seq), unique(entry_hash); append-only trigger forbids UPDATE/DELETE. Lineage queries via recursive CTE over C4 `derived_from`/`inputs` mirrored read-model.

### S9.9 Public interfaces
All HTTP/gRPC calls mTLS-authenticated, scoped by least-privilege capability tokens; envelopes carry `trace_id`, `principal_id`/`service_id`, `capability_scopes[]`. Errors use the C1/C2 typed envelope `{code, category, message, retry_after?, provenance_ref}` with S9 categories added: `SIGNATURE_INVALID | GUARDRAIL_BLOCK | POLICY_UNAVAILABLE | LEDGER_UNAVAILABLE | COI_CONFLICT | BUDGET_EXHAUSTED | NOT_ELIGIBLE | IMMUTABLE_VIOLATION | BACKPRESSURE`.

**Intake / Orchestration API (consumed by S5 via C2, and S3 via events)**
- `POST /v1/review-tasks` → `CreateReviewTask(req: {root_request_id, job_id, validation_report_ref(C3), artifact_refs[](C4), claim_tier_claimed, emission_class?, contamination_index_version, deadline?, idempotency_key}) -> {task_id, state, deferred: bool, backpressure_gauge}`  (idempotent; verifies signature+hashes; returns `deferred=true` under admission back-pressure).
- `GET /v1/review-tasks/{task_id}` -> `ReviewTask` (full, with signoffs, guardrail_result, decision).
- `POST /v1/review-tasks/{task_id}/cancel` -> `{task_id, state}` (S5 cancel of a superseded job).
- `GET /v1/backpressure` -> `BackPressureGauge` (polled/streamed by S5; also on NATS `s9.backpressure`).
- **Temporal activities** exposed to S5 workflows: `AwaitHumanReview(task_ref) -> ReviewDecisionSignal{outcome, final_claim_tier, emission_authorization_id?}` (the durable wait lives in S5; S9 signals on decision).

**Verifier interaction (consumes C3).** Internal call `RequestChallenge(report_ref) -> challenge_task_id` → invokes C3 `challenge(report_ref)`; result linked back to task as new evidence (state NEEDS_MORE_INFO → IN_REVIEW).

**Review Workflow API (consumed by UI/CLI reviewers)**
- `GET /v1/queue?role=&subtopic=&state=&limit=&cursor=` -> `[ReviewTaskSummary]` (respects reviewer eligibility & COI filtering; ordered by priority_score).
- `POST /v1/review-tasks/{task_id}/assign` -> `{task_id, assignee_id, lease_expires_at}` (self-assign/claim with lease).
- `POST /v1/review-tasks/{task_id}/signoff` → `SignOff(body: {decision: APPROVE|REJECT|ABSTAIN|REQUEST_INFO, role_asserted, rationale, coi_attestation, evidence_reviewed, step_up_auth?}) -> {signoff_id, task_state, remaining_signoffs}`  (validates eligibility, distinctness, COI, novelty gate; APPROVE for emission requires WebAuthn step-up).
- `POST /v1/review-tasks/{task_id}/escalate` -> `{task_id, state: ESCALATED}`.
- `GET /v1/review-tasks/{task_id}/evidence` -> `{c3_report(rendered), c4_lineage_graph, novelty_context(vs frozen index), calibration_view}` (aggregates read-only from S3/S8/S6/S11).

**Emission / Governance API (consumed by Governance Officer + external-emission actor)**
- `POST /v1/review-tasks/{task_id}/authorize-emission` -> `EmissionAuthorization`  (requires all signoffs + guardrail ALLOW + budget; mints HSM-signed single-use token; re-verifies signatures TOCTOU-safe).
- `POST /v1/emission-authorizations/{authorization_id}/verify` -> `{valid: bool, bound_hashes[], expires_at, consumed}` (called by external-emission actor before acting; structural gate).
- `POST /v1/emission-authorizations/{authorization_id}/consume` -> `{consumed: true, consumed_at}` (single-use enforcement; records `emission.completed`).
- `GET /v1/guardrails/evaluate?task_id=` -> `GuardrailResult` (dry-run preview).

**Reviewer / Policy Admin API (consumed by Reviewer-Admin, Governance Officer)**
- `POST /v1/reviewers` / `PATCH /v1/reviewers/{id}` / `GET /v1/reviewers/{id}` — CRUD roles, eligible_subtopics, status.
- `POST /v1/coi` / `DELETE /v1/coi/{coi_id}` / `GET /v1/coi?principal_id=` — COI declarations.
- `POST /v1/policies` (publish versioned bundle) / `GET /v1/policies/{kind}/current`.
- `POST /v1/rate-budgets` / `PATCH /v1/rate-budgets/{bucket_id}` — set queue-admission & emission budgets.

**Federation Admission API (consumes C5)**
- `POST /v1/federation/admissions` `AdmitReview(body:{descriptor_revision_ref(C5), conformance_evidence_ref}) -> review_task_id`.
- `POST /v1/federation/admissions/{task_id}/decide` -> `{outcome: ADMIT|DENY, reason, ledger_entry_hash}` (governance decision; grants no runtime trust).

**Audit API (consumed by Auditor, S11)**
- `GET /v1/ledger?from_seq=&to_seq=&event_type=&task_id=` -> `[GovernanceLedgerEntry]`.
- `GET /v1/ledger/verify?from_seq=&to_seq=` -> `{intact: bool, break_at_seq?, checkpoints_verified}` (recompute hash chain).
- `GET /v1/audit/export?range=&format=json|csv` -> signed audit bundle (write-once).
- `GET /v1/kpis` -> `{queue_depth, aging_p50/p95, signoff_latency_p50/p95, override_rate, guardrail_block_rate, reviewer_agreement_rate, emission_rate_vs_budget}` (also pushed to S11).

**Events (NATS JetStream; produced by S9)**
- `s9.review.task_created`, `s9.review.state_changed`, `s9.review.signoff_recorded`
- `s9.guardrail.blocked`, `s9.emission.authorized`, `s9.emission.completed`
- `s9.backpressure` (gauge), `s9.ledger.checkpoint`, `s9.federation.decided`
- Consumed by S9: `s3.novel.candidate`, `s5.review.requested` (C2 wait), registry change events `s6.registry.changed` (C5).

**CLI (`argusctl s9 …`; for governance officers/auditors, WebAuthn-gated for emission)**
- `argusctl s9 queue [--role --subtopic]`
- `argusctl s9 task get <task_id>` / `signoff <task_id> --decision --role --rationale`
- `argusctl s9 authorize-emission <task_id>` (prompts WebAuthn step-up)
- `argusctl s9 ledger verify [--from --to]` / `argusctl s9 audit export --range`
- `argusctl s9 policy publish <bundle>` / `argusctl s9 budget set <bucket> --capacity --window`
- `argusctl s9 coi add <principal> --scope --subject` / `reviewer add <...>`

---

## S10 — Security, Sandbox & Runtime

**Owns contract:** none (primary enforcer of budget/scope/isolation semantics of C1–C6). **Consumes:** C2 (S5), C4 (S8), C5 (S6/S12), C6 (S7), KMS/Vault, Kubernetes + cgroup v2 + gVisor/Firecracker + NVIDIA MIG/DCGM.

### S10.1 Architecture overview
S10 is a set of cooperating control-plane services plus a per-node data-plane enforcement layer. Trust decreases outward; the **untrusted zone** (agent sandboxes) is the outermost ring and can reach *inward* only through mediated, mTLS-authenticated, scope-checked control-plane calls.

```
                    ┌────────────────────────── S10 CONTROL PLANE (trusted) ─────────────────────────┐
 S5 ──mint──▶ [Token Service (Rust)] ──sign(KMS)──▶ budget_token / scope_token                        │
 S1/S2/S4 ─launch─▶ [Sandbox Orchestrator (Rust+K8s)] ──admits via──▶ [Quota/Cost Service (Rust)]      │
                    │  [Policy Service] ──signed bundle──▶ (seccomp, egress ACL, ceilings)             │
                    │  [Secrets Broker(s)] ◀──brokered call── (adapter/store credentialed ops)         │
                    │  [Audit Ledger Writer (Rust)] ──hash-chain──▶ write-once store (tamper-evident)  │
                    └────────┼─────────────────────────────────────────────────────────────────────── ┘
        ┌────────────────────▼───────────────── PER-NODE DATA PLANE (per K8s node) ──────────────────┐
        │  [Node Supervisor (Rust daemon)]                                                            │
        │     ├─ Sandbox Runtime: gVisor (runsc) | Firecracker microVM  (chosen by risk class)        │
        │     ├─ seccomp-BPF profile + read-only rootfs + no-new-privileges + user-ns remap           │
        │     ├─ cgroup v2 controllers (cpu, memory, pids, io) + GPU cgroup / MIG slice               │
        │     ├─ Egress Proxy sidecar (Rust) — allowlist + DNS-pin + TLS SNI check + per-req log       │
        │     ├─ Resource Meter (cgroup+DCGM sampler) → Quota/Cost Service                             │
        │     └─ Forensic Snapshotter (on Sev-1: freeze, snapshot rootfs+scratch+netlog)               │
        │  [UNTRUSTED SANDBOX]  rootfs:ro  scratch:rw(noexec-optional)  net:egress-proxy-only           │
        │     runs: S2 training code / S4 variants / S7 wrapped binaries / federated subagent code     │
        └──────────────────────────────────────────────────────────────────────────────────────────── ┘
 Emits: NATS events (spend, quota, security) → S11 ; C4 launch-provenance → S8 ledger writer.
```

### S10.2 Components

**2.1 Token Service (Rust).** Mints and verifies two token types used platform-wide:
- **budget_token** — a signed, TTL-bounded credential encoding the C2 `budget` (max_compute_units, max_gpu_seconds, max_model_tokens, max_wallclock_s, max_cost_usd), `job_id`, `root_request_id`, and a monotonically increasing `budget_epoch`. It is the *metered credential*: every metered operation debits against the server-side ledger keyed by the token's `budget_id`.
- **scope_token (capability_scopes[])** — a signed set of least-privilege grants (allowed_adapters, allowed_datasets, allowed egress destinations, allowed broker audiences, sandbox risk class). Enforcement everywhere checks the requested action ⊆ granted scopes.
Tokens are Biscuit/Macaroon-style attenuable capabilities (so a parent job can mint a strictly-narrower child token for a sub-job without contacting KMS), signed by a KMS-held root key. Verification is offline (public key in trust store). TTL default 15 min; refresh requires re-presenting the parent grant. Never enters a sandbox.

**2.2 Sandbox Orchestrator (Rust + Kubernetes).** Stateless admission + placement front door. On `launch_sandbox`:
1. Verify budget_token & scope_token signatures and TTL (fail-closed on any failure).
2. Call Quota/Cost Service `admit(budget_id, requested_envelope)` — pre-flight reservation. Reject if the *cost ceiling* (flagship-HPC guard) or remaining budget is insufficient.
3. Resolve the OCI image by **digest** (reject tag-only refs), fetch signature (cosign) & verify.
4. Select runtime class by **risk class** from policy: `gvisor` (default), `firecracker` (federated / high-risk / GPU-heavy multi-tenant).
5. Materialize the pod spec: read-only rootfs, `no_new_privileges`, user-namespace remap, drop all Linux capabilities, seccomp profile (from signed policy bundle), cgroup v2 limits from admitted envelope, egress-proxy-only network namespace, scratch emptyDir (size-capped), GPU/MIG allocation if requested.
6. Hand off to the Node Supervisor on the placed node; record launch-provenance (C4) to S8; emit `sandbox.launched` audit event.
Returns a `SandboxHandle{sandbox_id, exec_endpoint(mTLS), scratch_ref, budget_epoch}`.

**2.3 Node Supervisor (Rust daemon, one per node).** The local enforcement authority. Owns runsc/Firecracker lifecycle, programs cgroups, attaches the egress proxy sidecar and Resource Meter, and holds the *kill switch*. It runs as a privileged system daemon with its own identity; **its binary and config are on read-only mounts invisible to the sandbox** (satisfies NFR-2). It performs the mid-flight halt and drives the Forensic Snapshotter on Sev-1.

**2.4 Quota / Cost Service (Rust).** Authoritative spend ledger. Maintains per-`budget_id` reservations and actuals for all five budget dimensions plus a derived USD roll-up (via a signed price table mapping GPU-seconds/CPU-seconds/tokens → USD). Receives resource-meter samples (≤5s cadence) and token-meter debits (from the LLM Metering Hook and adapter brokers), applies **reserve → consume → release** accounting, and pushes `spend` events and `quota.breach` events on NATS. On breach it signals the owning Node Supervisor(s) to halt. Backed by Postgres (durable ledger) + Redis (hot counters, never system-of-record). Fail-closed: if unreachable, Orchestrator refuses new launches and in-flight jobs continue only until their next reservation checkpoint, then pause.

**2.5 Egress Proxy (Rust sidecar, per sandbox).** The *only* network path out of a sandbox (enforced by netns + iptables/nftables DROP default + redirect to proxy). Implements: destination allowlist from scope_token ∩ policy bundle; DNS resolution *pinned* by the proxy (sandbox cannot do its own DNS → prevents DNS-rebinding/tunneling); TLS SNI/host validation; per-request structured log (dst, bytes, verdict) to the audit ledger; byte-count exfiltration heuristics (volume/entropy anomaly → alert, optional hard cap). Permitted classes: content-addressed store (read/write of artifacts), declared adapter/broker endpoints, and the exec control channel. Everything else → DENY + `egress.denied` event.

**2.6 Secrets Broker(s) (Rust).** Out-of-sandbox services that hold real credentials (from Vault/KMS) and expose *brokered operations* to sandboxes: e.g. "call adapter X with these normalized inputs" or "PUT this artifact to the store". The sandbox presents its scope_token; the broker checks the audience/scope, performs the credentialed action itself, and returns only the result. Secrets never cross the boundary. Tokens minted per job are short-lived, audience-bound, and least-privilege. The store-writer broker is the S8 ledger writer's front for agent-origin writes (agents cannot write the ledger directly — C4 IMMUTABLE guarantee).

**2.7 Policy Service.** Serves the **signed policy bundle**: seccomp profiles (per runtime class), egress allowlist, resource ceilings (incl. the flagship-HPC cost ceiling), risk-class → runtime-class mapping, token TTLs, snapshot retention. Bundles are semver-versioned, signed by the Security Engineer's key, content-addressed (C4), and rolled out **atomically** (Orchestrator/Supervisor pin a version; a new bundle changes decisions only for launches after cutover). Every launch records `policy_bundle_version` in provenance (NFR-11). Decision logic is a **pure function** `decide(bundle, request) → verdict` (NFR-9) for golden-file testing.

**2.8 Audit Ledger Writer (Rust).** Append-only, hash-chained (each record includes prev-hash; periodic Merkle-root anchoring to the write-once bucket) tamper-evident log of every trust-boundary action. Distinct from S8's artifact provenance (S10 also *emits* C4 launch records via S8's writer, but its *security* audit trail is this dedicated chain). Consumed by S9 (quarantine review) and S11 (security KPIs).

**2.9 LLM Metering Hook.** A brokered wrapper around the Anthropic API path (agents only reach the model through this hook, never with a raw key). It counts prompt/response tokens, debits the budget via Quota/Cost, and captures prompt/response provenance to S8 (per shared stack). Halts model calls when `max_model_tokens` or `max_cost_usd` is exhausted.

### S10.3 Key algorithms

**3.1 Sandbox admission & launch (pure-decision + side-effect split)**
```
launch(req):
  verify_token(req.budget_token); verify_token(req.scope_token)      # fail-closed
  bundle = PolicyService.current(pin=req.policy_pin)
  verdict = decide(bundle, req)          # PURE: runtime_class, seccomp_ref, cgroup limits,
                                          #       egress_acl, risk_class, ceiling_check
  if verdict.deny: audit(deny); return SANDBOX/POLICY error
  res = Quota.admit(req.budget_id, verdict.envelope)   # reserve; fail-closed if ceiling exceeded
  if !res.ok: audit(budget_reject); return BUDGET error
  img = resolve_digest(req.image); verify_cosign(img)  # reject tag-only / unsigned
  pod = build_pod(img, verdict)          # ro-rootfs, nnp, userns, seccomp, cgroups, egress-only netns
  place_and_start(pod)                    # via Node Supervisor
  emit C4 launch-provenance(S8); audit(launched)
  return SandboxHandle
```

**3.2 Reserve → consume → release cost accounting.**
- **Admit/reserve:** on launch, reserve `max_wallclock_s × worst-case rate` (or an explicit per-launch reservation) against remaining budget across all dims; deny if any dim would go negative. This prevents oversubscription races (compare-and-swap on the per-`budget_id` counter row).
- **Consume:** Resource Meter samples cgroup CPU-seconds, memory-peak, `io`; DCGM samples GPU-seconds/MIG utilization; token hook debits tokens. Each sample converts to USD via the signed price table and atomically increments `actual`.
- **Release:** on sandbox exit, release the unused reservation. Net actuals persist for cost-per-verified-artifact.
- **Overshoot bound:** `overshoot ≤ sample_interval × max_rate`; declared per risk class, part of the contract, tested.

**3.3 Mid-flight halt on breach**
```
on quota.breach(budget_id, dim):        # from Quota service, ≤2s after crossing
  supervisors = owners_of(budget_id)
  for s in supervisors:
     s.freeze(sandbox_ids)              # SIGSTOP cgroup freeze (no cleanup by agent code)
     capture_partial_results(scratch)   # copy declared outputs to store via broker
     s.terminate(sandbox_ids)           # SIGKILL, reclaim cgroup
  emit spend.final; audit(halted, dim); JobResult.status = QUARANTINED|FAILED(BUDGET)
```
Freeze-before-terminate ensures the agent cannot run a cleanup hook that hides evidence or spends more.

**3.4 Egress decision**
```
on connect(sandbox, dst_host, port, sni):
  acl = scope.egress ∩ bundle.egress_allowlist
  ip  = proxy_resolve(dst_host)          # proxy owns DNS; pin ip for connection lifetime
  if (dst_host,port) ∉ acl or sni≠dst_host or ip∉acl.resolved:
      audit(egress.denied); DROP
  else: audit(egress.allowed, bytes); FORWARD
  if bytes_out(sandbox) > policy.exfil_soft: alert; if > exfil_hard: DROP+halt
```

**3.5 Escape / trust-path-write detection.** Layered: (a) seccomp-BPF denies dangerous syscalls (ptrace, mount, kexec, bpf, unshare of privileged ns, keyctl, etc.) → EPERM + audit; (b) read-only trust mounts → any `write()`/`open(O_WRONLY)` to them fails at VFS + is logged by an eBPF/fanotify watcher on the host; (c) an eBPF host monitor watches for boundary-relevant events (namespace escapes, unexpected `/proc/<host-pid>` access). Any confirmed trust-path write or escape → **Sev-1**: freeze, forensic snapshot (rootfs + scratch + netlog + audit slice), quarantine job, page Security Engineer.

### S10.4 Sequence flows
- **F1 — S2 training run:** S5 mints budget+scope tokens → S1 `build()` calls Orchestrator.launch_sandbox → admit/reserve → gVisor pod up → S2 code runs, writes model to scratch → needs S7 adapter → calls Secrets Broker (scope-checked) → broker invokes adapter, returns C6 result → S2 finishes → broker PUTs artifact to store (S8) → sandbox exits → release reservation → emit spend.final + C4 launch-provenance.
- **F2 — S4 Evolver loop:** S5 mints one job budget → S4 requests N sequential sandboxes → each admitted against the *shared* budget → cumulative spend tracked → on generation-cap or spend-cap, Quota fires breach → halt → S4 receives BUDGET error → loop terminates (structural "no unguarded loop"). S4 reward comes only from S3 signed reports fetched via broker; the sandbox has no path to the reward computation.
- **F3 — Verifier support:** S3 (own zone) asks Orchestrator to run a *frozen pipeline* in an isolated exec context with **no** egress to anything but the store; S3's signing key and blind data live in the verifier zone, unreachable by the sandbox. S10 guarantees the pipeline cannot phone home or read held-out labels.
- **F4 — Policy rollout:** Security Engineer signs bundle vN+1 → Policy Service publishes → new launches pin vN+1 (recorded in provenance) → in-flight sandboxes keep vN → audit records the cutover.

### S10.5 Tech choices (consistent with shared stack)
- **Rust** for all trust-boundary/hot components (Token, Orchestrator admission, Node Supervisor, Egress Proxy, Quota, Audit Writer, Brokers) — memory safety at the boundary.
- **gVisor (runsc)** default sandbox; **Firecracker microVM** for the strongest boundary (federated/high-risk); **Kata**-style where multi-tenant. **OCI** images pinned by digest; **cosign/Sigstore** for image + report + bundle signatures.
- **Kubernetes** scheduling with hard `ResourceQuota`/`LimitRange`; **cgroup v2**; **seccomp-BPF**; **user namespaces**; **NVIDIA MIG** + **DCGM** for GPU isolation/metering.
- **HashiCorp Vault / cloud KMS** for secrets & signing keys (never in sandbox).
- **PostgreSQL 16** durable spend ledger + audit chain metadata; **Redis** hot counters/rate-limits (ephemeral only); **object store (MinIO/S3, write-once bucket)** for audit-chain anchors & forensic snapshots.
- **NATS JetStream** for spend/quota/security events; **OpenTelemetry** traces/metrics to Prometheus/Grafana/Tempo (S11).
- **JSON Schema (2020-12)** for all S10 wire types; bindings generated (pydantic/TS/serde). CBOR optional compact encoding.

### S10.6 Failure & degradation handling
- **Quota service down →** fail-closed: no new launches; in-flight pause at next reservation checkpoint (NFR-10).
- **Policy service down →** last-known-good signed bundle is cached locally by supervisors and used; if cache missing/expired → deny launch.
- **Token verification fails / expired →** deny, audit, typed `POLICY`/`SANDBOX` error (non-retryable per C1/C2).
- **Broker down →** brokered call returns a typed unavailable error; agent code cannot fall back to a direct credentialed path (there is none).
- **Egress proxy crash →** netns default-DROP means fail-closed (no egress) rather than fail-open.
- **Node Supervisor crash →** K8s liveness reaps the node's sandboxes (cgroup kill); orphaned budget reservations reconciled by a sweeper.
- **KMS unavailable for signing →** Token Service serves cached verification keys (verify still works); minting pauses (fail-closed).
- **Metering gap (sampler stall) →** treated as at-max-rate for the gap window (conservative), and a `meter.gap` alert; if gap > threshold, halt.
- **Forensic snapshot store full →** halt still occurs; snapshot queued with alert; job stays quarantined until snapshot persists (never released un-snapshotted).

### S10.7 Data models (JSON Schema 2020-12 canonical; serde/pydantic/TS generated)

**BudgetToken (signed capability)**
```json
{
  "budget_id": "uuid", "job_id": "uuid", "root_request_id": "uuid", "budget_epoch": "int",
  "caps": { "max_compute_units":"float","max_gpu_seconds":"float",
            "max_model_tokens":"int","max_wallclock_s":"int","max_cost_usd":"float" },
  "risk_class": "standard|federated|high",
  "issued_at":"rfc3339","expires_at":"rfc3339","ttl_s":"int",
  "parent_budget_id":"uuid|null",           "signer_key_id":"string","signature":"bytes"
}
```

**ScopeToken (capability_scopes[])**
```json
{
  "scope_id":"uuid","job_id":"uuid",
  "allowed_adapters":["adapter_ref(C6)"], "allowed_datasets":["dataset_ref(C4)"],
  "egress_allowlist":[{"host":"string","port":"int","proto":"https|grpc"}],
  "broker_audiences":["store|adapter:<id>|model"],
  "producer_subsystems":["S2|S3|..."],
  "sandbox_risk_class":"standard|federated|high",
  "disallowed_actions":["string"], "expires_at":"rfc3339","parent_scope_id":"uuid|null",
  "signer_key_id":"string","signature":"bytes"
}
```

**LaunchRequest**
```json
{
  "job_id":"uuid","subagent_id":"string","trace_id":"otel",
  "budget_token":"BudgetToken","scope_token":"ScopeToken",
  "image":"oci-ref (MUST be digest-pinned)",
  "entrypoint":["string"],"args":["string"],"env_allowlist":["KEY"],  // values never carry secrets
  "requested_envelope":{ "cpu_m":"int","mem_bytes":"int","gpu":{"count":"int","mig_profile":"string|null"},
                          "wallclock_s":"int","scratch_bytes":"int","pids":"int" },
  "runtime_class_hint":"gvisor|firecracker|auto",
  "policy_pin":"policy_bundle_version|null", "seeds_passthrough":{"global":"int"}
}
```

**SandboxHandle**
```json
{ "sandbox_id":"uuid","job_id":"uuid","node":"string",
  "exec_endpoint":"mtls-url","scratch_ref":"artifact-ref(C4)",
  "runtime_class":"gvisor|firecracker","budget_epoch":"int",
  "policy_bundle_version":"semver","seccomp_profile_hash":"blake3",
  "state":"ADMITTED|RUNNING|FROZEN|TERMINATED|QUARANTINED","started_at":"rfc3339" }
```

**ExecEnvironmentDigest (for C4 lineage / NFR-11 reproducibility)**
```json
{ "image_digest":"string","kernel_version":"string","runtime":"gvisor@ver|firecracker@ver",
  "seccomp_profile_hash":"blake3","cgroup_limits":{},"gpu_model":"string|null",
  "mig_profile":"string|null","policy_bundle_version":"semver","node_kernel_caps_dropped":["ALL"] }
```

**SpendRecord (ledger row) & SpendEvent (NATS)**
```json
{ "budget_id":"uuid","job_id":"uuid","dim":"cpu|gpu|mem|wallclock|tokens|usd",
  "reserved":"float","actual":"float","remaining":"float","rate_ref":"price_table_version",
  "as_of":"rfc3339","sample_seq":"int" }
```

**QuotaBreachEvent**
```json
{ "budget_id":"uuid","job_id":"uuid","dim":"...", "cap":"float","actual":"float",
  "overshoot":"float","action":"HALT","detected_at":"rfc3339" }
```

**PolicyBundle (signed, content-addressed C4)**
```json
{ "bundle_version":"semver","content_hash":"blake3",
  "seccomp_profiles":{"gvisor":"ref","firecracker":"ref"},
  "egress_allowlist":[{"host":"string","port":"int","proto":"string"}],
  "resource_ceilings":{ "cpu_m":"int","mem_bytes":"int","gpu_count":"int",
                        "wallclock_s":"int","max_cost_usd":"float" },  // flagship-HPC guard
  "risk_to_runtime":{"standard":"gvisor","federated":"firecracker","high":"firecracker"},
  "token_ttls":{"budget_s":"int","scope_s":"int","broker_s":"int"},
  "exfil_thresholds":{"soft_bytes":"int","hard_bytes":"int"},
  "snapshot_retention_days":"int",
  "signer_key_id":"string","signature":"bytes","issued_at":"rfc3339" }
```

**AuditEvent (hash-chained, tamper-evident)**
```json
{ "event_id":"uuid","seq":"int","prev_hash":"blake3","this_hash":"blake3",
  "type":"token.mint|token.verify_fail|sandbox.launched|sandbox.terminated|egress.allowed|egress.denied|quota.reserve|quota.breach|policy.rollout|secret.brokered|escape.detected|trustwrite.detected|quarantine.open|snapshot.captured",
  "job_id":"uuid|null","budget_id":"uuid|null","sandbox_id":"uuid|null",
  "trace_id":"otel","severity":"info|warn|sev2|sev1","payload":{},
  "actor":"service-id","at":"rfc3339" }
```

**QuarantineRecord**
```json
{ "quarantine_id":"uuid","job_id":"uuid","sandbox_id":"uuid","reason":"escape|trustwrite|egress|budget|policy",
  "sev":"sev1|sev2","snapshot_refs":["artifact-ref(C4)"],"audit_slice_ref":"ref",
  "opened_at":"rfc3339","status":"open|reviewing|closed","reviewer":"string|null","disposition":"string|null" }
```

**BrokeredCallRequest / Result**
```json
{ "scope_token":"ScopeToken","audience":"store|adapter:<id>|model","op":"string",
  "payload_ref":"artifact-ref(C4)|inline","trace_id":"otel","budget_token":"BudgetToken" }
// Result: { "status":"ok|denied|error","result_ref":"artifact-ref|inline","cost":{},"provenance_ref":"C4" }
```

**PriceTable (signed)**
```json
{ "price_table_version":"semver","usd_per_cpu_second":"float","usd_per_gpu_second":{"model":"float"},
  "usd_per_1k_model_tokens":{"model":"float"},"signer_key_id":"string","signature":"bytes" }
```

### S10.8 Public APIs (gRPC/HTTP, mTLS; CLI; events)

**Token Service (consumed by S5, all sandboxed subsystems)**
```
POST /v1/tokens/budget  MintBudget(caps, job_id, risk_class, ttl_s, parent_budget_token?) -> BudgetToken
POST /v1/tokens/scope   MintScope(scopes, job_id, ttl_s, parent_scope_token?) -> ScopeToken
POST /v1/tokens/attenuate Attenuate(parent_token, narrower_caps_or_scopes) -> Token  (offline, no KMS)
POST /v1/tokens/verify  Verify(token) -> {valid:bool, reason?, decoded}  (offline verify via trust store)
POST /v1/tokens/revoke  Revoke(token_id, reason) -> {}  (propagates: in-flight ops re-checked)
```

**Sandbox Orchestrator (consumed by S1/S2/S4, and S3 for frozen-pipeline exec)**
```
POST /v1/sandbox/launch      Launch(LaunchRequest) -> SandboxHandle | TypedError
POST /v1/sandbox/{id}/exec   Exec(cmd, stdin_ref?) -> {stdout_ref, stderr_ref, exit_code}  (mTLS control channel)
POST /v1/sandbox/{id}/freeze Freeze(reason) -> {}
POST /v1/sandbox/{id}/terminate Terminate(reason) -> {captured_partial_refs[]}
GET  /v1/sandbox/{id}        Get() -> SandboxHandle
GET  /v1/sandbox/{id}/health Heartbeat() -> {state, spend_so_far, wallclock_left_s}
```

**Quota / Cost Service (consumed by S5, Orchestrator, brokers, meter)**
```
POST /v1/quota/admit    Admit(budget_id, requested_envelope) -> {ok:bool, reservation_id, reason?}
POST /v1/quota/consume  Consume(budget_id, dim, amount, sample_seq) -> {remaining, breached:bool}
POST /v1/quota/release  Release(reservation_id) -> {}
GET  /v1/quota/{budget_id} Status() -> {caps, reserved, actual, remaining, usd}
POST /v1/quota/ceiling/check Check(requested_envelope, bundle_version) -> {within_ceiling:bool}  (flagship-HPC guard)
```

**Secrets Broker (consumed by sandboxed code via mTLS + scope_token)**
```
POST /v1/broker/adapter/{adapter_id}/evaluate  Brokered C6 evaluate (scope-checked) -> EvalResult(C6)
POST /v1/broker/store/put   PutArtifact(scope_token, bytes|ref, kind) -> artifact_ref(C4)  (only path for agent-origin writes)
POST /v1/broker/store/get   GetArtifact(scope_token, artifact_ref) -> bytes|stream  (scope-checked reads)
POST /v1/broker/model/complete  ModelCall(scope_token, budget_token, request) -> {response, tokens_used}  (LLM metering hook)
```

**Policy Service (consumed by Orchestrator, Supervisor, Security Engineer)**
```
GET  /v1/policy/current            Current(pin?) -> PolicyBundle
POST /v1/policy/publish            Publish(signed_bundle) -> {bundle_version}  (Security-Engineer scope only)
POST /v1/policy/decide             Decide(bundle_version, LaunchRequest) -> Verdict  (PURE; for golden tests)
GET  /v1/policy/history            History() -> [bundle_version, issued_at, signer]
```

**Audit Ledger (consumed by S9, S11)**
```
POST /v1/audit/append   Append(AuditEvent) -> {seq, this_hash}  (internal services only)
GET  /v1/audit/verify   VerifyChain(from_seq,to_seq) -> {intact:bool, break_at?}
GET  /v1/audit/query    Query(filter{job_id?,type?,sev?,time_range}) -> [AuditEvent]
GET  /v1/quarantine/{id}  GetQuarantine() -> QuarantineRecord  (S9 review)
POST /v1/quarantine/{id}/close Close(disposition, reviewer) -> {}  (S9 sign-off)
```

**Events (NATS JetStream; consumed by S11, S5, S9)**
```
s10.spend            SpendEvent (≤5s cadence per active budget)
s10.quota.breach     QuotaBreachEvent
s10.security         AuditEvent where severity ≥ sev2 (escape/trustwrite/egress-denied/quarantine)
s10.sandbox.lifecycle launched|frozen|terminated|quarantined
s10.policy.rollout   {bundle_version, at}
```

**CLI (`argusctl s10 …`, for P7/P8 operators)**
```
argusctl s10 policy publish --bundle f.json --key <kms>
argusctl s10 policy diff <vA> <vB>   /   policy rollback <version>
argusctl s10 quota show <budget_id>  /   quota top   (live utilization)
argusctl s10 sandbox ls [--job]  /  sandbox inspect <id>  /  sandbox kill <id> --reason
argusctl s10 quarantine ls  /  quarantine open <id>  /  quarantine snapshot fetch <id>
argusctl s10 audit verify --from <seq> --to <seq>  /  audit tail --sev sev1
argusctl s10 redteam run <suite>   (escape-attempt battery, gates CI)
argusctl s10 token mint-budget|mint-scope|verify   (operator/testing)
```

**Contracts touched.** Consumes: C2 (budget/capability_scopes/verifier_profile fields drive admission & metering), C4 (emits launch-provenance & forensic-snapshot artifacts via S8 writer; reads image/dataset refs), C5 (reads adapter descriptors for broker validity/cost_class ceiling), C6 (broker invokes adapters on behalf of sandboxed code). Produces (S10-internal APIs above) used by S1/S2/S3/S4/S5; S10 does **not** own any of C1..C6 but is a primary enforcer of the budget/scope/isolation semantics they declare.

---

## S11 — Observability & Evaluation

**Owns contract:** none. **Consumes (read-only):** C4 (S8), C3 read+challenge (S3), C2 read + advisory pause (S5), C1 drive-for-eval (S1), C6 read (S7), C5 read (S6/S12), S10 sandbox + security events, OTLP from all instrumented subsystems.

### S11.1 Architecture overview
S11 is a **read-only measurement plane** with five planes:

```
                       ┌───────────────────────────────────────────────────────┐
   OTel spans/metrics  │  INGEST PLANE (Rust collector + OTel Collector)        │
   NATS platform events│   scrub → validate → buffer(JetStream) → fan-out       │
   (S5,S1,S2,S3,S7,S10)│                                                        │
                       └───────┬─────────────┬──────────────┬──────────────────┘
                    ┌──────────▼───┐  ┌──────▼───────┐ ┌────▼──────────────┐
                    │ TRACE STORE  │  │ METRIC STORE │ │ EVENT STORE       │
                    │ Tempo/Jaeger │  │ Prometheus + │ │ Postgres (audit)  │
                    │              │  │  Thanos LTS  │ │ OpenSearch (logs) │
                    └──────┬───────┘  └──────┬───────┘ └────┬──────────────┘
                    ┌──────▼─────────────────▼──────────────▼──────────────┐
                    │  KPI & ANALYTICS PLANE                                │
                    │   stream processor (Flink/Faust) + batch rollups      │
                    │   KPI defs (versioned) → KPI series (Postgres/Prom)   │
                    │   detectors: transparency, reward-hacking, cost-anom  │
                    └──────┬───────────────────────────────┬───────────────┘
                    ┌──────▼──────────┐            ┌────────▼─────────────────┐
                    │ EVAL PLANE      │            │  SERVING PLANE            │
                    │  re-run canary  │            │  Query API (gRPC/REST)    │
                    │  MLE-bench harn.│            │  Grafana + Next.js dash   │
                    │  physics recap. │            │  Alertmanager, digests    │
                    │  (all in S10)   │            │  audit/export             │
                    └──────┬──────────┘            └───────────────────────────┘
                           │  reads C2/C3/C4/C6 (read-only), runs in S10 sandbox
        Consumes: C2(read) C3(read) C4(read) C6(read for adapters in eval) C5(read)
```

**Design stance:** ingest is append-only and buffered; analytics is deterministic and versioned; eval runs untrusted (in the sandbox, no elevated trust); serving is read-only.

### S11.2 Components

**2.1 Ingest Plane.**
- **OTel Collector (per-cluster deployment)** receives OTLP traces/metrics/logs from all subsystems. Pipeline: `receive(OTLP) → memory_limiter → scrubber(processor) → attributes(enrich with subsystem/contract tags) → batch → export(Tempo/Prom/OpenSearch)`.
- **Rust telemetry gateway (`s11-gateway`)** — the security-critical hot path at S11's boundary. Terminates mTLS, enforces read-only, applies the **PII/secret scrubber** (deny-list of key patterns: `budget_token`, `signer_key_id` values, blind_dataset_handle contents, vault refs, any field tagged `sensitive`), validates span/event schemas, and publishes normalized events to **NATS JetStream** subjects (`s11.spans`, `s11.metrics`, `s11.events`, `s11.cost`). Rust chosen because this is a trust-boundary, high-throughput component where a memory bug is a security bug.
- **Platform event consumer** subscribes to the platform NATS bus for domain events: `job.state_changed` (S5/C2), `validation.report_issued` (S3/C3), `artifact.committed` (S8/C4), `registry.changed` (C5), `sandbox.policy_violation` (S10), `budget.breach` (S10). These are the semantic events KPIs are computed from.

**2.2 Storage.**
- **Traces:** Grafana **Tempo** (default) with Jaeger-compatible query; object-store backed, keyed by `trace_id`. Tail-sampling policy (keep all error/quarantine/reward-hacking traces + 10% baseline) applied in the collector.
- **Metrics:** **Prometheus** for short-term + **Thanos** (or Mimir) for long-term/global query; recording rules materialize KPI numerators/denominators.
- **Events/audit:** **PostgreSQL 16** is the system of record for KPI series, findings, canary results, eval scorecards, and the audit log (append-only, tamper-evident via hash-chaining each audit row). **OpenSearch** indexes logs + serves full-text over events.
- **Self-artifacts:** scorecards, canary verdicts, and KPI-snapshot exports are written as **C4 artifacts to S8** (content-addressed, BLAKE3) via the S8 client, so S11's own outputs are reproducible and immutable — S11 *produces* C4 records for its evaluation outputs but never mutates others' artifacts.

**2.3 KPI & Analytics Plane.**
- **KPI Definition Registry** — each KPI is a versioned, declarative spec (numerator query, denominator query, window, unit, SLO, owner). Stored in Postgres, content-hashed. Changing a definition mints a new version; historical series stay tied to the version that produced them.
- **Stream processor** (Flink or Python **Faust** on JetStream) maintains streaming KPIs with exactly-once semantics via JetStream durable consumers + idempotent upserts keyed by event id.
- **Batch rollup jobs** (scheduled via Temporal or cron) recompute daily/weekly aggregates deterministically from the event store for KPIs that need full-window correctness (cost-per-verified-artifact, reproducibility rate).
- **Detectors** (below) run as stream operators emitting `finding` records.

**2.4 Eval Plane.**
- **Re-run Canary** — samples signed C4 artifacts (weighted toward tier > ran-toy and toward artifacts feeding S9). For each: (a) reads the C4 lineage (container digest, code commit, seeds, config, input hashes) and re-executes the producing step **inside an S10 sandbox** with identical pins; OR (b) for verifier outputs, calls S3 `challenge(report_ref)` (C3) to re-run/audit. Compares outputs by artifact-kind-specific comparators (bit-exact for deterministic; statistical-within-tolerance for declared-nondeterministic kernels, using the tolerance recorded in the C4 record). Emits a `CanaryResult` (reproducible / divergent / infra-error) and, on divergence, a `non_reproducible` finding.
- **MLE-bench-style Harness** — a curated suite of agent-ML tasks (Kaggle-like, tabular/vision/time-series) with held-out scoring. It drives Argus end-to-end (submits a C2 job through S5 for a task-shaped subtopic, or drives a subagent directly through C1) and scores the produced model against a held-out set via a **scoring shim outside the sandbox**. Produces per-task medal/percentile and an aggregate.
- **Physics Recapitulation Harness** — a curated set of *established* physics results (e.g., a known EWPT→GW relation, a known Higgs-sector observable) held out from the model. Argus must rediscover them; the harness scores rediscovery against the held-out truth via the shim, and cross-checks the platform's own S3 tier assignment (should be `recapitulated-known`). Detects the failure mode "claims novel on a known result" (a transparency/leakage red flag) and "fails to recapitulate a known result" (capability gap).
- **Eval Vault** — access-controlled store of ground-truth labels/answers for both harnesses. Only the shim (a separate service, egress-restricted, no path into the sandbox) can read it. This enforces eval-label isolation and prevents the harness from becoming a leakage vector.

**2.5 Serving Plane.**
- **Query API** (gRPC + REST, generated from JSON Schema per stack) — KPI queries, trace fetch, finding queries, scorecard queries, lineage-impact queries, audit export.
- **Dashboards** — **Grafana** for metrics/traces/SLOs; **Next.js + React (TypeScript)** app for the platform-semantic views (Trust Digest, Eval Scorecards, Reproducibility, Reward-Hacking board, Cost attribution).
- **Alerting** — Prometheus **Alertmanager** for KPI/SLO breaches + a S11 finding-router that posts to NATS (`s11.alerts`) and to S9 review queues when a finding requires human governance action (advisory).

### S11.3 Key algorithms

**3.1 Trace Assembly & Completeness.** Each C2 job carries a `trace_id` (OTel) propagated across C1/C6/C3 calls. S11 computes **trace completeness** per job: expected span-set derived from the C2 DAG node + declared plan steps (from S5 events) and the subsystem hop model `{S5.dispatch, S1.accept, S1.plan, S1.build→S2, S2→S7*, S1.validate→S3, S3.checks*}`. Completeness = observed_required_spans / expected_required_spans. Missing spans → `broken_trace` finding; the **broken-span/orphan rate** is the **transparency-of-observability** KPI feeding G1. Algorithm handles late/out-of-order spans with a 10-min lateness window before finalizing.

**3.2 KPI Formulas (canonical, versioned).**
- **Validation pass rate** = signed C3 reports with `aggregate.passed=true` / total C3 reports issued, per window, per profile/subtopic.
- **Transparency-failure rate** = count of artifacts/results asserting `claim_tier > ran-toy` **without** a signature-valid C3 report whose tier matches, **plus** tier/report mismatches, **plus** broken-lineage promotions / total tier>ran-toy assertions. (S11 detects these by cross-joining S8 C4 records with S3 C3 reports read-only; any nonzero value is a Sev event because the trust NFR says these must be quarantined by S8/S3 — S11 catching one means a gate leaked.)
- **Cost-per-verified-artifact** = Σ metered spend (compute_units×price + gpu_seconds×price + model_tokens×price) attributed to jobs / count of artifacts with a valid signed C3 report at tier ≥ recapitulated-known, per window/subtopic.
- **Reward-hacking-catch rate** = (reward-hacking signatures caught by gates: leakage-check FAILs, null-control FAILs, verifier INCONCLUSIVE-treated-as-nonimprovement in S4, blind-data-access-denied events, sandbox-policy violations) / (estimated exploit attempts) — reported as caught-count and, where a planted-exploit canary exists, as a true catch rate.
- **Reproducibility rate** = canary `reproducible` / total canary runs, weighted and unweighted, per artifact-kind.
- **Calibration coverage** = fraction of predictive artifacts whose stated uncertainty passes the coverage test recorded in C3 CALIBRATION checks / total (mirrors the S3 gate; S11 aggregates).
Each KPI is computed as `value = num(window) / denom(window)` with the definition version pinned; recomputation is deterministic because it reads the append-only event store, not live mutable state.

**3.3 Reward-Hacking Detector.** Composite detector over the event stream, emitting scored findings:
1. **Score-without-signature:** any consumer (esp. S4) observed using a score not traceable to a signature-valid C3 report → hard finding.
2. **Score-improves-but-checks-degrade:** S4 aggregate.score rising while INJECTION/NULL/LEAKAGE check margins fall → suspicious optimization pressure on the metric not the physics.
3. **Anomalous check-pass with anomalous input-hash reuse:** same input_hashes across "independent" cross-code checks → independence violation (join C4 lineage + C3 independence_attestation).
4. **Leakage-signature:** LEAKAGE check FAIL, or a `novel` candidate whose content overlaps the frozen contamination index version pinned in the C2 provenance_context.
5. **Blind-data touch:** any egress/read attempt toward verifier-zone handles from a sandbox (S10 event).
Findings are ranked; high-severity ones page P5 and open an S9 review.

**3.4 Cost Anomaly Detection.** Per-job spend metered from S10 budget events + model-token logs. Anomaly = spend trajectory exceeding a robust forecast (EWMA + seasonal baseline per subtopic) or an S4 loop where `Δspend` is high while `Δaggregate.score ≈ 0` over N generations (the "burning budget without improvement" signature). Emits `cost_anomaly` finding + optional advisory to S5 to pause (human-approved).

**3.5 Planted-Exploit Canary (reward-hacking ground truth).** To make reward-hacking-catch rate a *true* rate, S11 periodically (in coordination with S3, using S3's own held-out injection machinery — S11 never sees blind labels) requests injection of **known reward-hacking scenarios** (a deliberately leaked label, a trivially-recoverable planted signal, an independence-collapsed cross-code pair). It then checks that the gates caught them. Catch rate = caught planted exploits / total planted. This is the closest thing to measuring the security thesis empirically. Planted scenarios are tagged so they never contaminate real KPIs.

**3.6 Re-run Canary Comparator.** Comparator selection by `C4.kind` and `C4.lineage.determinism`:
- `deterministic` → BLAKE3 content-hash equality (must match exactly).
- `seeded`/`stochastic` with declared tolerance → statistical comparator (e.g., per-metric relative error ≤ tolerance, or two-sample KS/coverage test for distributions), tolerance read from the C4 record. Divergence beyond tolerance → `non_reproducible`.

### S11.4 Sequence flows
- **F1 — Live trace of a job:** S5 dispatches C2 → subsystems emit OTel spans with shared `trace_id` → `s11-gateway` scrubs+buffers → Tempo stores → P1 queries `/traces/{job_id}` → serving plane joins trace with C2 envelope (read) and C3 report (read) for context.
- **F2 — Streaming KPI update:** S3 publishes `validation.report_issued` → JetStream → stream processor updates validation-pass-rate rolling window (idempotent upsert by report_id) → recording rule/Postgres series updated → Grafana/API reflect within 60 s.
- **F3 — Re-run canary:** scheduler picks a sampled C4 artifact → reads lineage (S8 read) → requests S10 sandbox with pinned container digest → re-executes producer step OR calls S3 `challenge()` → comparator → writes `CanaryResult` (Postgres) + a C4 artifact to S8 → on divergence emits `non_reproducible` finding → S9 review queued (advisory).
- **F4 — Eval run on release:** CI triggers eval harness → for each task, drive Argus (C2 via S5 or C1 direct) inside instrumented run → collect produced model artifact → scoring shim reads eval vault + model output (outside sandbox) → compute score → assemble `EvalScorecard` (versioned, C4 artifact) → diff vs previous release → post regressions to P4 dashboard + alert on regression > threshold.
- **F5 — Transparency-failure detection:** on `artifact.committed` with `claim_tier>ran-toy`, detector fetches referenced C3 report (read), verifies signature validity and tier match against the trust store's registered S3 keys, checks lineage completeness → if any fails, emit `transparency_failure` finding (Sev-1, because a gate should have blocked it) + page + S9.

### S11.5 Tech choices (consistent with shared stack)
OpenTelemetry (traces/metrics/logs) → Tempo/Jaeger + Prometheus/Thanos + Grafana; PostgreSQL 16 (KPI series, findings, canary, scorecards, audit — append-only, hash-chained); OpenSearch (log/event full-text + vector where needed); NATS JetStream (durable event buffering + exactly-once KPI consumers); Rust (`s11-gateway` trust-boundary/hot path, hash-chain audit writer); Python 3.11 + pydantic-from-JSON-Schema (analytics, detectors, harnesses, canary); JAX/PyTorch/sklearn available inside eval/canary sandboxes for re-execution; TypeScript + React/Next.js (dashboards); S10 for all eval/canary execution isolation; S8 client for writing S11's own C4 outputs; mTLS + least-privilege scopes everywhere; Sigstore/cosign signature verification for C3 reports (verify-only — S11 holds no signing key).

### S11.6 Failure & degradation handling
- **Downstream (S8/S3/S5) unavailable:** KPIs that depend on it switch to `stale` state with last-known-good value + staleness banner in UI and a `data_staleness` metric; never silently serve wrong values (fail-loud NFR). Canary/eval jobs referencing the unavailable dep back off and retry with jitter; after max retries → `infra_error` (not counted as non-reproducible / not as eval failure).
- **Ingest buffer pressure:** JetStream persists; if analytics consumers lag, tail-sampling tightens (keep all error/security traces, drop more baseline) and a `ingest_lag` alert fires; no telemetry is dropped from the durable log, only from best-effort trace baseline.
- **Query plane outage:** ingest continues (buffered), so no data loss; SLO 99.5% on query plane only.
- **Scrubber failure (fail-closed):** if the scrubber cannot classify a field, it redacts by default and flags a `scrub_uncertain` event rather than forwarding possibly-sensitive data.
- **Clock skew / late spans:** lateness window + explicit `finalized_at`; completeness recomputed if a very-late span arrives, with an amendment record (append-only).
- **Detector false-positive control:** findings carry a confidence and are deduplicated; transparency/reward-hacking findings are always surfaced (never suppressed) but tagged `needs_triage` vs `confirmed`.
- **Eval vault compromise defense:** shim is the only reader, egress-restricted; any access from outside the shim identity → Sev-1 security event.
- **Self-metering:** S11's own resource use is metered like any job; if S11 observability overhead on a job exceeds the 2% budget, sampling degrades and an `observability_overhead` alert fires.

### S11.7 Data models (canonical JSON Schema draft 2020-12; pydantic/TS/serde generated)

**TraceIndexRecord (Postgres index over Tempo)**
```
{
  trace_id: string,            // OTel, == C2 job trace_id
  root_request_id: uuid, job_id: uuid, parent_job_id?: uuid, dag_node_id: string, subtopic: string,
  subsystems_observed: [ "S5"|"S1"|"S2"|"S3"|"S7"|"S10" ],
  span_count: int, error_span_count: int,
  expected_required_spans: int, observed_required_spans: int, completeness: float,   // observed/expected
  status: "complete"|"partial"|"broken",
  started_at, finalized_at, duration_ms: int, claim_tier?: string, validation_report_ref?: string
}
```

**MetricSample (Prometheus-native; mirrored labels).** Labels: `subsystem, subtopic, subagent_id, adapter_id, verifier_profile, check_type, job_id, trust_class`. Series include `s11_span_latency_ms`, `s11_adapter_eval_ms`, `s11_check_result_total{type,status}`, `s11_cost_usd_total{resource}`, `s11_model_tokens_total`, `s11_ingest_lag_seconds`, `s11_data_staleness_seconds`.

**KPIDefinition (versioned)**
```
{
  kpi_id: string, version: semver, content_hash: string,
  title, description, unit,
  numerator_query: {engine:"promql"|"sql"|"stream", expr:string},
  denominator_query?: {engine, expr},
  window: {kind:"rolling"|"calendar", size:"1h"|"1d"|"7d"|"30d"},
  slo?: {comparator:"<"|"<="|">"|">=", threshold:float, severity:"S1"|"S2"|"S3"},
  owner, tags[], created_at
}
```

**KPISample**
```
{ kpi_id, kpi_version, window_start, window_end,
  numerator: float, denominator: float, value: float,
  status: "fresh"|"stale"|"degraded", source_event_watermark: string, computed_at,
  breakdown?: {dimension:string, key:string}[] }
```

**Finding (unit of S11 detection)**
```
{ finding_id: uuid, kind:
    "broken_trace"|"transparency_failure"|"reward_hacking"|
    "cost_anomaly"|"non_reproducible"|"calibration_failure"|
    "independence_violation"|"budget_breach"|"sandbox_violation"|"eval_regression",
  severity: "S1"|"S2"|"S3", confidence: float, state: "needs_triage"|"confirmed"|"dismissed"|"resolved",
  subject: { job_id?, artifact_ref?(C4), report_ref?(C3), subagent_id?, trace_id? },
  evidence: { metric_refs[], trace_ref?, event_refs[], detail_json },
  detected_at, detector_id, detector_version, routed_to: ["s9"|"p5"|"p6"|null], audit_ref }
```

**CanaryResult**
```
{ canary_id: uuid, artifact_ref(C4), artifact_kind, determinism, method: "reexec"|"challenge",
  original_hash: string, rederived_hash?: string,
  comparator: "hash_equal"|"stat_tolerance", tolerance?: {representation, value}, divergence?: float,
  verdict: "reproducible"|"non_reproducible"|"infra_error",
  sandbox_run_ref, container_digest, seeds, cost_actual, ran_at, result_artifact_ref(C4) }   // itself written to S8
```

**EvalScorecard (written as C4 artifact to S8)**
```
{ scorecard_id: uuid, harness: "mle_bench"|"physics_recap",
  platform_build: {commit, container_digest, contract_versions{c1..c6}}, suite_version, run_id,
  tasks: [ { task_id, subtopic, metric_name, score, held_out_truth_ref(vault, opaque),
             platform_claim_tier?, expected_claim_tier?, tier_match?: bool,
             recovered: bool, cost_actual, trace_ref } ],
  aggregate: { primary_metric, value, medal_distribution?, recap_rate?,
               tier_consistency_rate?, regression_vs_prev?: float },
  ran_at, prev_scorecard_ref?, content_hash, signature? }
```

**AuditRecord (append-only, hash-chained)**
```
{ seq: bigint, prev_hash: string, this_hash: string, actor, action, target, params_redacted, at, request_id }
```

**CostAttributionRecord**
```
{ job_id, subagent_id, subtopic, dag_node_id, root_request_id,
  compute_units: float, gpu_seconds: float, model_tokens: int, cost_usd: float, budget_max_usd: float, breach: bool,
  verified_artifact_count: int,   // artifacts with valid signed C3 tier>=recap
  window_start, window_end }
```

**PlantedExploitRecord**
```
{ exploit_id, scenario: "leaked_label"|"trivial_signal"|"independence_collapse",
  injected_via: "S3_injection_channel", planted_at,
  caught: bool, caught_by_check?: string, caught_at?, excluded_from_real_kpis: true }
```

### S11.8 Public interfaces
All gRPC+REST, JSON Schema (draft 2020-12) canonical, mTLS, least-privilege scopes. S11 read-scopes on C2/C3/C4/C5/C6; write-scope only to its own Postgres/S8-C4-outputs. Namespaced `/v1/obs/*`.

**Query API (REST/gRPC)**
- `GET /v1/obs/traces/{job_id}` → `TraceIndexRecord` + span tree (Tempo passthrough). Scope: `obs.read`.
- `GET /v1/obs/traces?trace_id|root_request_id|subtopic&status=&from=&to=` → `[TraceIndexRecord]`.
- `GET /v1/obs/kpis` → `[KPIDefinition]`; `GET /v1/obs/kpis/{kpi_id}?version=&window=&from=&to=&breakdown=` → `[KPISample]`.
- `POST /v1/obs/kpis/definitions` (governance-scoped) `KPIDefinition` → new version (append-only).
- `GET /v1/obs/findings?kind=&severity=&state=&subject=&from=&to=` → `[Finding]`; `PATCH /v1/obs/findings/{id}` (triage state, governance-scoped).
- `GET /v1/obs/canary?verdict=&artifact_kind=&from=&to=` → `[CanaryResult]`; `POST /v1/obs/canary/run` `{artifact_ref|sample_policy}` (governance/SRE) → enqueue.
- `GET /v1/obs/eval/scorecards?harness=&build=` → `[EvalScorecard]`; `GET /v1/obs/eval/scorecards/{id}`; `POST /v1/obs/eval/run` `{harness, suite_version, build}` (CI/governance) → run_id.
- `GET /v1/obs/cost?groupby=subtopic|subagent|dag&from=&to=` → `[CostAttributionRecord]` + `cost_per_verified_artifact`.
- `GET /v1/obs/lineage/impact?artifact_ref=` → downstream consumers (read-only view over S8 C4 graph): `[artifact_ref, job_id, claim_tier]`.
- `GET /v1/obs/digest?date=` → daily Trust Digest (all KPIs vs SLO, open findings, canary summary, quarantined jobs).
- `POST /v1/obs/export` `{scope, from, to, format}` → signed audit bundle ref (append-only, logged).

**Events published (NATS JetStream, S11-owned subjects)**
- `s11.finding.created` / `s11.finding.updated` → `Finding`.
- `s11.kpi.slo_breach` → `{kpi_id, version, value, threshold, severity}`.
- `s11.canary.result` → `CanaryResult`.
- `s11.eval.scorecard_ready` → `{scorecard_id, harness, regression_vs_prev}`.
- `s11.alert` → routed to Alertmanager/S9.

**Events consumed (from platform bus / OTLP)**
- OTLP traces/metrics/logs from S5,S1,S2,S3,S7,S10 (via C1/C2/C3/C6 span conventions).
- `job.state_changed` (C2), `validation.report_issued` (C3), `artifact.committed` (C4), `registry.changed` (C5), `sandbox.policy_violation`/`budget.breach` (S10), `adapter.evaluated` (C6).

**Contract calls consumed (read-only)**
- S8/C4: `get_artifact(ref)`, `get_lineage(ref)`, `query_consumers(ref)` — read-only.
- S3/C3: `challenge(report_ref)` (for canary), `list_profiles()`; verify report signatures against trust store.
- S5/C2: read job/DAG state (job status, plan steps) via read endpoint; `recommend_pause(job_id|subtopic, finding_ref)` — **advisory only**, human-gated, no direct blocking authority.
- S10: request sandbox for canary/eval execution via the standard sandbox API (same as any job).
- S6/C5: `resolve()` to enumerate adapters/subagents for eval routing and independence auditing.

**CLI (`argusobs`)**
```
argusobs trace <job_id> ; argusobs kpi <kpi_id> --window 30d --breakdown subtopic
argusobs findings --kind reward_hacking --severity S1
argusobs canary run --artifact <ref> ; argusobs canary status
argusobs eval run --harness physics_recap --build <commit> ; argusobs eval diff <build_a> <build_b>
argusobs cost --groupby subtopic --from ... --to ...
argusobs digest --date today ; argusobs export --scope kpis --from ... --to ... --format ndjson
argusobs kpi-def apply <file.json> (governance)
```

---

## S12 — Interop Standard & Federation

**Co-owns contract:** **C5** (with S6). **Consumes:** C1 (S1), C4 (S8), C6 (S7), C2 (S5), C3 (S3), S10, S8 object store/signing, OTel+NATS (S11).

### S12.1 Architecture overview
S12 is a set of decoupled services + a client toolchain, all speaking only through C1..C6 and internal S12 APIs. It never imports another subsystem's internal types.

```
                       ┌─────────────────────────── Client toolchain (contributor machine) ──────────┐
                       │  argus CLI  ──uses──▶  argus-sdk (wraps S1 runtime)  ──emits──▶ C4 provenance   │
                       │      │ scaffold/lint/local-run(S10 local shim)/self-test/package/submit        │
                       └──────┼───────────────────────────────────────────────────────────────────────┘
                              │ submit (signed bundle)
                              ▼
   ┌───────────────────────────────── S12 services (control zone) ─────────────────────────────────┐
   │  (A) Standard Service        (B) Codegen Pipeline      (C) Conformance Service                 │
   │      - spec docs/versions        - JSONSchema→bindings     - orchestrates runs on S10          │
   │      - Standard Release mgr       (pydantic/TS/serde)      - Bronze/Silver/Gold batteries       │
   │      - deprecation calendar       - schema registry (C5)   - golden fixtures + oracles          │
   │                                                            - signs Conformance Record (C4)      │
   │  (D) Federation Registry Gateway (governs C5)   (E) Governance Engine (workflow)                │
   │      - submission portal API                        - review queue (Temporal + S9-style)        │
   │      - admission gate → calls S6 C5 publish         - approve/deprecate/revoke/appeal           │
   │      - identity & signature verification            - taxonomy RFC process                       │
   │      - directory/discovery/badges                   - governance ledger (append-only, C4)        │
   └──────────────┬───────────────────────┬───────────────────────┬───────────────────────┬─────────┘
                  │ C5 publish/resolve      │ C4 store/sign         │ S10 execute            │ NATS/OTel
                  ▼                         ▼                        ▼                        ▼
               S6 (C5)                    S8 (C4)                  S10 sandbox              S11
```

### S12.2 Components

**(A) Standard Service.** System of record for the *published* standard. Holds each **Standard Release** = an immutable bundle `{ release_version(semver), contracts:{C1..C6 schema @ pinned versions}, spec_docs, changelog, migration_notes, deprecation_calendar, binding_artifacts_ref(C4) }`. Serves the public docs site (Next.js) and a machine endpoint `GET /standard/{release}`. Enforces dual-serve during migration windows. Does not mutate schemas (those are the frozen JSON Schemas owned collectively at M0); it *packages, versions, and publishes* them and maintains compatibility metadata.

**(B) Codegen Pipeline.** Deterministic JSON Schema (draft 2020-12) → language bindings: pydantic v2 (Python), TypeScript types, Rust serde. Runs in CI on any Standard Release cut. Output bindings are content-addressed (C4) and referenced from the release. Includes a **compatibility checker** that diffs two schema revisions and classifies the delta as `additive-minor | breaking-major | patch` (drives semver enforcement). Publishes binding packages to internal PyPI/npm/crates mirrors, each signed (cosign) with SBOM.

**(C) Conformance Service.** The objective admission oracle for *contract behavior* (not physics). Given a submitted subagent bundle, it:
1. Verifies bundle signature + SBOM + container digest.
2. Schedules an isolated run **inside S10** (egress-denied, quota-capped) that exercises the subagent's C1 lifecycle against **golden fixtures** (synthetic C2 job envelopes, mock C3 verifier profiles, mock C6 adapters, mock C4/C8 sinks).
3. Runs the level battery and evaluates each check against a **deterministic oracle**.
4. Emits a signed **Conformance Record** (C4) with `{level, suite_version, checks[], environment_digest, pass:bool, signer_key_id, signature}`.

Levels (mirroring C1 conformance requirements):
- **Bronze:** lifecycle state-machine correctness (`REGISTERED→…→REPORTED` and terminal states), complete provenance emission (C4) for every artifact, idempotent+refusing `accept`, no egress beyond declared adapters, no self-tier-above-`recapitulated-known`.
- **Silver:** Bronze + injection/null *self-checks* wired (advisory), mandatory uncertainty tagging on outputs, correct `VERIFIER_UNAVAILABLE` refusal (no verifier → refuse), typed error envelope conformance.
- **Gold:** Silver + recursion-safety under S4 (deterministic, bounded, no reward-path writes, respects budget_token halts), cross-code participation (implements C6 adapter surface with `independence_tags`, units-mandatory, uncertainty-mandatory, `grad` iff differentiable), and reproducibility manifest sufficiency (re-run yields matching artifact hashes within declared nondeterminism tolerance).

**Mock harness (critical design choice):** Conformance uses **hermetic mocks** of C2/C3/C4/C6 so results are deterministic and independent of live subsystems. The mocks are themselves versioned within `suite_version`. This keeps conformance an *isolated, reproducible* judgment of contract behavior.

**(D) Federation Registry Gateway.** The governance-aware front door to the C5 registry. External `publish` requests do **not** go directly to S6; they go here. The Gateway performs the **admission gate**:
- identity verified (maintainer key in federation trust store),
- bundle signature valid,
- a **passing Conformance Record** exists for the claimed level and matches the descriptor's `conformance` block,
- container digest pinned & scanned,
- `trust_class` forced to `federated`, capability_scopes stripped to the federation default (no elevated grants),
- descriptor schema-valid against the current Standard Release.
On pass, it calls S6 `publish(descriptor)` (C5) and records the admission in the governance ledger. Also serves the public **federation directory/discovery** (search by subtopic/level/independence) and renders **badges**.

**(E) Governance Engine.** Durable workflows (Temporal) for the human-in-the-loop governance lifecycle: submission → automated admission checks → registrar review queue (reuses S9-style review plane pattern, but S12-owned queue for *federation* decisions) → decision. Handles deprecate/revoke/appeal, and the **taxonomy RFC process** (propose subtopic → community comment → steward decision → taxonomy version bump). All actions are written to an **append-only governance ledger** (C4 artifacts + Postgres index), signed and attributed. Revocation triggers a NATS `entity.revoked` event; S5/S6 honor C5 revocation semantics (halt in-flight jobs); S12 verifies propagation and alerts on SLA breach.

### S12.3 Key algorithms

**3.1 Semver compatibility classification (Codegen).** Given old/new JSON Schema for a contract: walk the schema tree; a change is *additive-minor* iff every new required field has a default or the field is optional and no existing field's type/enum/constraint narrowed; *breaking-major* iff any required field added without default, any type/enum narrowed, any field removed, or `additionalProperties` tightened. Deterministic tree-diff with a fixed traversal order → reproducible classification. Enforcement: a release whose declared bump is *lower* than the computed class is rejected in CI.

**3.2 Conformance run determinism.** Pin: `suite_version` (includes mock versions + fixtures), subagent container digest, and a **seed vector** injected into all randomness (fixtures, mock adapter outputs). The runner sets `PYTHONHASHSEED`, library seeds, and disables wallclock-dependent behavior in mocks (frozen clock). Oracle comparison is on canonicalized JSON (sorted keys, normalized floats to declared tolerance). Re-run canary (S11) re-executes and asserts byte-equality of the Conformance Record modulo `{issued_at, signature}`.

**3.3 Admission gate decision (Registry Gateway).** Boolean AND of independent predicates, each fail-closed with a typed reason: `sig_valid ∧ identity_trusted ∧ conformance_record_valid_and_matches_level ∧ digest_pinned_and_scanned ∧ descriptor_schema_valid ∧ scopes_are_federation_default`. Any false → `REJECTED` with `{category}` (mirrors C5 error taxonomy). Crucially, `scopes_are_federation_default` is enforced by *overwriting*, not validating, the scope set — the gate cannot be tricked into elevation.

**3.4 Revocation propagation.** On revoke: (1) S6 C5 `revoke(entity_id, reason)` (source of truth), (2) publish `entity.revoked` on NATS JetStream, (3) start a Temporal saga that polls S5 for in-flight jobs referencing the entity and confirms halt (via C2 job status), (4) if not halted within SLA (60 s), escalate Sev-2 and page. Idempotent; revocation is terminal.

**3.5 Taxonomy RFC merge.** Subtopic taxonomy is a versioned DAG (`taxonomy_id` nodes with parent edges). A proposed change is validated for acyclicity, id-uniqueness, and no-orphan; on steward approval the taxonomy version bumps (semver) and a `taxonomy.updated` event fires; existing descriptors pin the taxonomy version they were admitted under (reproducible routing).

### S12.4 Sequence flows
- **4.1 Build → Bronze (local).** `argus init` → scaffold → contributor edits → `argus conformance run --level bronze --local` → SDK spins a **local S10-shim** (same gVisor policy, offline mocks) → runs Bronze battery → prints deterministic report. No network, no submission.
- **4.2 Submit → Admit.** `argus submit` → packages signed bundle (code + container digest + descriptor draft + SBOM) → POST to Registry Gateway `/submissions` → Gateway enqueues Conformance run (Conformance Service, executes in S10) → on pass, Conformance Record (C4) signed & stored → submission enters Governance review queue → registrar approves → Gateway admission gate → S6 C5 `publish` → `entity.admitted` event → directory updated → contributor notified with badge.
- **4.3 Revoke.** Registrar (or automated abuse signal) → Governance Engine `revoke` → ledger append (signed) → S6 C5 `revoke` → NATS `entity.revoked` → propagation saga confirms S5 halts in-flight jobs → audit closed.
- **4.4 Standard Release + migration.** Maintainer opens RFC → schema delta computed (3.1) → if major, dual-serve window scheduled → `release cut` builds bindings (Codegen) → Standard Service publishes release + deprecation calendar → NATS `standard.released` → SDK/CLI advertise new target; old minor still accepted until calendar end → at end-of-window, Standard Service stops serving deprecated major (returns `VERSION_UNSUPPORTED`).

### S12.5 Tech choices (consistent with shared stack)
- **Python 3.11+** for SDK, Conformance Service checks, Registry Gateway logic; pydantic v2 models generated from schemas.
- **Rust** for the bundle-signature/SBOM verifier and the governance-ledger writer (trust-boundary + append-only, mirrors S8's Rust ledger writer choice).
- **TypeScript + React + Next.js** for the public standard docs site, federation directory, submission portal, and registrar review UI.
- **Temporal** for Governance workflows (durable, human-wait states) and conformance-run orchestration.
- **PostgreSQL 16** for submission/governance/taxonomy indexes (system of record for governance state; ledger artifacts in S8).
- **NATS JetStream** for `entity.*`, `standard.*`, `taxonomy.*`, `conformance.*` events.
- **S10 (gVisor/Firecracker)** to execute all submitted code during conformance — never on host.
- **Object store (S8, BLAKE3)** write-once for Conformance Records, governance-ledger entries, binding artifacts, Standard Release bundles.
- **JSON Schema draft 2020-12** canonical IDL; **cosign/Sigstore** for signing records, bindings, and CLI releases; **Vault/KMS** for signing keys (never in sandbox).
- **OpenTelemetry** tracing; **OpenSearch** for directory search/discovery over descriptors.

### S12.6 Failure / degradation handling
- **S6 (C5) unavailable:** Gateway queues admissions (Temporal), returns `202 pending`; conformance and review continue; publish retried with backoff. Never auto-publishes on timeout (fail-closed).
- **S10 unavailable:** Conformance runs park in `PENDING`; contributors informed; no local-only "pass" is ever accepted server-side (local passes are advisory).
- **S8 write-once bucket unavailable:** Conformance/governance actions block (cannot sign→store an unstored record = no admission). Fail-closed.
- **Conformance flakiness detected (re-run canary disagreement):** the specific check is quarantined, submission marked `INCONCLUSIVE` (never auto-pass), suite maintainers paged; a flaky suite version can be yanked.
- **Signature/identity failure:** submission `REJECTED (SCHEMA_INVALID/REVOKED)`; no execution.
- **Revocation propagation SLA breach:** escalate; the C5 revoke remains authoritative so consumers already refuse the entity; S12 only guarantees *notification*, not runtime halt (that's S5/S6).
- **Standard major-version end-of-window with stragglers:** deprecated entities move to `status: deprecated`; resolve still works but flagged; hard cutoff moves them to requiring re-conformance against the new major.
- **Taxonomy proposal conflict (two RFCs touch same node):** optimistic-concurrency on taxonomy version; second merge rebases or is rejected with conflict.

### S12.7 Security design (S12-specific)
- **Admission ≠ trust:** enforced structurally in the gate (scope overwrite, `trust_class: federated`). Test-covered.
- **All submitted code executes only in S10;** the Gateway/Conformance host never runs contributor code in-process.
- **Signing keys** for Conformance Records and governance ledger live in Vault/KMS, used by the Rust signer service, never reachable from conformance sandboxes.
- **Supply chain:** SDK/CLI releases signed + SBOM; contributors verify; server verifies submitted bundle signatures against the federation trust store.
- **Governance tamper-evidence:** append-only ledger (content-addressed, hash-chained), every action attributed to a KMS-signed registrar identity.
- **Least-privilege scopes** minted per conformance run (read fixtures, write one record) — nothing else.

### S12.8 Data models
(JSON Schema draft 2020-12 canonical; shown as annotated structures. All persisted signed artifacts are C4 ArtifactRecords in S8; Postgres holds queryable indexes.)

**StandardRelease (Standard Service, immutable, C4-stored)**
```
StandardRelease {
  release_id: uuid, release_version: semver,                 // e.g. "2.1.0"
  status: draft | current | deprecated | withdrawn,
  contracts: { c1_version, c2_version, c3_version, c4_version, c5_version, c6_version },  // pinned schema versions
  schema_bundle_ref: C4.artifact_ref,      // the JSON Schemas (content-addressed)
  binding_artifacts: [ { lang: python|typescript|rust, package, version, artifact_ref, sbom_ref, signature } ],
  spec_docs_ref: C4.artifact_ref, changelog_ref, migration_notes_ref,
  compatibility: { supersedes: [release_version], breaking_from: semver|null, min_supported_contract: {...} },
  deprecation_calendar: { deprecated_at?, dual_serve_until?, hard_cutoff_at? },
  signature, signer_key_id, created_at
}
```

**ConformanceSuiteVersion (Conformance Service, immutable)**
```
ConformanceSuiteVersion {
  suite_version: semver, standard_release_ref: release_id,        // which contracts it tests
  levels: { bronze: { checks: [check_id], budget },
            silver: { checks: [check_id], budget },
            gold:   { checks: [check_id], budget } },
  fixtures_ref: C4.artifact_ref,           // golden C2 envelopes, mock profiles/adapters
  mock_versions: { c2_mock, c3_mock, c4_mock, c6_mock },
  seed_vector: [int],                      // pinned randomness
  yanked: bool, yank_reason?, signature, created_at
}
```

**ConformanceCheck (definition)**
```
ConformanceCheck {
  check_id: string,                        // e.g. "BRZ-LIFECYCLE-STATEMACHINE"
  level: bronze|silver|gold,
  category: LIFECYCLE|PROVENANCE|REFUSAL|EGRESS|TIERING|UNCERTAINTY|ERROR_ENVELOPE|
            RECURSION_SAFETY|CROSS_CODE|REPRODUCIBILITY|UNITS|CALIBRATION_WIRING,
  description, oracle_spec: string,        // deterministic pass/fail definition
  fixture_refs: [ref], budget
}
```

**ConformanceRecord (signed, C4-stored — the admission oracle output)**
```
ConformanceRecord {
  record_id: uuid, submission_id: uuid, entity_id, entity_type: subagent|adapter,
  claimed_level: bronze|silver|gold, achieved_level: bronze|silver|gold|none,
  suite_version, standard_release_ref, subagent_container_digest: string, environment_digest: string,
  checks: [ { check_id, status: PASS|FAIL|INCONCLUSIVE, metric?, threshold?, evidence_ref(C4), duration } ],
  aggregate: { passed: bool, level_awarded },
  seed_vector, determinism_hash,           // hash of canonicalized record minus {issued_at,signature}
  issued_at, signature, signer_key_id
}
```

**SubmissionBundle (contributor-uploaded)**
```
SubmissionBundle {
  submission_id: uuid, maintainer_id, maintainer_key_id,        // federation identity
  descriptor_draft: C5.CapabilityDescriptor (unsigned, trust_class ignored on input),
  code_ref: C4.artifact_ref,               // source snapshot
  container_digest: string,                // reproducibly-built OCI image digest (pinned)
  sbom_ref: C4.artifact_ref,
  bundle_signature, target_standard_release: release_version, claimed_level, submitted_at
}
```

**FederationIdentity (governance)**
```
FederationIdentity {
  maintainer_id: uuid, display_name, contact, org?,
  public_keys: [ { key_id, alg, added_at, revoked_at? } ],   // for bundle signing
  standing: active | suspended | banned, created_at, verified_at?
}
```

**GovernanceLedgerEntry (append-only, hash-chained, C4-stored)**
```
GovernanceLedgerEntry {
  entry_id: uuid, seq: int, prev_hash: string,   // hash chain
  action: SUBMIT | CONFORMANCE_ATTACHED | APPROVE | ADMIT | DEPRECATE | REVOKE | APPEAL_OPEN |
          APPEAL_RESOLVE | TAXONOMY_PROPOSE | TAXONOMY_MERGE | IDENTITY_SUSPEND | KEY_ROTATE,
  actor: { kind: registrar|system|maintainer, id, key_id },
  subject: { entity_id?, submission_id?, taxonomy_id?, maintainer_id? },
  payload: object, reason?, conformance_record_ref?: C4.ref,
  signature, signer_key_id, created_at
}
```

**TaxonomyVersion (versioned DAG)**
```
TaxonomyVersion {
  taxonomy_version: semver,
  nodes: [ { taxonomy_id, name, description, parents: [taxonomy_id], status: active|deprecated } ],
  derived_from: taxonomy_version|null, approved_by, approved_at, signature
}
```

**SubmissionState (Postgres index; Temporal owns workflow)**
```
SubmissionState {
  submission_id, status: RECEIVED | SCANNING | CONFORMANCE_RUNNING | CONFORMANCE_PASSED |
          CONFORMANCE_FAILED | IN_REVIEW | APPROVED | ADMITTED | REJECTED | WITHDRAWN | QUARANTINED,
  conformance_record_ref?, entity_id?, rejection: { category, message }?, reviewer_id?, updated_at
}
```

**Relationships / invariants**
- A `SubmissionBundle` MUST reference a `container_digest`; conformance runs pin it into the `ConformanceRecord`.
- Admission REQUIRES a `ConformanceRecord` with `aggregate.passed=true` and `level_awarded >= claimed_level`, whose `standard_release_ref` == the target release's `current`/compatible.
- Every governance action = one `GovernanceLedgerEntry`; the chain (`prev_hash`) is verifiable end-to-end.
- Published C5 descriptor's `conformance` block MUST equal the ConformanceRecord's `{level, suite_version, passed_at, evidence_ref}` (Gateway copies, does not trust contributor's claim).
- `trust_class` on any admitted descriptor is ALWAYS `federated` (overwritten, never read from input).

### S12.9 Public interfaces

**A. `argus` CLI (contributor-facing)**
```
argus init --subtopic <taxonomy_id> [--lang python] [--level bronze|silver|gold]
        # scaffolds a compliant subagent skeleton (C1 lifecycle stubs, C6 adapter stubs if gold),
        # descriptor draft (C5), reproducible container spec, self-test wiring. Passes Bronze locally out of the box.
argus lint            # static checks: descriptor schema-valid (C5), contract-version range set, units on adapter I/O (C6)
argus build           # reproducibly builds OCI image, prints container_digest, generates SBOM
argus conformance run --level <lvl> [--local]     # runs the battery (local S10-shim if --local); deterministic report
argus conformance explain <check_id>              # shows oracle_spec + how to fix
argus package         # produces signed SubmissionBundle (code_ref, digest, sbom, descriptor_draft)
argus submit [--target-release <semver>]          # uploads bundle to Registry Gateway; returns submission_id
argus status <submission_id>                      # polls SubmissionState
argus keys gen | list | rotate                    # manage FederationIdentity signing keys
argus standard versions | show <release>          # inspect Standard Releases / migration calendar
```

**B. Registry Gateway REST/gRPC API (federation admission; governs C5)**
```
POST   /v1/submissions                → {submission_id}          (body: SubmissionBundle; 401 on bad identity/sig)
GET    /v1/submissions/{id}           → SubmissionState
POST   /v1/submissions/{id}/withdraw  → 204
GET    /v1/directory?subtopic=&level=&independence=&status=      → [PublicDescriptorView]   (search; OpenSearch)
GET    /v1/directory/{entity_id}                                 → PublicDescriptorView + badge
GET    /v1/badge/{entity_id}.svg                                 → conformance badge image
# Admission (internal path, not contributor-callable): Gateway → S6 C5 publish(descriptor)
```

**C. Conformance Service API (internal; invoked by Gateway/Temporal)**
```
POST /v1/conformance/runs   {submission_id, container_digest, claimed_level, suite_version?, seed_vector?}  → {run_id}
GET  /v1/conformance/runs/{run_id}   → {status, conformance_record_ref?}
POST /v1/conformance/records/{ref}/challenge  → re-run for S11 canary → {matches: bool, diff?}
GET  /v1/conformance/suites          → [ConformanceSuiteVersion]   (list, incl. yanked flag)
```

**D. Standard Service API**
```
GET  /v1/standard/releases                 → [StandardRelease summary]
GET  /v1/standard/releases/{version}       → StandardRelease (schemas, bindings refs, deprecation_calendar)
GET  /v1/standard/releases/current         → StandardRelease
GET  /v1/standard/bindings/{lang}/{version}→ binding package (redirect to signed artifact)
POST /v1/standard/releases  (maintainer)   {release_version, contract_versions, ...} → release_id  (CI-gated by compat checker)
POST /v1/standard/releases/{v}/deprecate (maintainer) {deprecated_at, dual_serve_until, hard_cutoff_at}
```

**E. Governance Engine API (registrar-facing; human-gated)**
```
GET  /v1/governance/queue?status=IN_REVIEW           → [SubmissionState]
POST /v1/governance/submissions/{id}/approve  {reviewer_id, notes}   → GovernanceLedgerEntry
POST /v1/governance/submissions/{id}/reject   {reviewer_id, category, message}
POST /v1/governance/entities/{entity_id}/deprecate {reason}
POST /v1/governance/entities/{entity_id}/revoke    {reason}          → triggers propagation saga
POST /v1/governance/appeals            {entity_id|submission_id, argument} → appeal_id
POST /v1/governance/appeals/{id}/resolve {decision, notes}
POST /v1/governance/taxonomy/proposals {change_set}                  → proposal_id
POST /v1/governance/taxonomy/proposals/{id}/merge {steward_id}       → taxonomy_version
GET  /v1/governance/ledger?entity_id=&since=                         → [GovernanceLedgerEntry]  (verifiable chain)
POST /v1/governance/identities              {display_name, contact, public_key} → maintainer_id
POST /v1/governance/identities/{id}/suspend {reason}
```

**F. Events (NATS JetStream, S11 consumes)**
```
standard.released         { release_version, breaking: bool, deprecation_calendar }
standard.deprecated       { release_version, hard_cutoff_at }
conformance.run.completed { run_id, submission_id, passed, level_awarded, record_ref }
conformance.suite.yanked  { suite_version, reason }
submission.received       { submission_id, maintainer_id, claimed_level }
entity.admitted           { entity_id, level, subtopics[], trust_class:"federated" }
entity.deprecated         { entity_id, reason }
entity.revoked            { entity_id, reason }                 # C5 revocation propagation trigger
taxonomy.updated          { taxonomy_version, changed_nodes[] }
governance.action         { entry_id, action, actor, subject }  # mirrors every ledger append
```

**G. `argus-sdk` (Python library, wraps S1 runtime)**
```python
class Subagent(ABC):                      # implement C1 lifecycle
    def register(self) -> CapabilityDescriptor: ...
    def accept(self, job: JobEnvelope) -> Acceptance: ...       # may refuse (first-class)
    def plan(self, job) -> Plan: ...
    def build(self, plan) -> BuildResult: ...                   # runs in S10; emits C4 provenance via sdk.provenance
    def validate(self, br) -> ValidationRequest: ...            # hands to S3; never self-grades
    def report(self) -> SubagentReport: ...
sdk.provenance.record(kind, inputs, code, env, seeds, ...) -> ArtifactRecord(C4)
sdk.adapter.Adapter(ABC): describe/evaluate/grad/batch_evaluate  # C6 surface for Gold
sdk.testing.LocalConformance(level).run() -> ConformanceReport   # local S10-shim
sdk.uncertainty.tag(value, representation)                       # mandatory tagging helper
```

**Interfaces consumed (exact contracts).** C1 (the SDK implements it; the suite tests it); C5 (Registry/Capability Descriptor + Registry API `publish/resolve/revoke/subscribe`, co-owned; Gateway calls S6's `publish`/`revoke`); C4 (all records/bindings/ledger entries stored as C4); C6 (Gold cross-code participation tested against C6); C2 (golden fixtures are C2 envelopes); C3 (mocked in conformance; `challenge` mirrors C3's re-run/audit pattern); **S10** runtime — execute submitted code; **S8** store/sign; **S11** consumes events; **S3** for Gold cross-code eligibility semantics.

---

## Consolidated Cross-Subsystem Interfaces

This section is assembled from every subsystem's declared `interfaces_produced` and `interfaces_consumed`. It is the authoritative map of how Argus's subsystems couple. All coupling is **contract-only**: the six published contracts (C1–C6) plus a small number of subsystem-internal APIs, events, CLIs, and shared schemas.

### X.1 Contract ownership & consumer map

| Contract | Owner(s) | Primary consumers |
|----------|----------|-------------------|
| **C1** Subagent Contract (SLHA-for-agents) | S1 | S5, S2 (via build), S3 (validate handoff), S4, S11, S12 |
| **C2** Task/Job Envelope + JobResult | S5 | S1, S2, S3, S4, S7, S9, S10, S11, S12 |
| **C3** Verifier Interface + Validation Report (v1.1) | S3 | S1, S2 (presence-only), S4, S5, S7, S8, S9, S11, S12 (mocked) |
| **C4** Artifact + Provenance Record | S8 | S1, S2, S3, S4, S5, S6, S7, S9, S10, S11, S12 |
| **C5** Registry / Capability Descriptor | S6 + S12 (co-owned) | S1, S2, S3, S4, S5, S7, S9, S10, S11 |
| **C6** Compute-Adapter Tool Interface | S7 | S1, S2, S3, S5 (refs/errors), S6, S10 (broker), S11 (read), S12 |

### X.2 Produced interfaces (by subsystem)

**S1 (owns C1)**
- **C1 Subagent Contract (SLHA-for-agents)** *(contract)* — canonical versioned JSON-Schema contract + gRPC/HTTP wire API for register/accept/plan/build/validate/report/heartbeat/cancel, the lifecycle state machine, and the shared typed error envelope. Consumed by S5/S2/S3/S4/S11/S12.
- **argus-subagent SDK (Subagent base class + ExecContext)** *(api)* — Python SDK: the Subagent ABC (describe/accept/plan/build hooks), framework-final validate/report/heartbeat/cancel, and the restricted ExecContext (submit_sandbox_job/emit_artifact/call_adapter/read_dataset) with no tier-set or credential access.
- **CapabilityDescriptor (C5) emission** *(schema)* — assembles, signs, and publishes the C5 CapabilityDescriptor revision (subtopics, required_adapters, resource_envelope, uncertainty_support, conformance block, contract version range, independence_tags) to the S6 registry.
- **Reference conformance suite (Bronze/Silver/Gold)** *(contract)* — executable conformance checks with deterministic oracles; consumed by S12 to admit federated subagents and reused by S1 to attest descriptors.
- **frozen_pipeline_ref (validate handoff)** *(contract)* — content-addressed C4 artifact packaging the exact pipeline (container digest, commit, config, adapter versions, seeds, input hashes) that S3 fetches and re-runs without importing subagent code.
- **S1 lifecycle events (NATS)** *(event)* — s1.lifecycle.transition, s1.subagent.registered, s1.job.refused, s1.job.quarantined, s1.artifact.emitted — consumed by S5, S11, S6, S9.
- **argus-subagent CLI** *(cli)* — init/validate-descriptor/run/conformance/replay/codegen/freeze; reused by S12's contribution tooling.

**S2 (ML Builder Engine)**
- **S2.build(plan, envelope) → BuildResult** *(api)* — executes the C1 build step; turns a C2-derived Plan into a trained, physics-aware, provenanced FrozenPipeline + BuildResult with claim_tier capped at ran-toy; raises typed C1 errors.
- **S2.build_variant(base_pipeline_ref, mutation, envelope, warm_start_ref?) → BuildResult** *(api)* — Evolver-facing deterministic variant build; reuses cached splits/features, warm-starts HPO, returns a built pipeline with NO score channel.
- **FrozenPipeline artifact (C4)** *(schema)* — self-contained deterministic S3-executable inference pipeline with predict(units-tagged)→{outputs,uncertainty}, container digest, adapters+versions, seeds, hashes, self_replay_passed; write-once.
- **BuildResult / Diagnostics / TrainingLog / UQSpec artifacts (C4)** *(schema)* — content-addressed build outputs with complete lineage, uncertainty summary, repair log, advisory self-checks, cost_actual; consumed by S1/S3/S9/S11.
- **s2.build.* events (NATS)** *(event)* — started/phase/heartbeat/repair/completed/failed/quarantined with spend and progress for S5/S11.
- **argus-s2 CLI** *(cli)* — build/build-variant/replay/explain/zoo/priors/diagnose for developers and the S12 conformance harness.
- **ModelDescriptor / PriorInjectorDescriptor / RepairPlaybookDescriptor** *(contract)* — plugin descriptors enabling model families, physics-prior injectors, and repair playbooks to be registered without S2 core changes.

**S3 (owns C3)**
- **C3 Verifier Interface + Validation Report (current v2.0; v1.1 compatibility baseline)** *(contract)* — list_profiles/verify/challenge plus the C3 debate methods run_perturbation_pair/detect_insensitivity/attest_challenger_independence over gRPC+HTTP (mTLS, scoped); returns a signed ValidationReport that is the sole admissible source of a claim tier > ran-toy and the sole admissible reward signal for S4.
- **ValidationReport (signed, current C3)** *(schema)* — signed, write-once C4 artifact: checks[], aggregate{passed,score}, claim_tier (novel is candidate-only), justification, independence_attestation, degradations, pins, signature + signer_key_id; plus the debate fields perturbation_pairs, insensitivity_flags, challenger_panel, independence_attestation_debate (debate: min_independent_challengers/lineage_disjoint/correlation_warning), referee{referee_id,non_gameable,signed_by,distinct_from_proponent}, and debate_ref (pointer into the C4 DebateLedger). The Observatory VERIFIED gate requires schema validity, every check status PASS, pass verdicts for both perturbation directions, empty insensitivity flags, and `referee.distinct_from_proponent == true`.
- **VerifierProfile registry** *(api)* — append-only versioned profile store (publish/get/deprecate/revoke, dry-run) keyed by subtopic; pinned immutably into every report.
- **Signature-verification library (argusverify)** *(contract)* — Python/Rust/TS library that recomputes the canonical form and verifies the report signature against the versioned trust store; used at every C3 consumption point.
- **Frozen-pipeline entrypoint contract** *(contract)* — standard opaque entrypoint (inputs→prediction+uncertainty, pure, no network) every C1 subagent frozen artifact must satisfy so S3 can invoke it identically inside a nested sandbox.
- **IndependenceAttestation** *(schema)* — machine-checkable attestation that a cross-code adapter is lineage/repo disjoint from the code under test; carries verdict + pinned registry revision.
- **Reward-admission spec (for S4)** *(contract)* — defines that aggregate.score is admissible only from a signature-valid report and that INCONCLUSIVE is non-improvement; supplies conformance vectors for the Evolver.
- **S3 events** *(event)* — s3.report.issued, s3.report.candidate_novel (→S9), s3.canary.alarm (→S11), s3.independence.unavailable, s3.quarantine.
- **argusverify CLI** *(cli)* — profiles list, verify, report show/verify-signature, challenge, profile author/dry-run, independence resolve, explain-tier.

**S4 (Recursive Improvement Loop / Evolver)**
- **POST /v1/evolver/jobs** *(api)* — start a durable evolution job from an EvolutionJobSpec (embedded in a C2 JobEnvelope); returns ACCEPTED with workflow handle or REFUSED (first-class) when no valid/cheap/independent verifier exists.
- **POST /v1/evolver/preflight** *(api)* — dry-run precondition gate returning admissibility, verifier validity, independence availability, cheapness, max achievable tier, estimated cost, without committing budget.
- **GET /v1/evolver/jobs/{id} (status/result/genealogy/heartbeat/generations/{n})** *(api)* — query status, terminal EvolutionResult, genealogy DAG ref, heartbeat, per-generation records.
- **POST /v1/evolver/jobs/{id}/{pause|resume|cancel|checkpoint}** *(api)* — durable cooperative control operations surviving restart, with partial-result capture on cancel.
- **EvolutionResult** *(schema)* — terminal payload in C2 JobResult: best signed report ref, seed/best score, cost_actual, cost_per_verified_improvement, reward_hack_events_count, human_review_required, genealogy_ref, refusal_reason.
- **Variant / GenerationRecord / EvolutionCheckpoint / GeneSchema** *(schema)* — content-addressed C4 schemas for genotype+phenotype, per-generation genealogy, durable checkpoints, subagent-supplied search space.
- **ChallengeRound / Attack / ChallengeVerdict / DebateLedger** *(schema)* — S4-owned content-addressed C4 schemas for the Adversarial Red-Blue Debate loop (referenced by S3 v1.1 and by C4 provenance); DebateLedger is the append-only record of all ChallengeRounds for an artifact, pointed at by the report's debate_ref.
- **select_challenger_panel / run_debate_round / evolve_under_debate** *(api)* — the debate-orchestration surface: pick a ≥K lineage-disjoint challenger panel, run one proponent/challenger/referee round, and drive the full red-blue evolution loop under the precondition gate.
- **evolver.* NATS events** *(event)* — job.accepted/refused/quarantined/completed, generation.complete, best.improved, reward_hack.detected, budget.breached, human_review.requested — consumed by S5 and S11.
- **argusctl evolver CLI** *(cli)* — start/preflight/status/pause/resume/cancel/genealogy/replay/quarantine/redteam.
- **S4 reward-integrity contract** *(contract)* — guarantee that any variant fitness or tier carried out of S4 is backed by a signature-valid C3 report with matching binding; consumers (S5/S9/S11) may rely on S4 never emitting an unsigned score or self-promoted tier.

**S5 (owns C2)**
- **C2 Task/Job Envelope + JobResult** *(contract)* — the immutable C2 envelope that routes work to subagents and the JobResult aggregated back; canonical JSON Schema with generated bindings; consumed by S1, S2, S3, S4, S7, S9, S10, S11, S12 (not S6 or S8 directly).
- **Intake & Request API (/v1/requests)** *(api)* — submit/inspect/cancel research requests with admission back-pressure (429 THROTTLED).
- **Planning API (/v1/requests/{id}/plan, /v1/dags/*)** *(api)* — decomposition, DAG inspection/edit, approval producing an inspectable DecompositionPreview before spend.
- **Execution/Job API (/v1/jobs/*)** *(api)* — envelope mint/dispatch, job status, cancel, result retrieval.
- **Recursion Governance API (/v1/recursion)** *(api)* — S4-facing surface that refuses recursion without a valid S3 verifier and enforces max-generations/max-spend bounds.
- **Operator API (/v1/admin/*)** *(api)* — concurrency-class/budget-pool config, drain, pause/resume, health.
- **Query/Audit API (/v1/audit/*)** *(api)* — routing, budget-ledger, guardrail, replay-pin histories for auditors and the S11 canary.
- **S5 NATS events (argus.s5.*)** *(event)* — request.status, job.state, routing.decided, budget.event/breach, review.opened, guardrail.blocked, backpressure.
- **RoutingDecision (signed)** *(contract)* — append-only signed record of candidates considered and selection, verifiable at every consumption point.
- **argusctl CLI** *(cli)* — command-line control of requests, DAGs, jobs, budgets, admin, audit, recursion.

**S6 (co-owns C5)**
- **s6.retrieval.retrieve / get_curated_docs / get_unit_conventions** *(api)* — hybrid RAG retrieval returning ranked chunks with CitationProvenance, curated-doc sets, unit-convention priors; index_version/date_ceiling/curated/units/license filters; reproducible retrieval_manifest_hash.
- **s6.contamination.novelty_query / recall_query / list_index_versions / freeze / get_manifest** *(api)* — frozen contamination-index API: calibrated novelty/overlap and recall against a pinned index_version, snapshot creation, manifest retrieval; primary input to S3 leakage/novelty screens.
- **C5 Registry API (publish/resolve/get_descriptor/deprecate/revoke/subscribe/resolve_independent_code)** *(api)* — capability-descriptor registry: append-only signed immutable revisions, conformance-enforced publish, routing resolve, cross-code independence resolution.
- **CapabilityDescriptor (C5 schema)** *(schema)* — authoritative machine-readable descriptor for subagents/codes/adapters/datasets/verifiers/contamination_index, incl. conformance, independence_tags, trust_class, provenance_ref.
- **SnapshotManifest (C4 artifact)** *(contract)* — immutable, signed, content-addressed manifest defining a frozen contamination index_version (included docs, embed model version, cutoff date) in a write-once bucket.
- **NormalizedDoc / Chunk / HEPDataTable / CitationProvenance (C4 + wire types)** *(schema)* — content-addressed normalized documents, indexed chunks with units metadata, typed HEPData tables, per-hit citation provenance carrying external_source_ref.
- **s6.admin.* + argusctl s6 CLI** *(cli)* — ingest/index/registry/curation operations for SRE/curators (elevated scope).
- **NATS events s6.ingest.* / s6.registry.* / s6.index.frozen / s6.curation.changed** *(event)* — lifecycle and change events for observability (S11), routing-cache invalidation (S5), and revocation propagation.

**S7 (owns C6)**
- **C6 Compute-Adapter Tool Interface (Describe/Evaluate/Grad/BatchEvaluate)** *(contract)* — the uniform, units-tagged, uncertainty-tagged, validity-guarded forward-model interface served by the Adapter Broker; owner of C6. Consumed by S1/S2/S3/S5/S12 (S4's use is C5-mediated descriptors-only, not a direct C6 consumer).
- **C6 AdapterDescriptor** *(schema)* — machine-readable adapter capability declaration (units schemas, validity domain, uncertainty model, determinism, independence_tags, differentiable, cost_class, versions) published into C5.
- **C4 per-call provenance record** *(schema)* — one ArtifactRecord per evaluate/grad pinning adapter+underlying versions, seed, input hashes, container digest, unit-registry version.
- **CalibrationEvidence artifact** *(contract)* — coverage/calibration evidence (via C4) that S3's CALIBRATION check consumes.
- **argus.s7.* events** *(event)* — adapter.registered/deprecated/revoked/health, call.metered — consumed by S5 routing caches and S11.
- **argus-adapter CLI + Adapter SDK** *(cli)* — scaffold, validate, eval, grad, register (cost-ceiling gate), calibrate, independence, cache-stats; SDK base class + unit/uncertainty/domain decorators.

**S8 (owns C4)**
- **C4 Artifact + Provenance Record** *(contract)* — canonical C4 JSON Schema (ArtifactRecord/ExternalSourceRef/DatasetRecord), versioning/compat rules, generated bindings; consumed by S1–S12.
- **CreateArtifact** *(api)* — fail-closed content-addressed write with schema+lineage+tier+hash+cycle validation and idempotent commit; returns ArtifactRef.
- **GetArtifact / GetArtifactRecord / QueryArtifacts** *(api)* — verify-on-read retrieval and filtered/paginated record queries.
- **HashBlob** *(api)* — pre-commit BLAKE3 streaming hash returning content_hash+size+canon_version.
- **VerifySignature** *(api)* — verifies a C3 report artifact's signature against active S3 keys in the trust store; returns validity+tier.
- **GetLineage / QueryImpactSet / GetReproducibilityManifest / AssertLineageComplete** *(api)* — lineage traversals, contamination/retraction impact-set, reproducibility manifest, completeness assertion.
- **RecordReproducibilityCheck** *(api)* — S11 canary callback recording re-derivation PASS/FAIL as an annotation without mutating the original record.
- **RegisterDataset / GetDataset / ResolveSplit / ListDatasetVersions** *(api)* — dataset registry with versioned families, typed splits, verifier-only blind-split label sealing.
- **RegisterExternalSource / GetExternalSource** *(api)* — immutable external-source ingestion provenance records.
- **PlaceHold / ReleaseHold / RunGC / SetRetentionPolicy** *(api)* — retention, legal/audit holds, quorum-gated GC that never collects write-once/reachable/held artifacts.
- **ExportAuditSlice** *(api)* — tamper-evident audit export with Merkle checkpoints and inclusion proofs.
- **PublishSchema / GetSchema / GenerateBindings** *(api)* — C4 schema registry publish/fetch and byte-stable multi-language binding generation.
- **S8 provenance events** *(event)* — artifact.created/promoted/flagged/tamper_detected, lineage.edge_added, hold.*, gc.swept, ledger.checkpoint, dataset.registered (at-least-once, idempotent by content_hash).
- **argusctl s8 CLI** *(cli)* — put/get/lineage/impact-set/verify-sig/hold/gc/audit-export/schema.

**S9 (Human-in-the-loop Review & Governance)**
- **S9 Intake/Orchestration API (CreateReviewTask, GET/cancel review-task, /backpressure)** *(api)* — endpoints (+ Temporal activities/signals) by which S5 creates human-review tasks over C2 wait-states, receives ReviewDecisionSignal, and reads the BackPressureGauge; idempotent and signature-verifying at intake.
- **S9 Review Workflow API (queue, assign, signoff, escalate, evidence)** *(api)* — reviewers/UI/CLI list eligible tasks, claim leases, record structured sign-offs with rationale + COI attestation, escalate, fetch aggregated C3/C4/S6/S11 evidence.
- **S9 Emission/Governance API (authorize-emission, verify, consume, guardrail evaluate)** *(api)* — mint and validate the single-use EmissionAuthorization and evaluate guardrails; the structural non-bypassable external-emission gate.
- **EmissionAuthorization token** *(contract)* — HSM-signed, single-use, scope-bound token binding exact artifact content_hashes and emission_class; MUST be verified by any external-emission actor before acting.
- **ReviewDecision & SignOff records (persisted as C4 artifacts)** *(schema)* — immutable, attributable decision/sign-off records pinning report_id, artifact hashes, contamination_index_version, policy_version; sole basis for novel-needs-human promotion (with S3).
- **GovernanceLedgerEntry + Audit API** *(contract)* — append-only BLAKE3 hash-chained, per-actor-signed governance ledger with query, verify, signed export.
- **S9 events (s9.review.*, s9.guardrail.blocked, s9.emission.authorized/completed, s9.backpressure, s9.federation.decided)** *(event)* — consumed by S5 (decisions/back-pressure), S11 (KPIs), S6/registry (federation admission outcomes).
- **argusctl s9 CLI** *(cli)* — queue, signoff, authorize-emission (WebAuthn), ledger verify, audit export, policy/budget/COI/reviewer admin.
- **S9 KPI feed** *(api)* — governance KPIs (queue depth, aging, sign-off latency, override/guardrail-block/agreement rates, emission-vs-budget) pushed to S11.

**S10 (Security, Sandbox & Runtime)**
- **Token Service API (/v1/tokens/*)** *(api)* — mint/verify/attenuate/revoke signed budget & capability-scope tokens encoding C2 budget caps and capability_scopes; offline verification via trust store. Consumed by S5 and every sandboxed subsystem.
- **Sandbox Orchestrator API (/v1/sandbox/*)** *(api)* — launch/exec/freeze/terminate/get/health for isolated execution contexts; enforces admission, digest-pin+cosign, isolation. Consumed by S1 build(), S2, S4, S3 frozen-pipeline exec.
- **Quota/Cost Service API (/v1/quota/*)** *(api)* — admit/consume/release/status/ceiling-check spend ledger across cpu/gpu/mem/wallclock/tokens/usd with the flagship-HPC ceiling guard.
- **Secrets Broker API (/v1/broker/*)** *(api)* — credentialed adapter(C6)/store(C4)/model(LLM) operations performed outside the sandbox on scope-checked requests; the only agent write path to the store.
- **Policy Service API (/v1/policy/*) + decide()** *(api)* — serve/publish signed versioned policy bundles and the pure decide(bundle,request)→Verdict driving admission.
- **Audit Ledger + Quarantine API (/v1/audit/*, /v1/quarantine/*)** *(api)* — append/verify/query the hash-chained tamper-evident trust-boundary audit log and quarantine records with S9 close-out.
- **S10 NATS events (s10.spend, s10.quota.breach, s10.security, s10.sandbox.lifecycle, s10.policy.rollout)** *(event)* — consumed by S5 (back-pressure), S9 (review), S11 (KPIs).
- **C4 launch-provenance records (ExecEnvironmentDigest)** *(contract)* — C4 ArtifactRecords capturing the full execution environment per launch via the S8 writer, enabling reproducibility and S11's re-run canary.
- **argusctl s10 CLI** *(cli)* — policy publish/diff/rollback, quota show/top, sandbox ls/inspect/kill, quarantine management, audit verify/tail, red-team run, token mint/verify.

**S11 (Observability & Evaluation)**
- **/v1/obs/* Query API (gRPC+REST)** *(api)* — read-only traces, KPIs, findings, canary results, eval scorecards, cost attribution, lineage-impact, daily digest, audit export.
- **argusobs CLI** *(cli)* — traces, KPIs, findings, canary, eval, cost, digest, export, governance kpi-def apply.
- **s11.finding.created / updated** *(event)* — findings for broken_trace, transparency_failure, reward_hacking, cost_anomaly, non_reproducible, calibration_failure, independence_violation, eval_regression, with severity/confidence/subject/evidence.
- **s11.kpi.slo_breach** *(event)* — emitted when a KPI violates its versioned SLO; routed to Alertmanager/S9.
- **s11.canary.result** *(event)* — re-run reproducibility verdict with divergence and pinned lineage.
- **s11.eval.scorecard_ready** *(event)* — completed MLE-bench-style or physics-recapitulation scorecard with regression-vs-previous-build.
- **EvalScorecard C4 artifact** *(schema)* — content-addressed scorecard in S8 recording per-task scores, tier-consistency, aggregates.
- **CanaryResult C4 artifact** *(schema)* — content-addressed re-run verdict in S8 with comparator, tolerance, divergence, sandbox run refs.
- **KPI series (KPISample) + versioned KPIDefinition registry** *(contract)* — deterministic, version-pinned platform KPIs (validation pass rate, transparency-failure rate, cost-per-verified-artifact, reward-hacking-catch rate, reproducibility rate, calibration coverage) queryable with staleness status.
- **S11 telemetry span/attribute conventions** *(contract)* — required OTel span/attribute conventions (trace_id==C2 job trace_id, subsystem/contract tags) subsystems must emit.

**S12 (co-owns C5)**
- **argus CLI** *(cli)* — init/lint/build/conformance/explain/package/submit/status/keys/standard; scaffolds a Bronze-passing subagent and drives submission.
- **argus-sdk (Python)** *(contract)* — implements the C1 subagent lifecycle and C6 adapter surface with mandatory provenance (C4) + uncertainty tagging and a local conformance harness.
- **Registry Gateway API** *(api)* — federation admission front door governing C5: POST /submissions, GET /submissions/{id}, /directory search, /badge; runs the admission gate and routes publish to S6 C5.
- **Conformance Service API** *(api)* — POST /conformance/runs, GET runs/{id}, records/{ref}/challenge, GET /suites; executes submitted code in S10 and emits signed ConformanceRecords.
- **Standard Service API** *(api)* — GET/POST /standard/releases (list/show/current/bindings/deprecate); serves versioned Standard Releases and enforces dual-serve migration windows.
- **Governance API** *(api)* — registrar/steward endpoints: queue, approve/reject, deprecate, revoke, appeals, taxonomy proposals/merge, identities, ledger query.
- **ConformanceRecord** *(schema)* — signed, write-once C4 artifact recording conformance level, suite_version, digests, per-check results, determinism_hash — the admission oracle output.
- **ConformanceSuiteVersion** *(schema)* — immutable, semver-versioned, yankable Bronze/Silver/Gold batteries, mocks, fixtures, seed vector.
- **StandardRelease** *(schema)* — immutable versioned bundle of C1..C6 schemas + docs + bindings + deprecation calendar; the published SLHA-for-agents standard.
- **GovernanceLedgerEntry** *(schema)* — append-only, hash-chained, signed record of every governance action.
- **TaxonomyVersion** *(schema)* — versioned subtopic taxonomy DAG governing argus-init subtopics and C5 descriptor taxonomy pinning.
- **FederationIdentity** *(schema)* — maintainer identity with signing keys, standing, rotation history; basis of the federation trust store.
- **S12 federation events** *(event)* — standard.released/deprecated, conformance.run.completed, conformance.suite.yanked, submission.received, entity.admitted/deprecated/revoked, taxonomy.updated, governance.action.

### X.3 Consumed interfaces (by subsystem)

**S1 consumes:** C4 (S8) — write ArtifactRecords fail-closed on incomplete lineage / illegal tier coupling, read lineage; **S10 sandbox/runtime API** — submit sandboxed OCI jobs with budget token/scopes/seeds/caps, metered results, brokered adapter proxy, egress-deny; no in-process execution; C3 (S3) — on validate(), verify(VerificationRequest) with frozen_pipeline_ref + blind handle, relay claim_tier verbatim; C2 (S5) — receive JobEnvelope, return JobResult/SubagentReport; C5 (S6/S12) — publish descriptor revisions, resolve adapter/verifier availability for accept() gate; C6 (S7) — via ctx.call_adapter invoke describe/evaluate/grad/batch_evaluate under egress allowlist + brokered credentials.

**S2 consumes:** C2 JobEnvelope + Plan (S5); C4 writer/reader (S8) — put/get with content-hash verification, write-once for frozen pipelines, fail-closed on incomplete lineage; C6 (S7) — describe/evaluate/grad/batch_evaluate for forward-model features + differentiable physics losses; C5 resolve (S6/S12) — resolve dataset/adapter descriptors, pin revisions, discover independence tags; C3 list_profiles presence-only (S3) — confirm verifier profile resolvable before building, never calls verify(); S6 curated docs/priors (RAG, read-only); S10 sandbox/egress/budget enforcement; S11 OTel sink + re-run canary consumption.

**S3 consumes:** C4 (S8) — fetch frozen pipeline/model/config/lineage by ref, write signed reports + evidence to write-once with validation_report_ref/tier coupling, and emit the DebateLedger (C4) whose ref the current C3 report carries in debate_ref; C5 (S6/S12) — resolve(query{observable, independence_needed, min_conformance}) for genuinely independent cross-code adapters; C6 (S7) — describe/evaluate/grad/batch_evaluate for CROSS_CODE + forward-model consistency, units + uncertainty mandatory, and MUST consume S7's extrapolation / out-of-validity flag and set the affected check to INCONCLUSIVE (reciprocal to S7's obligation to emit it); S6 frozen contamination index (read-only, pinned) for LEAKAGE overlap; S10 nested sandbox lifecycle for the Frozen-Pipeline Runner; Vault/KMS signer identity to the Signer process only; C2 (S5) — verifier_profile_ref + metered budget_token, C2-compatible typed errors + JobResult fields; C1 validate handoff (S1); S11 OTel/NATS + challenge() re-run canary.

**S4 consumes:** C1.build / C1.validate (S1) — drive the subagent lifecycle to train a frozen variant pipeline (build in S10 via S2) and hand the frozen pipeline to S3; S4 never trains directly; C3.list_profiles / verify / challenge (S3) — the ONLY reward source; C3 ValidationReport signed (S3) — read aggregate.score + claim_tier, verify signature, honor leakage/calibration/cross-code at admission; C4.put/get/query_lineage (S8) — persist/retrieve variants, checkpoints, LLM prompts, generation records; build genealogy DAG; enforce tier↔report coupling; C5.resolve (S6/S12) — verifier profile applicability + at least one INDEPENDENT cross-code adapter, detect revocation mid-run; C6 adapter descriptors read-only via C5 (S7) — confirm cross-code independence; S4 never calls C6 evaluate/grad (S2 does); C2 JobEnvelope/JobResult (S5) — inbound dispatch, outbound EvolutionResult, S9 wait-state on novel; S10 sandbox + budget_token + read-only trust store.

**S5 consumes:** C1 (S1) — drive subagents accept/plan/build/validate/report/heartbeat/cancel; consume Acceptance (incl. REFUSED), heartbeats, SubagentReport; respect typed error envelope; C3 list_profiles + Validation Report (S3) — bind verifier_profile_ref at plan time, read signature-valid reports as sole admissible source of tier>ran-toy and sole admissible recursion reward; C4 commit/is_committed/query_lineage (S8) — gate downstream on provenance commit, event-source lifecycle/routing/budget, query lineage for audit/replay; C5 resolve/subscribe (S6/S12) — resolve candidate subagents, subscribe to revocation/deprecation; C6 descriptors via C5 + error categories (S7) — allowed_adapters constraints, map UNITS_MISMATCH/OUT_OF_DOMAIN to failure/retry; S9 open_review / ReviewDecided; S10 capability_scopes + metered budget_token enforcement; S11 queue-depth/back-pressure signals; S4 recursion requests.

**S6 consumes:** C4 (S8) — write raw/normalized docs, embedding shards, snapshot manifests, audit records with external_source_ref, read for reindex; content-hashing + immutable/write-once buckets; S10 security/sandbox & egress-allowlist proxy for all internet-touching ingestion; C6 units contract from S7 adapter descriptors — align unit-annotation vocabulary; S12 conformance evidence — publish() requires level/suite_version/passed_at/evidence_ref; NATS JetStream (shared bus); OpenTelemetry / S11 collectors — export traces/metrics (freshness lag, latency, KPI counters).

**S7 consumes:** C4 ArtifactRecord write (S8) — fail-closed provenance per call (else PROVENANCE_UNAVAILABLE); C5 publish/resolve/deprecate/revoke/subscribe (S6/S12) — publish AdapterDescriptors, resolve independent implementations for S3 cross-code, consume revocation/deprecation; C2 budget_token semantics (S5) — metered per call; S10 sandbox/resource-limit/egress-proxy substrate for subprocess/binary backends; OpenTelemetry ingest (S11); C3 verifier profile consumption of extrapolation flags (S3) — S3 reads in_validity_domain/extrapolation_flag and treats extrapolated outputs as INCONCLUSIVE unless a profile permits.

**S8 consumes:** C3 Validation Report signed (S3) — store reports as immutable artifacts and verify signature+tier+passed to enforce the C4 tiering-coupling invariant; S10 KMS/trust store & sandbox runtime — read active/non-revoked S3 verifier keys and its own ledger signing key, mTLS identity, ensure agent sandboxes hold no ledger credentials; frozen contamination index + external snapshots (S6) — store as immutable C4, record contamination_index_version on derived artifacts; re-derivation execution / canary (S11) — S11 re-runs artifacts from S8 manifests in S10 and calls RecordReproducibilityCheck; base infra (PostgreSQL 16, S3/MinIO Object-Lock, NATS JetStream).

**S9 consumes:** C3 verify-signature / read-checks / challenge (S3) — verify report at intake and emission (TOCTOU), render checks, invoke challenge(report_ref); C4 content_hash verify + lineage graph (S8) — verify referenced hashes, render lineage DAG, persist ReviewDecision/SignOff as C4; C2 human-review wait state + back-pressure (S5) — route review requests via C2 wait-states, consume ReviewDecisionSignal + BackPressureGauge, map outcomes to JobResult status; C5 taxonomy/independence tags/federation conformance (S6/S12) — reviewer eligibility, self-review COI detection, federation admission; S6 frozen contamination index (novelty context); S11 calibration/telemetry (calibration view, KPI sink); S10 secrets/isolation substrate (Vault/KMS/HSM, mTLS) — emission-authorization signer + per-principal signing; agent-zone identities denied all S9 write paths.

**S10 consumes:** C2 (S5) — budget caps + capability_scopes to mint tokens and admit/meter/halt jobs; verifier_profile presence gates the frozen-pipeline exec profile; budget breach → C2 BUDGET halt; C4 (S8) — S8 ledger writer to emit launch-provenance + forensic-snapshot artifacts, read image/dataset refs; brokered store put/get produce/consume C4 (agents cannot write the ledger directly); C5 (S6/S12) — read adapter descriptors to validate broker targets, enforce cost_class ceiling, select independent cross-code adapters; C6 (S7) — Secrets Broker invokes adapter evaluate/grad on behalf of sandboxed code; KMS/Vault (base infra); Kubernetes + cgroup v2 + gVisor/Firecracker + NVIDIA MIG/DCGM (base infra).

**S11 consumes:** C4 read (S8) — read artifacts, lineage, consumer closure for transparency detection, reproducibility canary, lineage-impact, cost verification; writes its OWN scorecard/canary outputs as C4 but never mutates others'; C3 read + challenge (S3) — read signed reports for KPIs + transparency/reward-hacking detection, call challenge(report_ref), coordinate injection channel for planted-exploit catch-rate; C2 read + recommend_pause advisory (S5) — read job/DAG state + plan steps, issue human-gated advisory pause recommendations with no direct blocking authority; C1 drive-for-eval (S1) — drive subagents in MLE-bench-style and physics-recapitulation harnesses; C6 read for eval/independence (S7); C5 read (S6/S12) — resolve for eval routing + independence auditing, observe registry.changed; S10 sandbox + budget/security events — run all canary/eval execution in the sandbox with no elevated trust, consume sandbox.policy_violation + budget.breach; OTLP telemetry from all instrumented subsystems (S1/S2/S3/S5/S7/S10).

**S12 consumes:** C1 (S1) — the SLHA-for-agents lifecycle standardized, wrapped in argus-sdk, tested by the conformance suite; C5 Registry / Descriptor + Registry API (S6) — co-owns C5; the Gateway calls S6's publish/resolve/revoke/subscribe and enforces conformance-gated admission (forcing trust_class=federated, federation-default scopes); C4 (S8) — all StandardReleases, bindings, ConformanceRecords, ledger entries, fixtures are content-addressed C4 stored write-once with lineage; C6 (S7) — Gold cross-code participation tested against C6; C2 (S5) — golden conformance fixtures are C2 job envelopes (incl. null verifier_profile_ref cases); revocation saga reads C2 job status; C3 (S3) — mocked in conformance, challenge/re-run pattern mirrors C3, Gold independence recording feeds S3 cross-code selection; S10 Security/Sandbox Runtime — all submitted code executes only inside S10 (local harness uses an equivalent offline shim); S3-compatible object store & signing (S8) — write-once buckets, BLAKE3, cosign/KMS kept out of sandboxes; OTel + NATS JetStream (S11) — emit traces/events for federation KPIs, re-run canary, flaky-suite detection.

### X.4 Structural invariants enforced across the interface fabric

These invariants are the load-bearing guarantees that the contract fabric makes real. Each is enforced at more than one point (defense in depth):

1. **No verifier, no run.** A job with an unresolvable `verifier_profile_ref` is refused at the S1 `accept()` gate, refused again at S2 SpecCompiler, and the S4 precondition gate never enters the loop. (C1, C2, C3.)
2. **Claim tier sourced only from a signed C3 report.** S1 `report()` reads `claim_tier` solely from the C3 `ValidationReport`; there is no code path for a subagent-supplied tier. S8 refuses to commit any artifact with `claim_tier > ran-toy` lacking a signature-valid, tier-matching C3 report (`ILLEGAL_TIER`). S4 reward is admissible only from a signature-valid, binding-matched report. (C1, C3, C4.)
3. **novel-needs-human is a candidate, never final-external.** S3 emits it only as a candidate; S9 dual/quorum sign-off + guardrail ALLOW + a single-use HSM-signed EmissionAuthorization is the sole path to any external artifact; the four enforced non-goals are hard-blocked regardless of role. (C3, S9.)
4. **Fail-closed provenance.** Every artifact write goes through the S8 C4 writer with complete lineage or is refused (`INCOMPLETE_LINEAGE`); agents cannot write the ledger directly (only via the S10 brokered store-writer). (C4, S10.)
5. **Cross-code independence is machine-checked.** S3 requires an `IndependenceAttestation` (lineage/repo-disjoint via C5) for the top tier; absence caps the tier and is surfaced as `INDEPENDENCE_UNAVAILABLE`, never hidden. (C3, C5, C6.)
6. **Recursion is bounded by a cheap external verifier.** S4's cheapness/independence/existence precondition gate is the structural defeat of unguarded self-improvement loops; budget breach halts the loop mid-flight (freeze-before-terminate). (S4, S10.)
7. **Strict sandboxing + metered budgets.** All agent/variant/federated code runs only in S10 (gVisor/Firecracker, read-only rootfs, egress-deny, seccomp); the metered `budget_token` and least-privilege `capability_scopes` are enforced at every call; secrets never enter a sandbox. (C2, S10.)
8. **Reproducibility & tamper-evidence.** Content addressing (BLAKE3), Merkle-chained ledgers (S8, S9, S10), and the S11 re-run canary + `challenge()` make every claim re-derivable and every trust-boundary action auditable. (C4, C3, S11.)
9. **Admission ≠ trust.** Federated entities are admitted by S12 only via a passing ConformanceRecord, with `trust_class` overwritten to `federated` and scopes stripped to the federation default; C5 revocation propagates and consumers halt in-flight references. (C5, S12.)
10. **Bidirectional perturbation + insensitivity, both directions.** A claim passes only when the must-react probe recovers a planted KNOWN-REAL signal proportionally AND the must-not-react probe (noise/shuffle/contamination) does not manufacture a signal AND no insensitivity (invariance-to-a-should-react-perturbation) is detected; the three conditions are recorded in the current C3 `perturbation_pairs[]` + `insensitivity_flags[]`. (C3, S3, S4.)
11. **Non-gameable referee, referee ≠ proponent.** The debate REFEREE is the S3 verifier, oracle-backed and signed, and NEVER the same agent as the PROPONENT (Builder subagent); S3 fails closed if `referee.distinct_from_proponent` is false (a builder cannot self-attest), and emission of any such artifact is blocked at the S9 gate (X-16). (C3, S3, S9.)
12. **Challenger independence is machine-checked.** The challenger panel must be ≥K and lineage-disjoint (cross-code) via `attest_challenger_independence`; correlated/collusion-prone panels raise `correlation_warning` and are refreshed each round. (C3, C5, S3, S4.)
13. **C3 field flow S4 → S3 → C4.** S4 (proponent + challenger panel) drives each debate round; S3 (referee) adjudicates and emits the signed current C3 ValidationReport with the debate fields; the DebateLedger of all ChallengeRounds is persisted to C4 provenance and pointed at by `debate_ref`. (S4, C3, C4.)
14. **Extrapolation reciprocity S7 ↔ S3.** S7 MUST emit an extrapolation / out-of-validity flag in its C6 tool result and S3 MUST consume it and set the affected check to INCONCLUSIVE (unless a profile explicitly permits); enforced at both the producer (S7) and consumer (S3) ends. (C6, C3.)

---

*End of Technical Design.*
