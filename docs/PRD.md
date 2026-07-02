# Project Argus — Product Requirements Document (PRD)

> Part of the Project Argus design set. Start at README.md for the doc map and reading order. Related docs: Architecture.md, PRD.md, TechDesign.md, Backlog-and-Interfaces.md, TestPlan.md, Roadmap.md.

> A verifier-gated, agent-built ML foundry for fragmented theoretical-particle-physics and particle-cosmology research.

**Document status:** Complete implementation design (not an MVP).
**Scope:** Product overview, cross-cutting thesis and non-goals, then one section per subsystem (S1–S12) with goals, personas, user stories, and full functional / non-functional requirement tables.

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Core Thesis](#2-core-thesis)
3. [Non-Goals (Platform-Wide)](#3-non-goals-platform-wide)
4. [Design Principles](#4-design-principles)
5. [Claim Tiering](#5-claim-tiering)
6. [Published Contracts (C1–C6)](#6-published-contracts-c1c6)
7. [Subsystem Dependency Map](#7-subsystem-dependency-map)
8. [Subsystem PRDs](#8-subsystem-prds)
   - [S1 — Subagent Framework & Contract (SLHA-for-agents)](#s1--subagent-framework--contract-slha-for-agents)
   - [S2 — ML Builder Engine](#s2--ml-builder-engine)
   - [S3 — Physics Validation & Verifier Framework](#s3--physics-validation--verifier-framework)
   - [S4 — Recursive Improvement Loop (Evolver)](#s4--recursive-improvement-loop-evolver)
   - [S5 — Control Tower / Orchestration (总台)](#s5--control-tower--orchestration-总台)
   - [S6 — Knowledge & Ingestion](#s6--knowledge--ingestion)
   - [S7 — Physics Compute Adapters](#s7--physics-compute-adapters)
   - [S8 — Data, Artifact & Provenance](#s8--data-artifact--provenance)
   - [S9 — Human-in-the-loop Review & Governance](#s9--human-in-the-loop-review--governance)
   - [S10 — Security, Sandbox & Runtime](#s10--security-sandbox--runtime)
   - [S11 — Observability & Evaluation](#s11--observability--evaluation)
   - [S12 — Interop Standard & Federation](#s12--interop-standard--federation)

---

## 1. Product Overview

**Argus** is a verifier-gated, agent-built ML foundry for fragmented theoretical-particle-physics and particle-cosmology research. The domain is a chain of loosely-coupled subtopics — for example, the electroweak phase transition → the stochastic gravitational-wave background it sources → the Higgs-sector observables that constrain it. Each subtopic is scientifically deep but poorly served by ML, because the scarce people are those who are simultaneously domain experts **and** ML engineers.

Argus's product is the **automated ML-engineer half** of that pairing. Rather than trying to discover physics directly, Argus builds, trains, validates, and iterates ML models for each physics subtopic under a discipline of external verification and mandatory human sign-off. A central **Control Tower (总台)** orchestrates a federation of standardized domain **subagents**, each of which conforms to a published contract ("SLHA-for-agents"). Every ML artifact is gated by a **Physics Verifier** before it is trusted, and nothing external leaves the platform without a human decision.

---

## 2. Core Thesis

- **ML extracts information humans cannot see; an agent by itself only automates human labor.** Therefore the agent's job is **not** to discover physics directly, but to be an **automated ML researcher** that **builds, trains, validates, and iterates** ML models for each physics subtopic. The scarce bottleneck in this field is people who are **both** domain experts **and** ML engineers; Argus supplies the "ML-engineer half".
- **Each physics subtopic is served by a domain subagent** that conforms to a standardized contract ("SLHA-for-agents"). A central **Control Tower (总台)** orchestrates a federation of subagents.
- **Every ML artifact is gated by a physics verifier** — injection tests, held-out / null tests, cross-code consistency, physical-consistency checks, and leakage / contamination screens. **Recursion** (self-improvement of an ML pipeline) is allowed **only** under a cheap external verifier. Nothing is trusted without validation.
- **Every claim is tiered:** `ran-toy` / `recapitulated-known` / `novel-needs-human`. **Human sign-off is mandatory** before any external artifact.

---

## 3. Non-Goals (Platform-Wide)

These are explicitly **out of scope** for the entire platform. Individual subsystems restate and mechanically enforce the ones they own.

- **NG-A — No autonomous discovery/confirmation of new fundamental theory.**
- **NG-B — No autonomous submission of papers to venues.**
- **NG-C — No autonomous configuration/execution of flagship HPC simulations** (numerical relativity, large hydro). Compute is scoped to lightweight solvers, emulators, differentiable surrogates, and ML training.
- **NG-D — No claiming of empirical validation.** The empirical arbiter is a real experiment / observation, which is out-of-band and years away.

---

## 4. Design Principles

- **Oracle-gated autonomy** — autonomy is permitted only where an external oracle can check the result.
- **Verify-before-trust** — nothing an agent produces is trusted until an independent verifier signs off.
- **Claim-tiering** — every output is labelled `ran-toy` / `recapitulated-known` / `novel-needs-human`.
- **Full provenance & reproducibility** — every artifact is content-addressed and re-derivable from its lineage.
- **Strict sandboxing of agent-executed code** — agent code is presumed adversarial and physically isolated.
- **Breadth-over-depth near-term** — cover the many subtopics that have no ML today; do not try to beat the specialist on the flagship problem.
- **Human-in-the-loop mandatory** — a human gate precedes any external artifact.
- **Decoupled subsystems** — subsystems communicate only through published contracts.

---

## 5. Claim Tiering

Argus assigns exactly one **claim tier** to every result, and the tier is load-bearing across the whole trust stack:

| Tier | Meaning | Who may assign it |
| --- | --- | --- |
| `ran-toy` | A pipeline ran and produced output on toy/known inputs; no external validation of correctness. | A subagent / builder may self-report at most this tier. |
| `recapitulated-known` | The pipeline reproduces an established, held-out result under the verifier's checks. | The **S3 verifier only**, via a signed Validation Report. |
| `novel-needs-human` | A **candidate** result absent from the frozen contamination corpus, passing leakage and cross-code independence gates. | Marked **candidate** by **S3**; finalized only by a human via **S9**. |

**Structural invariants:** a subagent can never self-promote above `recapitulated-known`; `recapitulated-known` requires a signature-valid S3 report whose tier matches; `novel-needs-human` is never emitted as a *final external* label by any automated component — it requires S3 candidacy **plus** an S9 human sign-off.

**Adversarial-debate strengthening:** a claim that *survives* the S4 "Adversarial Red-Blue Debate Evolution" — passing both the MUST-REACT and MUST-NOT-REACT perturbation probes with no insensitivity detected, adjudicated by a non-gameable referee (S3, distinct from the proponent) against an independent (lineage-disjoint) challenger panel — carries a strengthened tier. Surviving debate does **not** create a new tier and never bypasses the S9 human gate; rather, it is the evidentiary basis recorded in the C3 v1.1 ValidationReport (via `perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, `debate_ref`) that justifies raising a claim to `recapitulated-known` or marking a `novel-needs-human` **candidate**. A claim that fails either perturbation direction, or that a challenger shows to be insensitive to data (memorized / constant / spurious-feature), cannot hold a tier above `ran-toy`.

---

## 6. Published Contracts (C1–C6)

Subsystems couple only through these versioned, language-neutral contracts (canonical JSON Schema draft 2020-12, with generated pydantic / TypeScript / Rust-serde bindings; semver with additive-minor / breaking-major and dual-serve migration windows).

| Contract | Name | Primary owner | Purpose |
| --- | --- | --- | --- |
| **C1** | Subagent Contract ("SLHA-for-agents") | S1 | Subagent lifecycle methods, envelope fields, typed error envelope. |
| **C2** | Task / Job Envelope | S5 | Job identity, DAG node, budget, constraints, verifier profile ref, capability scopes. |
| **C3** (v1.1) | Validation Report (verifier interface) | S3 | Verifier requests + cryptographically signed Validation Reports. **v1.1 (additive, backward-compatible; frozen at v1.1 from M0)** adds six ValidationReport fields for adversarial red-blue debate: `perturbation_pairs[]` ({perturbation_id, kind: "must_react"\|"must_not_react", expected, observed, verdict}), `insensitivity_flags[]` ({perturbation_id, reason}), `challenger_panel[]` ({challenger_id, code_lineage_hash, independence_class}), `independence_attestation_debate` ({min_independent_challengers, lineage_disjoint, correlation_warning}), `referee` ({referee_id, non_gameable, signed_by, distinct_from_proponent}), and `debate_ref` (pointer into the C4 provenance DebateLedger). C3 also documents the C3↔S7 extrapolation reciprocity: S7 emits an extrapolation/out-of-validity flag in its C6 tool result, and S3 consumes that flag and sets the affected check to INCONCLUSIVE. |
| **C4** | Artifact + Provenance Record | S8 | Content-addressed artifacts, lineage/reproducibility manifests. |
| **C5** | Capability Descriptor + Registry | S6 (co-owned with S1/S7/S12) | Machine-readable catalog of subagents, codes, adapters, datasets, verifiers. |
| **C6** | Compute-Adapter Tool Interface | S7 | Uniform, units- and uncertainty-tagged forward-model calls. |

---

## 7. Subsystem Dependency Map

Argus is deliberately layered so that trust flows upward from a zero-dependency bedrock. **S8** (data/provenance) and **S10** (security/sandbox) sit at the bottom with no Argus-internal dependencies. **S1** (subagent framework) depends only on S8 and S10. Everything else (S2, S3, S4, S5, S6, S7, S9, S11, S12) couples through the published contracts, never through another subsystem's internals. This inversion is what lets many teams build in parallel.

| Layer | Subsystems | Notes |
| --- | --- | --- |
| Bedrock (zero Argus-internal deps) | S8, S10 | Data plane and security substrate. |
| Contract substrate | S1, S6, S7 | Subagent framework, registry/knowledge, adapters. |
| Verification & optimization | S3, S2, S4 | Verifier oracle, ML builder, evolver. |
| Orchestration & governance | S5, S9 | Control tower, human gate. |
| Cross-cutting | S11, S12 | Observability/eval (read-only), interop/federation. |

---

## 8. Subsystem PRDs

Each subsystem PRD below is self-contained: product summary, goals, non-goals, personas, user stories, functional requirements (every `FR` id included), and non-functional requirements.

---

## S1 — Subagent Framework & Contract (SLHA-for-agents)

**One-liner:** The SDK, runtime, and standardized C1 contract every domain subagent implements — lifecycle state machine, capability descriptor emission, sandboxed execution context, provenance emission, and conformance requirements — sitting at the bottom of Argus's trust stack so all other subsystems couple to it only through published contracts.

### S1.1 Product Summary

S1 owns **C1 (the Subagent Contract, "SLHA-for-agents")** plus the SDK and runtime that make the contract executable. It is the substrate that turns "a domain expert's ML idea for one physics subtopic" into a **federated, interchangeable, provenance-emitting, sandbox-confined, verifier-gated unit of work**. S1 defines and enforces the lifecycle `REGISTERED → ACCEPTED → PLANNING → BUILDING → VALIDATING → REPORTED` (with terminals `FAILED`, `REJECTED`, `QUARANTINED`), the `CapabilityDescriptor` (C5), the sandboxed execution context (bridging to S10), the provenance-emission discipline (bridging to S8), and the conformance levels (Bronze / Silver / Gold) that S12 admits against.

S1 is deliberately at the **bottom of the dependency stack**: it depends only on **S8** (provenance / artifact store, C4) and **S10** (sandbox / runtime). It does **not** depend on S5, S2, S3, or S4 — those depend on S1. This inversion is what lets twelve teams build in parallel.

### S1.2 Goals

- **G1 — One contract, many subagents.** A single, versioned, language-neutral contract so any subtopic subagent is interchangeable and routable by S5, gradable by S3, and evolvable by S4 without bespoke glue.
- **G2 — A batteries-included SDK.** A Python SDK (`argus-subagent`) that reduces "implement a conformant subagent" to filling in domain hooks; the framework supplies the state machine, provenance wiring, sandbox marshaling, budget metering hooks, error envelopes, and heartbeat/cancel plumbing.
- **G3 — Structural trust, not trust-by-instruction.** The runtime makes it *impossible* for subagent code to (a) self-assign a tier above `recapitulated-known`, (b) run code outside the S10 sandbox, (c) egress outside declared adapters, or (d) emit an artifact without a complete reproducibility manifest.
- **G4 — Refusal is first-class.** `accept()` may legitimately refuse (out-of-scope, missing adapter, budget-too-small, no valid verifier); refusal is a normal outcome, never an error.
- **G5 — Complete provenance by construction.** Every artifact produced through the SDK carries a C4 lineage record automatically; a subagent cannot "forget" provenance because the write path is the only path.
- **G6 — Conformance is executable.** Bronze / Silver / Gold levels map to concrete, machine-checkable behaviors the S12 conformance suite exercises; S1 provides the reference test harness those levels are defined against.
- **G7 — Deterministic, event-sourced lifecycle.** Every transition is event-sourced to the provenance ledger so any job's history is queryable and replayable.

### S1.3 Non-Goals (S1-specific)

- Does **not** grade work (S3), orchestrate DAGs or own budgets (S5), run the AutoML search (S2), run the recursion loop (S4), implement the sandbox kernel / syscall broker (S10 does; S1 consumes it), or own the artifact store internals (S8 does; S1 writes through C4).
- Is **domain-agnostic plumbing** — it does not define new physics.
- Does **not** decide claim tiers above `recapitulated-known` — it structurally *forbids* self-promotion and only relays the S3-assigned tier.

### S1.4 Personas

- **P1 — Internal subtopic author (Argus ML engineer).** Writes a first-party subagent (e.g. electroweak-phase-transition). Wants the SDK to handle everything except the domain-specific plan/build hooks.
- **P2 — Federated contributor (external physicist).** Uses the public SDK + CLI (shipped by S12, built on S1) to author a subagent, run the conformance suite locally, and submit for admission. Runs in the same untrusted zone; gains no elevated trust.
- **P3 — Control Tower (S5, machine consumer).** Calls `register/accept/plan/build/validate/report/heartbeat/cancel` over the C1 wire API; needs stable semantics, typed errors, idempotency, and refusal handling.
- **P4 — Physics Verifier (S3, machine consumer).** Receives `ValidationRequest` handles and *frozen pipeline* references from S1; must be able to fetch and re-run the frozen pipeline without importing subagent code.
- **P5 — Evolver (S4, machine consumer).** Drives repeated `build`/`validate` cycles on pipeline variants under S1's sandbox and provenance discipline.
- **P6 — Conformance / Federation engineer (S12).** Consumes S1's reference conformance harness and level definitions to admit external subagents.
- **P7 — Platform SRE / auditor.** Queries lifecycle event streams, replays a job from its provenance, investigates quarantines.

### S1.5 User Stories

- **U1 (P1):** As an internal author, I subclass `Subagent`, implement `plan()` and `build()` domain hooks, declare my `CapabilityDescriptor`, and the framework gives me a conformant Bronze subagent with zero provenance boilerplate.
- **U2 (P1):** As an author, when my `build()` throws, the framework runs bounded auto-repair attempts, captures each attempt's provenance and diagnostics, and, if still failing, transitions to `FAILED` with a typed error and full logs.
- **U3 (P3):** As the Control Tower, I `accept()` a `JobEnvelope`; if the subagent lacks a required adapter it returns `accepted:false, reason:MISSING_ADAPTER` and I route elsewhere — no exception, no retry storm.
- **U4 (P3):** As the Control Tower, I call `accept()` twice with the same `job_id` (retry after a network blip) and get the identical `Acceptance` (idempotent).
- **U5 (P4):** As the Verifier, I receive a `frozen_pipeline_ref` from `validate()`, fetch it from content-addressed storage, and re-run it in my own zone with blind data — the subagent never sees my labels.
- **U6 (P2):** As a federated contributor, I run `argus-subagent conformance --level silver` locally and see exactly which behaviors pass/fail before submitting.
- **U7 (P5):** As the Evolver, I request a variant `build()` with a new hyperparameter config; the framework produces a fresh artifact with a `derived_from` edge to the prior and a distinct content hash.
- **U8 (P7):** As an auditor, I query the lifecycle event log for `job_id=X` and replay the exact sequence of transitions, spend, and artifacts.
- **U9 (P1):** As an author, I try to set `claim_tier = "novel-needs-human"` in my report; the SDK rejects it at construction time with a policy error — I *cannot* ship a self-promoted novel claim.
- **U10 (P3):** As the Control Tower, I `cancel(job_id)` a long build; the subagent stops cooperatively, captures partial provenance, and transitions to `FAILED(category=CANCELLED)` within the declared grace period.

### S1.6 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-S1-01 | Canonical C1 JSON Schema | P0 | Define C1 (all lifecycle method request/response shapes, envelope fields, typed error) as canonical JSON Schema draft 2020-12, versioned with semver. This is the single source of truth for the contract. |
| FR-S1-02 | Multi-language binding codegen | P0 | Generate pydantic v2, TypeScript, and Rust serde bindings from the C1 schema in CI; fail the build on any drift between schema and generated code. |
| FR-S1-03 | Semver compatibility gate | P0 | Provide a schema-diff tool that classifies changes as additive-minor vs breaking-major and enforces semver on publish; consumers accept any compatible minor version (ignore unknown fields), reject incompatible major with VERSION_UNSUPPORTED. |
| FR-S1-04 | Event-sourced lifecycle FSM | P0 | Implement the REGISTERED→ACCEPTED→PLANNING→BUILDING→VALIDATING→REPORTED state machine with terminals FAILED/REJECTED/QUARANTINED; every transition event-sourced to Postgres and mirrored to the S8 provenance ledger. |
| FR-S1-05 | Legal-transition enforcement | P0 | Reject any illegal state transition with a POLICY error (non-retryable); the legal transition table is static and authoritative. |
| FR-S1-06 | Deterministic replay | P0 | Reconstruct current state as a pure fold over the event log; identical logs yield identical state; used for restart recovery and auditor replay. |
| FR-S1-07 | Idempotent methods | P0 | register, accept, report, and cancel are idempotent keyed by (job_id, method, request_hash); duplicate calls return the stored prior result. |
| FR-S1-08 | Cooperative cancellation & heartbeat | P1 | cancel() sets a cooperative flag, SIGTERMs the sandbox, waits a grace window, hard-kills, captures partial provenance, transitions to FAILED(CANCELLED); heartbeat() reports status/progress/spend. |
| FR-S1-09 | SDK base class with domain hooks | P0 | Provide the Subagent base class where authors implement only describe/plan/build (and optionally extend accept); the framework provides the rest, with trace/budget/provenance/sandbox wrapping. |
| FR-S1-10 | Refusing, idempotent accept() with default gate | P0 | Ship a default accept() implementing the gate algorithm (version, subtopic, adapter, verifier-present, budget) that returns first-class REFUSED outcomes; refusal is never an error. |
| FR-S1-11 | Automatic provenance emission (fail-closed) | P0 | Every artifact emitted through ctx.emit_artifact carries a complete C4 lineage block; a missing required field refuses the write (INCOMPLETE_LINEAGE) and commits nothing. |
| FR-S1-12 | Uncertainty tagging (Silver+) | P1 | Provide helpers that require every predictive artifact and forward-model call to carry calibrated uncertainty; a bare point estimate is rejected at Silver+ conformance. |
| FR-S1-13 | Sandbox marshaling (no direct exec) | P0 | All build/train/model-generated code executes via the S10 sandbox; the SDK forbids direct in-process execution (build-time lint + runtime Sev-1 on bypass). |
| FR-S1-14 | Egress allowlist from declared adapters | P0 | Derive the network egress allowlist as the intersection of the subagent's declared required_adapters and the job's allowed_adapters plus the content store; default-deny everything else. |
| FR-S1-15 | No-secret guarantee in sandbox | P0 | The marshaler never places secrets into the sandbox; adapters needing credentials are invoked through the S10-brokered proxy outside the sandbox. |
| FR-S1-16 | Structural tier-promotion prevention | P0 | There is no code path by which a subagent can self-assign a claim_tier above recapitulated-known; report() sources claim_tier ONLY from the S3 ValidationReport, and novel-needs-human is never emitted as final-external by S1. |
| FR-S1-17 | validate() always defers to S3 | P0 | validate() is framework-final and non-overridable; it freezes the pipeline and hands off to S3; any subagent self-grade is advisory-only and cannot set a tier. |
| FR-S1-18 | Policy/sandbox errors quarantine | P0 | POLICY and SANDBOX category errors are terminal, fully logged, never auto-retried, and transition the job to QUARANTINED with a forensics-frozen sandbox image. |
| FR-S1-19 | CapabilityDescriptor (C5) emission & validation | P0 | Emit and validate the C5 descriptor from author declarations plus framework-derived fields; publish an immutable signed revision to the S6 registry. |
| FR-S1-20 | Conformance attestation block | P1 | Include the conformance block (level, suite_version, passed_at, evidence_ref, expires_at) produced by the reference harness in the emitted descriptor. |
| FR-S1-21 | Reference conformance harness | P0 | Provide executable Bronze/Silver/Gold conformance checks that S12 reuses to admit federated subagents; each check has a deterministic pass/fail oracle. |
| FR-S1-22 | Frozen-pipeline packaging | P0 | On validate(), package the exact pipeline (container digest, commit, config, adapter versions, seeds, input hashes) into a content-addressed frozen_pipeline_ref that S3 can fetch and re-run without importing subagent code. |
| FR-S1-23 | OTel tracing & lifecycle events | P1 | Every method emits a child span of the incoming trace_id; every transition emits a NATS lifecycle event consumed by S5/S11. |
| FR-S1-24 | Typed error envelope & CLI | P1 | Implement the shared typed error envelope (code, category, message, retry_after, provenance_ref) and ship the argus-subagent CLI (init, validate-descriptor, run, conformance, replay, codegen, freeze). |

### S1.7 Non-Functional Requirements (S1-scoped, aligned to global NFRs)

| ID | Property | Requirement |
| --- | --- | --- |
| NFR-01 | Reproducibility | Every artifact the SDK emits carries a lineage block sufficient for bit-for-bit (or declared-tolerance) re-derivation; validated by S11's re-run canary. S1 guarantees the manifest is *complete-or-fail-closed*. |
| NFR-02 | Isolation | The SDK NEVER executes model-generated or training code in the subagent's own process; it always marshals to S10. A direct-exec bypass is a build-time lint failure and a runtime Sev-1. |
| NFR-03 | Trust integrity | The SDK cannot construct a `SubagentReport` with `claim_tier > ran-toy` unless it carries a `validation_report_ref` to a signature-valid C3 report whose tier matches. |
| NFR-04 | Contract compatibility | The runtime accepts any message valid under a compatible *minor* version; rejects incompatible *major* with a typed `VERSION_UNSUPPORTED`. |
| NFR-05 | Latency | `accept()` and `plan()` (no heavy compute) respond within seconds (p95 ≤ 3s excluding adapter/registry round-trips). `build`/`validate` are async/durable and may be long. |
| NFR-06 | Determinism of lifecycle | Given the same event log, replaying yields the same state; transitions are pure functions of (current_state, event). |
| NFR-07 | Observability | Every method emits a distributed trace span child of the incoming `trace_id`; lifecycle transitions emit NATS events. |
| NFR-08 | Idempotency | `register`, `accept`, `report`, and `cancel` are idempotent keyed by `(job_id, method)`. |
| NFR-09 | Provenance completeness | 100% of artifacts emitted through the SDK have a complete, queryable lineage; a broken edge is non-promotable and flagged (fail-closed on write via C4). |
| NFR-10 | Security | No secret ever enters the SDK's in-sandbox surface; adapter credentials are brokered by S10 outside the sandbox; all inter-subsystem C1 calls are mTLS + least-privilege scopes. |

### S1.8 Scope Boundaries with Adjacent Subsystems (contract seams)

- **→ S8 (C4):** S1 writes ArtifactRecords and reads lineage; never touches S8 internals.
- **→ S10:** S1 requests sandboxed execution and receives resource-metered results; never implements isolation itself.
- **← S5 (C2):** S1 receives `JobEnvelope`, returns `JobResult`/`SubagentReport` shapes; S5 owns the DAG.
- **← S3 (C3):** S1 hands off `frozen_pipeline_ref` + artifacts; receives back a `validation_report_ref`.
- **← S4:** drives repeated build/validate through S1's SDK.
- **← S2:** runs *inside* the S1 lifecycle/sandbox; S1 exposes the `build()` hook S2 plugs into.
- **↔ S6/S12 (C5):** S1 emits the descriptor; S6 registry stores it; S12 admits against conformance.
- **↔ S7 (C6):** S1's egress allowlist is derived from a subagent's declared `required_adapters`; S1 does not implement adapters.

---

## S2 — ML Builder Engine

**One-liner:** The automated-ML-researcher core inside a subagent that turns a C2 problem spec into a trained, physics-aware, fully-provenanced model via physics-aware feature engineering, model synthesis/selection, AutoML/HPO, training orchestration, and failure diagnosis/auto-repair — building candidates for the external verifier (S3) to grade, never self-grading.

### S2.1 Mission & Positioning

S2 is the "ML-engineer half" of Argus made concrete: the AutoML brain that lives *inside* a domain subagent (S1) and executes the `build(Plan) -> BuildResult` step of the C1 lifecycle. Given a Job Envelope (C2) describing a physics subtopic, target observable, inputs schema, success criteria, budget, and required verifier profile, S2 produces one or more trained, documented, uncertainty-tagged candidate models plus a complete reproducibility manifest (C4), and hands the *frozen pipeline* to S3 for grading. S2 **never** assigns a claim tier above `ran-toy` and **never** grades its own work; it optimizes only against cheap *advisory* self-checks and, when driven by the Evolver (S4), against **signed** S3 reports it receives back through the loop.

S2's differentiator vs. a generic AutoML library is *physics-awareness*: units/dimensions are first-class, physical priors (symmetries, positivity, unitarity, known asymptotic limits) are injected as feature constructors, model-architecture constraints, loss terms, and post-hoc gates; forward models are called through C6 adapters (with mandatory uncertainty) both for feature generation and for physics-informed training targets; every predictive artifact carries a calibrated uncertainty representation.

### S2.2 Goals

- **G1 (Breadth-first competence):** Produce a competitive trained model for the long tail of subtopics that have no ML today, favoring robust classical/tabular baselines (scikit-learn/XGBoost/LightGBM) before deep nets; escalate model complexity only when justified by held-out gain.
- **G2 (Physics-aware by construction):** Enforce units/dimensions, inject symmetry/positivity/unitarity/limit priors as features, constraints, and losses; reject dimensionally-inconsistent pipelines before training.
- **G3 (Uncertainty is first-class):** Every model output carries a calibrated uncertainty representation; a bare point estimate is a build failure.
- **G4 (Reproducible & provenanced):** Every artifact (dataset split, feature set, model, training log, config) is content-addressed with a complete C4 lineage sufficient for bit-level (or declared-tolerance) re-derivation.
- **G5 (Auto-repair & fail-loud):** Diagnose common training failures (divergence, NaNs, OOM, degenerate metrics, leakage smell) and attempt *bounded, logged* repairs; on exhaustion, quarantine with full diagnostics rather than degrade silently.
- **G6 (Verifier-ready, self-grade-free):** Emit a frozen, deterministic pipeline artifact S3 can independently execute; expose only *advisory* self-checks; recursion (S4) accepts reward only from signed C3 reports.
- **G7 (Budget-disciplined):** Operate within hard C2 budget caps (compute/GPU-seconds/model-tokens/wallclock/cost), meter spend continuously, and halt cleanly on breach with partial-result capture.
- **G8 (Sandbox-native):** All training/eval executes inside the S10 sandbox with no egress beyond declared C6 adapters and the content-addressed store.

### S2.3 Non-Goals

- **Not a verifier:** never runs injection/null/cross-code/leakage gates as authoritative (may pre-screen as advisory only). No claim-tier promotion.
- **Not an orchestrator:** does not build DAGs across jobs (that's S5); operates within a single C2 job.
- **Not a flagship-HPC runner:** forward models come only from C6 adapters within the platform cost ceiling; S2 never configures numerical relativity / large hydro.
- **Not a data ingestor:** raw corpus ingestion is S6; S2 consumes datasets by C4 ref.
- **Not the sandbox:** isolation/quotas/secrets are S10; S2 assumes and respects them.

### S2.4 Personas

- **P1 — Domain Subagent (machine consumer, primary):** the C1 subagent that calls S2's `build`. Wants a reliable, budget-bounded build with clean provenance and a frozen pipeline.
- **P2 — Evolver / S4 (machine consumer):** proposes pipeline variants and needs S2 to build+train them deterministically so signed S3 scores can drive selection.
- **P3 — Control Tower / S5 (indirect):** meters cost, expects heartbeats/cancellation, budget-breach halts.
- **P4 — Physics-ML Researcher (human, via S9/S11):** inspects the build report, feature rationale, uncertainty calibration plots, and repair log to judge trustworthiness.
- **P5 — S2 Platform Engineer (internal maintainer):** extends the model zoo, feature constructors, physics-prior library, and repair playbooks.
- **P6 — External Federated Contributor (via S12):** builds a subagent that embeds or replaces S2 components and must pass the conformance suite.

### S2.5 User Stories (selected)

- **US1:** As a subagent, I call `build(plan)` with a C2-derived Plan and receive a `BuildResult` with artifact refs, a training log ref, diagnostics, and a frozen-pipeline ref within budget — or a typed, quarantined failure.
- **US2:** As a subagent building an electroweak-phase-transition surrogate, S2 injects dimensionless combinations (e.g. α, β/H) as features honoring units, and rejects any feature that is dimensionally inconsistent before training.
- **US3:** As the Evolver, I submit a variant spec (change model family, feature subset, HPO budget) and get a deterministically re-trainable pipeline whose only reward comes from a signed S3 report.
- **US4:** As a researcher, I open the build report and see: chosen model family and why, HPO trace, physics-prior gates applied, an uncertainty calibration (coverage) plot, and every auto-repair action taken.
- **US5:** As S5, when a job exceeds `max_gpu_seconds`, S2 halts within a bounded grace window, captures the best-so-far checkpoint as a partial artifact, and returns a `BUDGET` typed error.
- **US6:** As a platform engineer, I register a new model family or physics-prior constructor via a plugin descriptor without changing S2 core.
- **US7:** As a subagent, S2's advisory self-checks flag a probable leakage smell (target-correlated feature with suspicious AUC) and *refuse to raise tier*, surfacing it so S3's authoritative LEAKAGE check is expected to catch it.
- **US8:** As the Evolver, I request warm-started HPO seeded from a prior generation's best trial to converge faster within budget.

### S2.6 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-1 | Units algebra & dimensional validation | P0 | Attach a dimension vector to every input/target/feature; reject dimensionally inconsistent constructed features before training. Every feature carries a derived, checked dimension. |
| FR-2 | Physics-prior feature injection | P0 | Pluggable injectors emit dimensionless groups (Buckingham-π), symmetry-invariant features, positivity/monotonicity transforms, asymptotic-limit anchors, and forward-model-derived features via C6 (with propagated uncertainty). |
| FR-3 | Deterministic replayable FeatureGraph | P0 | Feature engineering is a content-addressed DAG that is serialized into the frozen pipeline and replays identically at inference. |
| FR-4 | Pluggable model zoo | P0 | Model families are registered via descriptors declaring task types, cost class, differentiability, native-UQ, and constraint hooks; new families added without core changes. |
| FR-5 | Complexity-escalation selection | P0 | Start from classical baselines; escalate to deep/physics-informed models only on statistically significant held-out gain and remaining budget. |
| FR-6 | Physics-constraint model hooks | P1 | Attach constraints as architecture (monotonic/non-negative outputs), loss terms (symmetry/unitarity penalties via differentiable C6 surrogate), and post-hoc gates. |
| FR-7 | Multi-objective HPO/AutoML | P0 | Optuna+Ray Tune search over {held-out score, calibration error, cost} with ASHA pruning and a policy selection from success_criteria. |
| FR-8 | Warm-start HPO for recursion | P1 | Seed HPO from a prior generation's completed trials to accelerate S4 variant builds within budget. |
| FR-9 | Budget-derived search sizing | P0 | HPO/train/package budgets are apportioned from C2 caps with reserves; search stops cleanly when budget is exhausted. |
| FR-10 | Backend-abstracted training runtime | P0 | JAX/PyTorch/sklearn/XGBoost/LightGBM backends behind one trainer with seeded determinism, checkpointing, early stopping, and mixed precision. |
| FR-11 | Continuous budget metering & halt | P0 | Meter GPU-seconds/wallclock/model-tokens/cost in near-real-time; halt within a bounded grace on breach, capturing best-so-far checkpoint. |
| FR-12 | Checkpoint/restart durability | P1 | Long training survives restarts via checkpointed workflow state (Temporal activity + object-store checkpoints). |
| FR-13 | First-class uncertainty representation | P0 | Every predictive artifact carries a calibrated uncertainty (interval/covariance/samples/quantiles/GP posterior); a bare point estimate is a build failure. |
| FR-14 | Coverage calibration & validation | P0 | Calibrate via conformal/quantile/native methods and validate empirical coverage against nominal on a held-out split; store calibration map in the frozen pipeline. |
| FR-15 | Failure diagnosis | P0 | Detect NaN/divergence/OOM/degenerate/slow-convergence/leakage-smell/adapter-error/calibration-fail symptoms from training telemetry. |
| FR-16 | Bounded auto-repair | P0 | Apply bounded, budget-charged, logged repairs with short probe re-trains and loop detection; quarantine on exhaustion. |
| FR-17 | Frozen-pipeline packaging for S3 | P0 | Serialize a self-contained, deterministic, S3-executable pipeline with predict() signature, pinned container digest, adapters, seeds, hashes; run a self-replay before emitting. |
| FR-18 | Per-artifact provenance emission | P0 | Every artifact written via the C4 writer with complete lineage; fail-closed on incomplete lineage. |
| FR-19 | Advisory-only self-checks | P0 | Non-authoritative injection/null/dimensional/leakage/calibration pre-screens that may only lower confidence or trigger repair, never raise a claim tier. |
| FR-20 | Deterministic variant-build API for Evolver | P0 | build_variant() applies a mutation spec deterministically, reuses cached splits/features by hash, warm-starts HPO, and returns a built pipeline with no score channel. |
| FR-21 | Fail-loud quarantine & degradation | P0 | On any gate failure, adapter disagreement handled advisory, repair exhaustion, non-repro freeze, or budget breach, halt into a fully-logged quarantined state. |
| FR-22 | Self-grade prohibition enforcement | P0 | No code path sources a reward from a non-C3 signal or assigns claim_tier > ran-toy; violations are fail-closed policy errors. |
| FR-23 | Group/temporal leakage-safe splitting | P1 | When grouping/temporal keys are declared, splits are group- or time-aware to prevent naive train/test overlap. |
| FR-24 | Explainability report | P1 | Produce a human-readable build report (model choice rationale, HPO trace, priors applied, calibration plot, repair log) for S9/S11 consumption. |
| FR-25 | Contract-version tolerance | P1 | Accept any minor-compatible C1/C2/C4/C6 message; ignore unknown fields; reject unsupported major versions with a typed error. |

### S2.7 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR-1 | Reproducibility | Every artifact re-derivable from its C4 lineage; nondeterministic kernels declared with a statistical tolerance; a re-run of the frozen pipeline on the same inputs matches within tolerance (validated by S11 re-run canary). |
| NFR-2 | Isolation | All S2 execution inside S10; no egress except declared C6 adapters + content store; no secrets in-process. |
| NFR-3 | Self-grade prohibition | S2 emits no claim tier > `ran-toy`; any code path that could source a reward from a non-C3 signal is a policy violation and is fail-closed. |
| NFR-4 | Budget | Hard caps honored; spend metered in near-real-time; halt on breach; cost-per-build reported. |
| NFR-5 | Uncertainty completeness | 100% of predictive artifacts carry a calibrated uncertainty representation. |
| NFR-6 | Latency | Planning-adjacent build setup returns within seconds; training/HPO are async, durable, and survive restarts via checkpointed state. |
| NFR-7 | Scalability | A single build can fan HPO trials across Ray workers up to the job's concurrency class; hundreds of concurrent builds platform-wide. |
| NFR-8 | Determinism control | Seeds captured globally and per-library; deterministic-mode flag; nondeterminism sources enumerated in provenance. |
| NFR-9 | Observability | Every build emits an OTel trace spanning feature-eng → model-select → HPO → train → package, with per-phase spend and metrics. |
| NFR-10 | Security | Contract calls mTLS + least-privilege scopes; adapter calls via brokered C6 endpoints; write-once for frozen pipelines referenced by reports. |
| NFR-11 | Contract compatibility | Accepts any minor-compatible C1/C2/C4/C6 message; unknown fields ignored. |

---

## S3 — Physics Validation & Verifier Framework

**One-liner:** The load-bearing external oracle: runs injection, null/negative-control, cross-code, physical-consistency, leakage, and calibration checks on frozen agent pipelines and emits a cryptographically signed Validation Report (C3) that is the sole admissible source of a claim tier above `ran-toy` and the sole admissible reward signal for recursion.

### S3.1 Purpose & Thesis Alignment

S3 is the structural heart of Argus's "verify-before-trust" wager. Nothing an agent produces is trusted until S3 signs a Validation Report. S3 is *external* to and *unreachable from* the agent execution zone: it runs as a separate service, with its own identity and signing key, fetches its own inputs from content-addressed storage (S8/C4), holds blind/held-out test data the subagent cannot see, and never imports or in-processes subagent code. S3 is simultaneously (a) the claim-tier authority (`ran-toy` < `recapitulated-known` < `novel-needs-human`, candidate-only for the top tier) and (b) the reward function for the Evolver (S4). Both roles depend on the same invariant: a score/tier is admissible ONLY if it comes from a signature-valid C3 report.

### S3.2 Goals

- **G1:** Provide a stable, versioned verifier interface (C3) that accepts a `VerificationRequest{frozen_pipeline_ref, artifact_refs, profile_ref, blind_dataset_handle}` and returns a signed `ValidationReport`.
- **G2:** Implement six check families as independently versioned, sandboxed, deterministic-where-possible plugins: INJECTION, NULL_CONTROL, CROSS_CODE, PHYSICAL_CONSISTENCY, LEAKAGE, CALIBRATION.
- **G3:** Assign claim tiers by fixed, auditable rules; guarantee monotonicity (tier can only be raised by passing a defined gate); never let a subagent self-assign `novel-needs-human`.
- **G4:** Guarantee verifier independence — cross-code checks use at least one physics code (S7/C6) implemented independently of the one under test; the verifier process shares no code/credentials/memory with the graded subagent.
- **G5:** Emit reproducible, signed, write-once reports whose signature covers a canonical serialization; support `challenge()` re-audit for the S11 re-run canary.
- **G6:** Be cheap enough to serve as the S4 reward oracle: each declared profile completes within its budget; expose `cost_estimate` before running.
- **G7:** Fail loud and quarantine — any independence violation, signing failure, budget breach, or gate anomaly halts into a logged, reviewable state rather than degrading silently.

### S3.3 Scope (In)

- The C3 verifier service (owner of contract C3): `list_profiles`, `verify`, `challenge`, plus profile registry.
- Six check-family plugin engines and their shared execution harness (frozen-pipeline runner, blind-data manager, tolerance/statistics library).
- Verifier profiles: named, versioned bundles of checks + thresholds + independence requirements, keyed by subtopic.
- Claim-tiering rule engine (deterministic tier assignment from check outcomes).
- Report canonicalization, signing (cosign/Sigstore-style, keys in vault/KMS), signature verification library shipped to all consumers.
- Independence resolver: queries the registry (C5) to select genuinely independent cross-code adapters.
- Blind/held-out/injection/null dataset vault (verifier-zone-only), with delivery-as-opaque-input semantics.
- Cross-code consistency engine invoking forward models via S7/C6.
- Calibration/coverage statistics engine.
- Leakage/contamination screen against the frozen contamination index (S6).
- Degradation policy engine (INDEPENDENCE_UNAVAILABLE → tier downgrade, INCONCLUSIVE handling).

### S3.4 Scope (Out / Non-Goals)

- **N1:** Does NOT build, train, or repair models (that is S2). S3 only runs a *frozen* pipeline as an opaque callable/artifact.
- **N2:** Does NOT grade itself; does NOT depend on S2/S4 (the things it grades) — preserves independence.
- **N3:** Does NOT promote to `novel-needs-human` as a *final* external label; it only marks a *candidate* that S9 must sign off. External emission is S9's gate.
- **N4:** Does NOT run flagship HPC; cross-code adapters are bounded by the C6 cost ceiling (enforced at S7 registration, re-checked by S3 at profile compile time).
- **N5:** Does NOT claim empirical validation; the empirical arbiter is out-of-band.
- **N6:** Does NOT ingest external corpora (that is S6); it consumes the *frozen* contamination index by pinned version only.

### S3.5 Personas

- **P1 — Subagent runtime (S1/C1):** submits `validate()` → S3 `verify()`, consumes the signed report reference in its `report()`.
- **P2 — Evolver (S4):** reads `aggregate.score` from a signature-valid report as its ONLY reward; treats INCONCLUSIVE as non-improvement.
- **P3 — Control Tower (S5):** references `verifier_profile_ref` in every C2 envelope; a null/unavailable profile forces subagent refusal.
- **P4 — Human reviewer (S9):** reads the report to judge a `novel-needs-human` candidate; is the sole external promoter with S3.
- **P5 — Observability/eval (S11):** runs the re-run canary via `challenge()`, computes validation-pass-rate and reward-hacking-catch-rate KPIs.
- **P6 — Verifier-profile author (physics domain expert, internal or S12-federated):** authors/reviews profiles and thresholds for a subtopic; needs a profile DSL, dry-run, and conformance harness.
- **P7 — Security/audit (S10/S9):** audits independence attestations, signing-key usage, and quarantine events.

### S3.6 User Stories

- **U1:** As a subagent, I submit a frozen pipeline and get back a signed report telling me which checks passed and my claim tier, so I never self-grade.
- **U2:** As the Evolver, I score a variant only from a signed report, so reward hacking via self-reported scores is structurally impossible.
- **U3:** As a profile author, I declare "for EWPT→GW spectrum, require INJECTION recovery within 10%, NULL false-positive rate <1%, CROSS_CODE agreement within combined 2σ, and dimensional consistency", and the platform enforces it verbatim.
- **U4:** As the verifier, when no independent cross-code exists for observable O, I surface INDEPENDENCE_UNAVAILABLE and cap the achievable tier rather than silently passing.
- **U5:** As a human reviewer, I open a candidate-novel report and see every check, its evidence artifact, the pinned contamination-index version, and the independence attestation, so I can sign off responsibly.
- **U6:** As S11, I re-run a prior report via `challenge()` and confirm bit-level (or within-tolerance) reproducibility, catching verifier nondeterminism or tampering.
- **U7:** As security, I confirm the verifier holds a signing key the sandbox cannot reach and that any write attempt to the verifier's mounts is a Sev-1.
- **U8:** As a leakage screen, I detect that a model's "novel" result overlaps the frozen index and downgrade it, so memorization cannot masquerade as novelty.

### S3.7 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-01 | Verifier interface (C3) implementation | P0 | Implement list_profiles, verify, challenge over gRPC+HTTP with mTLS and capability-scope authorization; verify() fetches all inputs itself from S8 by content-addressed ref and never runs subagent code in-process. |
| FR-02 | Signed Validation Report emission | P0 | Assemble, canonicalize (RFC 8785 JCS or deterministic CBOR), and sign every report with a verifier key from vault/KMS; write to a write-once bucket before returning; embed signature + signer_key_id + issued_at. |
| FR-03 | INJECTION check family | P0 | Inject known signal of known amplitude per a profile injection grid + noise model; run frozen pipeline; require recovery within tolerance and calibrated residual z; deterministic given seeds. |
| FR-04 | NULL_CONTROL check family | P0 | Run pipeline on signal-free and label-shuffled inputs; estimate false-positive rate at the pipeline's own threshold; PASS iff FPR below profile alpha with a binomial upper bound. |
| FR-05 | CROSS_CODE check family | P0 | Compare the pipeline/forward-under-test against ≥1 independently-implemented S7/C6 adapter across validity-domain points; apply chi-square/z agreement within combined uncertainty; exclude out-of-domain points; require independence attestation. |
| FR-06 | PHYSICAL_CONSISTENCY check family | P0 | Enforce dimensional/units correctness (units algebra over the C2 units_contract), positivity, unitarity/normalization bounds, symmetry invariance/covariance under declared group elements, and correct asymptotic limits; each sub-gate independently reported. |
| FR-07 | LEAKAGE / contamination screen | P0 | Detect train/test overlap (MinHash/LSH near-duplicate), target leakage (permutation/MI probe), and overlap with the frozen contamination index (S6) via vector+lexical query at a pinned index version; FAIL blocks novelty. |
| FR-08 | CALIBRATION check family | P0 | Compute coverage of stated uncertainty intervals and PIT uniformity (KS test) on known-truth points; reject overconfident/underconfident predictions per profile tolerance. |
| FR-09 | Deterministic claim-tiering engine | P0 | Compute claim_tier from check outcomes via fixed, auditable, monotone rules; never assign novel-needs-human as final (candidate only, requires S9); record claim_tier_justification with exact rules fired. |
| FR-10 | Independence resolver | P0 | Query the C5 registry to select cross-code adapters whose lineage/repos/independence_tags are disjoint from the code-under-test; emit an IndependenceAttestation or INDEPENDENCE_UNAVAILABLE with a tier cap. |
| FR-11 | Blind-data vault & opaque delivery | P0 | Store injection/null/held-out/recap/blind datasets in a verifier-zone-only vault; deliver only opaque inputs to the frozen pipeline; retain truth server-side for scoring; hash-verify integrity before use. |
| FR-12 | Frozen-pipeline runner in nested sandbox | P0 | Execute the frozen pipeline (container digest + entrypoint) inside a disposable S10 sandbox with egress-deny, read-only rootfs, and resource caps; capture (prediction, uncertainty) with per-call provenance; the grading logic and blind labels stay outside this sandbox. |
| FR-12b | Frozen-pipeline entrypoint contract | P0 | Define and enforce a standard opaque pipeline entrypoint (inputs→prediction+uncertainty, pure, no network) so any C1 subagent's frozen artifact is invocable identically by the runner. |
| FR-13 | Verifier profile registry | P0 | Append-only, versioned store of VerifierProfile revisions with checks, thresholds, independence & determinism policy, cost estimate, and review signatures; profiles are immutable per revision and pinned into reports. |
| FR-14 | Reward-for-recursion semantics | P0 | Expose aggregate.score only from signature-valid reports; INCONCLUSIVE counts as non-improvement (never reward); provide the signature-verification library so S4 cannot accept scores from any other source. |
| FR-15 | Challenge / re-audit | P0 | Re-run a prior report from its pins (check_suite_version, contamination_index_version, seeds, environment_digest); require bit-exact match for deterministic checks and within-tolerance for stochastic; raise a canary alarm + quarantine on mismatch. |
| FR-16 | Degradation handling & reporting | P0 | Represent INDEPENDENCE_UNAVAILABLE, out-of-domain exclusions, budget breach, and INCONCLUSIVE as first-class degradations[] with explicit tier_effect; never silently pass a capped result. |
| FR-17 | Signature-verification library (multi-language) | P0 | Ship a Python/Rust/TS library that recomputes the canonical form and verifies the signature against the trust store; used at every consumption point; rejects unsigned/tampered reports. |
| FR-18 | Cost estimation & budget enforcement | P1 | Return per-profile cost_estimate from list_profiles; meter spend via the C2 budget_token during verify; halt on breach with partial-result capture and BUDGET error. |
| FR-19 | Recapitulation-benchmark gate | P1 | For known subtopics, include a held-out established-result benchmark check that must PASS before recapitulated-known tier is granted; the held-out result is verifier-zone-only. |
| FR-20 | Statistics library | P1 | Provide seeded, pure implementations of tolerance tests, chi-square/z agreement, coverage/PIT calibration, false-positive-rate binomial bounds, bootstrap CIs, and Benjamini-Hochberg multiple-comparison correction, shared across check families. |
| FR-21 | Profile-author tooling & dry-run | P1 | Provide a profile DSL/schema, dry-run against gold/known-bad fixtures (no signature), and a profile conformance harness that verifies thresholds behave sanely (gold passes, known-bad fails). |
| FR-22 | Observability & KPIs | P1 | Emit OTel spans across resolve→stage→run→check→tier→sign; emit validation-pass-rate, reward-hacking-catch-rate, transparency-failure-rate, cost-per-verified-artifact; publish report/canary/quarantine events on NATS. |
| FR-23 | CLI (argusverify) | P2 | Provide profiles/verify/report/challenge/profile-author/independence/explain-tier commands for operators and profile authors, all going through the same C3 API and signature lib. |
| FR-24 | Multiple-comparison / statistical rigor guard | P1 | When many injection/cross-code points are tested, apply multiple-comparison correction and report family-wise/false-discovery-controlled thresholds so a large point count cannot manufacture spurious PASS/FAIL. |
| FR-25 | Quarantine & fail-closed | P0 | On signing failure, blind-data hash mismatch, sandbox write-attempt, or independence-policy violation, halt into a fully-logged quarantined state and emit s3.quarantine; never emit an unsigned or degraded-but-unlabelled report. |
| FR-PR01 | Bidirectional perturbation oracle (must-react + must-not-react) | P0 | Implement `run_perturbation_pair(model_ref, perturbation_spec) -> PerturbationResult` running BOTH directions: a MUST-REACT probe plants a KNOWN-REAL signal and requires the claim to recover it proportionally (amplitude-linearity) — absence is FAIL (blind/insensitive); a MUST-NOT-REACT probe injects noise / shuffled labels / fake-contamination and requires the claim to NOT manufacture a signal and to degrade appropriately — a strong result surviving unchanged is FAIL. A claim passes only when BOTH directions pass. Populates the C3 v1.1 `perturbation_pairs[]` field ({perturbation_id, kind, expected, observed, verdict}). [maps S3-TPR2] |
| FR-PR02 | Insensitivity detector | P0 | Implement `detect_insensitivity(model_ref, perturbation_set) -> InsensitivityReport`: flag INSENSITIVITY when a result is invariant to a perturbation it should have reacted to (not data-driven: memorized / constant / spurious-feature). Any insensitivity flag blocks a PASS regardless of other checks and is recorded in the C3 v1.1 `insensitivity_flags[]` field ({perturbation_id, reason}). A claim passes only when both perturbation directions pass AND no insensitivity is detected. [maps S3-TPR3] |
| FR-PR03 | Challenger-independence attestation (lineage-disjoint cross-code) | P0 | Implement `attest_challenger_independence(challenger_ids[]) -> IndependenceAttestation`: query the C5 registry to confirm the challenger panel is lineage-disjoint (disjoint repos/forks/derived_from and non-overlapping independence tags) across code lineages, detect correlated challengers, and emit `independence_attestation_debate` ({min_independent_challengers, lineage_disjoint, correlation_warning}) and `challenger_panel[]` ({challenger_id, code_lineage_hash, independence_class}) into the C3 v1.1 report. Correlated/insufficiently-independent panels cap the achievable tier. [maps S3-TPR5] |
| FR-PR04 | Non-gameable referee enforcement | P0 | The referee that adjudicates a ChallengeVerdict is the S3 verifier itself: oracle-backed, NON-GAMEABLE, signed, and NEVER the same agent as the proponent (the builder). Enforce `distinct_from_proponent=true` and `non_gameable=true`; a builder self-attestation is rejected and emission is blocked. Populates the C3 v1.1 `referee` field ({referee_id, non_gameable, signed_by, distinct_from_proponent}). [maps S3-TPR4] |

### S3.8 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR1 | Independence (hard) | Verifier process shares no code/creds/memory with the graded subagent; cross-code uses ≥1 independently-implemented code. Violations fail closed. |
| NFR2 | Trust integrity | Every report is signed over a canonical serialization; unsigned/tampered → treated as failure + quarantine. Ships a signature-verification lib to all consumers. |
| NFR3 | Reproducibility | A report is re-derivable from its pins (check_suite_version, contamination_index_version, input_hashes, environment_digest, seeds) within declared tolerance; enforced by `challenge()` canary. |
| NFR4 | Latency/cost | A single profile completes within its declared budget (typically minutes); `cost_estimate` returned by `list_profiles`; hard budget enforcement via C2 `budget_token`. |
| NFR5 | Durability | Reports written to write-once bucket, ≥11 nines durability, immutable/append-only. |
| NFR6 | Calibration | Reject results whose stated uncertainty fails a coverage test; calibration is itself a check family. |
| NFR7 | Scalability | Hundreds of concurrent verify jobs; profile & report lookups scale to 10^5+ reports without degradation. |
| NFR8 | Determinism policy | Checks declare determinism class; nondeterministic kernels carry a declared statistical tolerance used by the canary. |
| NFR9 | Security | Signing keys in vault/KMS, never in the sandbox; mTLS between subsystems; blind data never delivered as labeled data. |
| NFR10 | Auditability | Every check emits an evidence artifact (C4) and every tiering decision records its justification and the exact rule fired. |

---

## S4 — Recursive Improvement Loop (Evolver)

**One-liner:** A verifier-gated evolutionary optimizer that iteratively proposes, trains, and selects ML-pipeline variants for a physics subtopic — scoring EVERY variant solely from a cryptographically-signed external S3 Validation Report, refusing to run without a valid cheap verifier, and defeating reward-hacking, runaway spend, and diversity collapse by construction.

### S4.1 Problem & Thesis Alignment

Argus's wager is that ML extracts information humans cannot, and that recursive self-improvement of an ML pipeline is the highest-leverage capability in the foundry — and simultaneously the highest-risk, because an optimizer will reward-hack any measurable proxy it can reach. S4 is the subsystem that makes recursion **safe by construction**: it runs an AlphaEvolve-style propose→train→score→select loop over ML pipelines for a physics subtopic, but the ONLY admissible score is `aggregate.score` from a signature-valid C3 Validation Report produced by the external S3 verifier. S4 holds no reward function of its own, cannot see held-out/blind test data, and refuses to start unless a valid, cheap-to-evaluate verifier profile exists for the target (the "cheap-verifier precondition"). It is the structural embodiment of the design principle *reward comes only from a signed oracle*.

### S4.2 Goals

- **G1 — Oracle-gated optimization.** Improve a subtopic's ML pipeline against a fixed objective where "improvement" is defined exclusively by monotone, signed S3 Validation Reports. No internal proxy reward ever influences selection.
- **G2 — Refuse-without-verifier.** Structurally decline to begin (or continue) any loop for which a valid, independent, cheap S3 verifier profile is not available; surface `VERIFIER_UNAVAILABLE` loudly.
- **G3 — Hard-bounded resource use.** Guarantee termination under hard caps on generations, wall-clock, compute, GPU-seconds, model tokens, and USD; halt-and-quarantine on breach.
- **G4 — Reward-hacking defense in depth.** Detect and reject variants that inflate score via leakage, verifier-profile exploitation, overfitting to a fixed injection amplitude, signature spoofing, or held-out contamination — before they can enter the population.
- **G5 — Diversity & anti-collapse.** Maintain population/archive diversity (novelty search / MAP-Elites-style behavior descriptors) so the loop explores rather than converging prematurely to a fragile local optimum.
- **G6 — Full provenance & reproducibility.** Every variant, mutation, evaluation, and selection decision is a content-addressed C4 artifact with complete lineage; the whole run is bit-for-bit (or within declared tolerance) re-derivable.
- **G7 — Human-review handoff.** When the loop produces a candidate whose S3 report reaches `novel-needs-human`, S4 stops autonomous promotion and routes to S9 via S5 — never self-promotes.
- **G8 — Cost-per-verified-improvement** as a first-class KPI, emitted to S11.

### S4.3 Non-Goals (inherited + subsystem-specific)

- **NG1** — S4 never grades its own variants; it never computes, mutates, or approximates the reward. (Grading is S3.)
- **NG2** — S4 never trains models directly; training is delegated to S2 inside the S10 sandbox.
- **NG3** — S4 never promotes a claim tier; only S3 (+ S9) do.
- **NG4** — No autonomous discovery of new theory, no paper submission, no flagship-HPC execution, no empirical-validation claims. S4 inherits all Argus hard guardrails.
- **NG5** — S4 does not run unguarded / "exploratory-only" loops; a loop without a signed reward source is rejected, not run and discarded.
- **NG6** — S4 does not define new physics forward models or verifier checks; it composes existing S7 adapters and S3 profiles.

### S4.4 Personas

- **P1 — Domain-ML Subagent (machine actor, primary consumer).** A C1 subagent whose pipeline for a subtopic S4 is asked to evolve. It supplies the seed pipeline, the search space (mutation operators / gene schema), and the C6 adapters. It receives an improved, signed-and-tiered pipeline back.
- **P2 — Control Tower / S5 (machine actor, invoker & governor).** Dispatches an evolution job via a C2 envelope, enforces global budget/concurrency, inserts the S9 wait-state on `novel-needs-human`, and consumes the `JobResult`.
- **P3 — Physics Verifier / S3 (machine actor, oracle).** The only scorer. S4 calls `verify()` and consumes signed reports; S3 is deliberately unreachable-from and independent-of S4.
- **P4 — ML-Ops / Platform Engineer (human).** Configures evolver strategies, bounds, and defaults; investigates quarantined runs; tunes diversity/selection knobs; owns S4 SLOs.
- **P5 — Reviewing Physicist (human, via S9).** Receives `novel-needs-human` candidates with the full evolution lineage (the "fitness genealogy") to judge before any external artifact.
- **P6 — Safety/Red-Team Engineer (human).** Audits reward-hacking-catch rate, injects known-hackable verifier stubs to test defenses, reviews the abort/quarantine trail.

### S4.5 User Stories

- **US1** (P2): As the Control Tower, I dispatch a C2 evolution job with a `verifier_profile_ref`, hard budget, and seed pipeline ref; I get back either a signed improved pipeline, a `REFUSED` (no verifier), or a `QUARANTINED` with full audit.
- **US2** (P1): As a subagent, I hand S4 my seed pipeline + a declared search space (gene schema + mutation operators) and receive the best verifier-scored variant with its Validation Report and reproducibility manifest.
- **US3** (P3-driven): As the loop, for each proposed variant I train via S2, submit the frozen pipeline to S3, and use ONLY the signed `aggregate.score`; `INCONCLUSIVE` is treated as non-improvement, never as reward.
- **US4** (P4): As platform engineer, I set `max_generations`, `max_spend_usd`, `population_size`, `diversity_target`, and selection strategy per job or per subtopic default, and the runtime enforces them.
- **US5** (P6): As red-team, I register a deliberately leaky verifier stub and confirm S4's pre-admission leakage/independence checks reject variants that exploit it, and that the event is logged as a caught hack.
- **US6** (P5): As reviewing physicist, when a candidate reaches `novel-needs-human` I see the entire lineage: every generation, the mutation that produced the winner, all intermediate signed reports, and diversity metrics.
- **US7** (P4): As platform engineer, I can pause, resume, checkpoint, and cancel a long-running evolution job durably (survives restarts) and re-derive any generation from its checkpoint.
- **US8** (P2): As Control Tower, I observe near-real-time spend, generation progress, best-score curve, and diversity via heartbeats and OTel traces, and I can back-pressure or cancel on budget/queue pressure.

### S4.6 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-01 | Verifier-precondition gate (refuse without verifier) | P0 | Before entering the loop, S4 MUST resolve and validate the C3 verifier profile for the subtopic (existence, applicability, signer-key trust, single-call cost within declared budget, and total-cost feasibility across generations). If any check fails, S4 MUST return REFUSED with a typed reason (VERIFIER_UNAVAILABLE/PROFILE_UNSUPPORTED/POLICY) and MUST NOT enter the loop. Refusal is a first-class non-error outcome. |
| FR-02 | Independence resolution & tier capping | P0 | S4 MUST query C5 for at least one INDEPENDENT cross-code S7 adapter for the target observable. If none exists, S4 continues but caps the maximum achievable claim tier at recapitulated-known and surfaces INDEPENDENCE_UNAVAILABLE; it MUST NOT allow novel-needs-human without cross-code independence. |
| FR-03 | Reward exclusively from signed C3 report | P0 | Variant fitness MUST be sourced ONLY from aggregate.score of a signature-valid C3 Validation Report. S4 MUST hold no internal reward function, MUST NOT use self-reported or S2-reported scores, and MUST treat INCONCLUSIVE as non-improvement (never reward). |
| FR-04 | Signature verification of every report | P0 | S4 MUST verify the cryptographic signature of every C3 report against the trust store at ingestion. An unsigned or tamper-detected report is a Sev-1 event: the variant is rejected and the job quarantined. |
| FR-05 | Report-binding check (anti-replay/anti-swap) | P0 | S4 MUST confirm the report's frozen_pipeline_ref, input_hashes, environment_digest, profile_ref, and contamination_index_version exactly match what S4 submitted. Any mismatch flags a reward-hack attempt and rejects the variant. |
| FR-05b | Honor leakage/calibration/cross-code check outcomes | P0 | A variant whose report has a FAIL on LEAKAGE or CALIBRATION, or whose CROSS_CODE check disagrees beyond stated uncertainty, is inadmissible regardless of aggregate.score, and MUST NOT enter the population or archive. |
| FR-06 | Hard bounds & guaranteed termination | P0 | S4 MUST enforce max_generations, max_variants_total, max_wallclock_s, max_compute_units, max_gpu_seconds, max_model_tokens, and max_cost_usd as hard caps. The loop MUST provably terminate whichever binds first; no unbounded recursion is permitted. |
| FR-07 | Near-real-time budget metering & halt | P0 | The Budget Ledger MUST meter spend per phase (build/verify/llm_proposal/overhead) in near-real-time and halt the workflow within one generation of a cap breach, capturing partial results (best-so-far admitted variant) with no double-spend. |
| FR-08 | Population & archive management | P0 | S4 MUST maintain a fixed-size population with elitism and a MAP-Elites/novelty archive keyed by physics-meaningful behavior descriptors, retaining the best-scoring elite per cell. |
| FR-09 | Variant proposal (operators + LLM-guided) | P0 | S4 MUST generate child variants via typed mutation/crossover operators over the gene schema and, optionally, LLM-guided proposals (Claude). Every proposal MUST be schema-validated and lie within the declared search space/validity domain; out-of-domain or invariant-violating proposals are rejected before build. |
| FR-10 | Train delegation to S2 in sandbox | P0 | S4 MUST delegate all training to S2 via the C1 build lifecycle, executing inside the S10 sandbox. S4 MUST NOT train models itself and MUST NOT execute variant/LLM-generated code outside S10. |
| FR-11 | Selection with fitness + novelty | P1 | S4 MUST select parents using signed fitness plus a novelty/diversity component (archive sampling, k-NN novelty), per the configured strategy (map_elites\|tournament_ga\|novelty_search\|hybrid). |
| FR-12 | Diversity guard / anti-collapse | P1 | When population entropy drops below diversity_target, S4 MUST inject diverse variants (archive-sampled or freshly mutated) to prevent premature convergence; if diversity cannot be restored within N generations it early-stops with a flag. |
| FR-13 | Profile-invariance / verifier-overfit probe | P1 | At configured intervals S4 MUST re-score the current best under a rotated injection amplitude / sibling held-out profile via S3; a variant whose score collapses beyond overfit_score_tolerance is demoted and flagged as suspected verifier-overfit. |
| FR-14 | Per-generation checkpoint & durable resume | P0 | S4 MUST checkpoint full evolution state (population, archive, RNG streams, budget ledger, best-so-far, pending evaluations) as a content-addressed C4 artifact each generation and resume durably across restarts with no double-training and no lost provenance. |
| FR-15 | Idempotent evaluation | P0 | Train and verify activities MUST be idempotent keyed by frozen_pipeline_ref content hash so a replay/restart never re-trains or re-scores an already-evaluated variant. |
| FR-16 | Full provenance & genealogy emission | P0 | S4 MUST emit a complete C4 lineage for every variant, mutation, evaluation, and selection decision, forming a queryable genealogy DAG that reproduces the run's decision path. |
| FR-17 | No autonomous tier promotion / human handoff | P0 | S4 MUST NOT self-promote any tier. When the best variant's signed report reaches novel-needs-human, S4 sets human_review_required=true and routes the candidate + full genealogy to S9 via S5; it never emits an external artifact. |
| FR-18 | KPI emission to S11 | P1 | S4 MUST emit cost-per-verified-improvement, reward-hacking-catch count, generation best-score curve, diversity/archive-coverage, and refusal/quarantine counts to S11 via OTel/NATS. |
| FR-19 | Quarantine on systemic anomaly | P0 | Any signature failure, sustained reward-hack rate over threshold, sandbox violation, or checkpoint corruption MUST halt the job into a fully-logged QUARANTINED state (fail-loud), never silent degradation. |
| FR-20 | Cooperative control (pause/resume/cancel/heartbeat) | P1 | S4 MUST support durable pause, resume-from-checkpoint, cooperative cancel (with partial-result capture), and heartbeat reporting status/progress/spend, all surviving process restart. |
| FR-21 | Preflight dry-run | P1 | S4 MUST expose a preflight endpoint that runs the precondition gate without committing budget, returning admissibility, verifier validity, independence availability, cheapness, max achievable tier, and estimated cost. |
| FR-22 | Early-stop under bounds | P2 | S4 MUST support early stopping on no-improvement patience and on diversity-collapse, always subordinate to the hard max_generations/max_wallclock/max_cost caps. |
| FR-23 | Deterministic decision path | P0 | Given identical seed pipeline, gene schema, master seed, profile/index versions, pinned adapters/containers, and the same signed scores, S4's selection/mutation/acceptance decisions MUST be bit-identical (replayable), independent of stochastic training kernels. |
| FR-24 | Gene-schema & invariant enforcement | P1 | S4 MUST reject any variant that violates the gene schema's declared domains or physics invariants (units, positivity, symmetry constraints) before dispatching it to S2, backstopping S3's physical-consistency gate. |
| FR-DB01 | Debate-round orchestrator (proponent / challenger / referee) | P0 | S4 MUST run the "Adversarial Red-Blue Debate Evolution" loop: the PROPONENT (builder subagent) produces a candidate (model + claim); `run_debate_round(candidate_ref, challenger_pool, referee) -> ChallengeRound` drives challenger attacks and a REFEREE (S3; != proponent; signed) adjudication via `ChallengeVerdict` (require must_react_pass AND must_not_react_pass AND NOT insensitivity_detected). Produces a `ChallengeRound` ({round_id, proponent_ref, challenger_ids[], attacks[], referee_verdict, survived, feedback}) and a `ChallengeVerdict` ({round_id, must_react_pass, must_not_react_pass, insensitivity_detected, overall}). [maps S4-TDB1] |
| FR-DB02 | Precondition gate — recursion only under oracle | P0 | S4 MUST refuse to run a debate loop unless a CHEAP, VALID S3 verifier + oracle exists for the subtopic (recursion only under oracle), reusing the FR-01 verifier-precondition gate. Without a valid oracle, `evolve_under_debate(seed_candidate, budget, stop_criteria)` returns REFUSED (VERIFIER_UNAVAILABLE) and MUST NOT enter the loop. [maps S4-TDB3] |
| FR-DB03 | Independent challenger panel + diversity policy | P0 | S4 MUST select the challenger panel via `select_challenger_panel(subtopic, k, diversity_policy) -> challenger_ids[]`: >=K challengers, lineage-disjoint, with diversity across BOTH attack types AND code lineages; independence is attested by S3 (FR-PR03). The panel is refreshed each round to prevent overfitting to a fixed challenger set. [maps S4-TDB2] |
| FR-DB04 | Reward-hacking + challenger-collusion screens | P0 | S4 MUST run screens that detect proponent overfitting to a fixed challenger set, challenger correlation/collusion, and referee tampering; enforce a hard bound on rounds; and refresh challenger diversity each round. A detected hack/collusion event is logged and blocks admission. [maps S4-TDB4] |
| FR-DB05 | DebateLedger provenance emission via C4 | P0 | S4 MUST emit an append-only `DebateLedger` (C4 provenance record of all `ChallengeRound`s for an artifact) and set `debate_ref` in the emitted signed C3 v1.1 ValidationReport; the ChallengeRound/Attack/ChallengeVerdict data models (owned by S4, referenced by S3 and C4) are all provenance-committed. [maps S4-TDB5] |
| FR-DB06 | Feedback -> revise -> retrain step | P0 | On a FAIL ChallengeVerdict, S4 MUST convert the referee/challenger evidence into structured `feedback`, hand it to the proponent to revise/retrain the candidate (via the S2 build lifecycle), and iterate to the next round under the hard round bound; the loop converges by survival and sets the claim tier accordingly on emission. [maps S4-TDB6] |

### S4.7 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR1 | Determinism/Reproducibility | Given the same seed pipeline, gene schema, master seed, verifier profile version, contamination-index version, and pinned adapters/containers, an evolution run reproduces the same population trajectory and the same winning variant hash (within declared nondeterminism tolerance for stochastic training kernels; the *decision path* — selection, mutation choices, acceptance — is strictly deterministic given seeds and the same signed scores). |
| NFR2 | Isolation | All variant code (candidate pipelines, mutation-generated code) executes only inside the S10 sandbox; S4's orchestrator holds no held-out data and no verifier key; the reward path is read-only signature verification. |
| NFR3 | Bounded termination | Every loop provably terminates: hard `max_generations` AND `max_wallclock_s` AND `max_spend_usd` — whichever binds first; no unbounded recursion; a stalled S3 call has a timeout that counts as `INCONCLUSIVE`. |
| NFR4 | Trust integrity | No variant may carry a tier > `ran-toy` without a signature-valid C3 report whose tier matches; S4 verifies signatures at ingestion and rejects unsigned/tampered reports (Sev-1). |
| NFR5 | Durability | Evolution jobs are durable Temporal workflows; state (population, archive, RNG, budget ledger, best-so-far) checkpointed each generation to S8; survive process/host restart with no double-spend and no lost provenance. |
| NFR6 | Cost governance | Near-real-time metering; halt within one generation of budget breach; `cost-per-verified-improvement` emitted continuously; a generation that spends but yields no admitted improvement is still fully accounted. |
| NFR7 | Latency | Control-plane operations (start/pause/resume/status) respond in seconds; a single generation's latency is dominated by S2 training + S3 verify (async, minutes-to-hours) and is durable across restarts. |
| NFR8 | Scalability | Support hundreds of concurrent variant evaluations across many jobs; population and archive scale to 10^4+ variants per run without selection-query degradation. |
| NFR9 | Observability | Every generation emits an OTel span chain S4→S2→(adapters via S2)→S3; best-score curve, diversity metric, spend, refusal/quarantine counts, and reward-hacking-catch count always queryable in S11. |
| NFR10 | Fail-loud | Any signature failure, independence-unavailable, budget breach, sandbox violation, or verifier disagreement halts the job into a fully-logged QUARANTINED state — never silent degradation. |

### S4.8 Scope Boundaries (contract seams)

S4 couples to the rest of Argus ONLY through: C2 (job in/result out, with S5), C1 (drives a subagent's `build`/`validate` lifecycle), C3 (verify + signed report, from S3), C4 (all artifacts/lineage, to/from S8), C6 (adapters are invoked by S2, not S4 directly), C5 (registry resolve to confirm verifier profile & independent cross-code exist). S4 imports no internal types of any other subsystem.

### S4.9 Success Metrics

- **M-metric-1:** Reward-hacking-catch rate on the red-team suite ≥ target (100% of the seeded hackable-verifier scenarios rejected pre-admission).
- **M-metric-2:** 0 loops started without a valid verifier (refusal precision 100%).
- **M-metric-3:** Reproducibility: re-run canary reproduces winning-variant hash for ≥ configured fraction of runs (decision path 100%).
- **M-metric-4:** On recapitulation benchmarks, S4 improves seed→best verified score by a measurable, held-out margin without any leakage-flag.
- **M-metric-5:** 0 budget overshoots beyond one-generation tolerance.
- **M-metric-6:** 0 autonomous tier promotions to `novel-needs-human` (always routed to S9).

---

## S5 — Control Tower / Orchestration (总台)

**One-liner:** The durable meta-orchestrator that intakes a human research request, decomposes it into a provenance-committed job DAG, routes each C2 job envelope to a conformant subagent, and governs scheduling, concurrency, budget, retries, human-review wait states, and cross-subagent workflow composition.

### S5.1 Mission & Goals

S5 is Argus's meta-layer. It converts a human research request into a coordinated, durable, budget-governed set of subagent jobs and holds the workflow state that ties the federation together. It owns **contract C2 (Task/Job Envelope)** and is the sole authority for job identity, DAG composition, routing, scheduling, concurrency/budget governance, retry policy, and the insertion of human-review wait states.

**Primary goals**

- **G1:** Deterministically decompose a `root_request` into an inspectable, provenance-committed **job DAG** whose every node is a valid C2 envelope.
- **G2:** Route each job to the best-fit conformant subagent via the C5 registry, honoring independence, conformance level, verifier availability, and least-privilege scopes.
- **G3:** Execute the DAG **durably** (survive process/host restarts) with correct data-dependency ordering, where a node's outputs are consumable only after provenance commit (C4).
- **G4:** Enforce **hard budget and concurrency governance** end-to-end (compute, GPU, tokens, wallclock, cost), metering in near-real-time and halting on breach.
- **G5:** Implement **retry, refusal, quarantine, and degradation** semantics exactly as specified by the C1/C2 typed error envelope, never auto-retrying POLICY/SANDBOX/VERIFIER_UNAVAILABLE.
- **G6:** Insert **mandatory human-review wait states** (S9) before any external artifact and enforce non-goal guardrails as hard, non-bypassable gates.
- **G7:** Emit complete distributed traces (S11) and full lineage (S8) so every job is queryable and reproducible.

**Non-goals (S5 scope boundaries)**

- S5 does NOT build ML (S2), grade artifacts (S3), run recursion internals (S4 owns its loop; S5 only schedules/budget-governs it), ingest corpora (S6), execute forward models (S7), or render review UI (S9). It orchestrates them via contracts.
- S5 never assigns claim tiers, never signs Validation Reports, never bypasses the human gate, and never configures/executes flagship HPC.
- S5 does not itself run agent code; all agent execution is delegated into the S10 sandbox via subagents.

### S5.2 Personas

- **P1 Research Requester (physicist)** — submits a research request ("model the EWPT→SGWB link for parameter region R"), inspects the decomposition/plan, sets budget ceilings, approves cost, monitors progress.
- **P2 Argus Operator / SRE** — configures concurrency classes, global budget pools, quotas, back-pressure thresholds; drains/pauses the tower; investigates quarantined jobs.
- **P3 Governance Reviewer (S9 human)** — receives review items generated at wait states; approvals/rejections gate DAG continuation. (Consumes S5 via S9.)
- **P4 Subagent (system actor)** — receives C2 envelopes, may refuse; reports results. (Machine persona.)
- **P5 Evolver S4 (system actor)** — requests scheduling of bounded recursion jobs; S5 governs its budget/concurrency and enforces max-generations/max-spend.
- **P6 Platform Auditor** — queries historical DAGs, routing decisions, budget ledgers, guardrail-block events for compliance.

### S5.3 User Stories

- **U1:** As P1, I submit a research request with a natural-language objective, a subtopic taxonomy hint, a hard budget, and a required max claim tier, and receive a **decomposition preview** (DAG + plan + cost estimate + verifier availability) before any spend.
- **U2:** As P1, I approve or edit the decomposition; on approval the tower dispatches jobs and I can watch a live DAG with per-node status, spend, and ETA.
- **U3:** As P2, I set a global concurrency cap and per-subtopic budget pools; when queue depth exceeds the human-review throughput cap, the tower back-pressures intake rather than overflowing S9.
- **U4:** As P4, I receive a C2 envelope, refuse it (out-of-scope / no verifier / budget too small), and the tower re-routes to an alternative subagent or escalates to a human — without treating refusal as an error.
- **U5:** As P3, when a node produces a candidate external artifact, the DAG pauses at a human-review wait state; my sign-off resumes it, my rejection quarantines/prunes the branch.
- **U6:** As P5, I request N bounded recursion iterations; the tower refuses to start if no valid S3 verifier profile exists, and halts the loop at max-generations or max-spend.
- **U7:** As P6, I query "show the full routing + budget + guardrail history for root_request X" and get a complete, tamper-evident answer.
- **U8:** As P2, I trigger a graceful drain; in-flight durable workflows survive a control-plane restart and resume exactly where they left off with no double-dispatch and no lost budget accounting.

### S5.4 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-01 | Research request intake & validation | P0 | Accept a research request (objective, subtopic hint, required max claim tier, hard budget ceiling, policy flags), validate against schema and guardrail policy, pin contamination-index/registry/template-lib/planner-model versions, create a RootRequest, and return a handle. Reject malformed or guardrail-violating requests at the door. |
| FR-02 | NL→DAG decomposition with inspectable preview | P0 | Decompose a request into a job DAG using a tool-restricted planner agent + versioned template library + registry lookups; produce a DecompositionPreview (nodes, edges, per-node verifier profile, budget breakdown, feasibility, risk notes) BEFORE any execution. Decomposition is deterministic given pinned inputs and replayable. |
| FR-03 | Human-editable plan approval gate | P0 | Allow a requester to inspect, edit (add/remove nodes, edit edges, override budgets), and approve/reject the decomposition. No dispatch or spend occurs before explicit approval. |
| FR-04 | C2 envelope minting & immutability | P0 | Mint immutable C2 Job Envelopes from approved DAG nodes with job_id/parent_job_id/root_request_id/dag_node_id, verifier_profile_ref (REQUIRED), budget, constraints, provenance_context, capability_scopes, and a minted metered budget_token. A change produces a new envelope with new job_id linked via parent_job_id. |
| FR-05 | Verifier-availability precondition | P0 | Every dispatched envelope carries a non-null verifier_profile_ref bound from S3 list_profiles(); if no profile applies, the node is marked verifier_unavailable and cannot be promoted above ran-toy; recursion nodes with no verifier are refused outright. |
| FR-06 | Registry-driven routing with independence & conformance | P0 | Resolve candidate subagents via C5 resolve(), score by conformance level, verifier support, independence (for cross-code parents), cost/resource fit, and reliability; select deterministically; pin the chosen descriptor_revision into the envelope; record a signed RoutingDecision. |
| FR-07 | Durable DAG execution with data-dependency gating | P0 | Execute the DAG on a durable workflow engine; drive each node through the C1 lifecycle; admit a downstream node only after all its upstream artifact_refs are provenance-committed (and, for tier>ran-toy inputs, coupled to a signature-valid C3 report). Survive control-plane restarts with no lost/double-dispatched job. |
| FR-08 | Scheduling, priorities, concurrency classes & deadlines | P1 | Admit and schedule jobs across concurrency classes with priorities and deadlines under a global concurrency cap; deterministic admission ordering; deadline-aware preemption/escalation. |
| FR-09 | Hard budget governance & real-time metering | P0 | Enforce hierarchical hard budgets (job⊂DAG⊂pool⊂platform) via reserve/reconcile/release; meter spend near-real-time from heartbeats and C4 actuals; halt on breach within one metering interval, capture partial results, and report cost-per-verified-artifact. |
| FR-10 | Retry policy honoring typed error categories | P0 | On typed C1/C2 errors, retry ONLY RETRYABLE categories per retry_policy (max_attempts, backoff); never auto-retry PERMANENT/POLICY/SANDBOX/VERIFIER_UNAVAILABLE/BUDGET; POLICY & SANDBOX quarantine; VERIFIER_UNAVAILABLE blocks promotion and aborts S4 loops; BUDGET halts with partial capture. |
| FR-11 | Refusal handling, re-routing & escalation | P0 | Treat subagent REFUSED as a first-class non-error outcome; re-route to the next candidate subagent; if candidates are exhausted, escalate to a human via S9 rather than failing the DAG. |
| FR-12 | Human-review wait states & non-goal guardrails | P0 | Insert mandatory S9 review wait states before any external-facing artifact or novel-candidate promotion; translate approvals into continuation and rejections into prune/quarantine; enforce hard non-goal guardrails (no autonomous new-theory, no auto paper submission, no flagship-HPC, no empirical-validation claim) structurally. |
| FR-13 | External-emission rate limiting & back-pressure | P0 | Cap external emissions and items entering the S9 review queue per unit time; when the review queue nears capacity, back-pressure intake (429 THROTTLED) and defer dispatch of review-generating nodes, sizing autonomy to human throughput. |
| FR-14 | Recursion (S4) scheduling under verifier precondition & hard bounds | P0 | Expose a recursion-governance surface that refuses to start unless a valid S3 verifier profile exists for the target, schedules bounded generations as child jobs, and halts at max-generations or max-spend, recording stop_reason. |
| FR-15 | Cancellation, heartbeat & liveness | P1 | Support cooperative cancellation (C1 cancel) at request/DAG/job scope; consume C1 heartbeats for progress/spend; detect stalled subagents via heartbeat gaps and retry or quarantine while releasing budget reservations. |
| FR-16 | Provenance & lineage emission | P0 | Event-source every job lifecycle transition, envelope, routing decision, decomposition preview, and budget ledger to the C4 provenance ledger via S8; ensure 100% of externally-visible artifacts and tier promotions have complete queryable lineage. |
| FR-17 | Distributed tracing & KPIs | P1 | Emit an OpenTelemetry trace spanning control tower→subagent→builder→adapters→verifier for every job; expose S5 KPIs (routing latency, refusal rate, budget breach rate, cost-per-verified-artifact, back-pressure frequency, guardrail-block rate). |
| FR-18 | DAG replay / reproducibility | P1 | Replay a completed DAG run from its committed decomposition, envelopes, and pinned registry/template/index/model revisions; expose replayability status and pins for the S11 re-run canary. |
| FR-19 | Degradation & quarantine on dependency outage | P0 | Fail-closed on S8 commit failure (block downstream, pause durably), accumulate human waits on S9 outage with back-pressure, halt in-flight jobs on registry revocation, and mark DAGs PARTIAL with complete failure reports on branch failure — never degrade silently. |
| FR-20 | Contract-version compatibility for C2 | P1 | Accept any message valid under a compatible minor C2 version (ignore unknown additive fields); dual-serve during a documented migration window for breaking major changes. |
| FR-21 | Least-privilege scope & budget-token minting | P0 | Mint per-job capability_scopes and a metered budget_token scoped to exactly the adapters/datasets/resources the job needs; never mount secrets; ensure S5 itself cannot elevate trust of federated subagents. |
| FR-22 | Operator controls (drain, pause, pools, quotas) | P1 | Provide operator APIs to configure concurrency classes and budget pools, drain gracefully or immediately, pause/resume scopes, and inspect queue depths, utilization, and back-pressure state. |

### S5.5 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR-1 | Durability | DAG/job state persists across restarts; no job lost, double-dispatched, or double-budgeted. Exactly-once *effect* semantics on side-effecting steps (idempotency keys). |
| NFR-2 | Availability | Control-plane target 99.5%; intake/planning interactive responses within seconds; long jobs asynchronous via Temporal. |
| NFR-3 | Scalability | Hundreds of concurrent subagent jobs, thousands queued; routing/registry lookups and DAG state queries do not degrade at 10^5+ artifacts / 10^4+ historical DAGs. |
| NFR-4 | Budget accuracy | Spend metering reconciled against C4/actuals; drift between metered and actual bounded and alarmed; hard-cap halt latency within one metering interval. |
| NFR-5 | Security | All inter-subsystem calls mTLS + least-privilege scopes; S5 mints per-job `budget_token` and `capability_scopes` but never handles secrets or agent code; guardrails enforced structurally. |
| NFR-6 | Observability | Every job emits a trace spanning tower→subagent→builder→adapters→verifier; routing decisions, budget events, and guardrail blocks are queryable KPIs. |
| NFR-7 | Reproducibility | A DAG run is replayable from its committed decomposition + envelopes + pinned registry revisions + contamination index version; replay is verified by S11's re-run canary. |
| NFR-8 | Fail-loud | Any gate failure, adapter/verifier unavailability, budget breach, or guardrail violation quarantines into a fully-logged state; no silent degradation. |
| NFR-9 | Contract compatibility | Accepts any message valid under a compatible minor C2 version; breaking changes dual-served during a migration window. |

---

## S6 — Knowledge & Ingestion

**One-liner:** Bulk ingest and index of arXiv/GitHub/HEPData, curated-doc RAG that measurably lowers plausible-but-wrong rates, the subagent/code/tool registry (co-owner of C5), and the frozen literature/contamination index used for novelty and leakage discrimination.

### S6.1 Mission & Goals

S6 is Argus's memory and its ground-truth-about-the-literature. It has four load-bearing responsibilities:

1. **Bulk ingest + index** of external corpora (arXiv, GitHub, HEPData, plus extensible connectors) into content-addressed artifacts (C4) with full external-source provenance.
2. **Curated retrieval (RAG)** that measurably reduces "plausible-but-wrong" outputs of S2 (ML Builder) and subagent planners by grounding them in vetted, unit-aware, citable physics documentation.
3. **The Registry** (co-owner of contract **C5**) — the machine-readable catalog of subagents, physics codes, adapters, datasets, and verifiers used by S5 for routing and by S3 to find *independent* cross-check codes.
4. **The Frozen Contamination Index** — an immutable, version-pinned snapshot of the literature/data corpus that defines what "novel" means (absent-from-this-frozen-corpus-at-this-date) and powers S3 leakage/novelty screens.

**Primary success metrics (KPIs):**

- **Plausible-but-wrong reduction:** RAG-grounded S2/planner outputs show a statistically significant reduction (target ≥30% relative) in physical-consistency-gate failures vs. an un-grounded control, measured on a fixed eval set by S11.
- **Retrieval quality:** Recall@20 ≥ 0.85 and nDCG@10 ≥ 0.70 on a curated physics QA/retrieval gold set.
- **Contamination discrimination:** On a labeled benchmark of (memorized vs. genuinely-novel) claims, leakage-screen AUROC ≥ 0.95, false-novel rate < 1%.
- **Freshness:** New arXiv listings indexed within 24h of appearance (for the *live* index; the frozen index is deliberately static).
- **Registry integrity:** 100% of `resolve()` results reference conformance-valid, non-revoked descriptor revisions.

### S6.2 Scope

**In scope:**

- Connector framework + concrete connectors: arXiv (OAI-PMH + API), GitHub (repos/releases), HEPData (records/tables), extensible driver SPI for future sources.
- Normalization pipeline: PDF/LaTeX/HTML → structured text + math + tables + citation graph; code repo parsing; HEPData table typing with units.
- Chunking, embedding, and dual (lexical + vector) indexing in OpenSearch.
- Curation layer: quality/vetting signals, unit-annotation, "curated documentation" sets, staleness tracking.
- Retrieval API (RAG): hybrid search, reranking, unit-aware filtering, provenance-carrying citations.
- Registry service (C5): publish/resolve/deprecate/revoke/subscribe, independence resolution.
- Frozen contamination index: snapshot creation, immutability, versioning, novelty/recall query API for S3.
- Leakage-screen support primitives (n-gram/simhash/embedding overlap, near-duplicate detection) consumed by S3.

**Out of scope (belongs to other subsystems):**

- Running leakage *checks* as verifier gates (S3 owns the gate; S6 provides the frozen index + overlap primitives).
- Content-addressing/hashing and the lineage ledger writer (S8 owns C4 storage; S6 *produces* C4 records via S8).
- Sandbox/isolation of ingestion jobs (S10 provides isolation; S6 runs *inside* it).
- Human sign-off / governance decisions (S9).
- Federation governance & conformance-suite *execution* (S12 owns the suite; S6 stores the resulting conformance evidence in C5 and enforces it at publish/resolve).

### S6.3 Personas

- **P1 — Domain Subagent (machine, S1):** calls RAG to ground planning/feature engineering; publishes its C5 CapabilityDescriptor at register().
- **P2 — ML Builder Engine (machine, S2):** pulls curated docs/priors and unit conventions to reduce wrong outputs.
- **P3 — Physics Verifier (machine, S3):** queries the frozen contamination index for leakage/novelty; queries registry for an *independent* cross-code adapter.
- **P4 — Control Tower (machine, S5):** calls registry `resolve()` for routing; pins a `contamination_index_version` into every C2 envelope.
- **P5 — Human Curator / Librarian:** manages curated-doc sets, approves/blocks sources, triggers snapshots, reviews ingestion QA.
- **P6 — Federation Maintainer (S12/external):** publishes federated subagent/adapter descriptors, subject to conformance enforcement.
- **P7 — Platform SRE / Data Engineer:** operates ingestion pipelines, monitors freshness/lag, manages reindex and backfill.

### S6.4 User Stories (selected; exhaustive set in FRs)

- As **S2**, I want unit-annotated curated docs for a subtopic so my generated feature code uses correct dimensions and known limits.
- As **S3**, I want to ask "is claim/result X present in contamination_index_version v?" with a calibrated overlap score, so I can distinguish memorized from novel.
- As **S5**, I want `resolve(subtopic, required_verifier, min_conformance, independence_needed)` to return only admissible descriptor revisions, so routing is safe and reproducible.
- As a **Curator**, I want to freeze the current live index into an immutable snapshot with a version tag and manifest, so novelty is judged against a stable reference.
- As **SRE**, I want incremental, resumable ingest with dedup so re-ingesting arXiv daily doesn't re-embed unchanged documents.

### S6.5 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-01 | Pluggable source connector SPI | P0 | Provide a SourceConnector driver interface (list_since, fetch, describe_source, egress_allowlist) with concrete arXiv, GitHub, HEPData drivers and the ability to register new drivers via add_source_connector. |
| FR-02 | Incremental, resumable, idempotent ingest | P0 | Sync each source incrementally using persisted cursors; re-running a sync must not re-fetch/re-embed unchanged records (exact dedup via S8 content_hash on raw bytes). Partial batches commit idempotently; cursor advances only on committed progress. |
| FR-03 | Egress-allowlisted sandboxed ingestion | P0 | All internet-touching ingestion runs inside S10 sandboxes with network egress allowlisted to the declared source endpoints only; any other destination is blocked and quarantines the job. |
| FR-04 | Normalization to structured docs | P0 | Convert LaTeX/PDF/HTML to structured NormalizedDoc (sections, equations with symbol tables, tables, references), preferring LaTeX source; extract citation-graph edges. |
| FR-05 | HEPData typed-table ingest | P1 | Ingest HEPData tables into typed columns with units and uncertainty, linked to origin arXiv id. |
| FR-06 | Unit annotation | P1 | Annotate quantities/chunks with physical dimensions using a controlled vocabulary aligned with the C6 units contract; expose units_present metadata for filtering and to backstop S2/S3 dimensional checks. |
| FR-07 | Structure-aware chunking + embedding | P0 | Chunk respecting section/equation/table boundaries (never split an equation); embed with a pinned, per-chunk-recorded embedding model version; store embeddings as C4 shards and in OpenSearch kNN. |
| FR-08 | Hybrid retrieval with rerank | P0 | Serve hybrid BM25+dense retrieval fused via RRF then cross-encoder rerank; support subtopic/source/license/units/curated/date/index-version filters; return CitationProvenance per hit. |
| FR-09 | Curated documentation sets | P1 | Maintain human-vetted curated-doc sets and unit-convention priors per subtopic; retrieval can restrict to curated-only; changes are audited (CurationRecord + C4 audit_ref). |
| FR-10 | Measurable plausible-but-wrong reduction | P1 | Provide the RAG grounding used by S2/planners and support an A/B eval (grounded vs control) whose result S11 can measure; grounded outputs must reduce physical-consistency-gate failure rate by a target margin. |
| FR-11 | Registry publish with conformance enforcement | P0 | publish() stores an append-only, signed, immutable CapabilityDescriptor revision; refuses publication without valid, unexpired conformance evidence for the claimed level. |
| FR-12 | Registry resolve for routing | P0 | resolve() returns only conformance-valid, non-revoked descriptor revisions matching subtopic/verifier/min-conformance/entity-type/trust-class, as pinned revision refs for reproducible routing. |
| FR-13 | Independence resolution for cross-code | P0 | Given an observable and a code-under-test, resolve genuinely independent implementations by excluding shared repo/fork/derived_from lineage and overlapping independence_tags. |
| FR-14 | Revocation propagation | P0 | revoke() emits an event that consumers must honor; resolving a revoked entity fails closed; in-flight references are halted. |
| FR-15 | Frozen contamination index snapshot | P0 | freeze() creates an immutable, version-pinned snapshot (OpenSearch alias + write-once SnapshotManifest C4) whose creation timestamp is the novelty cutoff date; snapshots are never mutated (corrections create a superseding version). |
| FR-16 | Novelty / overlap query | P0 | novelty_query(text\|artifact, index_version) returns calibrated overlap combining n-gram, simhash, minhash, and embedding max-sim, with matches and calibrated_novelty_prob, for S3's leakage screen. |
| FR-17 | Recall / recapitulation query | P1 | recall_query supports the recapitulation-benchmark path: determine whether a known held-out result is present in a given index version. |
| FR-18 | Near-duplicate detection | P1 | Detect exact and near-duplicate documents (SimHash + MinHash LSH); link near_dup_of and skip redundant re-embedding; expose overlap primitives to S3. |
| FR-19 | License & access-scope enforcement | P1 | Every ingested item carries a license; retrieval enforces license/access-scope filters; non-redistributable full-text is stored but access-gated. |
| FR-20 | Calibrated novelty scores | P1 | Novelty/overlap scores are calibrated (coverage-tested) so S3 thresholds are meaningful; expose calibration_ref. |
| FR-21 | Event emission | P1 | Emit registry-change and ingest lifecycle events on NATS JetStream for caches, S11 observability, and S5. |
| FR-22 | Reindex & backfill | P1 | Support full reindex (e.g., new embedding model → new index alias) and historical backfill without downtime, rebuildable from C4 normalized artifacts. |
| FR-23 | Quarantine & requeue | P1 | Normalization/policy failures quarantine a doc with reason (raw retained), never partially indexing; curators can requeue. |
| FR-24 | Taxonomy management | P2 | Maintain a versioned subtopic taxonomy (add/rename/merge/deprecate) used for subtopic tagging and routing filters. |
| FR-25 | Degraded-mode retrieval | P2 | When the embedding model or vector index is unavailable, serve BM25-only results flagged degraded:true so callers know vector recall is reduced. |
| FR-26 | Reproducible retrieval | P2 | A retrieval is reproducible given (query, filters, index_version/date_ceiling, pinned embed+rerank model versions); response carries a retrieval_manifest_hash. |
| FR-27 | Snapshot integrity verification | P0 | Every read against a frozen index validates the SnapshotManifest hash; mismatch fails closed and blocks novelty queries against that version. |

### S6.6 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR-1 | Reproducibility | Every ingested artifact and every snapshot is content-addressed (C4) with `external_source_ref` (source, id, url, snapshot_hash, ingested_at, license). A retrieval result is reproducible given `contamination_index_version` + query. |
| NFR-2 | Immutability/durability | Frozen contamination index and its manifest are stored write-once (S8 immutable bucket), ≥11 nines durability, append-only. |
| NFR-3 | Isolation/security | All ingestion (which touches the untrusted internet) runs in S10 sandboxes with egress *allowlisted to declared source endpoints only*; RAG serving path holds no secrets reachable by agents; agents call S6 read APIs via mTLS + capability scopes and can never write the index. |
| NFR-4 | Freshness/latency | Live incremental sync SLA 24h; `resolve()` p99 < 150 ms; RAG hybrid query p95 < 800 ms for top-50 rerank. |
| NFR-5 | Scalability | ≥ 10^7 documents, ≥ 10^8 chunks; registry ≥ 10^5 descriptor revisions without query degradation. |
| NFR-6 | License compliance | Every ingested item carries a license tag; retrieval enforces license/access-scope filters; non-redistributable full-text is stored but access-gated. |
| NFR-7 | Calibration | Overlap/novelty scores are calibrated (coverage-tested) so S3's leakage gate thresholds are meaningful. |
| NFR-8 | Contract compatibility | C5 served under semver; minor changes additive/forward-compatible; registry entries are append-only immutable revisions. |

### S6.7 Explicit Non-Goals / Guardrails

- S6 does not decide novelty; it provides the frozen reference + overlap score. S3+S9 promote to `novel-needs-human`.
- S6 never grants elevated trust: publishing a federated descriptor with valid conformance does not change the runtime trust zone.
- No autonomous mutation of the frozen index: snapshots are created by an explicit, audited, human-or-orchestrated action and are immutable thereafter.

---

## S7 — Physics Compute Adapters

**One-liner:** A uniform, uncertainty-tagged tool layer that wraps lightweight physics codes, emulators, and differentiable surrogates as callable forward models (C6), so subagents (S2), the verifier (S3), and the Evolver (S4) invoke forward models identically with normalized units, mandatory uncertainty, validity-domain guarding, and full per-call provenance.

### S7.1 Mission & Goals

S7 owns contract **C6 (Compute-Adapter Tool Interface)** and the platform's entire forward-model tool plane. Its job is to make *every* physics code, emulator, and differentiable surrogate look identical to a caller: a typed, **units-tagged**, **uncertainty-tagged**, validity-domain-guarded, provenance-emitting function `evaluate` (and optionally `grad`, `batch_evaluate`). This is the substrate that lets S2 build physics-aware features/targets, lets S3 run cross-code consistency and physical-consistency checks against *independent* implementations, and lets S4 score cheaply via differentiable surrogates.

**Primary goals**

- **G1.** One interface, many codes: a single C6 surface over heterogeneous backends (Python/JAX/PyTorch native, shelled-out C++/Fortran binaries in pinned containers, GP/NN emulators, differentiable surrogates).
- **G2. Units are law:** every input/output field carries a physical unit; mismatch is a hard error, never coerced. This backstops the S3 dimensional-consistency gate.
- **G3. Uncertainty is mandatory:** every output carries a calibrated uncertainty (interval / covariance / samples); a bare point estimate is non-conformant and rejected.
- **G4. Validity-domain guarding:** out-of-domain inputs are flagged (`in_validity_domain:false`, `extrapolation_flag:true`) or refused per policy; the verifier treats extrapolation as INCONCLUSIVE unless a profile allows it.
- **G5. Independence machinery:** adapters declare `independence_tags` and pinned `underlying_code_version`/`code.repo` so S3 (via the registry C5) can select a genuinely independent cross-check.
- **G6. Differentiability:** adapters may expose `grad` (Jacobian) enabling gradient-based fitting and cheap differentiable verification for S4.
- **G7. Provenance per call:** every `evaluate`/`grad` emits a C4 record pinning adapter + underlying-code versions and seeds; reproducible (bit-level or within declared nondeterminism tolerance).
- **G8. Scope enforcement (non-goal guard):** adapters are for lightweight solvers, emulators, surrogates, and emulated fast-sim ONLY. Any adapter whose `cost_class` exceeds the platform ceiling is **rejected at registration** — this is how S7 mechanically enforces the "no flagship HPC" non-goal.

**Non-goals**

- **NG1.** S7 does not decide claim tiers, does not grade results, and holds no verifier signing key (that is S3).
- **NG2.** S7 does not schedule DAGs or manage budgets globally (S5) — it only *meters and enforces* the `budget_token` handed to a call.
- **NG3.** S7 does not run flagship numerical relativity / large hydro; it rejects such adapters.
- **NG4.** S7 does not train models (S2) or ingest literature (S6); it may *serve* an emulator that S2 trained, once registered as an adapter artifact.
- **NG5.** S7 does not decide independence policy; it *supplies* the tags/metadata the registry and S3 use.

### S7.2 Scope

**In scope**

- The C6 wire spec authoring (JSON Schema draft 2020-12) + generated pydantic/TS/Rust bindings.
- The **Adapter SDK** (Python) for authoring adapters: `describe/evaluate/grad/batch_evaluate` skeletons, unit decorators, uncertainty helpers, validity-domain declaration, provenance emission hooks.
- The **Adapter Runtime/Broker**: a brokered service that hosts adapters *outside* the agent sandbox, receives C6 calls over mTLS/gRPC, enforces `budget_token`, seeds, timeouts, and validity-domain policy, and returns EvalResults.
- A **units engine** (Pint-based, with a frozen unit registry + physics extensions) enforcing dimensional correctness and canonical normalization.
- An **uncertainty framework**: representations (interval, covariance, samples), propagation utilities, GP/ensemble emulator uncertainty, and calibration hooks feeding S3's CALIBRATION check.
- A **backend plugin system**: native-Python, JAX, PyTorch, subprocess/binary-in-container, emulator (GP/NN), differentiable-surrogate.
- **Registration** of adapter CapabilityDescriptors into the registry (C5) with cost-class/independence/differentiability metadata + the cost-ceiling admission gate.
- A **reference adapter suite** for the flagship physics thread (effective-potential/bounce solver; GW-spectrum solver; a differentiable GW-spectrum surrogate; a collider fast-sim/emulator; a Boltzmann/transport toy solver) plus at least one *independent* implementation per observable for cross-code.
- Batch/vectorized evaluation, caching (content-addressed by input hash), and fidelity levels (multi-fidelity emulators).
- Provenance emission via S8/C4 for every call.

**Out of scope:** flagship HPC execution; verifier logic; DAG orchestration; model training; literature ingestion; human review UI.

### S7.3 Personas

- **P1 — Subagent / ML Builder (S2):** needs physics-aware features & training targets from forward models; wants `batch_evaluate` and `grad` for differentiable fitting; must never see secrets; runs in sandbox and calls S7 through the broker.
- **P2 — Physics Verifier (S3):** needs to invoke *independent* forward models for CROSS_CODE, and units/positivity/limit info for PHYSICAL_CONSISTENCY; needs calibration metadata for CALIBRATION; must be able to find an independent adapter via the registry.
- **P3 — Evolver (S4):** needs cheap, differentiable surrogate evaluations to score variants; needs deterministic seeding and hard budget metering.
- **P4 — Adapter Author (physicist/ML engineer, internal or federated):** wraps a physics code/emulator with the SDK; declares units, validity domain, uncertainty model, independence tags, cost class.
- **P5 — Platform Operator/SRE:** registers/deprecates/revokes adapters, monitors adapter health, cost, latency, error taxonomy; manages backend containers.
- **P6 — Control Tower (S5):** resolves which adapters a job may use (`allowed_adapters`) and mints the `budget_token`; consumes S7 health/registry events.

### S7.4 User Stories

- **U1.** As S2, I call `evaluate` with units-tagged inputs and get units-tagged outputs + uncertainty, so I can build calibrated features without hand-rolling unit conversions.
- **U2.** As S2, I call `grad` on a differentiable surrogate and get a Jacobian with consistent units, so I can do gradient-based parameter fitting.
- **U3.** As S3, I query the registry for "an independent implementation of GW spectrum Ω_GW(f)" and get an adapter that does not share `code.repo`/`underlying_code_version` with the one under test.
- **U4.** As S3, I submit the same params to two independent adapters and get outputs+uncertainties I can compare within stated tolerance for CROSS_CODE.
- **U5.** As S4, I submit thousands of surrogate evaluations under a strict `budget_token`; the broker halts precisely at budget breach and returns a partial-with-provenance result.
- **U6.** As an adapter author, I decorate my function with input/output unit schemas and a validity domain, and the SDK auto-generates the descriptor + conformance stub.
- **U7.** As an operator, I register an adapter; the system rejects it if its `cost_class` exceeds the platform ceiling (enforcing the non-goal).
- **U8.** As any caller, I evaluate out-of-domain params and get `in_validity_domain:false` + `extrapolation_flag:true` rather than a silently-wrong number.
- **U9.** As any caller, every call I make produces a C4 provenance record pinning adapter + underlying code versions + seed, so my downstream artifact is reproducible.
- **U10.** As S3, I run a CALIBRATION check using the adapter's declared uncertainty model + a coverage test set the adapter exposes.
- **U11.** As an operator, when an underlying binary crashes, I get `UNDERLYING_CODE_ERROR` with captured stderr in provenance for S2 auto-repair — not a hung job.
- **U12.** As S4/S2, repeated identical evaluations hit a content-addressed cache (keyed by input hash + adapter version + seed) so I don't pay twice.

### S7.5 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-01 | C6 schema + generated bindings | P0 | Author canonical JSON Schemas (draft 2020-12) for AdapterDescriptor, EvalRequest, EvalResult, Jacobian, BatchResult, error envelope; generate pydantic v2, TS, and Rust serde bindings from a single source; register under semver in the schema registry. |
| FR-02 | Implement C6 methods | P0 | Implement Describe, Evaluate, Grad (iff differentiable), and BatchEvaluate over the broker with the exact C6 request/result shapes and error semantics. |
| FR-03 | Mandatory units engine | P0 | Every input/output field carries a physical unit; the units engine normalizes to canonical base, enforces dimensional consistency, and raises non-retryable UNITS_MISMATCH on any mismatch. No silent coercions. Frozen, versioned Pint registry pinned into every result. |
| FR-04 | Mandatory uncertainty on outputs | P0 | Every EvalResult carries a non-null uncertainty object (interval\|covariance\|samples) with a declared source; a bare point estimate is rejected as non-conformant. |
| FR-05 | Validity-domain guard | P0 | Each adapter declares a validity domain (box\|polytope\|density); each call is classified; out-of-domain returns in_validity_domain:false + extrapolation_flag:true (or refuses per policy). Diagnostics identify violating fields. |
| FR-06 | Per-call provenance (C4) | P0 | Every evaluate/grad emits a C4 record pinning adapter_version, underlying_code_version, seed, config_hash, input hashes, container digest, and unit-registry version. Fail-closed: no provenance ⇒ result not returned as trusted (PROVENANCE_UNAVAILABLE). |
| FR-07 | Deterministic seeding | P0 | Broker derives a deterministic per-call seed (KDF over job_seed, dag_node_id, call_index, adapter_id), injects into all RNGs including subprocess env, and records it. Honors caller-supplied seed when present. |
| FR-08 | Budget metering & halt | P0 | Broker meters CPU/GPU/wallclock/cost against budget_token in near-real-time and halts precisely on breach with BUDGET error + partial-result-with-provenance. No unbounded calls. |
| FR-09 | Backend plugin system | P0 | Pluggable backends: native_python, jax, pytorch, subprocess_binary (OCI digest-pinned), emulator_gp, emulator_nn, surrogate_diff, each implementing the Backend protocol (load/invoke/invoke_grad?/invoke_batch/warm/teardown). |
| FR-10 | Differentiability / grad | P0 | Adapters declaring differentiable:true implement grad returning a Jacobian with per-entry derived units; non-differentiable adapters return NOT_DIFFERENTIABLE on grad. |
| FR-11 | Registration + cost-class ceiling gate | P0 | Registration validates the descriptor, runs the conformance stub, and REJECTS any adapter whose cost_class exceeds the platform ceiling (enforcing the no-flagship-HPC non-goal), then publishes to the C5 registry. |
| FR-12 | Independence metadata | P0 | Descriptors carry independence_tags + underlying_code.repo/commit/algorithm_family so the C5 registry can resolve an implementation of an observable independent of a given code under test. |
| FR-13 | Broker isolation & security | P0 | Adapters run as brokered services outside the agent sandbox; subprocess binaries run under S10 (read-only rootfs, egress-deny, seccomp, resource caps); no secrets in EvalRequests; all calls mTLS + least-privilege scoped + audit-logged. |
| FR-14 | Batch evaluation | P1 | batch_evaluate vectorizes native/JAX backends (vmap) and pools subprocess backends; returns per-element results/errors preserving order; partial failure does not fail the batch. |
| FR-15 | Content-addressed cache | P1 | Cache deterministic/seeded results keyed by BLAKE3(adapter_id‖version‖underlying_version‖canonical(inputs)‖fidelity‖seed); cache hits emit fresh provenance marking the hit; stochastic-unseeded results are never cached. |
| FR-16 | Multi-fidelity | P1 | Adapters may declare fidelity_levels; callers select fidelity; results record fidelity_used; validity-domain and uncertainty may differ per fidelity. |
| FR-17 | Uncertainty propagation utilities | P1 | Provide linear (J Σ Jᵀ), Monte-Carlo, GP-posterior, and ensemble uncertainty helpers in the SDK, plus a coverage/calibration harness producing CalibrationEvidence for S3 CALIBRATION. |
| FR-18 | Degradation & error taxonomy | P0 | Implement the full C6 error taxonomy with correct retryability; bulkhead adapter backends (circuit breaker per adapter) so one backend failure never affects others; capture stderr on UNDERLYING_CODE_ERROR into provenance. |
| FR-19 | Reference adapter suite | P0 | Ship the flagship-thread adapters (eff-potential/bounce, GW spectrum, differentiable GW surrogate, collider fast-sim, Boltzmann/transport toy, Higgs observables) each with descriptor, validity domain, uncertainty model, calibration evidence, and at least one independent twin per observable for cross-code. |
| FR-20 | CLI + conformance harness | P1 | Ship argus-adapter CLI (new/validate/describe/eval/grad/register/calibrate/independence/cache-stats) and a conformance harness verifying units present, uncertainty present, domain declared, determinism honored, grad present iff differentiable, provenance emitted. |
| FR-21 | Determinism enforcement | P1 | Enforce declared determinism: a deterministic adapter producing differing output on identical (inputs,seed) trips a conformance/health alarm and is quarantined from resolve results until re-verified. |
| FR-22 | Observability | P1 | Every call emits an OTel span parented to the caller's trace plus cost/latency/error/cache metrics and an argus.s7.call.metered event; adapter health published as argus.s7.adapter.health. |
| FR-23 | Contract version compatibility | P1 | Broker accepts any request valid under a compatible minor C6 version; unsupported version ⇒ VERSION_UNSUPPORTED; breaking change dual-served during a migration window. |
| FR-24 | Log-space & compound units | P2 | Support log-space fields (e.g. log10 β/H) and compound/derived units with correct dimensional propagation into outputs and Jacobian entry units. |

### S7.6 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR-1 | Isolation | Adapters that need credentials run as **brokered services outside the agent sandbox**; the agent sandbox only sends C6 requests over the mediating proxy. Adapter code that shells out to binaries runs under S10 resource limits, read-only rootfs, egress-deny, seccomp. |
| NFR-2 | Units correctness | 100% of C6 fields carry units; any units mismatch is a hard, non-retryable error. Zero silent coercions. |
| NFR-3 | Uncertainty completeness | 100% of `evaluate` outputs carry a non-null uncertainty object of a declared representation; a null/absent uncertainty fails conformance. |
| NFR-4 | Reproducibility | An `EvalResult` is re-derivable from its C4 lineage (adapter_version, underlying_code_version, seed, config, input hash) bit-for-bit for `deterministic`/`seeded` adapters, or within a declared statistical tolerance for `stochastic`. |
| NFR-5 | Budget enforcement | The broker meters CPU/GPU/wallclock/cost against `budget_token` in near-real-time and halts on breach; no adapter call runs unbounded. |
| NFR-6 | Latency | A single lightweight `evaluate` returns within its declared `resource_envelope.typical_wallclock` (target: solver ≤ minutes, surrogate ≤ ms–seconds); `batch_evaluate` amortizes fixed cost. |
| NFR-7 | Scalability | Broker horizontally scalable to hundreds of concurrent adapter calls; cache reduces repeat cost; multi-fidelity supported. |
| NFR-8 | Independence guarantee | The registry can always answer "give me an implementation of observable O independent of code X" using `independence_tags` + `code.repo`. Two adapters sharing a repo/underlying code are never both counted as independent. |
| NFR-9 | Determinism control | `determinism ∈ {deterministic, seeded, stochastic}` is declared and enforced; a `deterministic` adapter that produces nondeterministic output on identical input is a conformance failure. |
| NFR-10 | Cost governance | Cost-class ceiling enforced at registration; per-call cost metered and emitted to S11; cost-per-call is a first-class metric. |
| NFR-11 | Security | No secrets in adapter EvalRequests; adapter descriptors + outputs are signed-artifact-eligible; every trust-boundary call is mTLS + least-privilege scoped + audit-logged. |
| NFR-12 | Contract compatibility | Broker accepts any request valid under a compatible minor C6 version; breaking change = major bump with dual-serving window. |
| NFR-13 | Observability | Every `evaluate`/`grad` emits an OTel span (parented to the calling job trace), cost/latency/error metrics, and a C4 record. |
| NFR-14 | Availability | Adapter broker control plane targets 99.5%; a single adapter backend failure degrades that adapter only (bulkheading), never the broker. |

---

## S8 — Data, Artifact & Provenance

**One-liner:** The foundational, zero-dependency data plane: a content-addressed artifact store, an append-only tamper-evident lineage/audit graph, pinned reproducibility manifests, and the fail-closed owner of contract C4 that makes every object in Argus addressable, reproducible, and contamination-auditable.

### S8.1 Mission & Positioning

S8 is the **bedrock** of Argus's dependency graph. It has **zero Argus-internal dependencies** (only base infra: PostgreSQL, an S3-compatible object store, and the S10 crypto/secrets primitives it links against) so that every other subsystem can safely depend on it. It owns contract **C4 (Artifact + Provenance Record)** and is the single writer of the provenance ledger.

The load-bearing thesis obligations S8 must physically guarantee:

- **Verify-before-trust / presumptive contamination:** nothing is trusted; every dataset, label, and literature match is auditable back to a frozen contamination-index version (S6) and a complete lineage chain. If it cannot be re-derived, it does not exist.
- **Trust integrity coupling:** an artifact's `claim_tier` may exceed `ran-toy` **only** if it references a signature-valid C3 Validation Report whose tier matches. S8 enforces this at write time and rejects (fail-closed) violations. S8 is where reward-hacking-by-relabeling is structurally blocked in the data plane.
- **Full provenance & bit-level reproducibility:** the lineage block is the reproducibility manifest; it must be sufficient to re-derive the artifact within a declared nondeterminism tolerance (validated continuously by the S11 re-run canary via the C4 `challenge`/re-derive path).
- **Structural safety:** S8 is in the **control/provenance trust zone**. All provenance writes go through the Rust ledger writer, **never** through agent-executed code. Agent sandboxes (S10) have no ledger credentials and no write path to S8's system of record.

### S8.2 Goals

- **G1:** Provide a content-addressed (BLAKE3) artifact store where the storage key IS the content hash, with write-once immutability for signed Validation Reports, the frozen contamination index, and any promoted artifact.
- **G2:** Provide an append-only, tamper-evident lineage/audit graph over C4 records, answering provenance queries ("what consumed contaminated dataset X?", "give me the full re-derivation manifest for model M", "what is the impact set if source S is retracted?") at 10^5+ artifacts without query degradation.
- **G3:** Enforce the C4 tiering-coupling invariant and reproducibility-manifest completeness at write time (fail-closed), so illegal artifacts never commit.
- **G4:** Guarantee bit-level (or declared-tolerance) reproducibility metadata: pinned container digest, code commit+dirty flag, adapter versions, seeds (global + per-library), config/params hashes, input hashes.
- **G5:** Provide a dataset registry with dataset versioning, splits, and blind/held-out segregation semantics that the verifier (S3) can rely on for leakage screens.
- **G6:** Provide external-source ingestion provenance (arXiv/GitHub/HEPData snapshots with `snapshot_hash`, license, `ingested_at`) so novelty questions are answerable against a frozen reference.
- **G7:** Meet the durability and immutability NFRs: ≥ 11 nines durability, write-once/append-only for reports, ledger, and frozen index.
- **G8:** Be language-neutral at the seam: C4 is canonical JSON Schema (draft 2020-12); S8 generates pydantic / TypeScript / Rust-serde bindings from one source of truth.

### S8.3 Scope

**In scope:** content hashing service; object store abstraction + retention/lifecycle; C4 schema ownership + binding generation; artifact record CRUD (create/read/query, no update — new record instead); lineage graph model + query API; tiering-coupling enforcement; reproducibility manifest capture + verification; dataset registry (versions, splits, blind segregation markers); external-source ingestion record capture; garbage-collection & retention with legal/immutability holds; signature-envelope storage & verification-at-consumption support; provenance event emission on NATS; re-derivation harness hooks for S11; audit export.

**Out of scope (owned elsewhere, consumed via contract):** the verifier signing key & report generation (S3/C3 — S8 only stores and verifies signatures at consumption); the frozen-index *construction* and RAG indexing (S6 — S8 stores the frozen-index artifacts as immutable C4 records and serves them); the sandbox/egress/secrets runtime (S10 — S8 links its KMS/crypto but does not implement isolation); orchestration/DAG (S5); human review (S9); actual re-run execution (S11 owns the canary scheduler; S8 provides the manifest + re-derivation comparison primitives).

### S8.4 Personas

- **P1 — Subagent runtime (S1/C1):** writes artifacts + provenance for every build step; consumes C4 create/read APIs and the reproducibility-manifest builder helper.
- **P2 — ML Builder (S2):** writes datasets, models, training logs, config/params artifacts; reads datasets and lineage.
- **P3 — Physics Verifier (S3):** fetches inputs by content hash (never runs agent code), writes signed Validation Reports to write-once storage, records leakage-screen provenance and independence attestations.
- **P4 — Evolver (S4):** writes variant lineage (`derived_from` chains across generations), reads scores' report provenance.
- **P5 — Control Tower (S5):** writes job/DAG-node provenance context, queries lineage to gate downstream nodes ("node outputs addressable only after provenance-committed").
- **P6 — Knowledge & Ingestion (S6):** writes external-source records + frozen-index artifacts as immutable C4 records; provides `contamination_index_version` pins.
- **P7 — Compute Adapters (S7):** emit a C4 provenance record per `evaluate`/`grad` call pinning adapter + underlying-code versions and seeds.
- **P8 — Human reviewer / governance (S9):** reads lineage graphs and Validation Report references in the review UI; needs impact-set queries and audit export.
- **P9 — Observability/Eval (S11):** reads artifacts, reports, and lineage to run the re-run canary and compute KPIs (provenance-completeness, reproducibility pass rate).
- **P10 — Federation/Interop (S12):** stores conformance evidence artifacts; federated entities write via the same untrusted-zone-brokered path (no elevated trust).
- **P11 — Platform SRE / auditor:** operates GC, retention, holds, disaster recovery, and tamper-evidence audits.

### S8.5 User Stories

- **US1:** As a subagent, I write a trained-model artifact with a full lineage block and get back a content hash so downstream nodes can reference it deterministically.
- **US2:** As the verifier, I write a signed Validation Report to a write-once bucket and it can never be silently overwritten; any consumer can verify the signature before trusting the tier.
- **US3:** As the ML Builder, I try to write a `novel-needs-human` model without a signed report and S8 **rejects** it (`ILLEGAL_TIER`), fail-closed.
- **US4:** As a human reviewer, I ask "what artifacts derive, transitively, from contaminated dataset X (frozen index v2026-06-01)?" and get a complete, correct impact set in bounded time.
- **US5:** As the S11 canary, I fetch an artifact's reproducibility manifest, re-run it, and get a deterministic pass/fail comparison against a declared tolerance.
- **US6:** As S6, I ingest an arXiv snapshot and its `external_source_ref` (snapshot_hash, license, ingested_at) becomes an immutable lineage input for any dataset built from it.
- **US7:** As an SRE, I place a legal/audit hold on an artifact family and GC cannot delete anything in that set until the hold is released, with full audit trail.
- **US8:** As any consumer, I fetch an artifact whose stored bytes no longer match its `content_hash` and S8 refuses to serve it (tamper detected → quarantine + Sev event).
- **US9:** As the Evolver, I persist a variant with a `derived_from` edge to its parent and the generation lineage is queryable as a DAG.
- **US10:** As a dataset producer, I register a dataset with train/blind splits and the blind split's labels are never materialized into any agent-readable artifact.
- **US11:** As a contract consumer, I regenerate pydantic/TS/Rust bindings from the frozen C4 JSON Schema and they are byte-stable per schema version.
- **US12:** As governance, I export a tamper-evident audit log slice (Merkle-anchored) for an external compliance review.

### S8.6 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-01 | Content-addressed storage | P0 | Every artifact blob is stored under its BLAKE3 content hash as the key; identical bytes dedup to one object; the hash is computable pre-commit via HashBlob and streaming-capable for large objects. |
| FR-02 | Canonical deterministic record hashing | P0 | Structured records hash over a pinned, versioned canonical serialization (sorted keys, normalized numbers/unicode) excluding volatile fields, so hashes are stable across Python/TS/Rust and platforms. |
| FR-03 | Write-once immutability | P0 | Signed Validation Reports, the frozen contamination index, promoted artifacts (tier>ran-toy), and ledger checkpoints are stored in Object-Lock write-once buckets and can never be overwritten or deleted while referenced/held. |
| FR-04 | Append-only tamper-evident ledger | P0 | Artifact records and lineage edges are INSERT-only; a Merkle hash chain with periodically signed checkpoints provides tamper-evidence and audit export with inclusion proofs. |
| FR-05 | Tiering-coupling enforcement (fail-closed) | P0 | A record with claim_tier>ran-toy commits ONLY if it references a signature-valid C3 report whose tier matches and passed==true; novel-needs-human additionally requires leakage PASS + cross-code present; violations reject with ILLEGAL_TIER and do not commit. |
| FR-05b | Report signature verification at write and read | P0 | Signed report artifacts are verified against active, non-revoked S3 verifier keys in the trust store at write time; consumers can call VerifySignature; unsigned/tampered reports are never served as tier-bearing. |
| FR-06 | Reproducibility manifest capture | P0 | Every artifact captures a complete lineage block (inputs, derived_from, code repo+commit+dirty, environment_digest, adapters+versions, seeds global+per-library, config_hash, params_hash) sufficient to re-derive it. |
| FR-07 | Lineage completeness gate | P0 | AssertLineageComplete and the commit path reject/flag artifacts with any missing required lineage field; incomplete-lineage artifacts are non-promotable. |
| FR-08 | Lineage graph queries | P0 | Provide ancestor/descendant/both traversals with edge-type filters and depth limits, plus impact-set/contamination-trace queries returning tiers and report refs, at 10^5+ nodes within SLO. |
| FR-09 | DAG enforcement / cycle rejection | P1 | Any edge insert that would create a cycle in the lineage graph is rejected with CYCLE_DETECTED at commit time. |
| FR-10 | Dataset registry with versions & splits | P0 | Register datasets as versioned families with typed splits (train/val/test/blind/null_control/injection), row counts, schema refs, and contamination_index_version. |
| FR-11 | Blind/held-out segregation | P0 | Splits with role in {blind,test-held-out,null_control,injection} are access_scope=verifier-only; their labels are never materialized to non-verifier scopes; ResolveSplit denies label access without a verifier-scope token. |
| FR-12 | External-source ingestion records | P0 | Register immutable ExternalSourceRef (source,id,url,snapshot_hash,ingested_at,license) as lineage nodes so datasets built from them are auditable against a frozen reference. |
| FR-13 | Contamination-index pinning | P0 | Any ingested/derived artifact records the contamination_index_version used, enabling novelty questions to be answered against a frozen index snapshot. |
| FR-14 | Verify-on-read integrity | P0 | On every artifact serve, integrity is verified against content_hash; a mismatch refuses the read, quarantines the record, and emits an ARTIFACT_TAMPER Sev-1 event. |
| FR-15 | Provenance event stream | P1 | Emit artifact.created/promoted/flagged/tamper_detected, lineage.edge_added, hold.*, gc.swept, ledger.checkpoint, dataset.registered on NATS JetStream, at-least-once, idempotent by content_hash. |
| FR-16 | Retention, GC & holds | P1 | GC collects only unreferenced scratch blobs; write-once and reachable-from-promoted/held artifacts are never collected; legal/audit holds block deletion; GC is dry-run-first and quorum-gated; ledger rows/Merkle leaves are never deleted. |
| FR-17 | Schema ownership & binding generation | P1 | Own canonical C4 JSON Schema (draft 2020-12); generate byte-stable pydantic/TS/Rust bindings per version; semver with minor-additive/major-breaking + dual-serve migration. |
| FR-18 | Re-derivation comparison hooks | P1 | Provide GetReproducibilityManifest and RecordReproducibilityCheck so the S11 canary can re-run and record a deterministic pass/fail against a declared nondeterminism tolerance without mutating the original record. |
| FR-19 | Audit export with inclusion proofs | P2 | Export a tamper-evident audit slice (records + Merkle checkpoints + inclusion proofs) for external compliance review. |
| FR-20 | Least-privilege scoped access | P0 | All APIs require mTLS + capability scopes; only the Rust ledger writer holds DB write creds; agent sandboxes have no ledger credentials or write path to the system of record. |
| FR-21 | Idempotent, crash-safe commit | P1 | Commit is transactional and idempotent by content_hash; partial uploads/crashes leave no committed record; orphan blobs are GC-eligible. |
| FR-22 | Contract version compatibility | P1 | Accept any message valid under a compatible minor C4 version (ignore unknown additive fields); reject incompatible major versions with VERSION_UNSUPPORTED outside migration windows. |

### S8.7 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR1 | Durability | Signed reports, ledger, frozen index stored write-once with ≥ 99.999999999% durability; immutable/append-only. |
| NFR2 | Reproducibility | Lineage block sufficient for bit-for-bit (or declared statistical tolerance) re-derivation; verified continuously by S11 canary; a broken lineage edge makes an artifact non-promotable and flags it. |
| NFR3 | Provenance completeness | 100% of externally-visible artifacts and 100% of tier promotions have complete, queryable lineage; incomplete-lineage artifacts are non-promotable. |
| NFR4 | Integrity/tamper-evidence | Content hash verified at every consumption; hash mismatch invalidates artifact everywhere and raises a Sev event; ledger is append-only + Merkle-anchored. |
| NFR5 | Scale | Registry and lineage graph scale to 10^5+ artifacts without query degradation; impact-set/transitive queries return within declared SLOs (P95 < 2 s at 10^5 nodes). |
| NFR6 | Fail-closed | Any write violating hash / lineage-completeness / tier-coupling / immutability fails and does NOT commit. |
| NFR7 | Security | Writes to system of record go through the Rust ledger writer; no ledger credentials in agent sandboxes; all inter-subsystem calls mTLS + least-privilege scopes; every trust-boundary action audit-logged. |
| NFR8 | Availability | Control-plane read/write APIs target 99.5%; object reads target higher via object-store SLA. |
| NFR9 | Latency | Single artifact write (hash + record commit) P95 < 300 ms for objects < 100 MB (excluding upload time); metadata read P95 < 50 ms. |
| NFR10 | Contract compatibility | Accept any message valid under a compatible minor C4 version; breaking changes bump major and dual-serve during migration. |
| NFR11 | Determinism of hashing | BLAKE3 over a canonical byte serialization; canonicalization is spec-pinned and versioned so hashes are stable across languages/platforms. |

---

## S9 — Human-in-the-loop Review & Governance

**One-liner:** The mandatory, non-bypassable human gate that queues verifier-signed candidates, drives claim-tier sign-off (sole promoter of `novel-needs-human` with S3), enforces publication guardrails and hard rate-limits, and produces a tamper-evident governance audit trail sized to human review throughput.

### S9.1 Mission & Positioning

S9 is Argus's **human governance zone**: the only pathway through which any external-facing artifact leaves the platform, and (jointly with the S3 verifier) the only promoter of the `novel-needs-human` claim tier. Its wager is that autonomy in Argus is *sized to human review throughput, not the reverse* — S9 owns the back-pressure signal that throttles the Control Tower (S5) when reviewers are the bottleneck. S9 does not produce physics, does not run agent code, and holds no ability to alter Validation Reports; it *reads* signed C3 reports and C4 lineage, *renders* them for humans, *records* decisions immutably, and *gates* emission.

### S9.2 Goals

- **G1 — Non-bypassable human gate.** No external-facing artifact (publication text, dataset release, `novel` claim, external subagent admission decision) is emitted without a recorded, authenticated, attributable human sign-off. There is no code path that emits externally without a committed S9 approval record.
- **G2 — Sole promoter (with S3) of `novel-needs-human`.** A subagent can never self-assign `novel`; even S3 only *marks a candidate*. S9 converts a candidate into an accepted `novel-needs-human` claim via a recorded human decision, and only S9 can authorize external emission of it.
- **G3 — Throughput-sized autonomy.** S9 enforces a global cap on items entering the review queue per unit time and emits a back-pressure signal that S5 honors; the platform never queues faster than humans can responsibly review.
- **G4 — Publication guardrails.** Encode the hard non-goals (no autonomous discovery/confirmation of new fundamental theory, no autonomous paper submission, no autonomous flagship-HPC execution, no empirical-validation claims) as *enforced policy gates*, not advice, blocking emission when violated.
- **G5 — Tamper-evident audit.** Every review action, sign-off, override, escalation, and emission decision is recorded to an append-only, hash-chained governance ledger with full attribution and links to the exact C3/C4 artifacts reviewed.
- **G6 — Reviewer efficiency & correctness.** Give reviewers a claim-tier review UI that surfaces exactly the evidence needed (verifier checks, injection/null results, cross-code agreement, leakage screen, lineage graph, uncertainty calibration) to make a defensible decision quickly, with structured decision capture.
- **G7 — Governance controls.** Multi-reviewer policies (dual sign-off / quorum for `novel` and for external emission), conflict-of-interest handling, reviewer role/credential management, delegation, and recusal.

### S9.3 Non-Goals (S9-specific)

- S9 does **not** grade physics or re-run verifier checks (that is S3). It may *request* a re-verification (via C3 `challenge`) but never computes a score itself.
- S9 does **not** execute or sandbox agent code (S10) and never mints compute budgets.
- S9 does **not** decide routing or job decomposition (S5); it only supplies the back-pressure signal and receives human-review wait states.
- S9 does **not** author scientific content; it reviews and approves/rejects/annotates.
- S9 does **not** perform the physical act of paper submission or dataset upload to an external venue — it *authorizes* an emission, and the actual transport is out of scope by policy (mandatory human performs external submission). S9 records the authorization and the guardrail evaluation.

### S9.4 Personas

- **Domain Reviewer (physicist).** Judges whether a candidate `novel` result is defensible given the Validation Report and lineage; assesses whether it merely recapitulates known physics (contamination), whether uncertainty is credible, whether cross-code agreement is real. Primary UI user.
- **ML Reviewer.** Assesses whether the pipeline, leakage screens, and calibration are sound; complements the domain reviewer for dual sign-off.
- **Governance Officer / Approver.** Owns publication guardrail decisions and final external-emission authorization; manages rate-limit budgets; handles escalations and quarantine dispositions.
- **Federation Admissions Reviewer.** Reviews S12 conformance evidence and admits/denies `federated` subagents (a governance decision even though runtime trust is unchanged).
- **Auditor / Compliance.** Read-only; queries the governance ledger, verifies hash-chain integrity, exports audit reports.
- **Reviewer-Admin.** Manages reviewer roster, roles, credentials, COI declarations, delegation rules, and policy configuration.
- **System actors (non-human):** S5 (enqueues review tasks via C2 wait states), S3 (supplies signed reports), S8 (lineage/artifacts), S6 (frozen contamination index for novelty context), S11 (KPIs/telemetry).

### S9.5 User Stories (representative; full FR list below)

- As a Domain Reviewer, I open a review task and see the signed Validation Report with each check (injection/null/cross-code/physical-consistency/leakage/calibration) rendered with pass/fail, metric, threshold, and evidence, plus the lineage graph and the frozen-contamination-index version, so I can decide in minutes.
- As a Governance Officer, when a `novel-needs-human` candidate arrives, I require a second independent reviewer and a guardrail check before I can authorize any external emission.
- As a Governance Officer, I set a weekly external-emission budget and the platform refuses (and audits) any emission beyond it, independent of agent throughput.
- As a Reviewer-Admin, I declare that Reviewer X is conflicted on subtopic Y (co-author of a cited result) and the system auto-recuses X from those tasks and blocks their sign-off.
- As an Auditor, I export a tamper-evident trail proving every external artifact in Q2 had a valid signed report and a human sign-off by an eligible reviewer.
- As S5, when I hit a human-review wait state, I create a review task and receive a back-pressure signal telling me whether to admit more jobs.
- As a Federation Admissions Reviewer, I review a Gold conformance record and either admit the subagent to the registry (governance approval) or reject with a recorded reason.

### S9.6 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| S9-FR01 | Signature-verified intake, fail-closed | P0 | On CreateReviewTask, verify the C3 Validation Report signature against the trust store and verify every referenced C4 artifact content_hash matches its bytes. Any failure quarantines the task (never queued) and raises a Sev alert. No unsigned/tampered report can ever enter the review queue. |
| S9-FR02 | Non-bypassable emission gate | P0 | No external-facing artifact is emitted without a committed ReviewDecision and a single-use, HSM-signed EmissionAuthorization bound to the exact artifact hashes and emission_class. External-emission actors MUST verify the authorization; there is no code path that emits without it. |
| S9-FR03 | Sole promoter of novel-needs-human (with S3) | P0 | A task claiming novel-needs-human is accepted only via S9 human sign-off; S9 records claim_tier_promoted=true only on that acceptance. Subagents/S3 candidates cannot self-finalize novel. Novelty acceptance requires all C3 LEAKAGE checks PASS and ≥1 CROSS_CODE PASS. |
| S9-FR04 | Guardrail policy engine enforcing non-goals | P0 | Evaluate every emission against versioned guardrail policies; hard-block emission_class in {new-fundamental-theory-confirmation, autonomous-paper-submission, flagship-HPC-execution, empirical-validation-claim} with no override by any role. Record GuardrailResult with policy_version. |
| S9-FR05 | Dual / quorum sign-off with distinct eligible principals | P0 | For novel acceptance require ≥1 domain + ≥1 ml distinct principals; for external emission additionally require ≥1 governance principal. A single principal cannot satisfy two required roles. Enforce eligibility (role, subtopic) and COI exclusion. |
| S9-FR05b | At-most-one active review (no double-review races) | P0 | Task assignment uses leases + DB optimistic locking so two reviewers cannot concurrently commit conflicting state transitions; sign-off commits are serialized per task. |
| S9-FR06 | Rate-limit & external-emission budget with back-pressure | P0 | Enforce a global queue-admission rate cap and per-emission-class external-emission budgets via token buckets; publish a BackPressureGauge to S5 and S11. When admission is exhausted, defer (audit) rather than drop; when emission budget is exhausted, block emission independent of agent throughput. |
| S9-FR07 | Hash-chained tamper-evident governance ledger | P0 | Every task creation, state transition, sign-off, guardrail evaluation, emission authorization/completion, COI recusal, policy/reviewer change, and challenge is appended to a BLAKE3 hash-chained, per-actor-signed, append-only ledger with periodic write-once checkpoints. UPDATE/DELETE forbidden. |
| S9-FR07b | Continuous ledger integrity verification | P0 | A canary recomputes the hash chain from the last checkpoint on a schedule and on demand (/ledger/verify); any break freezes emissions and raises Sev-1. |
| S9-FR08 | Claim-tier review UI | P0 | Render the signed C3 report (each check: type, PASS/FAIL/INCONCLUSIVE, metric, threshold, evidence, uncertainty), the C4 lineage graph, novelty context vs the frozen contamination index (S6), and calibration view (S11). Capture structured decision + rationale. |
| S9-FR09 | Decision reproducibility & immutability | P0 | Every ReviewDecision/SignOff pins the exact report_id, artifact content_hashes, contamination_index_version, and policy_version seen by the human. Committed records are immutable; corrections are new superseding records with supersedes edges. Decisions are persisted as C4 artifacts. |
| S9-FR10 | COI detection, recusal, and delegation | P1 | Maintain reviewer COI declarations; auto-exclude conflicted or self-reviewing principals from a task's eligible pool and block their sign-off; support recorded delegation chains and recusals. |
| S9-FR11 | Escalation, SLA aging, reassignment | P1 | Track task aging against SLA; warn, then escalate to Governance Officer or reassign on breach; quorum timeouts escalate. No path auto-approves on timeout. |
| S9-FR12 | Re-verification requests (C3 challenge) | P1 | A reviewer may request re-verification, invoking C3 challenge(report_ref); results are linked as new evidence and the task returns to review. INCONCLUSIVE results never count as approval basis. |
| S9-FR13 | Federation admission review | P1 | Review S12 conformance evidence (via C5 descriptor revision) and admit/deny federated subagents as a recorded governance decision; admission grants no elevated runtime trust. |
| S9-FR14 | Reviewer & role management | P1 | CRUD reviewers, roles, eligible subtopics (C5 taxonomy), credentials (WebAuthn), status; enforce least-privilege authz on all actions. |
| S9-FR15 | Quarantine disposition | P0 | Quarantined tasks (signature/hash/guardrail hard-fail) can only be routed to re-verification or permanent reject by a Governance Officer; never to emission. |
| S9-FR16 | Audit export & queryable trail | P1 | Provide queryable, exportable, signed audit bundles proving each external artifact had a valid signed report and eligible human sign-off; ledger queryable by task/event/range. |
| S9-FR17 | KPI emission to S11 | P2 | Emit queue depth, aging, sign-off latency, override rate, guardrail-block rate, reviewer-agreement rate, emission-vs-budget as first-class KPIs. |
| S9-FR18 | Notifications | P2 | Notify assignees, escalation targets, and governance officers via UI/email/push for assignment, SLA, escalation, quorum timeout, guardrail block, quarantine. |
| S9-FR19 | WebAuthn step-up for emission-grade actions | P1 | Emission authorization and governance sign-off require a fresh WebAuthn step-up assertion recorded in the SignOff/authorization. |
| S9-FR20 | Idempotent, ordered event integration | P1 | CreateReviewTask idempotent on (root_request_id, artifact hash set); duplicate S3/S5 signals coalesce; emitted events carry monotonic sequence for consumers. |

### S9.7 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR1 | Non-bypassability (hard) | No external emission without a committed approval record; enforced structurally (emission authorization token is minted only by S9 and required by any external-emission actor). Absence/tamper ⇒ fail-closed. |
| NFR2 | Tamper-evidence | Governance ledger is append-only, hash-chained (BLAKE3), and every entry is signed by the acting principal's key; integrity is continuously verifiable and any break is a Sev-1. |
| NFR3 | Signature trust | S9 verifies every C3 report signature against the trust store at intake and again at emission; unsigned/tampered ⇒ quarantine, never queue. |
| NFR4 | Throughput sizing | Global queue-admission rate cap is enforced and exposes a back-pressure gauge to S5; the cap is configurable and audited. |
| NFR5 | Availability/durability | Control-plane 99.5%; ledger and approval records stored write-once with ≥11 nines durability, immutable/append-only. |
| NFR6 | Attribution & authz | Every action mTLS-authenticated and authorized by least-privilege role scopes; a reviewer cannot approve outside their eligible roles/subtopics; dual-sign-off reviewers must be distinct principals. |
| NFR7 | Latency | Queue/list/detail views < 2 s p95; sign-off commit (ledger append + token mint) < 1 s p95; intake of a new report (signature verify + guardrail pre-screen) < 3 s p95. |
| NFR8 | Reproducibility of decisions | Every decision record pins the exact `content_hash`es of the report/artifacts reviewed and the contamination_index_version, so a decision can be re-audited against exactly what the human saw. |
| NFR9 | Least astonishment / immutability | A committed decision is immutable; corrections are new superseding records with `supersedes` edges, never edits. |
| NFR10 | Observability | Every review task and decision emits OTel spans and S11 KPIs (queue depth, aging, sign-off latency, override rate, guardrail-block rate, reviewer agreement rate). |
| NFR11 | Security | S9 holds no agent-executable code path; UI/API run in the control/governance zone; no secrets in agent sandboxes; emission-authorization signing key is HSM/vault-backed and never leaves the governance zone. |

### S9.8 Scope Boundaries (contract coupling)

S9 consumes ONLY: C3 (Validation Reports + `challenge`), C4 (artifacts/lineage), C5 (registry: reviewer-eligible independence tags, federation conformance descriptors), C2 (job/review-task envelopes & result/back-pressure to S5), and S11 telemetry APIs. S9 produces: the S9 Governance/Review API, the `EmissionAuthorization` token & event, the `ReviewDecision`/`SignOff` records (persisted as C4 artifacts with lineage), the back-pressure gauge, and the append-only governance ledger.

---

## S10 — Security, Sandbox & Runtime

**One-liner:** The structural trust boundary of Argus: hard isolation for all agent-executed code, network egress control, resource/time/cost governance, per-job secrets brokering, and tamper-evident enforcement that makes reward-hacking and self-modification physically impossible rather than merely disallowed.

### S10.1 Mission & Thesis Alignment

S10 is Argus's **structural safety substrate**. The platform's entire trust model rests on one assertion: agent-generated code (subagent reasoning steps, S2 ML-Builder training code, S4 Evolver variants, federated S12 subagents) is *presumed adversarial*, and the harness/verifier/reward/ledger path is *physically unreachable* from it. S10 is the subsystem that makes that assertion true by construction. It provides:

1. **Hard isolation** — every unit of agent-executed code runs in a gVisor/Firecracker sandbox with read-only rootfs, seccomp-filtered syscalls, no write access to any trust-path resource, and no ambient credentials.
2. **Egress control** — default-deny network, mediated by an allowlisting egress proxy that logs every request; the only reachable destinations are the content-addressed store and explicitly declared adapter/broker endpoints.
3. **Resource, time & cost governance** — hard CPU/GPU/memory/wallclock/token/USD quotas enforced by the runtime (not by the agent), metered in near-real-time, halting jobs on breach. No unbounded loops.
4. **Secrets brokering** — secrets never enter a sandbox; short-lived, least-privilege, audience-scoped tokens are minted per job; credentialed operations run in brokered services outside the sandbox.
5. **Tamper-evidence & policy enforcement** — any attempt to write the trust path, escape the sandbox, or exceed a scope is a Sev-1 event that halts and quarantines the job with full forensic capture.

S10 has **zero Argus-internal dependencies** (only base infrastructure: Kubernetes, Linux kernel, KMS/Vault, object store). This is deliberate: it is the bedrock the trust guarantees rest on, so nothing agent-executed can reach beneath it.

### S10.2 Goals

- **G1 (Isolation guarantee):** No agent-executed code can read or write the harness, verifier code, reward path, provenance ledger, budget enforcer, or its own supervisor. A sandbox escape is a Sev-1.
- **G2 (Egress guarantee):** Network egress is deny-by-default; only allowlisted destinations are reachable, every attempt is logged, and exfiltration attempts are detected and blocked.
- **G3 (Resource/cost guarantee):** CPU/GPU/memory/wallclock/token/USD are hard-capped and metered by the runtime; breach halts the job with partial-result capture; cost-per-verified-artifact is a first-class emitted metric.
- **G4 (Secrets guarantee):** No secret material ever resides inside a sandbox; all credentialed access is brokered by out-of-sandbox services holding short-lived scoped tokens.
- **G5 (Tamper-evidence):** Every trust-boundary action (mint token, launch sandbox, egress decision, quota breach, policy violation, quarantine) is audit-logged to an append-only, tamper-evident store.
- **G6 (Reproducible execution):** Every sandbox launch pins an OCI image by digest and records the full execution environment (image digest, kernel, seccomp profile, cgroup limits, seeds passthrough) so S8 lineage is complete and S11's re-run canary can reproduce it.
- **G7 (Determinism of enforcement):** Policy decisions (allow/deny/halt) are deterministic functions of a signed policy bundle + request, so they are auditable and testable.

### S10.3 Non-Goals (explicit)

- **NG1:** S10 does not grade physics or assign claim tiers (that is S3). It never inspects ML result quality.
- **NG2:** S10 does not decide *what* work to run or route jobs (that is S5). It executes and enforces; it does not orchestrate DAGs.
- **NG3:** S10 does not run flagship HPC (numerical relativity, large hydro). The cost ceiling structurally rejects such workloads (enforcing the platform non-goal); the *policy* of what constitutes flagship HPC is expressed as a cost/resource ceiling S10 enforces.
- **NG4:** S10 does not store provenance records itself (that is S8); it emits C4 records for its own launch events via the S8 writer and forwards its audit log to the tamper-evident ledger.
- **NG5:** S10 does not implement the physics adapters (S7) or verifier (S3); it hosts them under isolation and brokers their credentials.

### S10.4 Personas

- **P1 — Subagent Runtime (S1/C1):** an automated ML researcher whose `build()` step must run untrusted code. Needs a launch API, a scratch volume, brokered adapter access, and clear typed errors when it hits a wall (SANDBOX/POLICY/BUDGET).
- **P2 — ML Builder Engine (S2):** generates and executes training code; needs GPU-backed sandboxes, near-real-time spend feedback, and auto-repair-friendly error surfaces (captured stderr, OOM signals).
- **P3 — Evolver (S4):** launches many short-lived variant sandboxes under a hard generation/spend budget; needs fast launch, strict per-loop budget accounting, and structural guarantees that a variant cannot read the reward path or held-out data.
- **P4 — Physics Verifier (S3):** runs *outside* the agent sandbox in its own zone but relies on S10 to (a) fetch frozen pipelines into an isolated exec context, (b) keep its signing key and blind data unreachable from agent code, and (c) run cross-code adapters in isolation.
- **P5 — Control Tower (S5):** mints budget tokens and capability scopes per C2 job, needs to enforce concurrency classes and back-pressure, and consumes S10 spend/quota events.
- **P6 — Compute Adapters (S7):** wrapped C++/Fortran binaries that S10 sandboxes; brokered when they need credentials or external endpoints.
- **P7 — Platform Security Engineer (human):** authors and signs policy bundles, reviews Sev-1 quarantines, runs the escape-attempt red-team suite, rotates keys.
- **P8 — SRE / Cost owner (human):** monitors quota utilization, cost-per-verified-artifact, sandbox launch latency/failure rates via S11.
- **P9 — Federation partner (S12):** external subagent author whose code runs in the *same untrusted zone* with *no elevated trust*; interacts with S10 only through the same launch/broker/quota surface.

### S10.5 User Stories

- **US1:** As a Subagent, I call `launch_sandbox` with a job's budget_token and capability_scopes and get an isolated execution handle so I can run generated training code without any path to the trust plane.
- **US2:** As the Evolver, I run 200 variant trainings under a single job budget and the runtime halts me the instant cumulative spend hits the cap, capturing partial results, so no loop runs unguarded.
- **US3:** As a Security Engineer, when a sandbox attempts to write a read-only trust mount or open a disallowed egress socket, the job is halted, the sandbox image is snapshotted for forensics, a Sev-1 is raised, and nothing is silently degraded.
- **US4:** As an ML Builder, when my generated code needs an S7 adapter that requires a credential, the call is brokered outside my sandbox and I never see the secret — I only see normalized C6 results.
- **US5:** As the Control Tower, I mint a `budget_token` scoped to exactly this job's caps and capability_scopes, and S10 refuses any operation outside those scopes.
- **US6:** As the Verifier (S3), I trust that the subagent that produced a pipeline could not have read my signing key, my blind datasets, or the reward path, because S10 places those in zones physically unreachable from the sandbox.
- **US7:** As an SRE, I query near-real-time spend and quota utilization per job and see cost-per-verified-artifact roll up in Grafana.
- **US8:** As a Security Engineer, I publish a new signed policy bundle (egress allowlist, seccomp profile, resource ceilings) and it takes effect atomically with a version stamp recorded in every subsequent launch's provenance.
- **US9:** As a Federation partner, my externally contributed subagent runs under the identical isolation and gains no elevated trust; if it misbehaves it is quarantined like any internal code.
- **US10:** As the platform, every trust-boundary action is on an append-only tamper-evident audit log so a post-incident audit can reconstruct exactly what happened.

### S10.6 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-1 | Launch isolated execution context | P0 | Provide launch_sandbox that materializes a gVisor or Firecracker sandbox with read-only rootfs, dropped capabilities, no_new_privileges, user-namespace remap, and a size-capped scratch volume, returning a SandboxHandle. |
| FR-2 | Terminate & freeze | P0 | Provide terminate and freeze (cgroup SIGSTOP) so the runtime can halt a sandbox without letting agent code run cleanup hooks. |
| FR-3 | Digest-pinned, signed images only | P0 | Reject tag-only OCI references; resolve to digest and verify cosign signature before launch. |
| FR-4 | Seccomp-BPF syscall filtering | P0 | Apply a signed seccomp profile per runtime class that denies dangerous syscalls (ptrace, mount, kexec, bpf, keyctl, privileged unshare) with EPERM + audit. |
| FR-5 | Read-only trust mounts | P0 | Guarantee the harness, verifier code, reward path, provenance ledger, supervisor binary/config, and budget enforcer are unreachable/read-only from the sandbox; any write attempt is detected. |
| FR-6 | No ambient credentials in sandbox | P0 | Ensure no secret material (keys, tokens beyond the sandbox's own scope handle, env secrets) exists inside the sandbox filesystem, image, or environment. |
| FR-7 | Default-deny egress | P0 | Sandbox network namespace drops all egress by default and redirects permitted traffic through the egress proxy only. |
| FR-8 | Allowlisting egress proxy with DNS pinning | P0 | Proxy enforces destination allowlist = scope ∩ policy, owns DNS resolution (sandbox cannot resolve), validates TLS SNI/host, and pins IP for the connection. |
| FR-9 | Per-request egress logging & exfil detection | P1 | Log every egress request (dst, bytes, verdict) to the audit ledger; apply soft/hard byte thresholds triggering alert/halt. |
| FR-10 | Pre-flight budget admission | P0 | Admit a launch only if the requested envelope fits remaining budget across all dimensions via reserve-with-compare-and-swap. |
| FR-11 | Near-real-time resource metering | P0 | Sample cgroup CPU/mem/io and DCGM GPU-seconds/MIG at ≤5s cadence and debit the budget ledger. |
| FR-12 | Hard cap enforcement & mid-flight halt | P0 | On any dimension breach, freeze then terminate the sandbox within ≤2s (+declared overshoot), capturing partial results. |
| FR-13 | Wallclock & pids limits | P0 | Enforce max_wallclock_s and pids ceilings via cgroups/runtime timers. |
| FR-14 | USD cost roll-up | P0 | Convert all metered dimensions to USD via a signed price table and enforce max_cost_usd; emit cost-per-verified-artifact inputs. |
| FR-15 | Secrets broker for credentialed ops | P0 | Provide out-of-sandbox brokers that perform credentialed adapter/store/model operations on behalf of scope-checked sandbox requests, never exposing secrets. |
| FR-16 | Short-lived scoped tokens | P0 | Mint per-job, audience-bound, ≤15min TTL tokens; support offline verification and attenuation without KMS round-trips. |
| FR-17 | Broker is the only agent write path | P0 | Agent-origin artifact writes to the store/ledger go exclusively through the store-writer broker (enforces C4 immutability; agents cannot write the ledger directly). |
| FR-18 | Budget token minting/verification | P0 | Mint and verify signed budget tokens encoding C2 budget caps; verification enforced at every metered operation. |
| FR-19 | Capability-scope enforcement | P0 | Enforce that every action (egress dest, adapter, dataset, broker audience) is a subset of the scope_token grants; deny otherwise. |
| FR-20 | Trust-path write detection | P0 | Detect any write attempt to a read-only trust mount via VFS deny + host fanotify/eBPF watcher and raise Sev-1. |
| FR-21 | Sandbox escape detection | P0 | Host eBPF monitor detects namespace/cgroup/proc escape indicators and raises Sev-1. |
| FR-22 | Quarantine with forensic snapshot | P0 | On Sev-1, freeze, snapshot rootfs+scratch+netlog+audit slice to write-once store, open a QuarantineRecord, page Security Engineer, and never release un-snapshotted. |
| FR-23 | Tamper-evident audit log | P0 | Append every trust-boundary action to a hash-chained, periodically-anchored append-only log with chain-verify API. |
| FR-24 | Launch-provenance emission (C4) | P0 | Emit a C4 record capturing the full ExecEnvironmentDigest for each launch via the S8 ledger writer for reproducibility. |
| FR-25 | Signed, versioned policy bundles with atomic rollout | P0 | Serve semver-versioned, signed, content-addressed policy bundles; pin per-launch version; roll out atomically without affecting in-flight sandboxes. |
| FR-26 | Spend/quota/security event streams | P1 | Publish spend, quota.breach, sandbox.lifecycle, and security (sev≥2) events on NATS for S5/S9/S11. |
| FR-27 | LLM token metering hook | P0 | Provide a brokered model-call path that counts tokens, debits budget, captures prompt/response provenance, and halts on token/cost exhaustion. |
| FR-28 | GPU isolation & MIG partitioning | P1 | Allocate GPUs/MIG slices with per-sandbox isolation and DCGM-based metering; prevent cross-sandbox GPU memory access. |
| FR-29 | Flagship-HPC cost ceiling guard | P0 | Reject at admission any requested envelope exceeding the platform resource/cost ceiling (encodes the non-goal of flagship HPC execution). |
| FR-30 | Fail-closed degradation | P0 | On any dependency outage (quota, policy, KMS, broker) default to denial/pause rather than uncapped or credential-exposing execution. |
| FR-31 | Federated parity (no elevated trust) | P1 | Ensure federated (S12) subagent code runs under identical isolation with no elevated trust and is subject to the same quarantine path. |
| FR-32 | Reproducible re-launch support | P1 | Support relaunch of a prior execution environment from its ExecEnvironmentDigest to enable S11's re-run canary. |

### S10.7 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR-1 | Isolation hardness | The sandbox boundary must survive a defined red-team escape suite (syscall fuzzing, mount-escape, /proc & cgroup escapes, GPU-driver ioctl abuse, time-of-check/time-of-use races). Zero passes allowed to ship. |
| NFR-2 | Enforcement not in agent | All caps/policies are enforced by the supervisor/kernel/proxy — never by code the agent can read or modify. Testable by asserting the enforcement path is on read-only mounts with separate credentials. |
| NFR-3 | Launch latency | p50 sandbox cold-launch ≤ 3s (gVisor) / ≤ 5s (Firecracker microVM); warm-pool launch p50 ≤ 800ms. GPU attach adds ≤ 2s. |
| NFR-4 | Metering latency | Spend/quota telemetry reflects usage within ≤ 5s; halt-on-breach fires within ≤ 2s of the cap being crossed (bounded overshoot budget declared and enforced). |
| NFR-5 | Throughput/scale | ≥ hundreds of concurrent sandboxes; ≥ thousands queued; broker and proxy horizontally scalable; audit log ingest ≥ 10k events/s. |
| NFR-6 | Availability/durability | Control-plane (broker, policy service, quota service) 99.5% availability; audit log write-once/append-only with ≥ 11 nines durability; token-signing key HA with KMS. |
| NFR-7 | Secrets hygiene | Secret material never written to disk in a sandbox, never in a container image, never in an env var visible to agent code; tokens ≤ 15 min TTL by default, audience-bound, one-time where possible. |
| NFR-8 | Auditability | 100% of trust-boundary actions logged with trace_id, tamper-evident (hash-chained + periodically anchored). Any gap is a compliance failure. |
| NFR-9 | Determinism | Given the same signed policy bundle + request, the allow/deny/halt decision is identical and reproducible (pure decision function), enabling golden-file policy tests. |
| NFR-10 | Fail-closed | Any ambiguity, missing policy, unverifiable token, or broker unavailability results in denial, not permission. A quota-service outage pauses new launches rather than running uncapped. |
| NFR-11 | Reproducibility | Launch environment fully captured (image digest, kernel version, seccomp profile hash, cgroup limits, GPU model/MIG, policy bundle version) so S11 re-run canary reproduces execution context bit-for-bit modulo declared nondeterminism. |
| NFR-12 | mTLS everywhere | All S10 control-plane calls mutually authenticated; least-privilege scopes; every call authorized against the minted scope set. |

---

## S11 — Observability & Evaluation

**One-liner:** The read-only measurement plane for Argus: distributed tracing across the control-tower→subagent→builder→adapter→verifier path, platform KPIs (transparency-failure rate, validation pass rate, cost-per-verified-artifact, reward-hacking-catch rate), a continuous re-run reproducibility canary, and a benchmark/eval harness (MLE-bench-style agent-ML evals + physics held-out recapitulation benchmarks) that grades the platform itself.

### S11.1 Mission & Position in Argus

S11 is Argus's **measurement plane**. It answers three questions the rest of the platform cannot answer about itself:

1. **What is happening right now?** — distributed traces, metrics, and logs spanning every hop of a research job (S5 Control Tower → S1 subagent → S2 builder → S7 adapters → S3 verifier).
2. **Is the platform trustworthy and healthy?** — continuously-computed platform KPIs (transparency-failure rate, validation pass rate, cost-per-verified-artifact, reward-hacking-catch rate, calibration coverage, reproducibility rate) with SLOs and alerts.
3. **Is the platform actually good at its job?** — a benchmark/eval harness that scores Argus itself against (a) MLE-bench-style agent-ML tasks and (b) physics held-out recapitulation benchmarks, plus the **re-run canary** that independently re-derives signed artifacts to prove the reproducibility NFR.

**Critical architectural constraint (from shared design):** S11 *observes rather than participates* and is **not on the critical trust path**. It has **read-only** access to S8 artifacts/provenance (C4), S3 Validation Reports (C3), and S5 job state (C2). It MUST NOT be able to promote a claim tier, sign a report, mutate an artifact, or gate a job by writing to the trust path. Its only "gating" power is *advisory*: it can raise alerts, open findings, and (via a documented, human-owned control loop) recommend that S5 pause routing — but it never itself blocks the trust path. This keeps S11 outside the attack surface of the reward-hacking optimizer.

### S11.2 Goals

- **G1 — Total trace coverage.** Every job emits one distributed trace spanning S5→S1→S2→S7→S3. Trace completeness ≥ 99% of jobs; orphaned/broken-span rate is itself a monitored KPI.
- **G2 — Authoritative KPIs.** Compute and serve the platform KPIs named in the global NFRs as first-class, always-queryable time series with definitions, provenance, and SLOs.
- **G3 — Independent reproducibility proof.** Run a re-run canary that samples signed C4 artifacts and independently re-derives them (or challenges C3 reports via `challenge()`), reporting a reproducibility rate and flagging non-reproducible artifacts as non-promotable.
- **G4 — Platform self-evaluation.** Stand up an eval harness that runs MLE-bench-style agent-ML tasks and physics held-out recapitulation benchmarks on a schedule and on release, producing versioned scorecards.
- **G5 — Reward-hacking & transparency detection.** Detect and quantify reward-hacking signatures, transparency failures (claims without a valid signed report, tier/report mismatches, broken lineage), and adapter-disagreement anomalies — turning "fail loud and quarantine" into measurable signals.
- **G6 — Cost governance visibility.** Meter and attribute spend (compute + GPU + model tokens) per job/subagent/subtopic/DAG and compute cost-per-verified-artifact in near-real-time; surface budget-breach and anomalous-cost events.
- **G7 — Zero trust granted.** S11 never holds credentials that can write to the ledger, sign reports, or read blind/held-out verifier data; it consumes only already-emitted telemetry and read-scoped C2/C3/C4 handles.

### S11.3 Non-Goals

- **NG1** — S11 does not compute or assign claim tiers (that is S3+S9). It only *audits consistency* of tiers already assigned.
- **NG2** — S11 does not execute agent/ML training itself except inside the re-run canary and eval harness, and even there it runs everything through the **S10 sandbox** with the same isolation as any agent code. It has no privileged execution path.
- **NG3** — S11 does not store or index blind/held-out verifier test data. Physics held-out benchmark *answers* live in a separate, access-controlled eval vault the harness only reads through a scoring shim, never exposing labels to the platform under test.
- **NG4** — S11 is not the alerting/on-call system of record for infra (that is base infra Prometheus Alertmanager); S11 owns *platform-semantic* alerts (KPIs, reproducibility, reward-hacking), not node-down alerts, though it exports to the same Alertmanager.
- **NG5** — S11 does not modify contracts C1..C6; it consumes them.

### S11.4 Personas

- **P1 — Platform SRE / on-call.** Needs dashboards, traces, and alerts to diagnose stuck/slow/failing jobs and control-plane availability (99.5% SLO).
- **P2 — Argus Governance Lead (works with S9).** Needs KPIs (transparency-failure rate, validation pass rate, reward-hacking-catch rate) and reproducibility scorecards to certify the platform is behaving and to decide on routing pauses.
- **P3 — Subsystem team (S2/S3/S4/S5/S7 owners).** Need per-subsystem latency, error, cost, and quality breakdowns and per-check verifier statistics to improve their components.
- **P4 — ML/Physics Research Lead.** Needs the eval harness scorecards (MLE-bench-style + physics recapitulation) to know whether Argus is getting better at building ML for physics over releases.
- **P5 — Security engineer (S10 collaborator).** Needs reward-hacking-catch metrics, sandbox-escape/egress-attempt event streams, and tamper-evidence audit views.
- **P6 — Cost owner / FinOps.** Needs spend attribution and cost-per-verified-artifact trends and forecasts.
- **P7 — Federation reviewer (S12 collaborator).** Needs per-federated-subagent quality/cost/reproducibility profiles to inform trust-class decisions (advisory only).

### S11.5 User Stories (selected; exhaustive set in FRs)

- **US1** As P1, when a job hangs, I open its trace by `job_id` and see exactly which span (e.g. an S7 adapter call) is slow or errored, with linked logs and the C2 envelope.
- **US2** As P2, I view the transparency-failure-rate KPI over the last 30 days, drill into each failure (a claim tier > ran-toy without a valid signed C3 report), and export an audit bundle.
- **US3** As P2, the re-run canary flags an artifact whose independent re-derivation diverged beyond tolerance; I see the divergence report and the artifact is marked non-reproducible (advisory flag), triggering an S9 review.
- **US4** As P4, on each release I get an eval scorecard comparing this build's MLE-bench-style and physics-recapitulation scores to the previous build, with regressions highlighted.
- **US5** As P3 (S3 owner), I see per-check-type pass/fail/inconclusive rates and per-profile cost, so I can find flaky or too-expensive checks.
- **US6** As P5, I subscribe to a live stream of reward-hacking-signature detections and sandbox-policy-violation events with full provenance.
- **US7** As P6, I get cost-per-verified-artifact by subtopic and a forecast, and alerts on cost anomalies (e.g. an S4 evolution loop burning budget without score improvement).
- **US8** As P1, I query "which jobs consumed contaminated dataset X" via the lineage-observability view (built on S8's C4 graph) and see downstream impact.
- **US9** As P2, I get a daily "platform trust digest": all KPIs vs SLO, open findings, canary results, and any quarantined jobs.

### S11.6 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-01 | OTLP telemetry ingest | P0 | Receive OTLP traces, metrics, and logs from S5,S1,S2,S3,S7,S10 via an OTel Collector + Rust gateway; terminate mTLS, enforce read-only, buffer to NATS JetStream. Sustain 50k spans/s and 1M metric samples/min with <5% baseline-trace drop under 3x burst. |
| FR-02 | PII/secret scrubber (fail-closed) | P0 | At ingest, redact sensitive fields (budget_token, signer_key_id, blind_dataset_handle contents, vault refs, sensitive-tagged fields); unclassifiable fields are redacted by default and flagged. No secret ever lands in trace/log/event stores. |
| FR-03 | Distributed trace assembly & completeness | P0 | Assemble one trace per job across the S5→S1→S2→S7→S3 hop model using the shared trace_id; compute completeness vs expected span-set derived from the C2 DAG node + plan steps; flag partial/broken traces and expose broken-span/orphan rate. |
| FR-04 | Platform semantic event ingest | P0 | Consume job.state_changed(C2), validation.report_issued(C3), artifact.committed(C4), registry.changed(C5), sandbox.policy_violation & budget.breach(S10), adapter.evaluated(C6) as the basis for KPIs. |
| FR-05 | Versioned KPI definition registry | P0 | Store KPIs as declarative, content-hashed, semver-versioned specs (num/denom queries, window, unit, SLO). Editing mints a new version; historical samples stay bound to their definition version (deterministic recompute). |
| FR-06 | Streaming KPI computation | P0 | Maintain rolling-window KPIs (validation pass rate, calibration coverage, broken-trace rate) with exactly-once semantics (JetStream durable consumers + idempotent upsert by event id); freshness <60s. |
| FR-07 | Batch KPI rollups | P0 | Deterministically recompute daily/weekly aggregates (cost-per-verified-artifact, reproducibility rate) from the append-only event store; freshness <15min; identical output on recompute over same window+version. |
| FR-08 | Transparency-failure detector | P0 | Detect any claim_tier>ran-toy artifact/result lacking a signature-valid matching C3 report, any tier/report mismatch, and any broken-lineage promotion, by read-only cross-join of C4 and C3; emit S1 finding (a gate leaked) and page. |
| FR-09 | Reward-hacking detector suite | P0 | Emit findings for: score-without-signature, score-up-while-checks-degrade, input-hash reuse across 'independent' cross-code checks (independence violation), leakage-signature vs frozen contamination index, blind-data touch. Rank and route high-severity to P5/S9. |
| FR-10 | Planted-exploit reward-hacking canary | P1 | In coordination with S3's injection machinery (never seeing blind labels), request injection of known reward-hacking scenarios and verify the gates catch them; report a true reward-hacking-catch rate. Planted scenarios excluded from real KPIs. |
| FR-11 | Re-run reproducibility canary | P0 | Sample signed C4 artifacts (weighted to tier>ran-toy and S9-feeding), re-derive by re-executing the producer step in an S10 sandbox with pinned lineage OR via S3 challenge(); compare with kind-appropriate comparator (bit-exact or statistical-within-tolerance); emit CanaryResult and non_reproducible findings. |
| FR-12 | Reproducibility rate KPI | P0 | Compute weighted/unweighted reproducibility rate per artifact-kind from canary results; mark non-reproducible artifacts as non-promotable (advisory flag surfaced to S9). |
| FR-13 | MLE-bench-style eval harness | P1 | Run a curated suite of agent-ML tasks driving Argus end-to-end (via C2/S5 or C1 direct), scored against held-out sets by an out-of-sandbox shim; produce per-task and aggregate scorecards. |
| FR-14 | Physics held-out recapitulation harness | P1 | Run curated established-physics results held out from the model; score rediscovery via shim; cross-check platform's own S3 tier equals recapitulated-known; flag 'claimed novel on known' (leakage) and 'failed to recapitulate' (capability gap). |
| FR-15 | Eval vault & label isolation | P0 | Store ground-truth answers in an access-controlled vault readable only by the scoring shim (egress-restricted, no path into the sandbox); enforce that held-out answers never enter the pipeline-under-test. |
| FR-16 | Eval scorecards as C4 artifacts | P1 | Write every scorecard and canary verdict as a content-addressed C4 artifact to S8 with full lineage, so the platform's self-evaluation is reproducible and tamper-evident; diff against previous build and alert on regression. |
| FR-17 | Cost metering & attribution | P0 | Attribute compute/GPU/model-token spend per job/subagent/subtopic/DAG from S10 budget events + model-token logs; compute cost-per-verified-artifact; surface budget breaches. |
| FR-18 | Cost anomaly detection | P1 | Detect spend trajectories exceeding robust forecasts and S4 loops with high Δspend but ~0 Δscore; emit cost_anomaly findings and optional human-gated pause recommendation to S5. |
| FR-19 | SLO evaluation & alerting | P0 | Evaluate KPI SLOs, emit s11.kpi.slo_breach and route to Alertmanager and (for governance-relevant breaches) S9; own platform-semantic alerts, not infra node-down. |
| FR-20 | Lineage-observability queries | P1 | Serve read-only impact queries over the S8 C4 lineage graph (e.g. 'what consumed contaminated dataset X') with p95<3s over 10^5 artifacts. |
| FR-21 | Dashboards | P1 | Grafana for metrics/traces/SLOs; Next.js/React app for Trust Digest, Eval Scorecards, Reproducibility, Reward-Hacking board, Cost attribution. |
| FR-22 | Query API + CLI | P0 | Provide gRPC/REST endpoints and argusobs CLI for traces, KPIs, findings, canary, eval, cost, lineage-impact, digest, export. |
| FR-23 | Append-only hash-chained audit log | P0 | Every S11 governance/export/definition-change action is written to a hash-chained append-only audit log (Rust writer); tamper-evident and queryable. |
| FR-24 | Degradation & staleness handling | P0 | On S8/S3/S5 unavailability, serve last-known-good with explicit stale/degraded status and staleness metric; never serve silently-wrong KPIs; back off canary/eval with infra_error classification. |
| FR-25 | Daily Trust Digest | P2 | Assemble a daily digest: all KPIs vs SLO, open findings by severity, canary summary, eval regressions, quarantined jobs; deliver to P2/governance. |
| FR-26 | Self-metering & overhead cap | P2 | Meter S11's own compute/storage; keep per-job observability overhead <2% wallclock; degrade sampling and alert if exceeded. |
| FR-27 | Signature verification of C3 reports | P0 | Verify C3 report signatures against the registered S3 verifier keys in the trust store at every consumption point in detectors/KPIs; treat unsigned/tampered as transparency_failure. |
| FR-28 | Read-only enforcement & credential minimality | P0 | S11 holds no credentials to write the ledger, sign reports, mutate artifacts, or read blind verifier data; enforce by grant; log any attempted privileged action. |
| FR-29 | Observatory v0: static verified-run report page | P1 | Render one verified run as a self-contained static HTML page from its signed C3 v1.1 report and C4 lineage: six-check verdicts, perturbation pairs, insensitivity flags, claim tier + justification, referee identity (distinct_from_proponent), and the provenance chain. The report signature is re-verified offline via the shared argusverify library at render time; a tampered report or lineage renders an explicit FAIL banner, never a silent page. This is the M1.5 pilot-demo artifact — the first thing a pilot physicist sees. |
| FR-30 | Observatory v1: live pipeline view | P1 | Read-only live view of jobs flowing intake→build→adapter→verify→report, fed by the platform semantic events (FR-04), with a ledger-append stream and per-node drill-down into the underlying C2/C3/C4 records. Strictly obs.read-scoped (FR-28); degrades to last-known-good with an explicit staleness banner per FR-24. |
| FR-31 | Observatory v2: debate arena & evolution view | P2 | Render an artifact's C4 DebateLedger: per-round proponent / challenger panel / referee outcomes with ChallengeVerdict fields and attack kinds, a fitness series sourced exclusively from signature-valid `aggregate.score` (unsigned scores are never plotted), and a killed-spurious counter — making the M5 red-blue debate loop auditable at a glance for reviewers and governance. |

### S11.7 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR-Read-Only-Trust | Read-only | S11 credentials are read-scoped for C2/C3/C4; write attempts to ledger/report/sign paths are impossible by grant and are themselves logged if attempted. |
| NFR-Ingest-Throughput | Throughput | Ingest ≥ 50k spans/s and ≥ 1M metric samples/min sustained at target scale (hundreds of concurrent subagent jobs, thousands queued) with < 5% tail-drop under 3× burst. |
| NFR-Query-Latency | Latency | KPI dashboard queries p95 < 2 s over 90-day windows; single-trace fetch p95 < 1 s; lineage-impact query over 10^5 artifacts p95 < 3 s. |
| NFR-KPI-Freshness | Freshness | Streaming KPIs updated within 60 s of source events; batch/rollup KPIs within 15 min. |
| NFR-Canary-Isolation | Isolation | Re-run canary executes only in S10 sandbox with the same egress-deny and quota controls as agent code; canary never runs with elevated trust. |
| NFR-Eval-Label-Isolation | Label isolation | Physics held-out answers are never delivered into the sandbox running the pipeline-under-test; scoring is done by a shim outside the sandbox. |
| NFR-Retention/Immutability | Retention | Aggregated KPI series and eval scorecards and canary results are retained ≥ 2 years; scorecards and canary verdicts are written append-only and content-addressed (as C4 artifacts) so the platform's self-evaluation is itself reproducible and tamper-evident. |
| NFR-Availability | Availability | S11 query/dashboard plane targets 99.5%; ingest plane is buffered (JetStream) so a query-plane outage never loses telemetry. |
| NFR-Degradation | Degradation | If a downstream (S8/S3/S5) is unavailable, S11 degrades to last-known-good with staleness banners rather than emitting wrong KPIs; it fails loud, never silently wrong. |
| NFR-Determinism | Determinism | KPI definitions are versioned; recomputing a KPI over the same event window with the same definition version yields identical values (bit-stable rollups). |
| NFR-Security | Security | mTLS on all inter-subsystem calls; least-privilege scopes; every audit/export action is logged and tamper-evident; no PII/secrets in traces (a scrubber enforces this at ingest). |
| NFR-Cost-Of-Observability | Overhead | S11's own compute/storage cost is itself metered and capped; observability overhead added to any job < 2% wallclock. |

---

## S12 — Interop Standard & Federation

**One-liner:** Publishes the "SLHA-for-agents" (C1) specification, ships a contribution SDK/CLI and a tiered (Bronze/Silver/Gold) conformance suite so external physicists can build compliant subagents, and runs the audited community registry/governance that drives the federation network effect — all while granting federated entities zero elevated runtime trust.

### S12.1 Mission & Product Goals

S12 turns Argus from a single-operator platform into a **federation**: a growing network of externally-authored, contract-conformant domain subagents. It owns the *human-facing side of the standard* — the published spec, the SDK/CLI a physicist uses to build a subagent, the executable conformance suite that admits them, and the governed community registry that stores and revokes them. It is deliberately the **last milestone (M6)**: it presupposes that C1..C6, the S10 sandbox, the S6/C5 registry substrate, and the S3 verifier are all mature and trustworthy.

**Primary goals:**

- **G1 — Publish a stable, versioned, machine-checkable standard.** The canonical "SLHA-for-agents" spec (C1) plus its companion contracts, published as human docs + JSON Schemas + generated bindings, with explicit compatibility semantics and a migration policy.
- **G2 — Make compliance cheap for a domain expert.** A `argus-sdk` (Python-first) + `argus` CLI that scaffolds, locally runs, and self-tests a subagent so a physicist who is *not* a platform engineer reaches Bronze in an afternoon.
- **G3 — Make admission trustworthy and objective.** A conformance test suite (Bronze/Silver/Gold) with deterministic oracles that produces a **signed conformance record** (C4 artifact) which the C5 registry requires before `publish`.
- **G4 — Run community registry & governance.** Submission/review/approval/deprecation/revocation workflows, taxonomy stewardship, and full audit — with revocation that propagates to halt in-flight jobs (per C5 semantics).
- **G5 — Preserve the security invariant.** Federated entities enter as `trust_class: federated`, gain **no elevated runtime trust**, and execute in the same S10 untrusted zone as internal subagents. Admission ≠ trust.

### S12.2 Scope

**In scope (S12 owns):**

- Authoring, versioning, and publication of the SLHA-for-agents specification and the C1..C6 schema bundle as a **Standard Release** (semver, changelog, migration notes, deprecation calendar).
- Contract-binding **codegen toolchain** (JSON Schema → pydantic v2 / TypeScript / Rust serde) and the schema registry integration (co-owner of C5 with S6).
- `argus-sdk` (Python library) + `argus` CLI: scaffold, lint, local-run-in-sandbox, self-test, package, submit.
- The **Conformance Suite**: a versioned, executable battery (`suite_version`) with Bronze/Silver/Gold levels, a deterministic runner, golden fixtures, and a signed **Conformance Record**.
- The **Federation/Community Registry front-end + governance workflows** layered on top of the C5 registry API (submission portal, review queue, maintainer identity, approvals, deprecation/revocation, appeals, taxonomy proposals).
- Federation directory/discovery, badges, and a public standard docs site.
- Federation-level security policy enforcement at admission (identity verification, signature checks, sandbox-conformance attestation) — *not* runtime isolation (that is S10).

**Out of scope (owned elsewhere, consumed via contracts):**

- Runtime sandboxing/egress/quotas — **S10**.
- The registry storage engine and low-level C5 `publish/resolve/revoke` primitives — **S6** (S12 layers governance + admission gates on top; co-owns C5).
- Actual verification of ML artifacts (injection/null/cross-code) — **S3/C3**. (Conformance ≠ physics validation; S12 tests *contract behavior*, not physics correctness.)
- Provenance ledger and content-addressed storage — **S8/C4**.
- Job routing/orchestration — **S5/C2**.
- The subagent runtime SDK internals for provenance emission — **S1** (S12 wraps and re-exports S1's runtime in a physicist-friendly SDK, but does not own the C1 lifecycle engine).

### S12.3 Personas

- **P1 — External Domain Physicist ("Priya").** Expert in one subtopic (e.g. leptogenesis Boltzmann networks), competent in Python but not in Temporal/gVisor/mTLS. Wants to wrap her ML pipeline as a subagent and get it listed. Success = reaches Silver with the CLI in a day, no platform-internals knowledge.
- **P2 — External ML+Physics Contributor ("Marco").** Stronger engineer, wants Gold (recursion-safe + cross-code participation) so his subagent can be used by the Evolver (S4) and as an independent cross-code by S3.
- **P3 — Federation Registrar/Governance Steward ("Reika", Argus staff).** Reviews submissions, approves/deprecates/revokes, stewards the subtopic taxonomy, handles appeals and abuse.
- **P4 — Argus Platform Integrator (internal, S5/S3/S1 teams).** Consumes C5 descriptors S12 admits; needs stable resolve semantics and independence tags.
- **P5 — Security/Trust Auditor (internal, S9/S10 adjacent).** Audits that admission never confers runtime trust and that all governance actions are tamper-evident.
- **P6 — Standard Maintainer (Argus staff).** Owns spec evolution, runs the RFC/deprecation process, ships codegen.

### S12.4 User Stories (selected; exhaustive set in FRs)

- As Priya, I run `argus init --subtopic ewpt` and get a working skeleton subagent that already passes Bronze locally.
- As Priya, I run `argus conformance run --level silver` and get a deterministic pass/fail report I can fix against before submitting.
- As Marco, I declare `independence_tags` and `differentiable` adapters and my Gold submission is admitted so S3 can select my code as an independent cross-check.
- As Reika, I see a submission queue where each item carries a signed conformance record; I approve, and the C5 registry `publish` succeeds; I revoke a bad entity and in-flight jobs halt.
- As the Auditor, I query the governance ledger and confirm every approval/revocation is signed, attributed, and immutable, and that no federated entity holds elevated scopes.
- As the Standard Maintainer, I cut Standard Release `2.0.0`, dual-serve `1.x`, and the deprecation calendar is published and enforced.

### S12.5 Functional Requirements

| ID | Title | Priority | Description |
| --- | --- | --- | --- |
| FR-01 | Publish versioned Standard Releases | P0 | S12 MUST publish the SLHA-for-agents standard as immutable, semver-versioned Standard Releases bundling C1..C6 JSON Schemas, spec docs, changelog, migration notes, generated bindings (python/TS/rust), and a deprecation calendar. Each release is content-addressed and signed. |
| FR-02 | Compatibility semantics & dual-serve | P0 | A subsystem/subagent message valid under a compatible MINOR version MUST be accepted; a breaking change MUST require a MAJOR bump with a documented dual-serve migration window enforced by the Standard Service (both majors served until hard cutoff). |
| FR-03 | Deterministic schema→binding codegen | P0 | S12 MUST generate pydantic v2, TypeScript, and Rust serde bindings deterministically from the JSON Schemas; bindings are content-addressed, signed, SBOM-attached, and referenced by the Standard Release. |
| FR-04 | Semver compatibility checker (CI gate) | P0 | On any release cut, S12 MUST compute the schema delta and classify it additive-minor/breaking-major/patch, and REJECT a release whose declared version bump is lower than the computed class. |
| FR-05 | Contribution SDK | P0 | Ship argus-sdk (Python) that wraps the S1 runtime and exposes the C1 lifecycle (register/accept/plan/build/validate/report), the C6 adapter surface, mandatory provenance (C4) and uncertainty tagging helpers, and a local conformance harness. |
| FR-05b | Contribution CLI | P0 | Ship the argus CLI: init (scaffold), lint, build (reproducible image + digest + SBOM), conformance run (local/remote), explain, package, submit, status, keys, standard. A scaffold MUST pass Bronze locally out of the box. |
| FR-06 | Conformance suite Bronze | P0 | Bronze MUST verify: C1 lifecycle state-machine correctness incl. terminal FAILED/REJECTED/QUARANTINED; complete C4 provenance emission for every artifact; idempotent AND potentially-refusing accept(); no egress beyond declared adapters; MUST-NOT self-assign tier above recapitulated-known. |
| FR-07 | Conformance suite Silver | P0 | Silver MUST additionally verify: injection & null self-checks wired (advisory) and correctly reported; mandatory calibrated uncertainty tagging on all predictive outputs; correct refusal when verifier_profile_ref is null/unavailable (VERIFIER_UNAVAILABLE); typed C1/C2 error-envelope conformance. |
| FR-08 | Conformance suite Gold | P0 | Gold MUST additionally verify: recursion-safety under S4 (deterministic, bounded, no writes to reward/verifier/ledger path, respects budget_token halts); cross-code participation via a conformant C6 adapter (units mandatory, uncertainty mandatory, grad iff differentiable, independence_tags present); reproducibility-manifest sufficiency (re-run reproduces artifact hashes within declared tolerance). |
| FR-09 | Signed Conformance Record | P0 | Each conformance run MUST emit a signed ConformanceRecord (C4) capturing level, suite_version, standard_release, container/environment digests, per-check results with evidence refs, aggregate pass, and a determinism_hash. Records are write-once. |
| FR-10 | Hermetic, deterministic conformance runs | P0 | Conformance MUST run submitted code ONLY inside the S10 sandbox against hermetic mocks of C2/C3/C4/C6 with a pinned seed_vector and frozen clock, such that a re-run yields an identical record modulo timestamp/signature. |
| FR-11 | Registry admission gate governs C5 | P0 | External publish MUST route through the Registry Gateway, which admits to the C5 registry ONLY if identity+bundle signatures verify, a passing ConformanceRecord matches the claimed level, the container digest is pinned+scanned, and the descriptor is schema-valid. On pass it calls S6 C5 publish. |
| FR-12 | Zero elevated trust on admission | P0 | Admission MUST force trust_class=federated and OVERWRITE capability_scopes to the federation default (no elevated grants). Federated subagents execute in the same S10 untrusted zone as internal ones. Any path that could elevate is a Sev-1. |
| FR-13 | Governance workflows | P0 | Provide durable submit→review→approve/reject workflows with a registrar review queue (human decision required), plus deprecate, revoke, appeal, and identity management. No federated subagent is admitted without BOTH a passing conformance record AND a registrar approval. |
| FR-14 | Revocation propagation | P0 | Revoke MUST call S6 C5 revoke (source of truth), emit entity.revoked (NATS), and run a saga confirming S5 halts in-flight jobs referencing the entity within the SLA; on breach, escalate. Revocation is terminal and irreversible. |
| FR-15 | Append-only governance ledger | P0 | Every governance action MUST append a signed, hash-chained GovernanceLedgerEntry (C4) attributed to a KMS-signed actor; the chain MUST be end-to-end verifiable and queryable by entity/time. |
| FR-16 | Taxonomy stewardship (RFC) | P1 | Provide a versioned subtopic taxonomy DAG with a propose→comment→steward-merge RFC process; merges validate acyclicity/uniqueness/no-orphan, bump taxonomy semver, emit taxonomy.updated, and admitted descriptors pin the taxonomy version. |
| FR-17 | Federation directory & discovery | P1 | Serve a searchable public directory (by subtopic/level/independence/status) plus per-entity views and conformance badges, backed by OpenSearch over admitted C5 descriptors. |
| FR-18 | Federation identity & signing | P0 | Manage maintainer FederationIdentity with signing keys, verification, key rotation, suspension/ban; all submissions must be signed by an active maintainer key in the trust store. |
| FR-19 | Supply-chain integrity of toolchain | P1 | SDK/CLI and generated bindings MUST be published as signed (cosign) artifacts with SBOMs; the CLI verifies its own updates; the server verifies submitted bundle signatures. |
| FR-20 | Observability of federation | P1 | Every conformance run and governance action MUST emit an OTel trace and NATS event; federation KPIs (time-to-Bronze, admission/revocation rates, conformance determinism/flakiness) MUST be queryable via S11. |
| FR-21 | Suite versioning & yank | P1 | Conformance suites are semver-versioned and immutable; a flaky/incorrect suite version can be yanked (conformance.suite.yanked), invalidating auto-pass on that version and forcing re-run under a corrected suite. |
| FR-22 | Fail-closed degradation | P0 | When S6/S8/S10 are unavailable, S12 MUST NOT auto-admit or fabricate a pass; submissions park in durable pending states and resume; local-only passes are always advisory, never admission-sufficient. |
| FR-23 | Independence eligibility for cross-code | P1 | Gold submissions exposing C6 adapters MUST declare independence_tags and code lineage so S3 can select them as genuinely independent cross-checks; the Gateway records these so C5 resolve can answer 'independent implementation of observable O'. |
| FR-24 | Standard docs site | P2 | Publish a versioned public documentation site (Next.js) for the standard, SDK/CLI guides, conformance level requirements, and migration calendars, per Standard Release. |
| FR-25 | Appeals & abuse handling | P2 | Provide an appeals process for rejected/revoked entities and an abuse-report channel; decisions are ledger-recorded; repeated abuse escalates identity standing to suspended/banned. |

### S12.6 Non-Functional Requirements

| ID | Property | Requirement |
| --- | --- | --- |
| NFR-1 | Standard stability | Any message valid under a compatible **minor** version MUST be accepted; breaking changes require a **major** bump with a documented, calendared dual-serve migration window (global NFR: contract compatibility). |
| NFR-2 | Determinism of conformance | The suite MUST be reproducible bit-for-bit given (`suite_version`, subagent container digest, seeds); a re-run of the same submission yields the identical Conformance Record modulo timestamp/signature (feeds S11 re-run canary). |
| NFR-3 | Zero elevated trust | Admission grants no runtime scopes; federated subagents run in S10 untrusted zone (hard security invariant). Auditable and test-enforced. |
| NFR-4 | Tamper-evidence | All governance actions and conformance records are C4 content-addressed, signed, and append-only; revocation is irreversible and propagates. |
| NFR-5 | Human gate alignment | Registry governance actions (approve/revoke) are human decisions with recorded sign-off; no auto-approval of a federated subagent without a passing conformance record AND a registrar action. |
| NFR-6 | Scalability | Registry + conformance service scale to 10^4+ registered entities and 10^3+ submissions/month without query degradation; conformance runs are async/durable. |
| NFR-7 | Availability | Public docs/directory 99.5%; registry write path 99.5%; signed records durable ≥ 11 nines (write-once). |
| NFR-8 | Security | mTLS between S12 services and S6/S8/S10; SDK/CLI supply-chain integrity (signed releases, SBOM); submission uploads scanned and executed only inside S10. |
| NFR-9 | Latency | CLI local self-test feedback in seconds→minutes (per level budget); server-side conformance run within its declared budget; registry `resolve` p99 < 200 ms. |
| NFR-10 | Observability | Every conformance run and governance action emits an OTel trace and NATS event; federation KPIs (time-to-Bronze, admission rate, revocation rate, conformance flakiness) always queryable. |

### S12.7 Success Metrics / KPIs

- Time-to-first-Bronze (median) for a new external contributor.
- # federated subagents active by conformance level; cross-code-eligible (Gold + independence) count.
- Conformance determinism rate (re-run canary agreement) ≥ 99.9%.
- Zero admission→runtime-trust escalations (must be 0; any is a Sev-1).
- Registrar review SLA adherence; revocation propagation latency (halt in-flight ≤ 60 s).
- Standard adoption: fraction of subagents on the current vs deprecated Standard Release.

### S12.8 Assumptions & Dependencies

- C1..C6 JSON Schemas exist and are frozen at M0 (S12 publishes/versions them but does not invent their fields).
- C5 registry storage / `publish/resolve/revoke` primitives exist (S6). S8 content-addressed store + signing available. S10 sandbox available to execute submitted code during conformance. S3 verifier interface exists for Gold cross-code participation checks. S11 ingests S12 events.

---

*End of Project Argus Product Requirements Document.*
