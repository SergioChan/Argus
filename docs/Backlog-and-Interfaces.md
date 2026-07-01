# Argus — Decoupled Backlog & Interface Registry

> **Part of the Project Argus design set.** Start at **README.md** for the doc map and reading order. Related docs: **Architecture.md**, **PRD.md**, **TechDesign.md**, **Backlog-and-Interfaces.md**, **TestPlan.md**, **Roadmap.md**.

**Owner:** Tech-Program Manager
**Scope:** All 12 subsystems (S1–S12), 377 subtasks, contracts C1–C6 plus named subsystem APIs.
**Purpose:** This is the decoupling audit. It proves that every subtask can be built independently, that every cross-subsystem dependency crosses only through a published contract (C1–C6) or a named API, and that every produced interface has a matching consumer (and vice-versa). It is the coherence gate before parallel build begins.

## 0. How to read this document

- **Section 1** is the single consolidated backlog: every subtask across every subsystem with `id`, `title`, `est`, `depends_on`, `interfaces_touched`, `acceptance_criteria`.
- **Section 2** is the dependency analysis: it isolates every `depends_on` edge that crosses a subsystem boundary and confirms the edge travels only through a contract (C1..C6) or a named/bare subsystem-level dependency — never a direct task-to-task reach into another subsystem's internals.
- **Section 3** is the interface registry: every `interfaces_produced` row matched to its declared consumers, each marked **consistent / mismatch / missing-consumer / missing-producer**, with a fix note for each problem.
- **Section 4** lists the highest global coherence risks.

**Contract ownership (canonical):**

| Contract | Owner | Kind | One-line role |
|----------|-------|------|---------------|
| C1 | S1 | Subagent Contract (SLHA-for-agents) | register/accept/plan/build/validate/report/heartbeat/cancel lifecycle + typed error envelope |
| C2 | S5 | Task/Job Envelope + JobResult | the immutable work order the Control Tower mints and aggregates |
| C3 | S3 | Verifier Interface + Validation Report (**v1.1**) | list_profiles/verify/challenge; the **only** admissible source of tier > ran-toy and the **only** admissible recursion reward. **v1.1 (frozen from M0, additive, backward-compatible)** adds the 6 ValidationReport fields for adversarial red-blue debate: `perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, `debate_ref` |
| C4 | S8 | Artifact + Provenance Record | content-addressed, fail-closed, tier-coupled provenance ledger |
| C5 | S6 / S12 (co-owned) | Registry / Capability Descriptor | publish/resolve/revoke + cross-code independence resolution |
| C6 | S7 | Compute-Adapter Tool Interface | describe/evaluate/grad/batch_evaluate with mandatory units + uncertainty + validity domain |

**Estimate legend:** S = small, M = medium, L = large, XL = extra-large.
**Estimate distribution across the 377 subtasks:** S=39, M=208, L=118, XL=12. (The 11 new adversarial-debate subtasks add M=7, L=4.)

---

## 1. Consolidated backlog (all 377 subtasks)

Grouped by subsystem for readability; the id namespace is globally unique. Every subtask lists the exact `depends_on` and `interfaces_touched` used by the audit in Sections 2–3.

#### S1 - Subagent Framework & Contract (SLHA-for-agents)

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S1-T01 | Author canonical C1 JSON Schema | M | C1 | C1 | Schema validates all examples; passes meta-validation; semver 1.0.0 tagged |
| S1-T02 | Multi-language binding codegen pipeline | M | S1-T01 | C1 | S1-TC-38 passes; bindings compile in 3 langs; drift check fails on unregen change |
| S1-T03 | Semver schema-diff compatibility gate | M | S1-T01 | C1 | S1-TC-09/10/11 pass |
| S1-T04 | Lifecycle FSM & legal-transition table | M | S1-T01 | C1 | S1-TC-01/02 pass; table covers all documented transitions |
| S1-T05 | Event-sourced lifecycle store | L | S1-T04, C4 | C4 | S1-TC-03 replay determinism passes; job_current rebuildable; ledger mirror written |
| S1-T06 | Idempotency layer | M | S1-T05 | C1 | S1-TC-06 passes; duplicate calls do not re-execute side effects |
| S1-T07 | C1 wire API server (gRPC + HTTP/JSON) | L | S1-T02, S1-T04, S1-T06 | C1, C2 | All C1 methods over both transports; mTLS enforced; scope checks reject under-privileged |
| S1-T08 | SDK base class & IoC wrapping | L | S1-T07 | C1 | Author implements plan/build only; validate() not overridable |
| S1-T09 | Default refusing accept() gate | M | S1-T08 | C1, C2, C5 | S1-TC-04/05/10 pass; refusals are non-error |
| S1-T10 | ExecContext capability handle | M | S1-T08 | C1, C4, C6 | S1-TC-07 (no set_claim_tier) passes; exposes only documented capabilities |
| S1-T11 | Sandbox marshaler (S10 bridge) | L | S1-T10 | C1 | S1-TC-14/30 pass; no in-process domain-code execution |
| S1-T12 | Egress allowlist derivation | M | S1-T11 | C6 | S1-TC-26/27 pass |
| S1-T13 | No-secret brokered adapter proxy binding | M | S1-T11 | C6 | S1-TC-29 passes; credentialed calls succeed with zero secrets in sandbox |
| S1-T14 | Provenance emitter (fail-closed C4) | L | S1-T10, C4 | C4 | S1-TC-08/13/32 pass |
| S1-T15 | Uncertainty tagging helpers | S | S1-T14 | C4, C6 | S1-TC-12 passes; bare point estimate rejected at Silver |
| S1-T16 | Structural tier-promotion prevention | M | S1-T08 | C1, C3 | S1-TC-07/24 pass; no self-promotion path exists |
| S1-T17 | validate() frozen-pipeline packaging & S3 handoff | L | S1-T11, S1-T14, C3 | C3, C4 | S1-TC-15/15b/31 pass; subagent never reads blind labels |
| S1-T18 | Bounded auto-repair loop | M | S1-T11, S1-T14 | C1 | S1-TC-18/19 pass |
| S1-T19 | Cooperative cancel & heartbeat | M | S1-T11 | C1 | S1-TC-22/40 pass |
| S1-T20 | Quarantine handling for POLICY/SANDBOX errors | M | S1-T11, S1-T05 | C1 | S1-TC-28 passes; quarantined jobs never auto-retry |
| S1-T21 | CapabilityDescriptor (C5) builder & registry publish | M | S1-T08, C5 | C5 | S1-TC-17 passes; descriptor validates against C5 schema |
| S1-T22 | Reference conformance harness (Bronze/Silver/Gold) | L | S1-T14, S1-T15, S1-T16 | C1, C5 | S1-TC-12/36/37 pass; each check has deterministic oracle |
| S1-T23 | Conformance attestation block in descriptor | S | S1-T21, S1-T22 | C5 | Descriptor conformance block populated from passing run; expiry enforced |
| S1-T24 | OTel tracing & NATS lifecycle events | M | S1-T07, S1-T05 | C1 | S1-TC-17 event assertion passes; every method spans; events consumed by S11/S5 mocks |
| S1-T25 | Typed error envelope implementation | S | S1-T01 | C1, C2 | Categories map to behavior; POLICY/SANDBOX non-retryable; RETRYABLE carries retry_after |
| S1-T26 | argus-subagent CLI | L | S1-T08, S1-T21, S1-T22 | C1, C5 | Each subcommand functions; conformance/codegen exit codes correct; e2e local run works |
| S1-T27 | Runtime restart recovery & durable sandbox reattach | M | S1-T05, S1-T11 | C1 | S1-TC-16 passes; no lineage loss across restart |
| S1-T28 | Reference example subagent + physics-adapter integration test | L | S1-T10, S1-T12, S1-T17, S1-T22 | C1, C4, C6 | S1-TC-20/21/23/25/39 pass |
| S1-T29 | Perf & scale test harness | M | S1-T07, S1-T05 | C1 | S1-TC-33/34/35 pass against declared budgets |
| S1-T30 | C1 specification document & migration policy | M | S1-T01, S1-T03 | C1 | Spec matches schemas; dual-serve documented; reviewed by S5/S3/S12 owners |

#### S2 - ML Builder Engine

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S2-T01 | Contract-bound data models & codegen | M | C1, C2, C4, C6 | C1, C2, C4, C6 | S2-TC12/40 pass; models validate against canonical schemas |
| S2-T02 | SpecCompiler | M | S2-T01, C5, C3 | C2, C5, C3 | S2-TC23 passes; missing profile -> VERIFIER_UNAVAILABLE/POLICY before execution |
| S2-T03 | UnitsAlgebra engine | M | S2-T01 | - | S2-TC01 passes; dimension arithmetic exhaustively unit-tested |
| S2-T04 | Buckingham-pi & symmetry-invariant injectors | L | S2-T03 | - | S2-TC02 and S2-TC26/27 (arch/anchor) pass |
| S2-T05 | Forward-model-derived feature injector (C6) | M | S2-T04, C6 | C6 | S2-TC13/14 pass; uncertainty propagated; out-of-domain flagged |
| S2-T06 | FeatureGraph engine | L | S2-T03, S2-T04, S2-T11 | C4 | Deterministic replay verified; feature nodes carry checked dimensions |
| S2-T07 | DataManager (splits & folds) | M | S2-T01, S2-T11, C4 | C4 | S2-TC09/10 pass; blind inputs never surface labels |
| S2-T08 | Model zoo & descriptor registry | L | S2-T01 | - | list_model_families returns descriptors; new family registers w/o core change |
| S2-T09 | Deep/physics-informed families (JAX/Torch) | L | S2-T08 | - | S2-TC26/27/28 pass on fixtures; differentiable families expose grad |
| S2-T10 | ModelSynthesizer & complexity-escalation policy | M | S2-T08 | - | S2-TC03 passes; escalation only on significant held-out gain |
| S2-T11 | ProvenanceEmitter (C4 writer client) | M | S2-T01, C4 | C4 | S2-TC15 passes; zero INCOMPLETE_LINEAGE; tier>ran-toy coupling impossible |
| S2-T12 | BudgetMeter | M | S2-T01, C2 | C2 | S2-TC06/38 pass; halt within grace; cost_actual accurate |
| S2-T13 | TrainingRuntime (multi-backend) | L | S2-T08, S2-T12, S2-T11 | C4 | S2-TC19/20 pass; checkpoints emitted; cancel captures partial |
| S2-T14 | HPOEngine (Optuna + Ray Tune) | L | S2-T10, S2-T13, S2-T12 | - | S2-TC17/18/34 pass |
| S2-T15 | UQCalibrator | L | S2-T13, S2-T07 | - | S2-TC04/05/05b/37 pass |
| S2-T16 | FailureDoctor (diagnosis + bounded repair) | L | S2-T13, S2-T12 | - | S2-TC07/08 pass; repairs logged to provenance |
| S2-T17 | AdvisorySelfCheck | M | S2-T06, S2-T15 | - | S2-TC24/25/29 pass; tier never raised by self-check |
| S2-T18 | PipelineFreezer | L | S2-T06, S2-T15, S2-T11 | C4 | S2-TC16/36/37 pass; self_replay_passed required to emit |
| S2-T19 | BuildOrchestrator | L | S2-T02, S2-T06, S2-T07, S2-T10, S2-T14, S2-T15, S2-T16, S2-T17, S2-T18 | C1, C2, C4 | S2-TC21 e2e passes; claim_tier capped at ran-toy |
| S2-T20 | Self-grade prohibition & policy guards | S | S2-T19 | C1, C3 | S2-TC11/33 pass |
| S2-T21 | build_variant API (Evolver) | M | S2-T19, S2-T14, S2-T20 | C1, C4 | S2-TC22 passes; no score returned; cache reuse verified |
| S2-T22 | Sandbox/egress/secrets integration (S10) | M | S2-T19 | C6 | S2-TC30/31/32 pass |
| S2-T23 | Observability (OTel + NATS events) | S | S2-T19 | - | Trace spans present; all s2.build.* events emitted |
| S2-T24 | Explainability report & CLI | M | S2-T19, S2-T21 | - | S2-TC39 passes; all CLI subcommands functional |
| S2-T25 | Conformance harness hooks (S12) | M | S2-T17, S2-T21 | C1, C5 | S2 fixtures pass Silver; Gold recursion-safe path demonstrated |
| S2-T26 | Perf & latency benchmark suite | M | S2-T19 | - | S2-TC34/35/36 pass on reference hardware |

#### S3 - Physics Validation & Verifier Framework

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S3-T01 | Author C3 JSON Schemas & generate bindings | M | C3 | C3 | Schemas validate examples; bindings round-trip; semver+compat present |
| S3-T02 | Verifier API service skeleton (gRPC+HTTP, mTLS, scopes) | M | S3-T01, C2 | C3, C2 | Authorized calls dispatch; unauthorized rejected; 422 on invalid; traces emitted |
| S3-T03 | Verify Orchestrator (Temporal workflow) | L | S3-T02 | C3, C2 | Survives worker restart; produces report on happy path; halt+capture on budget breach |
| S3-T04 | Report canonicalizer + BLAKE3 hasher | M | S3-T01 | C3, C4 | S3-TC01 passes; identical bytes for reordered/numeric-equivalent inputs |
| S3-T05 | Signer service (Rust) + vault/KMS integration | M | S3-T04, S3-T15 | C3 | S3-TC30 fail-closed; verifiable sigs; key absent from agent-reachable surface |
| S3-T06 | Multi-language signature-verification library | M | S3-T04, S3-T05 | C3 | S3-TC02/03/49 pass in all 3 bindings with identical verdicts |
| S3-T07 | Verifier profile registry (Postgres, append-only) | M | S3-T01 | C3 | S3-TC38 passes; revision N unchanged after N+1 published |
| S3-T08 | Profile Resolver / compiler | M | S3-T07, C6 | C3, C6 | Over-ceiling adapter rejected at compile; determinism surfaced; PROFILE_UNSUPPORTED |
| S3-T09 | Check-plugin host + CheckPlugin API | M | S3-T03, C4 | C3, C4 | Plugins run concurrently respecting deps; each emits CheckResult + C4 evidence |
| S3-T10 | Frozen-Pipeline Runner (nested S10 sandbox) | L | S3-T09, S3-T11 | C4 | S3-TC25/27/44 pass |
| S3-T11 | Frozen-pipeline entrypoint contract | S | S3-T01 | C1, C4 | Reference pipeline invocable identically; non-conforming rejected with typed error |
| S3-T12 | Blind-Data Vault + Manager | L | S3-T10 | C4 | S3-TC26 passes; blind-hash-mismatch quarantine |
| S3-T13 | Statistics library | M | S3-T01 | C3 | S3-TC45 passes; deterministic values on fixed seeds; documented tolerances |
| S3-T14 | Independence Resolver (C5 queries) | M | S3-T08, C5 | C3, C5 | S3-TC24/23/50 pass |
| S3-T15 | Trust-store + key management | S | S3-T01 | C3 | S3-TC49 passes; keys never in agent zone; audit of key use |
| S3-T16 | INJECTION check plugin | M | S3-T09, S3-T12, S3-T13 | C3, C6 | S3-TC04/05/05b pass |
| S3-T17 | NULL_CONTROL check plugin | M | S3-T09, S3-T12, S3-T13 | C3 | S3-TC06/07/08 pass |
| S3-T18 | CROSS_CODE check plugin | L | S3-T09, S3-T13, S3-T14, C6 | C3, C6 | S3-TC09/10/11/47 pass |
| S3-T19 | PHYSICAL_CONSISTENCY check plugin + units algebra | L | S3-T09, S3-T13, C6 | C3, C6 | S3-TC12..16 pass |
| S3-T20 | LEAKAGE / contamination screen plugin | L | S3-T09, S3-T13, S3-T12 | C3, C4, C5 | S3-TC17/18/48 pass |
| S3-T21 | CALIBRATION check plugin | M | S3-T09, S3-T13, S3-T12 | C3 | S3-TC19/20 pass |
| S3-T22 | Claim-tiering rule engine | M | S3-T16, S3-T17, S3-T18, S3-T19, S3-T20, S3-T21, S3-T14 | C3 | S3-TC21/22/23/37 pass |
| S3-T23 | Report Builder + write-once commit + C4 coupling | M | S3-T04, S3-T05, S3-T22, C4 | C3, C4 | S3-TC31/32 pass; tier/report coupling enforced |
| S3-T24 | Recapitulation-benchmark gate | M | S3-T12, S3-T22 | C3 | recap-known requires benchmark PASS; held-out never delivered to pipeline |
| S3-T25 | Challenge / re-audit engine (canary) | M | S3-T03, S3-T22, S3-T23 | C3 | S3-TC34/35/36/46 pass |
| S3-T26 | Degradation & quarantine engine | M | S3-T03, S3-T22 | C3 | S3-TC16-degradations, S3-TC40 pass; fail-closed on signing/blind mismatch |
| S3-T27 | Cost estimation & budget metering | M | S3-T03, S3-T08, C2 | C3, C2 | S3-TC40 passes; cost_estimate returned; near-real-time metering; BUDGET halt |
| S3-T28 | Profile-author tooling, DSL & dry-run | M | S3-T07, S3-T08, S3-T09 | C3 | S3-TC39 passes; harness flags mis-thresholded profiles |
| S3-T29 | Observability, KPIs & events | M | S3-T03, S3-T22, S3-T25 | C3 | KPIs queryable; events fire on right transitions (S3-TC22/33/36) |
| S3-T30 | argusverify CLI | S | S3-T02, S3-T06, S3-T22, S3-T25 | C3 | All commands operate against service; report verify-signature works offline |
| S3-T31 | Reward-for-recursion integration contract & test | S | S3-T06, S3-T22 | C3 | S3-TC29/37/48 pass; fabricated scores rejected |
| S3-T32 | Performance & concurrency hardening | L | S3-T23, S3-T29 | C3 | S3-TC41/42/43 pass |
| S3-T33 | Security hardening & isolation audit | L | S3-T05, S3-T10, S3-T12, S3-T15 | C3, C4 | S3-TC26/27/28/44 pass; independence NFR1 audited |
| S3-TPR1 | Freeze C3 v1.1 schema with the 6 new ValidationReport fields (perturbation_pairs, insensitivity_flags, challenger_panel, independence_attestation_debate, referee, debate_ref) [M0] | M | S3-T01, C3 | C3 | S3-TC50-PR passes; v1.1 validates all examples; additive/backward-compatible with v1.0; semver 1.1.0 tagged; frozen from M0 (no migration) |
| S3-TPR2 | Bidirectional perturbation-pair runner (`run_perturbation_pair(model_ref, perturbation_spec)->PerturbationResult`): must_react (planted real signal recovered proportionally) + must_not_react (noise/shuffle/contamination must degrade) [M1] | L | S3-TPR1, S3-T13, S3-T16, C6 | C3, C6 | S3-TC51-PR/S3-TC52-PR pass: must-react recovers planted signal with amplitude-linearity; must-not-react rejects pure noise; both directions emitted into perturbation_pairs |
| S3-TPR3 | Insensitivity detector (`detect_insensitivity(model_ref, perturbation_set)->InsensitivityReport`): invariance-to-a-should-react perturbation -> FAIL (memorized/constant/spurious-feature) [M1] | L | S3-TPR2 | C3 | S3-TC53-PR passes: FAIL when result survives unchanged under contamination it should react to; insensitivity_flags populated with reason |
| S3-TPR4 | Non-gameable referee enforcement (referee != builder/proponent; signed; distinct_from_proponent) [M1] | M | S3-TPR1, S3-T05, S3-T23 | C3 | S3-TC55-PR passes: referee rejects builder self-attestation; referee.non_gameable + distinct_from_proponent enforced; emission blocked when referee==proponent |
| S3-TPR5 | Challenger-independence attestation (`attest_challenger_independence(challenger_ids[])->IndependenceAttestation`, lineage-disjoint cross-code via C5) [M3] | M | S3-TPR4, S3-T14, C5 | C3, C5 | S3-TC54-PR passes: flags correlated challengers; independence_attestation_debate reports min_independent_challengers, lineage_disjoint, correlation_warning |

#### S4 - Recursive Improvement Loop (Evolver)

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S4-T01 | Define S4 data-model JSON Schemas & bindings | M | C4 | C4, EvolutionJobSpec, Variant, EvolutionResult | Schemas validate; bindings compile py/ts/rust; no cross-subsystem internal import; semver present |
| S4-T02 | Precondition Gate (verifier existence/applicability/signer-trust) | M | S4-T01, C3, C5 | C3.list_profiles, C5.resolve | TC-01 passes; loop never entered on refusal; typed reasons emitted |
| S4-T03 | Cheap-verifier precondition & cost feasibility | S | S4-T02 | C3 VerifierProfile.cost_estimate, EvolverBounds | TC-02/40 pass; cheap_enough correct; no budget minted in preflight |
| S4-T04 | Independence resolution & tier-capping | M | S4-T02, C5 | C5.resolve, independence_tags | TC-03/27/37 pass; novel impossible without independent cross-code |
| S4-T05 | Gene schema + typed mutation/crossover operators | L | S4-T01 | GeneSchema, Variant.genotype | TC-07/24 pass; invariant-violating variants rejected pre-build; operators deterministic |
| S4-T06 | LLM-guided proposer (Claude, Agent SDK) | L | S4-T05, C4 | ProposerConfig, C4 artifact (prompt/response) | LLM proposals validated/logged; never see held-out/reward fn; TC-07 rejection path |
| S4-T07 | Population manager & MAP-Elites/novelty archive | L | S4-T01 | Variant.phenotype.behavior_descriptor, DiversityConfig | TC-08/10/34 pass; archive scales to 1e4; elitism preserves best |
| S4-T08 | Selector & diversity controller | M | S4-T07 | EvolverStrategy, DiversityConfig | TC-08/11/12 pass; fitness only from signed score; entropy restored/bounded stop |
| S4-T09 | Reward source & admission (signature + binding + leakage) | L | S4-T01, C3, C4 | C3 ValidationReport, trust store | TC-04/05/11/12/13 pass; unsigned/tampered/mismatched rejected |
| S4-T10 | Profile-invariance / verifier-overfit probe | M | S4-T09, C3 | C3.challenge, RewardDefenseConfig.profile_rotation | TC-17 passes; overfit variants demoted & flagged |
| S4-T11 | Budget Ledger (Rust) & halt-on-breach | L | S4-T01 | BudgetLedgerEntry, budget_token | TC-14/32/38 pass; no double-spend; cap not patchable from sandbox |
| S4-T12 | EvolutionWorkflow (Temporal) durable decision core | XL | S4-T05, S4-T07, S4-T08, S4-T09, S4-T11 | C1.build, C1.validate, C3.verify | TC-06/09/23 pass; deterministic decision path; hard termination guaranteed |
| S4-T13 | Train delegation via C1/S2 in S10 (idempotent) | M | S4-T12, C1 | C1.build, C4 BuildResult | TC-15/18 pass; no re-train on replay; failures do not loop |
| S4-T14 | Verify delegation via C3 (timeout=INCONCLUSIVE) | M | S4-T12, C3 | C1.validate, C3.verify, C3 ValidationReport | TC-19 passes; timeouts non-improvement; reports fetched content-addressed |
| S4-T15 | Checkpointer & durable resume | L | S4-T12, C4 | EvolutionCheckpoint, C4 | TC-16/22/39 pass; state reproduced exactly; corrupt checkpoint fails closed |
| S4-T16 | Provenance & genealogy emission | M | S4-T12, C4 | C4 ArtifactRecord, GenerationRecord, lineage_edges | TC-20/36 pass; genealogy DAG no broken edges; decision path reproducible |
| S4-T17 | Human-review handoff (no self-promotion) | S | S4-T12, S4-T16 | C2 JobResult, evolver.human_review.requested | TC-21 passes; no autonomous promotion or external artifact from S4 |
| S4-T18 | Control & Preflight APIs | M | S4-T12, S4-T15 | POST /v1/evolver/jobs, /preflight, C2 JobEnvelope | TC-22/35/40 pass; control ops durable; preflight commits no budget |
| S4-T19 | Events, OTel spans & S11 KPIs | M | S4-T12 | NATS evolver.* subjects, OpenTelemetry, S11 KPIs | TC-18(KPI)/38 pass; full trace span chain; KPIs queryable |
| S4-T20 | Quarantine & fail-loud state machine | M | S4-T09, S4-T11, S4-T15 | evolver.job.quarantined, status QUARANTINED | TC-11/29/39 pass; anomalies halt+log; Sev-1 events fired |
| S4-T21 | Security hardening: zone isolation, egress-deny, key/secret exclusion | M | S4-T11, S4-T12 | S10 sandbox policy, egress proxy allowlist | TC-29/30/31/32 pass; no key present; egress denied by default |
| S4-T22 | Red-team harness & reward-hacking-catch KPI | L | S4-T09, S4-T10, S4-T19 | argusctl evolver redteam, reward-hacking-catch KPI | TC-12/13/17/28 pass; 100% seeded scenarios caught |
| S4-T23 | CLI (argusctl evolver) & replay/canary | M | S4-T15, S4-T16, S4-T18 | argusctl evolver *, S11 re-run canary | TC-36 passes; replay reproduces winning-variant hash; full lifecycle |
| S4-T24 | Performance & scale test suite | M | S4-T07, S4-T12, S4-T18 | archive query API, control API | TC-33/34/35 pass at target p95; no lost evaluations under load |
| S4-T25 | Physics-validation integration suite | L | S4-T12, S4-T14, S4-T04 | C3 checks (INJECTION/NULL_CONTROL/PHYSICAL_CONSISTENCY/CALIBRATION/CROSS_CODE) | TC-20/23/24/25/26/27 pass on a real benchmark |
| S4-TDB1 | Debate-round orchestrator (`run_debate_round(candidate_ref, challenger_pool, referee)->ChallengeRound`): proponent / challenger / referee loop; emits ChallengeRound + ChallengeVerdict [M5] | L | S4-T12, C3, C4 | ChallengeRound, ChallengeVerdict, C3.verify, C4 | S4-TC41-DB passes: round adjudicated via ChallengeVerdict; PASS requires must_react_pass AND must_not_react_pass AND NOT insensitivity_detected |
| S4-TDB2 | Independent challenger-panel selection + diversity policy (`select_challenger_panel(subtopic, k, diversity_policy)->challenger_ids[]`): >=K, lineage-disjoint, diverse attack types AND code lineages [M5] | M | S4-TDB1, C5 | ChallengeRound.challenger_ids, C5.resolve, C3.attest_challenger_independence | S4-TC46-DB passes: >=K independent challengers; correlated challengers flagged and panel refreshed |
| S4-TDB3 | Red-blue evolution loop under the precondition gate (`evolve_under_debate(seed_candidate, budget, stop_criteria)->EvolutionResult`): recursion only under a cheap valid S3 oracle [M5] | L | S4-TDB1, S4-T02, S4-T03, C3 | EvolutionResult, Attack, C3.verify | S4-TC42-DB passes: precondition gate REFUSES to run without a valid oracle; debate loops on FAIL then converges |
| S4-TDB4 | Reward-hacking + challenger-collusion screens: detect proponent overfit to a fixed challenger set, challenger correlation/collusion, referee tampering; hard round bound; refresh diversity each round [M5] | M | S4-TDB1, S4-TDB2, S4-T10, S4-T22 | RewardDefenseConfig, ChallengeRound, C3.challenge | S4-TC43-DB/S4-TC44-DB pass: reward-hacking (overfit to fixed challenger set) caught; challenger collusion/correlation detected |
| S4-TDB5 | DebateLedger provenance emission via C4 (append-only record of all ChallengeRounds for an artifact; debate_ref pointer) [M5] | M | S4-TDB1, S4-T16, C4 | DebateLedger, C4 ArtifactRecord, debate_ref | S4-TC45-DB passes: DebateLedger recorded in C4; every ChallengeRound appended; debate_ref resolves |
| S4-TDB6 | Feedback -> revise -> retrain step (structured FAIL feedback drives proponent revision/retrain into next round) [M5] | M | S4-TDB1, S4-T13, C1 | ChallengeRound.feedback, C1.build | S4-TC41-DB passes: FAIL emits structured feedback; proponent revises/retrains; next round runs idempotently |

#### S5 - Control Tower / Orchestration

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S5-T01 | C2 JSON Schema authoring & codegen | M | C2 | C2 | Validates envelopes; additive minor forward-compat; major flagged; bindings compile 3 langs |
| S5-T02 | Intake & Request API service | M | S5-T01, C4 | C2, C4, Intake API | TC01/34 pass; RootRequest row with pinned versions; malformed rejected 400 |
| S5-T02b | Intake guardrail screen | M | S5-T02 | Intake API, GuardrailEvent | TC02/26 pass; blocked requests never reach RUNNING; every block writes GuardrailEvent |
| S5-T03 | Decomposer / Planner service | L | S5-T01, C4, C5, C3 | C4, C5, C3, Planning API | TC03 determinism under pinned inputs; preview as C4; coverage via C3 list_profiles() |
| S5-T04 | Verifier-profile binding & coverage | S | S5-T03, C3 | C3, Planning API | TC05 passes; no-profile nodes clamped; recursion precondition wired |
| S5-T05 | Plan approval & edit API | M | S5-T03 | Planning API, JobDag model | FR-03 satisfied; no dispatch before approve; edits produce new DAG version |
| S5-T06 | Envelope Factory & immutability | M | S5-T05, C2, C4 | C2, C4 | TC04 passes; envelopes immutable; parent_job_id correct; each has C4 record |
| S5-T07 | Least-privilege scope & budget-token minting | M | S5-T06, C6, C4, C5 | C2, C5, C6 | TC24/25 pass; scopes minimal; token metered/secret-free; federated==internal template |
| S5-T08 | Registry-driven Router & scoring | L | S5-T06, C5, C3 | C5, C3, C2 | TC06 passes; independence hard constraint; deterministic; descriptor_revision pinned |
| S5-T09 | Signed RoutingDecision ledger | M | S5-T08, C4 | C4, Audit API | TC27 passes; tampered decisions rejected on read; full candidate history |
| S5-T10 | Durable DAG Executor (Temporal) | XL | S5-T06, S5-T08, C1 | C1, C2, Execution API | TC18 passes; no double-dispatch across restart; transitions event-sourced |
| S5-T11 | Data-dependency gating on provenance commit | L | S5-T10, C4, C3 | C4, C3 | TC12/13/33 pass; downstream never admitted before commit; illegal-tier blocked; fail-closed on S8 error |
| S5-T12 | Scheduler & Concurrency Governor | L | S5-T10 | Execution API, Operator API | TC29/35 pass; caps respected; no class starved; deadline escalation works |
| S5-T13 | Budget Governor: reserve/reconcile/release | L | S5-T10, C4 | C4, C2, Operator API | TC10 passes; ledger arithmetic exact; reservations released |
| S5-T14 | Real-time metering & hard-breach halt | M | S5-T13, C1 | C1, C4, Events | TC11/30 pass; breach halts within interval; partial artifact captured |
| S5-T15 | Retry & typed-error handling | M | S5-T10 | C1, C2, C6 | TC07/20 pass; non-retryable never retried; correct terminal states |
| S5-T16 | Refusal handling, re-routing & escalation | M | S5-T08, S5-T18 | C1, C5, S9 coupling | TC08/09 pass; refusal never fails DAG; escalation opens review item |
| S5-T17 | Registry revocation & change subscription | M | S5-T08, C5 | C5, Execution API | TC16 passes; revoked-entity jobs halted within SLA; cache invalidated |
| S5-T18 | Human-Gate Coordinator (S9 wait states) | L | S5-T10 | S9 coupling, Execution API, ReviewWaitState | TC15 passes; DAG pauses/resumes; rejection prunes branch |
| S5-T19 | External-emission rate limiting & back-pressure | M | S5-T18, S5-T02 | Intake API, S9 coupling, Events | TC31 passes; throttling near S9 capacity; non-review nodes progress |
| S5-T20 | Non-goal guardrail enforcement in execution | M | S5-T10, S5-T02b | C2, GuardrailEvent, Execution API | TC26 passes; disallowed actions hard-blocked; novel never self-assigned |
| S5-T21 | Recursion Governor (S4 coupling) | L | S5-T10, S5-T13, C3 | C3, C2, Recursion API | TC21/22/23 pass; refuses without verifier; halts at bounds; self-score inadmissible |
| S5-T22 | Cancellation & liveness monitor | M | S5-T10, S5-T13, C1 | C1, Execution API | TC36/37 pass; cancel propagates; stalls detected; reservations released |
| S5-T23 | Provenance & lifecycle event-sourcing | M | S5-T06, S5-T09, S5-T13, C4 | C4 | FR-16 satisfied; 100% external artifacts have complete lineage; TC17 chain query works |
| S5-T24 | Distributed tracing & KPIs | M | S5-T10, S5-T13 | Events, Audit API | TC38 passes; per-job trace present; KPIs queryable |
| S5-T25 | State & Query/Audit API | M | S5-T09, S5-T13, S5-T23 | Audit API, C4 | TC29 query SLA met; routing/budget/guardrail audits return complete histories |
| S5-T26 | DAG replay / reproducibility | M | S5-T03, S5-T08, S5-T23 | Audit API, C4, C5 | TC19 passes; replayed topology + routing match original |
| S5-T27 | Operator controls (drain/pause/pools/quotas) | M | S5-T12, S5-T13 | Operator API | FR-22 satisfied; graceful drain preserves workflows; pause/resume per scope |
| S5-T28 | argusctl CLI | M | S5-T02, S5-T05, S5-T25, S5-T27 | Intake API, Planning API, Execution API, Operator API, Audit API | All CLI commands function against running control plane; help+examples documented |
| S5-T29 | NATS event publishing | S | S5-T10, S5-T13, S5-T18 | Events | All events emitted with correct payloads; consumers can subscribe |
| S5-T30 | Partial-DAG & degradation handling | M | S5-T10, S5-T11, S5-T18 | Execution API, C4, S9 coupling | TC32/33 pass; independent branches continue; DAG PARTIAL with failure report |
| S5-T31 | C2 version-compatibility & migration window | S | S5-T01 | C2 | TC34 passes; two majors served during window; breaking change flagged |
| S5-T32 | S5 test harness & fixtures (subagent/verifier/S8 stubs) | L | S5-T01, C1, C3, C4, C5 | C1, C2, C3, C4, C5 | All S5-TC runnable in CI hermetically with deterministic oracles |

#### S6 - Knowledge & Ingestion

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S6-T01 | Generate pydantic/JSON-Schema bindings for C4 & C5 | S | C4, C5 | C4, C5 | Models round-trip sample C4/C5; CI fails on schema drift |
| S6-T02 | SourceConnector SPI + driver registry | M | S6-T01 | s6.admin.add_source_connector | Stub driver passes harness; egress allowlist declared & surfaced |
| S6-T03 | arXiv connector (OAI-PMH + source tarballs) | M | S6-T02 | SourceConnector | Fixture batch lists+fetches deterministically; cursor resumes after crash (TC-02) |
| S6-T04 | GitHub connector | M | S6-T02 | SourceConnector | Fixture repo ingested; commit SHA cursor; license parsed |
| S6-T05 | HEPData connector + typed-table normalizer | M | S6-T02 | SourceConnector | TC-12 passes (units==pb, uncertainties parsed) |
| S6-T06 | Ingest orchestrator (resumable, idempotent, rate-limited) | L | S6-T02, S6-T10 | C4, s6.admin.trigger_sync | TC-01/02/28 dedup behavior pass |
| S6-T07 | Normalization pipeline (LaTeX/PDF/HTML -> structured doc) | L | S6-T01, S6-T10 | C4, s6.ingest.doc_quarantined | TC-31 quarantine; equations captured with symbol tables |
| S6-T08 | Citation-graph builder | M | S6-T07 | C4 | TC-32 edge query passes |
| S6-T09 | Unit-annotation tagger | L | S6-T07 | C6 (units contract) | TC-18 dimension accuracy >=0.95; dimensionless subset 0 errors |
| S6-T10 | S8 artifact/provenance client | M | C4 | C4 | Writes produce valid C4 records; incomplete-lineage writes rejected |
| S6-T11 | S10 sandbox + egress-allowlist integration | M | C4 | S10 runtime | TC-20 egress block + quarantine passes |
| S6-T12 | Structure-aware chunker | M | S6-T07, S6-T09 | - | TC-03 equation-preservation passes |
| S6-T13 | Embedder + pinned model versioning | M | S6-T12, S6-T10 | C4 | TC-04 no mixed-model index; degraded path flagged |
| S6-T14 | OpenSearch index layout (lexical+vector, versioned aliases) | M | S6-T13 | - | Aliases resolve correctly; filter fields queryable |
| S6-T15 | Dedup: SimHash + MinHash-LSH | M | S6-T07 | - | TC-33 near-dup skip passes |
| S6-T16 | Hybrid retrieval + RRF + rerank | L | S6-T14 | s6.retrieval.retrieve | TC-05/11/34 pass |
| S6-T17 | Curation layer + curated-doc sets | M | S6-T16, S6-T09 | s6.retrieval.get_curated_docs, s6.admin.curate | TC-19 curated conventions consistent; curation actions audited |
| S6-T18 | Degraded-mode retrieval | S | S6-T16 | s6.retrieval.retrieve | TC-30 degraded flag passes |
| S6-T19 | Registry service (C5) core: publish/get/deprecate | L | S6-T01, S6-T10 | C5, s6.registry.publish | TC-07/08/23 pass |
| S6-T20 | Registry resolve + routing filters | M | S6-T19 | C5, s6.registry.resolve | TC-15b pin reproducibility passes; excludes revoked/expired |
| S6-T21 | Independence resolution for cross-code | M | S6-T20, S6-T08 | C5, s6.registry.resolve_independent_code | TC-06/19b independence pass |
| S6-T22 | Revocation + propagation events | S | S6-T20, S6-T27 | C5, s6.registry.revoked | TC-14 revocation halt passes |
| S6-T23 | Frozen snapshot freeze() + SnapshotManifest | L | S6-T14, S6-T10, S6-T19 | C4, C5, s6.contamination.freeze | TC-10/22/35 pass |
| S6-T24 | Overlap primitives (ngram/simhash/minhash/embed max-sim) | M | S6-T15, S6-T14 | - | Each scorer matches golden fixtures on labeled pairs |
| S6-T25 | Novelty/recall query + calibration | L | S6-T24, S6-T23 | C4, s6.contamination.novelty_query | TC-09 ECE<0.05, TC-13/17 pass |
| S6-T26 | Snapshot integrity verification on read | S | S6-T23 | s6.contamination.novelty_query | TC-24 tamper detection passes |
| S6-T27 | Event bus (NATS JetStream) integration | M | S6-T01 | s6.ingest.*, s6.registry.*, s6.index.frozen, s6.curation.changed | Events observed with correct schemas; subscribe() streams changes |
| S6-T28 | AuthN/Z: mTLS + capability scopes | M | S6-T16, S6-T19 | all S6 APIs | TC-21 agent-write denial, TC-25 license-scope gating pass |
| S6-T29 | License & access-scope enforcement | M | S6-T16, S6-T28 | s6.retrieval.retrieve | TC-25 license gating passes |
| S6-T30 | Reindex & backfill jobs | M | S6-T14, S6-T13, S6-T06 | s6.admin.reindex | TC-15 rebuild parity passes |
| S6-T31 | Taxonomy management (versioned) | S | S6-T01 | s6.admin.manage_taxonomy | Taxonomy versions applied; subtopic filters resolve via aliases |
| S6-T32 | CLI (argusctl s6 ...) | M | S6-T16, S6-T19, S6-T23, S6-T25 | CLI | Each documented subcommand executes against staging |
| S6-T33 | OpenTelemetry tracing/metrics to S11 | S | S6-T16, S6-T06, S6-T25 | S11 telemetry | Traces span ingest->index and retrieve; freshness-lag metric emitted |
| S6-T34 | Plausible-but-wrong A/B eval harness | M | S6-T16, S6-T17 | s6.retrieval.retrieve | TC-16 >=30% relative reduction with p<0.05 measurable |
| S6-T35 | Perf & load test suite | M | S6-T16, S6-T20, S6-T25, S6-T06 | all S6 APIs | TC-26..29 SLOs met on staging-scale data |

#### S7 - Physics Compute Adapters

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S7-T01 | Author C6 JSON Schemas | M | C6 | C6 | All schemas validate reference examples; semver; published to registry |
| S7-T02 | Generate language bindings | M | S7-T01 | C6 | Round-trip in 3 langs passes; CI fails on schema drift |
| S7-T03 | Units engine with frozen registry | L | S7-T01, C4 | C6, C4 | S7-TC01/02/25/38 pass; registry version pinned into results |
| S7-T04 | Uncertainty engine | L | S7-T01 | C6 | S7-TC03 passes; propagation helpers unit-tested vs analytic references |
| S7-T05 | Calibration harness | M | S7-T04, C4 | C4, C6 | S7-TC29 passes; CalibrationEvidence written as C4 & resolvable |
| S7-T06 | Validity-domain guard | M | S7-T01 | C6 | S7-TC04/05 pass; density-model path works on emulator adapter |
| S7-T07 | Adapter SDK core | L | S7-T02, S7-T03, S7-T04, S7-T06 | C6 | Example adapter via SDK passes local validate; descriptor auto-generated |
| S7-T08 | Seed manager | S | S7-T01 | C6 | S7-TC06 passes; seed in provenance; deterministic adapters reproduce |
| S7-T09 | Backend plugin: native_python + jax | M | S7-T07 | C6 | JAX surrogate evaluates and grads; S7-TC08 passes |
| S7-T10 | Backend plugin: subprocess_binary | L | S7-T07, S7-T08, S10 | C6, S10 | S7-TC17/18 pass; binary runs under resource caps + egress-deny |
| S7-T11 | Backend plugin: emulator_gp + emulator_nn + surrogate_diff | L | S7-T07, S7-T04 | C6 | GP/ensemble variance surfaced; grad works on surrogate_diff |
| S7-T12 | Adapter Broker core | XL | S7-T02, S7-T09, C5 | C6, C5 | S7-TC19/20/21/33 pass; bulkheading verified |
| S7-T13 | Budget metering & halt | M | S7-T12, C2 | C6, C2 | S7-TC16 passes; halt precise at budget; partial provenance emitted |
| S7-T14 | Provenance emitter (C4) | M | S7-T12, C4 | C4, C6 | S7-TC14/15 pass; every call has complete lineage record |
| S7-T15 | Content-addressed cache | M | S7-T14, S7-T08 | C6, C4 | S7-TC12/13 pass; no caching of stochastic-unseeded |
| S7-T16 | Batch evaluation | M | S7-T12, S7-T09, S7-T10 | C6 | S7-TC36/41 pass; partial failure isolated |
| S7-T17 | Registration service + cost-ceiling gate | M | S7-T07, C5 | C5, C6 | S7-TC09/15b pass; heavy adapters rejected; conformant resolvable via C5 |
| S7-T18 | Independence metadata + resolution support | S | S7-T17, C5 | C5, C6 | S7-TC23/42 pass; resolve returns genuinely independent implementations |
| S7-T19 | Determinism enforcement & quarantine | S | S7-T12, S7-T17 | C5, C6 | S7-TC11 passes; quarantined adapters excluded from resolve |
| S7-T20 | Observability integration | S | S7-T12 | C6 | S7-TC22 traces span caller->adapter; metrics queryable in S11 |
| S7-T21 | Security hardening | L | S7-T12, S7-T10, S10 | C6, S10, C5 | S7-TC30/31/32/33/34 pass |
| S7-T22 | Reference adapter: eff_potential_bounce (+alt) | L | S7-T10, S7-T17 | C6, C5, C4 | S7-TC27 passes; independent twin registered; both resolvable |
| S7-T23 | Reference adapter: gw_spectrum (+alt) | L | S7-T09, S7-T17 | C6, C5, C4 | S7-TC24/26 pass; independent twin agrees within uncertainty on grid |
| S7-T24 | Reference adapter: gw_spectrum_surrogate (differentiable) | L | S7-T11, S7-T05, S7-T23 | C6, C5, C4 | S7-TC08/28/29/35 pass; grad correct; in-domain coverage meets nominal |
| S7-T25 | Reference adapters: collider_fastsim, boltzmann_transport_toy, higgs_observables (+twin) | XL | S7-T10, S7-T11, S7-T17 | C6, C5, C4 | Each passes conformance + physics-validation smoke; higgs twin enables cross-code |
| S7-T26 | CLI (argus-adapter) | M | S7-T07, S7-T17, S7-T05, S7-T18 | C6, C5 | All commands functional against running broker; validate catches non-conformance |
| S7-T27 | Conformance harness | M | S7-T07, S7-T14, S7-T17 | C6, C5 | Suite green for reference adapters; red for non-conformant fixtures |
| S7-T28 | Multi-fidelity + log-space + compound units | M | S7-T03, S7-T12 | C6 | S7-TC38 passes; two-fidelity adapter records correct fidelity_used |
| S7-T29 | Version compatibility & dual-serving | S | S7-T12 | C6 | S7-TC20/21 pass; dual-serving demonstrated |
| S7-T30 | Revocation propagation | S | S7-T12, C5 | C5, C6 | S7-TC40 passes |
| S7-T31 | Perf & scalability harness | M | S7-T12, S7-T16, S7-T24 | C6 | S7-TC35/36/37 pass at target SLOs |
| S7-T32 | Extrapolation->INCONCLUSIVE contract test with S3 | S | S7-T06, S7-T12 | C6, C3 | S7-TC39 passes against an S3 test double consuming C6 outputs |

#### S8 - Data, Artifact & Provenance

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S8-T01 | Freeze C4 JSON Schema as canonical IDL | M | C4 | C4 | Schemas validate examples; semver+compat rules documented; published immutable once S8-T05 exists |
| S8-T02 | Canonicalization spec + versioning | M | S8-T01 | C4 | Conformance vectors produce identical bytes; spec versioned; excluded fields enumerated |
| S8-T03 | BLAKE3 hashing library (Rust) + streaming | M | S8-T02 | HashBlob | S8-TC01/02/03/05 pass; streaming==single-pass |
| S8-T04 | Language bindings + binding generator | M | S8-T01, S8-T02 | C4, GenerateBindings | S8-TC29 byte-stable; bindings validate; hashing agrees cross-language (TC01) |
| S8-T05 | Object store facade with write-once + scratch bucket classes | L | S8-T03 | GetArtifact, CreateArtifact | S8-TC04/13/14 pass; write-once overwrite blocked; verify-on-read refuses mismatches |
| S8-T06 | PostgreSQL schema: append-only record/edge/closure tables + grants | M | S8-T01 | C4 | UPDATE/DELETE denied on record/edge; write role isolated to ledger writer |
| S8-T07 | Provenance Ledger Writer (Rust, single-writer, fail-closed) | L | S8-T05, S8-T06, S8-T09, S8-T10 | CreateArtifact, C4 | S8-TC07/20/21 pass; all-or-nothing commit; idempotent |
| S8-T08 | DAG / cycle enforcement on edge insert | S | S8-T06 | CreateArtifact | S8-TC06 (CYCLE_DETECTED); DAG invariant maintained |
| S8-T09 | Lineage completeness gate | M | S8-T01 | AssertLineageComplete, CreateArtifact | S8-TC07/33 pass; missing-field list returned; incomplete==non-promotable |
| S8-T10 | Tiering-coupling enforcer + report signature verification | L | S8-T01, C3 | CreateArtifact, VerifySignature, C3 | S8-TC08/09/10/11/12 pass; fail-closed on any violation |
| S8-T11 | Trust-store integration for verifier keys (S10 KMS) | M | S10 | VerifySignature | Revoked/unknown keys rejected (TC11); keys refreshed; no key writable by agents |
| S8-T12 | Lineage query engine: closure table + recursive CTE | L | S8-T06, S8-T07 | GetLineage, QueryImpactSet | S8-TC18/19/34/42 pass; closure==CTE; SLO met |
| S8-T13 | Reproducibility manifest + re-derivation comparison hooks | M | S8-T07 | GetReproducibilityManifest, RecordReproducibilityCheck | S8-TC31/32 pass; original immutable; tolerance comparators pluggable |
| S8-T14 | Merkle checkpoint chain + audit export | L | S8-T07, S8-T11 | ExportAuditSlice | S8-TC22/23 pass; proofs verify; tamper detected |
| S8-T15 | Dataset registry service | M | S8-T07 | RegisterDataset, GetDataset, ListDatasetVersions | S8-TC30 (dataset half); versions listed; splits typed |
| S8-T16 | Blind-split segregation + label sealing | M | S8-T15, S8-T18 | ResolveSplit | S8-TC16/17 pass; labels never materialized to non-verifier scopes |
| S8-T17 | External-source ingestion records (immutable) | S | S8-T06 | RegisterExternalSource, GetExternalSource | S8-TC37 passes; re-register with different snapshot_hash rejected |
| S8-T18 | API gateway: mTLS + capability-scope authorization | L | S10, S8-T07 | CreateArtifact, GetArtifact, QueryArtifacts, VerifySignature, GetLineage | S8-TC15/39 pass; no direct DB write path for agents |
| S8-T19 | Retention/GC + holds engine | L | S8-T05, S8-T12 | RunGC, PlaceHold, ReleaseHold, SetRetentionPolicy | S8-TC24/25/26/40 pass; write-once/reachable never collected |
| S8-T20 | Event emitter (NATS JetStream) | M | S8-T07 | artifact.created, artifact.flagged, artifact.tamper_detected, lineage.edge_added, ledger.checkpoint | S8-TC38 passes; events on each transition; idempotent consumption |
| S8-T21 | Query & read APIs (GetArtifact/QueryArtifacts/GetArtifactRecord) | M | S8-T05, S8-T06 | GetArtifact, GetArtifactRecord, QueryArtifacts | S8-TC14/35 pass; filters correct; P95<50ms metadata read |
| S8-T22 | CLI (argusctl s8 ...) | M | S8-T18, S8-T12, S8-T14, S8-T19 | CreateArtifact, GetArtifact, GetLineage, QueryImpactSet, ExportAuditSlice | Each command exercises its API; scope-checked; help documented |
| S8-T23 | Failure/degradation handling & fail-closed guarantees | L | S8-T07, S8-T12, S8-T20 | CreateArtifact, GetArtifact | S8-TC21/23/42 pass; no partial commits; typed retryable/fail-closed errors |
| S8-T24 | OpenTelemetry tracing + S11 metrics surface | S | S8-T18 | GetReproducibilityManifest, QueryArtifacts | Traces span gateway->writer->store; provenance/reproducibility metrics queryable |
| S8-T25 | E2E lifecycle + retraction-cascade test harness | M | S8-T07, S8-T10, S8-T12, S8-T15, S8-T20 | CreateArtifact, GetLineage, QueryImpactSet | S8-TC30/41 pass; green in CI |
| S8-T26 | Perf & scale harness (10^5 nodes) | M | S8-T12, S8-T21 | QueryImpactSet, GetArtifactRecord, CreateArtifact | S8-TC34/35/36 SLOs at 10^5 nodes |
| S8-T27 | Schema registry service + versioned publish/dual-serve | M | S8-T01, S8-T07 | PublishSchema, GetSchema, C4 | S8-TC27/28 pass; minor-additive accepted, major rejected outside migration |

#### S9 - Human-in-the-loop Review & Governance

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S9-T01 | Contract binding & S9 schema scaffolding | M | C2, C3, C4, C5 | C2, C3, C4, C5 | Bindings compile py+ts; round-trip every model; CI fails on incompatible contract minor |
| S9-T02 | PostgreSQL schema & append-only ledger storage | M | S9-T01 | - | UPDATE/DELETE on ledger/signoffs rejected; unique idempotency_key; recursive lineage correct |
| S9-T03 | Signature & hash verification module (Rust) | M | S9-T01 | C3, C4 | Valid report verifies; tampered rejected; TOCTOU re-verify (TC01/02/26) |
| S9-T04 | Intake & pre-screen service | L | S9-T03, S9-T08, S9-T11, S9-T02 | C2, C3, C4, S9 Intake API | TC01/02/08/31 pass; deferred back-pressure returned when admission exhausted |
| S9-T05 | Review task state machine & sign-off engine | L | S9-T02, S9-T07, S9-T08, S9-T10 | S9 Review Workflow API | TC04/05/12/13/32 pass; illegal transitions rejected |
| S9-T06 | Governance ledger writer (Rust) + checkpoints | L | S9-T02, S9-T03 | S9 Audit API, C4 | TC10/11/28 pass; verify detects injected break; append blocks state commit on fail |
| S9-T07 | Reviewer/role/COI registry | M | S9-T02 | C5, S9 Reviewer/Policy Admin API | TC06/27/41 pass; eligible-pool query excludes conflicted principals |
| S9-T08 | Guardrail policy engine | L | S9-T01, S9-T02 | S9 Emission/Governance API | TC03/04/22/23/24/38 pass; every eval records policy_version |
| S9-T09 | Emission authorization minter (Rust, HSM/Vault) | L | S9-T03, S9-T05, S9-T08, S9-T06 | S9 Emission/Governance API | TC14/20/25/26/34/39 pass; token binds exact hashes; single-use enforced |
| S9-T10 | Rate limiter, emission budgets & back-pressure gauge | M | S9-T02 | C2, S9 Intake API | TC08/09/18 pass; gauge reflects buckets; over-budget emission blocked |
| S9-T11 | Prioritizer & queue service | M | S9-T02, S9-T07, S9-T10 | S9 Review Workflow API | TC07/32 pass; ordering deterministic; at-most-one lease |
| S9-T12 | S5 Temporal integration (human-review wait states) | M | S9-T04, S9-T05 | C2 | TC15/42 pass; workflow resumes with correct outcome; REFUSED on guardrail block |
| S9-T13 | C3 challenge / re-verification integration | S | S9-T05 | C3 | TC16 passes; challenge results linked; inconclusive handling correct |
| S9-T14 | Federation admission review flow | M | S9-T05, S9-T07 | C5 | TC17 passes; no runtime trust elevation; decision recorded |
| S9-T15 | Evidence aggregation service (C3/C4/S6/S11 read-only) | M | S9-T02 | C3, C4, C5, S11 KPI API | Evidence bundle contains all four sources pinned by content_hash; contamination_index_version present |
| S9-T16 | Review UI - queue & claim-tier detail | L | S9-T15, S9-T05, S9-T11 | S9 Review Workflow API | Reviewer views evidence and records sign-off; FR08 satisfied; a11y baseline |
| S9-T17 | Review UI - governance/emission & admin consoles | L | S9-T09, S9-T08, S9-T07, S9-T14, S9-T19 | S9 Emission/Governance API, S9 Reviewer/Policy Admin API | TC19/29 flows usable; hard-blocks visibly non-overridable |
| S9-T18 | AuthN/AuthZ & mTLS + capability scopes | M | S9-T01 | S9 all APIs | TC27/30 pass; unauthorized/agent identities rejected |
| S9-T19 | WebAuthn step-up for emission-grade actions | M | S9-T18 | S9 Emission/Governance API | TC29 passes; emission blocked without fresh assertion |
| S9-T20 | Notifications & SLA/escalation engine | M | S9-T05, S9-T11 | S9 Review Workflow API | TC33 passes; no auto-approval on timeout; notifications delivered |
| S9-T21 | Audit API & signed export | M | S9-T06 | S9 Audit API | TC21/28 pass; export independently verifiable |
| S9-T22 | KPI computation & S11 emission | M | S9-T05, S9-T10 | S11 KPI API | TC40 passes; KPIs match ground truth; traces span intake->decision |
| S9-T23 | argusctl s9 CLI | M | S9-T05, S9-T06, S9-T08, S9-T09, S9-T21 | S9 all APIs | Each command maps to API and enforces authz/step-up where required |
| S9-T24 | Degradation & fail-closed handling | M | S9-T04, S9-T05, S9-T06, S9-T08, S9-T09 | S9 all APIs | TC19/28/38/39 pass; no path bypasses gate under dependency outage |
| S9-T25 | E2E, physics-validation, security & perf test harness | L | S9-T09, S9-T12, S9-T16, S9-T21 | S9 all APIs, C2, C3, C4, C5 | All S9-TC pass in CI; perf p95 targets met (TC35-37) |

#### S10 - Security, Sandbox & Runtime

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S10-T01 | Define S10 wire schemas + codegen | M | - | S10 data models | Models validate golden samples; bindings compile rust/py/ts; semver+registry entry |
| S10-T02 | Token Service: mint/verify budget & scope tokens | L | S10-T01 | Token Service API, C2 budget/capability_scopes | TC08/09/37 pass; mint requires KMS, verify offline; attenuation only narrows |
| S10-T02b | Token attenuation & revocation propagation | M | S10-T02 | Token Service API | TC09/38 pass; revoked token denied everywhere within propagation SLO |
| S10-T03 | Policy Service + pure decide() function | L | S10-T01 | Policy Service API, PolicyBundle model | TC07/17 pass; bundle signature verified; decide deterministic across machines |
| S10-T04 | Quota/Cost Service: reserve->consume->release ledger | L | S10-T01, S10-T02 | Quota Service API, C2 budget | TC10/11/34 pass; no negative remaining under concurrency; USD matches price table |
| S10-T04b | Flagship-HPC cost ceiling guard | S | S10-T03, S10-T04 | Quota Service API, PolicyBundle model | TC18 passes; over-ceiling envelope denied pre-launch (non-goal enforced) |
| S10-T05 | Node Supervisor daemon (lifecycle + kill switch) | XL | S10-T01 | Orchestrator-Supervisor internal API | TC13 freeze-before-terminate passes; supervisor unreachable from sandbox |
| S10-T06 | gVisor runtime class integration | L | S10-T05, S10-T03 | LaunchRequest->pod spec | TC02 seccomp, TC01 ro trust mounts pass under gVisor |
| S10-T07 | Firecracker microVM runtime class | XL | S10-T05, S10-T03 | LaunchRequest->pod spec, PolicyBundle risk_to_runtime | TC29 federated parity passes on Firecracker; runtime chosen by risk_class |
| S10-T08 | Sandbox Orchestrator admission+launch | L | S10-T02, S10-T03, S10-T04, S10-T05, S10-T06 | Orchestrator API, C4 launch-provenance | TC11/30 pass; pure-decision + side-effect split; fail-closed on verify failure |
| S10-T09 | Egress Proxy sidecar (allowlist + DNS pin + TLS SNI) | L | S10-T01, S10-T03 | Egress decision, AuditEvent egress.* | TC03/04/27 pass; zero fail-open; DNS pinned per connection |
| S10-T09b | Exfiltration byte-threshold detection | M | S10-T09 | Egress decision, PolicyBundle exfil_thresholds | TC33 passes; soft alerts, hard drops+halts |
| S10-T10 | Resource Meter (cgroup + DCGM sampler) | L | S10-T04, S10-T05 | Quota consume, SpendEvent | TC24 latency, TC28 gap conservatism pass; <=5s telemetry |
| S10-T11 | Mid-flight halt path (breach->freeze->capture->terminate) | L | S10-T04, S10-T05, S10-T14 | QuotaBreachEvent, Orchestrator terminate | TC12/13 pass; halt <=2s+overshoot; partial results captured |
| S10-T12 | GPU/MIG isolation & metering | L | S10-T05, S10-T10 | LaunchRequest gpu envelope | TC32 passes; no cross-slice memory access; slice-scoped metrics |
| S10-T13 | Secrets Broker: adapter/store proxies | L | S10-T01, S10-T02 | Broker API, C6 evaluate, C4 store put/get | TC14/15 pass; scope mismatch denied; no credential in sandbox |
| S10-T14 | Store-writer broker as sole agent write path | M | S10-T13, S10-T09 | Broker store/put, C4 ArtifactRecord | TC15 passes; direct writes denied; content_hash matches bytes |
| S10-T15 | LLM Metering Hook (model-call broker) | M | S10-T04, S10-T13 | Broker model API, C2 max_model_tokens, C4 provenance | TC16 passes; over-token call refused; provenance captured |
| S10-T16 | Audit Ledger Writer (hash-chained + anchoring) | L | S10-T01 | Audit API, AuditEvent model | TC19/40 pass; VerifyChain detects any tamper |
| S10-T17 | Trust-path write & escape detection (eBPF/fanotify) | XL | S10-T05, S10-T16 | AuditEvent escape/trustwrite | TC01/20/21 detections fire correctly |
| S10-T18 | Forensic Snapshotter + Quarantine workflow | L | S10-T05, S10-T16, S10-T17 | Quarantine API, C4 snapshot artifacts | TC22/35 pass; no release without durable snapshot |
| S10-T19 | Launch-provenance emission to S8 (C4) | M | S10-T08 | C4 ArtifactRecord, ExecEnvironmentDigest | TC21/31 pass; lineage complete; re-launch reproduces context |
| S10-T20 | Digest-pin & cosign image verification | S | S10-T08 | LaunchRequest image | TC30 passes; unsigned/tag-only rejected pre-launch |
| S10-T21 | Env/secret-shape sanitization | S | S10-T06 | LaunchRequest env_allowlist | TC05/36 pass; no secret-pattern value materialized |
| S10-T22 | NATS event publishing | M | S10-T04, S10-T16 | NATS s10.* subjects | Events emitted with correct schema & trace_id; consumers can subscribe |
| S10-T23 | OpenTelemetry tracing across S10 path | M | S10-T08, S10-T13 | OTel traces | TC40 trace join to S11 works; span covers full path |
| S10-T24 | Fail-closed degradation controllers | L | S10-T03, S10-T04, S10-T08, S10-T09 | Orchestrator admission, Supervisor checkpoints | TC26/27/37 pass; no fail-open path exists |
| S10-T25 | Warm-pool + launch-latency optimization | L | S10-T06, S10-T07, S10-T08 | Orchestrator launch | TC23 latency SLOs met (warm <=800ms, cold gVisor <=3s) |
| S10-T26 | Red-team escape-attempt suite (CI gate) | L | S10-T06, S10-T07, S10-T17 | argusctl s10 redteam | TC20 passes 0/N; any single escape fails the build |
| S10-T27 | argusctl s10 operator CLI | M | S10-T03, S10-T04, S10-T08, S10-T16, S10-T18 | CLI | Each subcommand maps to its API; covered by CLI tests |
| S10-T28 | Reproducible re-launch endpoint (S11 canary support) | M | S10-T19 | Orchestrator launch, ExecEnvironmentDigest | TC31 passes; relaunched digest matches on pinned fields |
| S10-T29 | Verifier-zone hosting for frozen-pipeline exec | M | S10-T08, S10-T09, S10-T13 | Orchestrator launch (verifier profile), C5 independence lookup | TC05b/39 pass; independence preserved |
| S10-T30 | Signed PriceTable service + rotation | S | S10-T04 | PriceTable model, Quota USD roll-up | TC34 passes; unsigned/stale table rejected |
| S10-T31 | Perf & scale harness | L | S10-T08, S10-T10, S10-T25 | S11 metrics | TC23/24/25 SLOs met; zero ledger drift |
| S10-T32 | e2e integration slice (S2 training + Evolver loop) | L | S10-T08, S10-T11, S10-T13, S10-T15, S10-T19 | C2, C4, C6 | TC21/22 pass end-to-end |

#### S11 - Observability & Evaluation

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S11-T01 | Define S11 JSON Schemas & generate bindings | M | - | S11 data models | Schemas validate examples; bindings compile 3 langs; drift check passes |
| S11-T02 | Rust telemetry gateway (mTLS, read-only, scrubber) | L | S11-T01 | OTLP ingest, s11.spans/metrics/events/cost subjects | TC01/02/28 pass; sustains target throughput in smoke bench |
| S11-T03 | OTel Collector pipeline & tail-sampling | M | S11-T02 | OTLP, Tempo, Prometheus, OpenSearch | Spans land in Tempo with correct tags; error/security traces always retained |
| S11-T04 | Storage provisioning (Tempo/Prometheus+Thanos/Postgres/OpenSearch) | M | S11-T01 | storage backends | Stores reachable; KPI-series & audit tables created; >=2y retention |
| S11-T05 | Platform semantic event consumers | L | S11-T02, S11-T04 | C2 events, C3 events, C4 events, C5 events, C6 events, S10 events | FR-04 events persisted with dedupe; TC13 exactly-once passes |
| S11-T06 | Trace assembly & completeness engine | L | S11-T03, S11-T05 | TraceIndexRecord, C2 plan/DAG (read) | TC05/05b/11 pass |
| S11-T07 | KPI definition registry | M | S11-T01, S11-T04 | /v1/obs/kpis/definitions | TC04 passes; edits mint new versions; historical binding preserved |
| S11-T08 | Streaming KPI processor | L | S11-T05, S11-T07 | KPISample, s11 subjects | TC03/12/13 pass; freshness<60s |
| S11-T09 | Batch rollup jobs | M | S11-T05, S11-T07, S11-T16 | KPISample, CostAttributionRecord | TC08 passes; recompute is bit-identical |
| S11-T10 | Signature verification & trust-store client | M | S11-T01 | C3 (read + signature verify) | TC26 passes; tampered/unsigned rejected |
| S11-T11 | Transparency-failure detector | M | S11-T05, S11-T10 | C4(read), C3(read), Finding, s11.finding.created | TC15/26/38 pass |
| S11-T12 | Reward-hacking detector suite | L | S11-T05, S11-T10 | C4(read), C3(read), S10 events, Finding | TC09/10 pass |
| S11-T13 | Re-run reproducibility canary | XL | S11-T04, S11-T10, C4, C3 | C4(read+write own output), C3 challenge(), S10 sandbox API, CanaryResult | TC06/07/14/25 pass |
| S11-T14 | Reproducibility rate KPI + non-promotable flagging | M | S11-T13, S11-T08 | KPISample, s11.finding.created | Reproducibility KPI computed; non-promotable flag surfaced to S9 |
| S11-T15 | Eval vault + scoring shim (label isolation) | L | S11-T04 | eval vault, scoring shim | TC24 passes; sandbox cannot read vault/shim |
| S11-T16 | Cost metering & attribution engine | M | S11-T05 | S10 budget events, CostAttributionRecord | TC08 passes; per-dimension attribution correct |
| S11-T17 | Cost anomaly detector | M | S11-T16 | Finding, S5 recommend_pause (advisory) | TC32/34 pass |
| S11-T18 | MLE-bench-style eval harness | XL | S11-T15, C2, C1 | C2(drive), C1(drive), EvalScorecard, scoring shim | TC18/36 pass |
| S11-T19 | Physics held-out recapitulation harness | XL | S11-T15, S11-T11, C2, C1, C6 | C2/C1(drive), C6(adapters read), EvalScorecard, Finding | TC19/20/21 pass |
| S11-T20 | Planted-exploit reward-hacking canary | L | S11-T12, C3 | C3 injection channel, PlantedExploitRecord, Finding | TC33 passes; planted excluded from real KPI denominators |
| S11-T21 | Eval scorecards & canary verdicts as C4 artifacts | M | S11-T13, S11-T18, C4 | C4(write own outputs), EvalScorecard | TC36 passes; scorecards resolve in S8 with valid lineage |
| S11-T22 | Lineage-observability impact queries | L | S11-T04, C4 | C4 lineage (read), /v1/obs/lineage/impact | TC17 passes; TC31 p95<3s |
| S11-T23 | SLO evaluation & alerting | M | S11-T08, S11-T09 | s11.kpi.slo_breach, s11.alert, Alertmanager | FR-19 alerts fire on breach; routing correct |
| S11-T24 | Query API (gRPC/REST) | L | S11-T06, S11-T08, S11-T11, S11-T13, S11-T16, S11-T22 | /v1/obs/* API | TC30 p95<2s; endpoints return documented shapes |
| S11-T25 | argusobs CLI | M | S11-T24 | Query API | All documented commands work against a live API |
| S11-T26 | Grafana dashboards & SLO views | M | S11-T03, S11-T08 | Grafana, Prometheus, Tempo | Dashboards render KPIs, traces, SLOs |
| S11-T27 | Next.js platform-semantic dashboards | L | S11-T24 | Query API | TC35 digest renders; all boards functional |
| S11-T28 | Append-only hash-chained audit log (Rust) | M | S11-T04 | AuditRecord, /v1/obs/export | TC23/27 pass |
| S11-T29 | Degradation & staleness controller | M | S11-T08, S11-T09, S11-T13 | KPISample.status, s11_data_staleness_seconds | TC16 passes; no silently-wrong values |
| S11-T30 | Read-only enforcement & least-privilege scopes | M | S11-T28 | capability scopes, AuditRecord | TC23/37 pass |
| S11-T31 | Advisory-only S5 pause recommendation | S | S11-T17, S11-T12 | S5 recommend_pause (advisory) | TC34 passes |
| S11-T32 | Daily Trust Digest assembler | S | S11-T08, S11-T13, S11-T21, S11-T23 | /v1/obs/digest | TC35 passes |
| S11-T33 | Self-metering & overhead cap | M | S11-T03, S11-T16 | MetricSample, tail-sampling policy | FR-26 overhead cap enforced |
| S11-T34 | Perf & load test harness | L | S11-T02, S11-T22, S11-T24 | ingest, Query API | TC29/30/31 pass |
| S11-T35 | Security test suite | L | S11-T02, S11-T10, S11-T13, S11-T15, S11-T28, S11-T30 | all S11 trust boundaries | TC23/24/25/26/27/28/37 pass |

#### S12 - Interop Standard & Federation

| id | title | est | depends_on | interfaces_touched | acceptance_criteria |
|----|-------|-----|-----------|--------------------|---------------------|
| S12-T01 | Standard Release data model & storage | M | C4 | C4, StandardRelease | Release write-once, content-addressed, signed, byte-identical on re-read; dedup by hash |
| S12-T02 | Semver compatibility checker | M | C1, C2, C3, C4, C5, C6 | StandardRelease | TC01/02 pass; classification deterministic; CI gate non-zero on under-declared bump |
| S12-T03 | Deterministic codegen pipeline | L | S12-T01, C4 | C4, StandardRelease | TC03 passes; bindings compile 3 langs; artifacts signed with valid SBOM |
| S12-T04 | Standard Service API + dual-serve | M | S12-T01 | StandardService API, standard.released, standard.deprecated | TC22 passes; GET current returns latest; deprecated major rejected after cutoff; events emitted |
| S12-T05 | Public standard docs site | M | S12-T04 | StandardService API | Renders each release's docs; version switcher works; 99.5% availability in staging |
| S12-T06 | argus-sdk core (C1 lifecycle wrapper) | L | C1, C4 | C1, C4, argus-sdk | Subagent completes REGISTERED->REPORTED lifecycle emitting provenance per artifact |
| S12-T07 | argus-sdk adapter surface (C6) | M | C6 | C6, argus-sdk | Adapter with units+uncertainty passes local validation; missing units/uncertainty/grad flagged |
| S12-T08 | Local conformance harness (S10-shim) | L | S12-T06, S12-T13 | argus-sdk, ConformanceSuiteVersion | TC09 passes; local report deterministic; marked advisory |
| S12-T09 | argus CLI | L | S12-T06, S12-T07, S12-T08, S12-T15 | argus CLI, Registry Gateway API, StandardService API | TC09/23/40(init) pass; scaffold builds reproducibly; CLI verifies own signed updates |
| S12-T10 | Hermetic conformance mocks (C2/C3/C4/C6) | L | C2, C3, C4, C6 | C2, C3, C4, C6, ConformanceSuiteVersion | Mocks deterministic under fixed seed; TC25 confirms no real S3 physics call |
| S12-T11 | Bronze conformance battery | L | S12-T10 | C1, C4, ConformanceCheck | TC10/11/12/39 pass; each check has documented oracle_spec |
| S12-T12 | Silver conformance battery | L | S12-T11 | C1, C2, C3, ConformanceCheck | TC13/14/38 pass; Silver strictly supersets Bronze |
| S12-T13 | Gold conformance battery | XL | S12-T12, S12-T07 | C1, C6, ConformanceCheck | TC15/16/17/18/26 pass; recursion-safety failure quarantines the run |
| S12-T14 | Conformance Service (orchestration + S10 execution) | XL | S12-T11, S12-T12, S12-T13, S12-T15, C4 | Conformance Service API, C4, conformance.run.completed, S10 runtime | TC24/27/28/34 pass; records signed, write-once, deterministic; runs resume after restart |
| S12-T15 | Bundle signer/verifier + SBOM (Rust) | M | C4 | ConformanceRecord, GovernanceLedgerEntry, SubmissionBundle | TC08/28/29 pass; keys from Vault/KMS never in sandbox; tampered bundles rejected pre-exec |
| S12-T16 | ConformanceRecord & SuiteVersion models + yank | M | S12-T15, C4 | ConformanceRecord, ConformanceSuiteVersion, C4, conformance.suite.yanked | TC36 passes; yank invalidates auto-pass and emits event; records immutable |
| S12-T17 | Federation identity service | M | C4 | Governance API (identities), FederationIdentity | TC30 passes; suspended keys cannot submit; rotation preserves history in ledger |
| S12-T18 | Registry Gateway + admission gate | L | S12-T16, S12-T17, C5 | Registry Gateway API, C5, entity.admitted, submission.received | TC04/05/05b/19/31/32/37 pass; publish only on all-predicates-true; scopes federation-default |
| S12-T19 | Governance ledger (append-only, hash-chained) | M | S12-T15, C4 | GovernanceLedgerEntry, C4, governance.action | TC06 passes; chain verifiable; any mutation detected; queryable by entity/time |
| S12-T20 | Governance Engine (workflows) | L | S12-T18, S12-T19 | Governance API, GovernanceLedgerEntry, SubmissionState | TC20 passes; no admission without registrar approval; all actions ledgered; durable across restart |
| S12-T21 | Revocation propagation saga | M | S12-T20, C5 | C5, entity.revoked, C2 | TC21 passes; revoke terminal; halt confirmed or escalated within SLA |
| S12-T22 | Taxonomy service (versioned DAG + RFC) | M | S12-T19, S12-T20 | Governance API (taxonomy), TaxonomyVersion, taxonomy.updated | TC07/40 pass; merges validated; version pinned in admitted descriptors |
| S12-T23 | Federation directory & discovery | L | S12-T18, C5 | Registry Gateway API (directory), C5 | TC33/35 pass; TC19/23 directory assertions pass; badges render |
| S12-T24 | Registrar review UI | M | S12-T20 | Governance API | Registrar actions succeed and are ledgered with attribution; UI reflects transitions |
| S12-T25 | Cross-code independence recording & resolve support | M | S12-T18, S12-T23, C5 | C5, C6 | TC26 passes; resolve(independence_needed) returns eligible, excludes same-lineage |
| S12-T26 | Observability & federation KPIs | M | S12-T14, S12-T20 | All S12 events, OTel | Every run/action emits trace+event; KPIs queryable; flaky-suite detection wired to yank |
| S12-T27 | Re-run canary integration (S11) | S | S12-T14, S12-T16 | Conformance Service API (challenge), conformance.suite.yanked | TC24 passes; disagreement quarantines the check and can trigger yank |
| S12-T28 | Conformance & governance security hardening | M | S12-T14, S12-T15 | S10 runtime, ConformanceRecord | TC27/28/31 pass; trust-path write attempt quarantines and alerts Sev-1 |
| S12-T29 | Appeals & abuse handling | S | S12-T20, S12-T17 | Governance API (appeals), FederationIdentity, GovernanceLedgerEntry | Appeals/abuse actions ledgered; repeat abuse escalates standing; decisions attributed |
| S12-T30 | Conformance suite authoring & golden fixtures | M | S12-T11, S12-T12, S12-T13, S12-T10 | ConformanceSuiteVersion | Suite immutable, signed, deterministic; drives TC09-TC18 reproducibly |
---

## 2. Dependency analysis — cross-subsystem edges

**Method.** Every `depends_on` entry is one of three kinds: (a) a contract token `C1..C6`; (b) a bare subsystem-level token (e.g. `S10`); or (c) a task id `Sx-Tyy`. The decoupling rule is: **no subtask may `depends_on` a task id belonging to a different subsystem.** Cross-subsystem coupling must be expressed only as a contract token or as a named/bare subsystem dependency, so the two teams integrate against a published surface, not each other's internals.

**Result of the full scan (all 377 subtasks, all 720+ `depends_on` edges):**

| Edge class | Count | Verdict |
|------------|-------|---------|
| task → task **within the same subsystem** | (all remaining task→task edges) | OK — internal ordering only |
| task → task **crossing a subsystem boundary** | **0** | **PASS** — no subtask reaches into another subsystem's internals (the 11 new debate subtasks route S3↔S4 coupling only through C3/C4/C5) |
| task → contract (`C1..C6`) | many | OK — routed through a published contract |
| task → bare subsystem token (`S10`) | 4 | OK — subsystem-level dependency, resolved below |
| unknown / dangling dep token | 0 | PASS — every task-id dep resolves to a real subtask |

**The single most important finding: zero cross-subsystem task-to-task dependencies.** Every place where one subsystem needs another, the edge is declared as a contract (`C1..C6`) or as a bare subsystem token. This is the structural guarantee that the backlog is genuinely decoupled.

### 2.1 The 4 bare subsystem-level dependencies (all legitimate)

These four edges name a subsystem (`S10`) rather than a contract, because the dependency is on the **sandbox/runtime substrate** itself, which is consumed as infrastructure rather than through one of C1–C6. Each is confirmed to route through the S10 runtime/orchestrator API (a named API), not a task internal:

| Subtask | Subsystem | Bare dep | Routes through | OK? |
|---------|-----------|----------|----------------|-----|
| S7-T10 | S7 | S10 | S10 Sandbox Orchestrator API (subprocess_binary backend runs in gVisor) | ✅ |
| S7-T21 | S7 | S10 | S10 runtime (read-only rootfs, seccomp, egress-deny) for security hardening | ✅ |
| S8-T11 | S8 | S10 | S10 KMS / trust store (read verifier keys) | ✅ |
| S8-T18 | S8 | S10 | S10 mTLS identity issuance for the gateway | ✅ |

**Fix note:** none required. Recommend a one-time normalization so these read as a named API (`S10 Sandbox Orchestrator API`, `S10 Token Service API`, `S10 KMS`) rather than the bare token `S10`, purely for registry hygiene. This is cosmetic, not a coupling defect.

### 2.2 Contract-crossing edges — coverage check

Every contract is both **produced by its owner** (owner subsystem has ≥1 subtask authoring/serving it) and **consumed with real subtask evidence** by the subsystems that depend on it. Confirmed produced-and-consumed:

- **C1** produced by S1 (S1-T01..); consumed with evidence by S2, S3, S4, S5, S11, S12. (**C1↔S9 removed** — over-declared; S9 sees subagent output only via C2/C3/C4.)
- **C2** produced by S5 (S5-T01..); consumed with evidence by S1, S2, S3, S4, S7, S9, S10, S11, S12. (**S6 and S8 removed** — over-declared; S6 ingests via C4/C5/S10, S8 stores via C4.)
- **C3** produced by S3 (S3-T01.., now **v1.1**); consumed with evidence by S1, S2, S4, S5, S7, S8, S9, S11, S12. (**S7 added** — extrapolation-flag reciprocity, §3.2. S4 is the heaviest v1.1 consumer via the debate loop; S8/S9 consume the new ValidationReport debate fields.)
- **C4** produced by S8 (S8-T01..); consumed with evidence by S1, S2, S3, S4, S5, S6, S7, S9, S10, S11, S12 (the most widely-consumed contract — the provenance spine; now also carries the **DebateLedger** produced by S4).
- **C5** produced by S6/S12 (S6-T19.., S12-T18..); consumed with evidence by S1, S2, S3, S4, S5, S7, S9, S10, S11. (S3-TPR5 and S4-TDB2 use C5 for challenger lineage-independence resolution.)
- **C6** produced by S7 (S7-T01..); consumed with evidence by S1, S2, S3, S5, S6, S10, S11, S12. (**S4 removed** — S4's C6 use is C5-mediated, not direct; **S12 added** — Gold cross-code conformance touches C6.)

No contract-crossing `depends_on` bypasses its owning contract. **PASS.**

---

## 3. Interface registry — producer ↔ consumer reconciliation

**Method.** For each `interfaces_produced` row I matched the declared consumer subsystems (from the producer's own summary) against (a) the consumer subsystem's own `interfaces_consumed` declaration and (b) hard subtask evidence — i.e. a real subtask in the consumer whose `interfaces_touched` references that contract/API. Each row is marked:

- **consistent** — declared consumers each have consuming subtask evidence, and the relationship is reciprocally declared.
- **mismatch** — the producer's consumer list and the consumer's own declaration disagree (over- or under-declared), even though no build breaks.
- **missing-consumer** — the interface is produced and declared to have a consumer, but no subsystem actually consumes it (dead interface).
- **missing-producer** — a subsystem consumes an interface that no subsystem produces (dangling dependency).

### 3.1 Contract-level registry (C1–C6)

| Interface | Producer | Declared consumers | Consumer evidence found | Status | Fix note |
|-----------|----------|--------------------|--------------------------|--------|----------|
| C1 Subagent Contract | S1 | S5,S2,S3,S4,S11,S12 | S5,S2,S3,S4,S11,S12 (all with subtasks) | **consistent (fixed)** | **FIX 1 applied:** S9 removed from C1's consumer list (was over-declared; S9 only ever sees subagent output via C2/C3/C4). No build impact. |
| C2 Task/Job Envelope | S5 | S1,S2,S3,S4,S7,S9,S10,S11,S12 | S1,S2,S3,S4,S7,S9,S10,S11,S12 (all with subtasks) | **consistent (fixed)** | **FIX 2 & 3 applied:** S6 and S8 removed from C2's consumer list (both over-declared; S6 ingests via C4/C5/S10, S8 stores artifacts via C4). No build impact. |
| C3 Verifier Interface + Validation Report (**v1.1**) | S3 | S5,S2,S4,S1,S7,S9,S11,S12,S8 | all present with subtasks | **consistent** | **v1.1** adds the 6 ValidationReport debate fields (`perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, `debate_ref`), produced by S3-TPR1..TPR5 and consumed heavily by S4 (debate loop), S8 (tier-coupling), S9 (emission gate). **FIX 5 (reciprocity):** S7 added to C3's acknowledged consumers — S7 emits the `extrapolation_flag` in its C6 result and S3 profiles consume it, setting the affected check to INCONCLUSIVE (see §3.2). |
| C4 Artifact + Provenance Record | S8 | S1,S2,S3,S4,S5,S6,S7,S9,S11,S12,S10 | all present with subtasks | **consistent** | Now also carries the **DebateLedger** (append-only record of all ChallengeRounds for an artifact), **produced by S4** (S4-TDB5) and **consumed by S3** (referee reads round history), S8 (provenance storage), S9 (evidence bundle). |
| C5 Registry / Capability Descriptor | S6 / S12 | S1,S2,S3,S4,S5,S7,S9,S11,S10 | all present with subtasks | **consistent** | Co-ownership (S6 runtime registry + S12 federation gateway) is coherent: both author publish/resolve/revoke against the same C5 schema; recommend a single C5 schema-of-record owner (S6) with S12 as gateway to avoid drift. Now also serves challenger lineage-independence resolution (S3-TPR5, S4-TDB2). |
| C6 Compute-Adapter Tool Interface | S7 | S1,S2,S3,S5,S6,S10,S11,S12 | S1,S2,S3,S5,S6,S10,S11,S12 (all with subtasks) | **consistent (fixed)** | **FIX 4 applied:** S4 removed from C6's direct-consumer list (S4 consumes C6 descriptors via C5 only — never calls C6 evaluate/grad directly; S2 does), and S12 added (three C6-touching subtasks S12-T07/T10/T13, Gold cross-code conformance). No build impact. |

### 3.2 Reciprocity / undeclared-toucher findings

| Interface | Issue | Status | Fix note |
|-----------|-------|--------|----------|
| C3 ↔ S7 | S7-T32 (`extrapolation → INCONCLUSIVE contract test`) touches C3 against an S3 test double, and S7 declares this coupling in its produced list ("C3 verifier profile consumption of extrapolation flags"), but S3's C3 consumer list did not name S7. | **consistent (fixed)** | **FIX 5 applied.** The coupling is real and intentional (contract-level, tested via a double). **S7 added to C3's acknowledged consumer/coupling list** so the extrapolation-flag contract has a named producer (S7 emits an extrapolation/out-of-validity flag in its C6 tool result) and named consumer (S3 must consume that flag and set the affected check to INCONCLUSIVE). Documented reciprocally in the C3 contract, in S3, and in S7. |
| C6 ↔ S12 | Same as row C6 above: S12 consumes C6 for Gold conformance but was unlisted by S7. | **consistent (fixed)** | Covered by FIX 4 in the C6 row: S12 added to C6's consumer list. |
| ChallengeRound / ChallengeVerdict / Attack | **Produced by S4** (S4-TDB1 debate-round orchestrator; owned by S4). Declared consumers: **S3** (referee adjudicates via ChallengeVerdict), **S8** (provenance storage of round records via C4), **S9** (evidence bundle for the human gate). | **consistent** | Producer S4 (S4-TDB1..TDB6) and consumers S3 (S3-TPR2/TPR3/TPR4), S8 (C4 provenance), S9 (evidence aggregation) all have subtask evidence. S3↔S4 coupling routes through C3 (verdict) and C4 (DebateLedger) — no raw cross-subsystem task edge. |
| DebateLedger | **Produced by S4** (S4-TDB5) as an append-only **C4** provenance record of all ChallengeRounds for an artifact; `debate_ref` in the C3 v1.1 ValidationReport points into it. Declared consumers: **S3** (referee reads history), **S8** (C4 storage/lineage), **S9** (evidence bundle). | **consistent** | Producer + all three consumers have subtask evidence; coupling is C4-mediated. |

### 3.3 Named (non-contract) cross-subsystem APIs — producer ↔ consumer

All named cross-subsystem couplings were checked to have both a producing subsystem (with a subtask that builds the API) and a consuming subsystem (with a subtask that references it). All resolve cleanly:

| Named API | Producer (build subtask) | Consumer (reference subtask) | Status |
|-----------|--------------------------|------------------------------|--------|
| S9 coupling / ReviewWaitState (open_review, ReviewDecided) | S9 (S9-T04/T05/T12 Intake+Workflow+Temporal) | S5 (S5-T16/T18/T19/T30) | consistent |
| S11 KPI API (governance KPI sink) | S11 (S11-T24 Query API) | S9 (S9-T15/T22) | consistent |
| S5 recommend_pause (advisory) | S5 (Operator/Execution API) | S11 (S11-T17/T31) | consistent |
| S11 re-run canary | S11 (S11-T13) | S4 (S4-T23), S5 (S5-T26), S8 (S8-T13), S10 (S10-T28), S12 (S12-T27) | consistent |
| S10 runtime / sandbox API | S10 (S10-T08 Orchestrator) | S6 (S6-T11), S12 (S12-T14/T28), S11 (S11-T13), plus C4/C6-mediated for others | consistent |
| S11 telemetry / OTel ingest | S11 (S11-T02/T03) | S6 (S6-T33), S10 (S10-T31), S4 (S4-T19), S7 (S7-T20), S8 (S8-T24), S5 (S5-T24) | consistent |

No named API is a **missing-producer** (something consumed but never built) and none is a **missing-consumer** (something built but never consumed).

### 3.4 Registry summary

| Status | Count |
|--------|-------|
| consistent | **all** C1–C6 contract rows + all named-API rows + the new debate data-model rows (ChallengeRound/ChallengeVerdict/Attack, DebateLedger) |
| **mismatch** | **0** — all 5 prior defects fixed (see below) |
| missing-consumer | 0 |
| missing-producer | 0 |

**The 5 previously-identified mismatches have all been applied and resolved, bringing the interface-registry mismatch count to 0:**

1. **FIX 1 — C1↔S9:** removed S9 from C1's consumer list (over-declared).
2. **FIX 2 — C2↔S6:** removed S6 from C2's consumer list (over-declared).
3. **FIX 3 — C2↔S8:** removed S8 from C2's consumer list (over-declared).
4. **FIX 4 — C6↔S4/S12:** removed S4 from C6's direct-consumer list (its use is C5-mediated, not direct) and added S12 (was omitted).
5. **FIX 5 — C3↔S7 reciprocity:** added S7 to C3's acknowledged consumers; S7 emits an extrapolation/out-of-validity flag in its C6 tool result, S3 consumes that flag and sets the affected check to INCONCLUSIVE — documented reciprocally in the C3 contract, in S3, and in S7.

All five were declaration-list defects (over- or under-declared consumers), not build-breaking dependency errors. No interface is produced-with-no-consumer and no interface is consumed-with-no-producer. The new adversarial-debate data models (ChallengeRound/DebateLedger, produced by S4, consumed by S3/S8/S9) are added with both ends present. **Interface-registry mismatch count = 0.**

---

## 4. Highest global coherence risks

Ranked most-severe first. These are the places where, even though the backlog is structurally decoupled, a coherence failure at integration time is most likely or most damaging.

1. **C4 is the single spine — its schema/canonicalization must land first and never break.** Eleven of twelve subsystems consume C4, and the entire tier-coupling invariant (no tier > ran-toy without a signature-valid C3 report) lives in the C4 writer (S8-T10). A late C4 major-version bump or a canonicalization change (S8-T02) ripples to every subsystem. **Mitigation:** freeze C4 v1 (S8-T01/T02/T27) and its bindings before any consumer starts; gate all C4 changes through the S8-T27 dual-serve migration path.

2. **C5 is co-owned by S6 and S12 — highest drift risk of any contract.** Two teams (runtime registry S6, federation gateway S12) both author `publish/resolve/revoke` against C5. Divergent independence-resolution or conformance-gating semantics would silently break cross-code selection (which S3/S4 rely on for the novel tier). **Mitigation:** designate S6 as the C5 schema-of-record and S12 as a gateway that must pass the same conformance vectors; add a shared C5 conformance suite both must satisfy.

3. **The reward-integrity chain (C3 signature → S4 admission → S8 tier-coupling → S9 emission gate) must be bit-consistent across four independent signature-verification implementations.** S3-T06, S4-T09, S8-T10, S9-T03, S11-T10 each re-verify C3 report signatures. If canonicalization (S3-T04) or the trust store diverges between them, a report valid to one is invalid to another — breaking either safety (a forged score admitted) or liveness (a valid score rejected). **Mitigation:** ship one shared `argusverify` library (S3-T06) as the sole verification path; forbid re-implementation; add a cross-binding conformance vector (S3-T31) all consumers run.

4. **The C3 v1.1 adversarial red-blue debate loop couples S4 (evolver/proponent) → S3 (referee) → S8/S9 (provenance + emission) across four contracts and must stay bit-consistent.** The self-improvement loop is now a multi-agent adversarial peer review: S4 produces the proponent candidate and runs the debate (S4-TDB1..TDB6), an independent challenger panel (≥K, lineage-disjoint via C5) attacks it with must-react/must-not-react probes, and the S3 referee (≠ proponent, signed, non-gameable) adjudicates via ChallengeVerdict — requiring `must_react_pass AND must_not_react_pass AND NOT insensitivity_detected`. The C3 v1.1 ValidationReport (perturbation_pairs/insensitivity_flags/challenger_panel/independence_attestation_debate/referee/debate_ref) is the sole channel carrying this verdict, and the DebateLedger (S4→C4) is the provenance spine for it. **Risk:** if S3's insensitivity detector (S3-TPR3) or the referee-≠-proponent enforcement (S3-TPR4) diverges from S4's admission logic, a planted-spurious model that ignores the data (insensitive) can survive to the human gate, or a valid claim can be wrongly killed. **Mitigation:** freeze C3 v1.1 at M0 (S3-TPR1); make the insensitivity-catch and referee-separation KPIs hard 100% gates; require the challenger panel to be refreshed and lineage-disjoint each round (S3-TPR5, S4-TDB2, S4-TDB4) so proponent overfit and challenger collusion are both caught.

5. **C6's extrapolation-flag → INCONCLUSIVE coupling (S7 ↔ S3) is a real cross-contract dependency.** If S3 profiles do not treat the S7-emitted extrapolation/out-of-validity flag as INCONCLUSIVE, the verifier can silently bless extrapolated physics — a validity-of-results failure. **Status: FIX 5 applied** — S7 now emits the flag in its C6 tool result, S3 consumes it and sets the affected check to INCONCLUSIVE, and the reciprocity is documented in the C3 contract, S3, and S7 (registry mismatch cleared, §3.2). **Mitigation:** keep the S7-T32 ↔ S3 double a required cross-subsystem contract test in CI.

6. **Sandbox/runtime (S10) is an implicit dependency of many subsystems but is only weakly modeled in `depends_on`.** S1/S2/S3/S4/S6/S7/S12 all execute agent/submitted code and all assume S10 isolation, egress-deny, and budget metering, yet most express this only through contracts, not a hard S10 edge. If S10 admission/quota semantics (S10-T04/T08/T24) are not ready, those subsystems cannot run end-to-end even though the backlog shows them unblocked. **Mitigation:** treat S10-T01/T02/T03/T04/T05/T08 as a platform-critical-path milestone that must precede any sandboxed-execution subtask; publish the S10 Orchestrator + Token + Quota APIs as named contracts consumed explicitly.

7. **No-self-grade / no-self-promotion is enforced independently in S1, S2, S4, S9 — a coherence invariant, not a local one.** S1-T16, S2-T20, S4-T17, S9-T08 each separately guarantee a subsystem cannot raise its own claim tier or emit externally without the C3 report + human sign-off. A gap in any one re-opens the reward-hacking surface globally. **Mitigation:** centralize the tier-source rule as a shared policy predicate (sourced only from a signed C3 report) and have each subsystem's conformance suite assert it, rather than four bespoke implementations.

---

*End of Backlog & Interface Registry. Total: 377 subtasks (S3 +5, S4 +6 for Adversarial Red-Blue Debate Evolution), 12 subsystems, 6 contracts (C3 at v1.1); 0 cross-subsystem task-to-task dependencies; 0 missing-producer / 0 missing-consumer; 0 interface-registry mismatches (all 5 prior declaration-list defects fixed).*
