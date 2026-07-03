# Project Argus — Master Test Plan

> **Part of the Project Argus design set.** Start at README.md for the doc map and reading order. Related docs: Architecture.md, PRD.md, TechDesign.md, Backlog-and-Interfaces.md, TestPlan.md, Roadmap.md.

**Document owner:** QA Lead
**Status:** Complete implementation-design test plan (not an MVP scope)
**Scope:** All subsystems S1–S12, cross-subsystem integration & end-to-end scenarios, and platform KPIs.

---

## 1. Test Strategy & Physics-Validation Philosophy

### 1.1 Why Argus's test plan is unusual

Argus is a **verifier-gated, agent-built ML foundry**. The agent's job is not to discover physics; it is to *build, train, validate, and iterate ML models* for physics subtopics. This inverts the usual QA burden: the highest-risk failure modes are not "the code crashes" but rather **the system silently claims something is true that a physics verifier never actually established**. Consequently the test plan is organized around a single overriding invariant:

> **Nothing is trusted without validation, and no trust claim can be self-issued.**

Every test category below exists to protect one of the four design pillars: *oracle-gated autonomy*, *verify-before-trust*, *claim-tiering with full provenance*, and *human-in-the-loop before any external artifact*.

### 1.2 Test taxonomy (types used throughout)

| Type | Purpose | Oracle discipline |
|------|---------|-------------------|
| **unit** | Single component/function contract | Deterministic assertion, fixed seeds/fixtures |
| **integration** | Two-or-more subsystems via published contracts (C1–C6) | Mock or live peer subsystem; deterministic |
| **e2e** | Full lifecycle across the federation | Terminal-state + artifact-shape assertion |
| **physics-validation** | The physics oracles themselves (injection, null, cross-code, physical-consistency, calibration, leakage) | Ground-truth held out of the pipeline; numeric tolerance |
| **security** | Sandboxing, egress, secrets, tier-coupling, reward-hacking, tamper-evidence | Fail-closed assertion; audit-event presence |
| **perf** | Latency, throughput, concurrency, scale | Percentile budget over N runs |

Every test case carries an **id, type, given/when/then, and a deterministic oracle**. "Deterministic oracle" means: given the fixture, pinned versions, and fixed seeds, the pass/fail decision is reproducible bit-for-bit (or within an explicitly declared numerical tolerance for stochastic checks).

### 1.3 The physics-validation philosophy (the six oracles)

These are the mechanisms by which Argus earns the right to *tier* a claim. They are applied by S3 (Physics Validation & Verifier Framework) and mirrored as advisory self-checks in S2/S1 (advisory = **never tier-promoting**).

1. **Injection tests.** Insert a synthetic signal of *known* amplitude/parameter into the data. A faithful model recovers it within tolerance; an inert or constant model does not. We additionally test **amplitude linearity** (recovered vs injected slope ≈ 1, intercept ≈ 0) so a model cannot fake recovery on a single point.

2. **Null / held-out tests.** Run the pipeline on signal-free or **label-shuffled** input. A trustworthy model reports *no* detection. This catches hallucinated signals and, critically, defeats **label leakage** — a leaked-label model collapses to chance when labels are shuffled.

3. **Cross-code consistency.** Compare the pipeline's forward output against an **independent** implementation (different repo/lineage) over the shared validity domain, using χ²/dof and max|z| against *combined* uncertainty. This is the primary defense against single-implementation bias. Independence is machine-verified via lineage-closure disjointness (S6/S7); a fork of the code-under-test is **not** independent.

4. **Physical-consistency checks.** Dimensional (units-algebra) consistency, positivity of non-negative observables, unitarity/normalization bounds, declared-symmetry invariance, and asymptotic-limit recovery. Any violation is a hard sub-gate FAIL with the offending point in evidence.

5. **Leakage / contamination screens.** Train/test overlap (MinHash/LSH), and overlap against a **frozen contamination index** pinned per job. A "novel" result that paraphrases an indexed paper is capped below novel. Leakage FAIL blocks novelty regardless of score.

6. **Uncertainty calibration.** Predictive artifacts must carry uncertainty; empirical coverage + PIT-KS must match nominal. A bare point estimate is rejected.

### 1.4 Claim-tiering (the trust ladder)

Every artifact is tiered exactly one of:

- **ran-toy** — executed, no strong validation. The floor. Self-assignable.
- **recapitulated-known** — reproduced an established result under a signed verifier profile.
- **novel-needs-human** — passed *all* gates incl. cross-code + leakage + independence attestation. **Always a candidate only**; routes to S9 human review; never auto-promoted; never externally emitted without human sign-off.

**Tiering invariants enforced everywhere (S1, S2, S3, S4, S8):**
- A subagent/builder/evolver **cannot self-promote** its tier. Tier comes only from a **signature-valid S3 report**.
- Tier > ran-toy at a provenance write (S8 C4) **requires** a coupled `validation_report_ref` whose signature verifies and whose tier matches — else `ILLEGAL_TIER`, fail-closed.
- Any `INCONCLUSIVE` mandatory check ⇒ non-improvement (for reward) and cannot support a tier above what the profile allows.
- Independence unavailable ⇒ tier capped at recapitulated-known (report still signed, degradation surfaced).

### 1.5 Provenance, reproducibility & fail-closed posture

- **Full lineage on every artifact:** inputs, code commit, environment digest, adapters+versions, seeds, content hashes. Missing any ⇒ `INCOMPLETE_LINEAGE`, no commit.
- **Reproducibility:** deterministic artifacts re-derive bit-for-bit; seeded/stochastic artifacts re-derive within a *declared* tolerance. S11 canary + S3 challenge re-run and compare.
- **Fail-closed default:** signing unavailable, verifier unavailable, provenance ledger unavailable, quota service down, egress proxy crash — all halt or refuse rather than proceed untrusted.

### 1.6 Non-goals asserted as tests

The plan actively tests that Argus **refuses** its non-goals: no autonomous new-theory confirmation, no autonomous paper submission, no flagship-HPC execution (ceiling rejection), and no claim of empirical validation. These appear as guardrail (S5/S9) and ceiling (S10) test cases.

### 1.7 Environments, fixtures & gating

- **Fixtures:** golden files for canonicalization/codegen determinism; synthetic datasets with injected signals of known amplitude; gold/known-bad physics fixtures; a frozen contamination index snapshot; red-team "hackable verifier" and escape batteries.
- **Determinism harness:** pinned template-lib / registry / model / profile / price-table versions; master seeds; RNG-state checkpointing.
- **CI gates:** schema-diff & codegen-drift must pass; conformance (Bronze/Silver/Gold) must pass for the reference subagent; the S10 escape battery must be 0/N; the S3 planted-exploit suite catch-rate must be 100%.
- **Traceability:** every test carries a stable id (e.g. `S3-TC09`, `S5-TC17`) referenced by the cross-subsystem scenarios in §15 and the KPI evidence in §16.

---

## 2. S1 — Subagent Framework & Contract (SLHA-for-agents)

The standardized subagent contract: lifecycle state machine, acceptance gating ("no verifier, no run"), provenance emission, sandboxed build, and tier relay (subagents can never mint tier).

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S1-TC-01 | unit | **Legal transition accepted.** Given a job in ACCEPTED; when plan() event applied; then state→PLANNING and a LifecycleEvent appended. | `job_current.state=='PLANNING'` AND exactly one new `lifecycle_events` row `from=ACCEPTED,to=PLANNING`. |
| S1-TC-02 | unit | **Illegal transition rejected.** Given a job in REGISTERED; when build() attempted (skipping accept/plan); then POLICY error, no event appended. | `error.category=='POLICY'` AND `lifecycle_events` count unchanged. |
| S1-TC-03 | unit | **Deterministic replay.** Given a 12-transition event log; when the reducer folds it twice on fresh state; then identical final state. | `reduce(log)==reduce(log)` byte-equal serialized; matches stored `job_current`. |
| S1-TC-04 | unit | **accept() refuses on missing adapter.** Given a JobEnvelope requiring `adapter:bounce-solver@1` not in descriptor/allowed_adapters; when default accept() runs; then accepted=false, MISSING_ADAPTER. | `Acceptance.accepted==false` AND `reason=='MISSING_ADAPTER'` AND `state=='REJECTED'`; no exception. |
| S1-TC-05 | unit | **accept() refuses when no verifier profile.** Given `verifier_profile_ref=null`; when accept() runs; then NO_VERIFIER. | `Acceptance.reason=='NO_VERIFIER'` (enforces "no verifier, no run"). |
| S1-TC-06 | unit | **accept() idempotency.** Given accept() already returned an Acceptance for job J; when called again with same envelope; then identical stored Acceptance, gate not re-run. | Second response byte-equal to first AND gate mock counter==1. |
| S1-TC-07 | unit | **Tier self-promotion impossible.** Given build() attempts to attach `claim_tier='novel-needs-human'`; when report() built; then subagent tier dropped, tier comes only from S3 (ran-toy if none). | `SubagentReport.claim_tier=='ran-toy'` AND warning event logged; no public `ctx.set_claim_tier`. |
| S1-TC-08 | unit | **Incomplete lineage refused.** Given emit_artifact with lineage missing environment_digest; when emitter validates; then refused INCOMPLETE_LINEAGE, nothing committed. | C4 write `category=='INCOMPLETE_LINEAGE'` AND object store has no new object. |
| S1-TC-09 | unit | **Version compat minor accept.** Given envelope 1.4.0 vs runtime 1.2.0; when method with unknown additive field received; then field ignored, call succeeds. | Success; unknown field absent from parsed model; no error. |
| S1-TC-10 | unit | **Version incompat major reject.** Given envelope 2.0.0 vs runtime 1.x; when accept() called; then REFUSED VERSION_UNSUPPORTED. | `Acceptance.reason=='VERSION_UNSUPPORTED'`. |
| S1-TC-11 | unit | **Schema-diff classifies breaking change.** Given a schema edit removing a required field; when compat gate runs; then MAJOR, fails minor-only publish. | schema-diff exit≠0 with `classification=='MAJOR'`. |
| S1-TC-12 | unit | **Uncertainty tag required at Silver.** Given a Silver build producing a predictive artifact with no uncertainty tag; when BuildResult finalized; then Silver conformance FAIL. | `conformance(silver)` FAIL on `uncertainty_present`. |
| S1-TC-13 | integration | **Provenance actually written to S8.** Given a build() emitting one model artifact vs live/mock S8; when emit_artifact completes; then an ArtifactRecord with matching content_hash + complete lineage exists. | `S8.get(content_hash)` returns record; `BLAKE3(bytes)==content_hash`; lineage query returns `derived_from` edges. |
| S1-TC-14 | integration | **Build executes only in sandbox.** Given a build() whose training code writes to disk; when marshaler runs it via S10; then writes only in scratch, none to trust-path mounts. | S10 audit shows all writes under `/scratch`; zero writes to read-only mounts; exit success. |
| S1-TC-15 | integration | **validate() hands frozen pipeline to S3.** Given a completed BuildResult; when validate() runs; then a frozen_pipeline_ref produced and S3.verify invoked with it + blind handle. | S3 mock receives VerificationRequest with resolvable `frozen_pipeline_ref`; subagent never reads blind labels (label-read counter==0). |
| S1-TC-15b | integration | **report() relays S3 tier verbatim.** Given S3 returns a signed report tier=recapitulated-known; when report() built; then SubagentReport tier==recapitulated-known and validation_report_ref set. | Report tier == S3 tier exactly AND `validation_report_ref` points to signed report. |
| S1-TC-16 | integration | **Runtime restart recovery.** Given a job in BUILDING when the runtime is killed; when it restarts and replays; then state restored to BUILDING and durable sandbox reattached. | Post-restart `state=='BUILDING'` AND sandbox handle resolves; no lineage rows lost. |
| S1-TC-17 | integration | **Descriptor published to registry.** Given register() on a valid descriptor; when runtime publishes to S6; then new immutable C5 revision + `s1.subagent.registered`. | `S6.resolve` returns new `revision_ref`; NATS subscriber receives event. |
| S1-TC-18 | integration | **Bounded auto-repair.** Given a build() failing then succeeding on 2nd repair (max=2); when build() runs; then success with repair_attempts==1 and per-attempt provenance. | `diagnostics.repair_attempts==1` AND provenance per attempt. |
| S1-TC-19 | integration | **Auto-repair cap exhausted.** Given build() failing all attempts (max=2); when build() runs; then FAILED with typed error after 2. | `state=='FAILED'`; `error.category in {PERMANENT,RETRYABLE}`; attempts==2. |
| S1-TC-20 | e2e | **Full happy-path lifecycle.** Given an internal subagent + valid envelope with resolvable verifier profile; when S5 drives register→accept→plan→build→validate→report; then REPORTED report with artifact_refs + validation_report_ref. | Final REPORTED; ≥1 artifact_ref, a validation_report_ref, S3 tier, complete reproducibility_manifest. |
| S1-TC-21 | e2e | **Refusal reroute.** Given a subagent refusing (out-of-scope) and an alternative that accepts; when S5 routes; then first REFUSED (not error), second completes. | First `status=='REFUSED'`; second reaches REPORTED. |
| S1-TC-22 | e2e | **Cancel mid-build.** Given a long-running build(); when cancel(job_id); then sandbox stops within grace, job FAILED(CANCELLED) with partial provenance. | FAILED category CANCELLED within grace+kill window; partial artifacts have lineage. |
| S1-TC-23 | physics-validation | **Units mismatch surfaces from adapter.** Given a build() calling a C6 adapter with wrong units (Hz vs GeV); when ctx.call_adapter runs; then UNITS_MISMATCH recorded, no silent coercion. | `EvalResult.error.category=='UNITS_MISMATCH'`; build diagnostics capture it; no numeric result. |
| S1-TC-24 | physics-validation | **Advisory self-check does not promote tier.** Given a Silver subagent whose advisory PHYSICAL_CONSISTENCY self-check passes; when validate()/report() run without an S3 report; then tier stays ran-toy. | `claim_tier=='ran-toy'` (self-checks advisory only). |
| S1-TC-25 | physics-validation | **Out-of-domain adapter output flagged.** Given a build() querying an adapter outside validity; when it returns in_validity_domain=false, extrapolation_flag=true; then marked extrapolated in provenance/risk_notes. | provenance/risk_notes record `extrapolation_flag==true`; downstream S3 treats as INCONCLUSIVE. |
| S1-TC-26 | security | **Egress default-deny.** Given a build() connecting to a non-allowlisted host; when policy evaluates; then denied and logged. | S10 egress log shows DENY; no bytes leave; build sees connection error. |
| S1-TC-27 | security | **Allowlisted adapter egress permitted.** Given a build() calling a declared+allowed adapter endpoint; when evaluated; then permitted and logged. | Egress log ALLOW for declared host; call succeeds. |
| S1-TC-28 | security | **Write to trust-path is Sev-1 quarantine.** Given malicious build() writing the verifier/reward mount; when attempted; then blocked, job QUARANTINED, Sev-1 fired. | `state=='QUARANTINED'`; `s1.job.quarantined` (category=SANDBOX); write blocked in audit; not auto-retried. |
| S1-TC-29 | security | **No secrets in sandbox.** Given a build() enumerating env/mounts; when it searches for creds; then none present. | Scan finds zero secret material; adapter calls needing creds still succeed via brokered proxy. |
| S1-TC-30 | security | **Direct in-process exec forbidden.** Given subagent code calling os.system/exec instead of submit_sandbox_job; when lint+runtime guard evaluate; then lint fails build, runtime raises Sev-1 SANDBOX. | CI lint exit≠0; runtime guard emits SANDBOX error and quarantines. |
| S1-TC-31 | security | **Unsigned validation report rejected.** Given an S3 response whose signature fails; when report() attaches it; then rejected, tier stays ran-toy. | Signature verify fails; `claim_tier=='ran-toy'`; no validation_report_ref attached. |
| S1-TC-32 | security | **Tier-report coupling enforced at C4 write.** Given an ArtifactRecord tier=recapitulated-known with no validation_report_ref; when emitter writes; then S8 rejects ILLEGAL_TIER. | C4 write `category=='ILLEGAL_TIER'`; artifact not committed. |
| S1-TC-33 | perf | **accept()/plan() latency.** Given 1000 sequential accept()+plan() with adapters/registry mocked; when latency measured; then p95 ≤ 3s/call. | Measured p95 ≤ 3000ms. |
| S1-TC-34 | perf | **Concurrency scaling.** Given 200 concurrent jobs; when they run build/validate/report; then sustained without state-store contention. | All 200 reach terminal state; zero deadlock/serialization failures; event log consistent. |
| S1-TC-35 | perf | **Lifecycle store scale.** Given 10^5 artifacts + lifecycle events; when a lineage/state query runs; then within budget. | Query p95 within budget (e.g. <500ms) at 10^5. |
| S1-TC-36 | integration | **Conformance Bronze passes reference subagent.** Given a minimal reference subagent; when conformance --level bronze runs; then all Bronze pass + evidence emitted. | Bronze all PASS; C4 evidence_ref produced and referenced in descriptor conformance block. |
| S1-TC-37 | integration | **Conformance Gold requires cross-code participation.** Given a subagent lacking independence_tags; when conformance --level gold runs; then Gold fails cross-code-participation. | Gold FAIL on `cross_code_ready`; Bronze/Silver still pass. |
| S1-TC-38 | integration | **Codegen drift detection.** Given a schema change without regenerated bindings; when CI codegen check runs; then build fails on drift. | `argus-subagent codegen --check` exit≠0 reporting drift. |
| S1-TC-39 | e2e | **Evolver-driven variant build.** Given S4 requests a variant config derived from a prior artifact; when build() runs; then new artifact with derived_from edge + distinct content_hash. | `content_hash` != prior; `lineage.derived_from` includes prior ref. |
| S1-TC-40 | unit | **Heartbeat reports spend.** Given a build() reporting spend heartbeats; when heartbeat() queried; then returns progress + spend_so_far. | `Health.spend_so_far` monotonically non-decreasing across heartbeats. |

---

## 3. S2 — ML Builder Engine

Compiles a build spec, engineers dimensionally-valid features, synthesizes and calibrates models with mandatory uncertainty, meters budget, auto-repairs, and freezes a self-replaying pipeline. Never self-scores.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S2-TC01 | unit | **Dimensional guard rejects inconsistent feature.** FeatureNode mixes energy+length with dimensionless output; validate FeatureGraph → rejected, node excluded. | build raises DimensionalError; graph node count excludes invalid node. |
| S2-TC02 | unit | **Buckingham-π group count.** Input dim matrix with null-space rank r; enumerate dimensionless groups within exponent bound → exactly the expected independent set. | Produced basis rank == analytic null-space rank r (exact). |
| S2-TC03 | unit | **Complexity escalation gated by significance.** Incumbent classical S* vs deep S_new with S_new−S* < δ·se; synthesizer decides → keep classical. | Selected `family_id` == classical incumbent (deterministic, fixed seeds/data). |
| S2-TC04 | unit | **Point-estimate-only model rejected.** `native_uq=none`, no conformal wrapper; UQCalibrator finalizes → missing-uncertainty error. | build raises UncertaintyRequiredError; no ModelArtifact. |
| S2-TC05 | unit | **Conformal interval nominal coverage.** Synthetic regression, split-conformal 1−α=0.9; compute empirical coverage on held-out fold → within tol of 0.9. | `|coverage − 0.9| ≤ tol` (e.g. 0.03), fixed seed. |
| S2-TC05b | unit | **Miscalibrated UQ flagged for repair.** Overconfident model, 90% covers ~70%; validate coverage → passed_internal_coverage=false + calibration_fail repair. | `AdvisoryCheck(calibration).status=FAIL` AND `RepairAction(calibration_fail)` recorded. |
| S2-TC06 | unit | **BudgetMeter halts on GPU-seconds breach.** max_gpu_seconds=T; job exceeds T → halt within grace, best checkpoint captured. | build raises BUDGET; partial ModelCheckpoint exists; `gpu_seconds ≤ T*(1+grace)`. |
| S2-TC07 | unit | **Auto-repair resolves NaN loss.** High-LR config → NaN; FailureDoctor lowers LR/adds grad-clip; probe re-train resolves. | `RepairAction(nan_loss).probe_result=resolved`; full train finite loss. |
| S2-TC08 | unit | **Repair loop detection prevents oscillation.** Symptom pair whose repairs toggle; search → detect loop, stop after bound, quarantine. | `RepairAction count ≤ max`; final `status=QUARANTINED`. |
| S2-TC09 | unit | **Deterministic split reproducibility.** Dataset ref + fixed split seed; produce train/val/test twice → identical partitions. | Split index arrays byte-identical. |
| S2-TC10 | unit | **Group-aware split prevents overlap.** Dataset with grouping_keys + repeated group ids; group-aware split → no group id in both train and test. | Intersection of train/test group-id sets empty. |
| S2-TC11 | unit | **Self-grade prohibition.** Path sets `claim_tier='novel-needs-human'` inside S2; assemble BuildResult → policy error, no tier > ran-toy. | Assembling tier>ran-toy raises PolicyError (fail-closed); emitted tier=='ran-toy'. |
| S2-TC12 | unit | **Contract minor-version tolerance.** C2 envelope with unknown additive field, compatible minor; parse → ignored, succeeds. | BuildSpec produced; unknown field absent. |
| S2-TC13 | integration | **Forward-model feature via C6 w/ uncertainty propagation.** PriorSpec(forward_model_feature) → mock C6 returns value+interval; evaluate → feature carries value + propagated uncertainty. | `FeatureNode.uncertainty_propagated=true`; output uncertainty non-null. |
| S2-TC14 | integration | **Adapter OUT_OF_DOMAIN handled.** C6 returns in_validity_domain=false for some inputs; request evals → extrapolated values flagged, dropped or marked, never silent. | Affected node `extrapolation_flag=true` or removed; recorded in Diagnostics. |
| S2-TC15 | integration | **Provenance completeness on every artifact.** Full build (splits, features, checkpoints, frozen pipeline); write each C4 → every record complete lineage. | C4 accepts all; validator finds zero INCOMPLETE_LINEAGE. |
| S2-TC16 | integration | **Frozen pipeline S3-executable & self-consistent.** Independent runner loads + predict(probe) → outputs+uncertainty, matching units + io_signature. | Independent load+predict succeeds; schema matches io_signature; units match. |
| S2-TC17 | integration | **HPO warm-start accelerates.** Prior HPOStudy as warm_start_ref vs cold under equal budget → warm ≥ cold best score. | `best(warm) ≥ best(cold)` on fixed synthetic objective/seeds. |
| S2-TC18 | integration | **Multi-objective Pareto honors success_criteria.** Trials trade score/calibration/cost, lexicographic; select final → Pareto-optimal + top by policy. | Selected trial non-dominated + ranks first under declared ordering (deterministic). |
| S2-TC19 | integration | **Checkpoint/restart resumes.** Interrupt mid-run with saved checkpoint; restart → resumes from checkpoint. | Resumed start epoch == checkpoint epoch; final matches uninterrupted within tolerance. |
| S2-TC20 | integration | **Cooperative cancel captures partial.** In-progress build; cancel(job_id) → stops within grace, partial artifact + diagnostics. | Ack; partial checkpoint + Diagnostics exist; `status=CANCELLED`. |
| S2-TC21 | e2e | **Full build on classical baseline subtopic.** C2 envelope for tabular regression w/ resolvable verifier profile; build() end-to-end → BuildResult w/ frozen_pipeline_ref, UQ, diagnostics, cost, tier=ran-toy. | BuildResult validates; `claim_tier=='ran-toy'`; frozen self-replay passed. |
| S2-TC22 | e2e | **Evolver variant build (no self-score).** Base pipeline + MutationSpec changing family; build_variant + S4 scores via stubbed signed S3 report → S2 exposes NO score; selection uses only signed report. | build_variant return has no score field; only S3-signed report drives S4. |
| S2-TC23 | e2e | **Missing verifier profile blocks execution.** C2 envelope whose verifier_profile_ref unresolvable; SpecCompiler → fail-closed before training. | build raises VERIFIER_UNAVAILABLE/POLICY; zero training artifacts. |
| S2-TC24 | physics-validation | **Injection sanity recovers known signal.** Injected amplitude A; AdvisorySelfCheck injection sanity → recovers A within tol (advisory). | `|recovered_A − A| ≤ tol`; `AdvisoryCheck(injection_sanity).status=PASS, advisory=true`. |
| S2-TC25 | physics-validation | **Null control yields no detection.** Signal-free/label-shuffled; null sanity → no significant detection. | Detection stat below threshold; `AdvisoryCheck(null_sanity).status=PASS`. |
| S2-TC26 | physics-validation | **Positivity constraint enforced.** PriorSpec(positivity, enforcement=arch) on non-negative target; predict on adversarial inputs → all ≥ 0. | `min(predictions) ≥ 0` across stress set (deterministic). |
| S2-TC27 | physics-validation | **Asymptotic-limit anchor.** PriorSpec(asymptotic_limit); evaluate near limit → approaches known value within tol. | `|prediction(limit) − known_limit| ≤ tol`. |
| S2-TC28 | physics-validation | **Unitarity penalty reduces violations.** Differentiable C6 surrogate provides unitarity measure as loss; train with vs without → penalized has fewer/no violations. | `violation_count(penalized) ≤ violation_count(unpenalized)`; ideally 0 (fixed seeds). |
| S2-TC29 | physics-validation | **Leakage smell surfaced, tier not raised.** Feature directly encodes target (perfect held-out AUC); leakage_smell → flags leakage, refuses elevation, defers to S3. | `AdvisoryCheck(leakage_smell).status=FAIL`; emitted tier=='ran-toy'; warning present. |
| S2-TC30 | security | **Egress attempt blocked and quarantined.** Build phase egress to non-allowlisted host; proxy intercepts → denied, quarantine. | Egress denied in proxy log; `status=QUARANTINED`; Sev-1 event. |
| S2-TC31 | security | **No secrets in sandbox.** Running S2 build sandbox; scan env/mounts → none. | Secret-scan zero matches; adapter creds only via brokered endpoint. |
| S2-TC32 | security | **Ledger write path not bypassable.** Attempt direct artifact-record write bypassing C4 → fails; only Rust C4 writer commits. | Direct write rejected/impossible (read-only mount); all committed records originate from C4 writer. |
| S2-TC33 | security | **Reward-source restriction (no non-C3 score).** Evolver harness offers fabricated non-signed score; build_variant → S2 ignores it. | S2 exposes no score-acceptance API; fabricated score has no effect on any S2 output. |
| S2-TC34 | perf | **HPO scales across Ray workers.** N trials, W workers; dispatch → wall-clock scales sub-linearly with W. | `wallclock(W) ≤ wallclock(1)/(0.7*W)` for fixed benchmark. |
| S2-TC35 | perf | **Build setup latency within seconds.** Resolvable C2 envelope; SpecCompile+DataManager+FeatureGraph pre-training → within interactive target. | Pre-training setup wallclock ≤ 10s on reference fixture. |
| S2-TC36 | perf | **Freeze self-replay overhead bounded.** Frozen pipeline; PipelineFreezer double self-replay → small bounded fraction. | `self_replay_time ≤ 5%` of total build wallclock. |
| S2-TC37 | integration | **Nondeterministic-kernel tolerance honored.** Model uses nondeterministic GPU kernel; replay frozen pipeline twice → within declared nondeterminism_tolerance. | `max|out1−out2| ≤ nondeterminism_tolerance`; `self_replay_passed=true`. |
| S2-TC38 | unit | **Cost-per-build reported.** Completed build; assemble BuildResult → cost_actual populated + consistent with metered spend. | `cost_actual` fields non-null == BudgetMeter totals within rounding. |
| S2-TC39 | integration | **Explainability report generated.** Completed build; `argus-s2 explain --build` → report w/ rationale, HPO trace, priors, calibration plot, repair log. | Report artifact contains all five sections. |
| S2-TC40 | unit | **Unsupported major contract version rejected.** C2 envelope incompatible major; parse → typed PERMANENT error. | build raises `{PERMANENT, VERSION_UNSUPPORTED}`; no execution. |

---

## 4. S3 — Physics Validation & Verifier Framework

The oracle. Canonicalizes & signs reports; runs injection/null/cross-code/physical-consistency/leakage/calibration gates; assigns tier (novel is candidate-only); supports deterministic challenge re-runs; never runs pipeline code in-process.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S3-TC01 | unit | **Canonicalization deterministic & order-independent.** Report with keys in two orders + equivalent numeric encodings; JCS serialize both → identical bytes + BLAKE3. | byte-equality + hash equality across the two inputs. |
| S3-TC02 | unit | **Signature verification rejects tamper.** Valid report vs copy with one metric mutated 1 ULP; verify both → valid=true then false. | boolean valid==true then valid==false. |
| S3-TC03 | unit | **Unsigned report rejected at consumption.** Report with signature removed; invoke shipped lib (Py/Rust/TS) → all reject same code. | each binding valid=false, error UNSIGNED. |
| S3-TC04 | unit | **Injection recovery PASS on faithful model.** Pipeline returns θ̂=θ_true+small noise; INJECTION (recovery_rate_min=0.9, tol_rel=0.1) → PASS. | `status==PASS` AND `metric.value≥threshold`. |
| S3-TC05 | unit | **Injection recovery FAIL on inert model.** Constant regardless of amplitude; INJECTION → FAIL. | `status==FAIL` AND `metric.value<threshold`. |
| S3-TC05b | physics-validation | **Injection amplitude linearity.** Grid of known amplitudes, linear-response ground truth; fit recovered vs injected → slope 1 within tol, intercept ~0. | fitted slope ∈ [1−tol,1+tol] AND `|intercept|<tol_abs` (deterministic seed). |
| S3-TC06 | unit | **Null control catches hallucinated signal.** Pipeline reports detections on pure noise above chance; NULL_CONTROL (α=0.01) → FAIL (FPR > binomial UB). | `status==FAIL` AND `FPR_upper>alpha`. |
| S3-TC07 | unit | **Null control PASS on well-behaved model.** No detection on signal-free input; NULL_CONTROL → PASS. | `status==PASS` AND `FPR_upper≤alpha`. |
| S3-TC08 | unit | **Label-shuffle null defeats leakage.** Pipeline succeeds only via leaked label; shuffle labels → collapse to chance → PASS on the null. | detection within chance CI; `status==PASS` on shuffled null. |
| S3-TC09 | physics-validation | **Cross-code agreement within combined uncertainty.** Pipeline forward vs independent S7 adapter over validity domain; CROSS_CODE χ²/dof → PASS when ∈[0.5,1.5] & max|z|≤z_max. | χ²/dof in band AND max|z| bound (deterministic fixtures). |
| S3-TC10 | physics-validation | **Cross-code detects single-implementation bias.** Systematic offset beyond combined uncertainty; CROSS_CODE → FAIL, elevated χ²/dof, max|z|>z_max. | `χ²/dof>high_threshold` AND `status==FAIL`. |
| S3-TC11 | unit | **Out-of-validity points excluded.** Some points extrapolation_flag=true; CROSS_CODE → excluded + counted; if excluded fraction>max → INCONCLUSIVE. | `points_excluded==count flagged`; status matches profile max-exclusion rule. |
| S3-TC12 | physics-validation | **Dimensional gate catches unit error.** Output units disagree with units_contract (energy vs energy²); dimensional sub-gate → FAIL. | units-algebra dimension vector mismatch → sub-gate FAIL. |
| S3-TC13 | physics-validation | **Positivity gate catches negative cross-section.** Negative value for declared non-negative observable; positivity sub-gate samples domain → FAIL w/ offending point. | `min output < 0` → FAIL; evidence contains offending point. |
| S3-TC14 | physics-validation | **Unitarity/normalization bound.** Probability outputs sum to 1.3; unitarity sub-gate (eps) → FAIL. | `sum>1+eps` → FAIL. |
| S3-TC15 | physics-validation | **Symmetry invariance gate.** Inputs transformed by declared symmetry g; compare f(x) vs f(g·x) → PASS iff agree within tol; FAIL for symmetry-breaking fixture. | `max|f(x)−f(g·x)|≤tol` → PASS; non-invariant fixture → FAIL. |
| S3-TC16 | physics-validation | **Asymptotic-limit gate.** Evaluate at declared limit (θ→0) with known analytic; asymptotic sub-gate → PASS iff within tol; FAIL for violating fixture. | `|f(limit)−analytic|≤tol` → PASS else FAIL (deterministic). |
| S3-TC17 | security | **Leakage: train/test overlap detected.** Declared training inputs (C4 lineage) contain near-duplicates of blind test items; MinHash/LSH → FAIL + overlap set; novelty blocked. | `overlap>threshold` → FAIL; overlapping ids in evidence. |
| S3-TC18 | security | **Leakage: frozen-index overlap blocks novelty.** Candidate "novel" matches frozen contamination index at pinned version; frozen-index vector+lexical query → FAIL, tier<novel. | `similarity≥threshold` → LEAKAGE FAIL AND final tier<novel. |
| S3-TC19 | unit | **Calibration rejects overconfident intervals.** 68% intervals contain truth 30%; CALIBRATION coverage+PIT-KS → FAIL. | coverage far below nominal, KS p<α → FAIL. |
| S3-TC20 | unit | **Calibration PASS on well-calibrated model.** 68% intervals cover ~68%; CALIBRATION → PASS. | coverage within tol band, KS p≥α → PASS. |
| S3-TC21 | unit | **Tiering monotonicity.** LEAKAGE=FAIL, all others PASS; tiering → capped at recapitulated-known (or lower), never novel. | tier≠novel when any leakage FAIL; rule_id recorded. |
| S3-TC22 | unit | **Novel is candidate-only.** All PASS, independence attested, no INCONCLUSIVE; tiering → novel-needs-human. | `tier==novel-needs-human` AND `claim_tier_is_candidate==true` AND `s3.report.candidate_novel` fired. |
| S3-TC23 | unit | **Independence unavailable caps tier.** No independent cross-code; profile requires cross-code for novel; verify → CROSS_CODE=INCONCLUSIVE, degradation INDEPENDENCE_UNAVAILABLE, tier≤recap, still signed. | tier≤recap AND degradations contains INDEPENDENCE_UNAVAILABLE AND signature valid. |
| S3-TC24 | integration | **Independence resolver rejects non-independent code.** Only other adapter shares repo/lineage with code-under-test; resolver queries C5 → NOT_INDEPENDENT, not used. | `IndependenceAttestation.verdict==NOT_INDEPENDENT`; cross_codes excludes it. |
| S3-TC25 | integration | **verify() never runs subagent code in-process.** Frozen pipeline + verify; pipeline runs only in nested S10 sandbox; verifier shows no dynamic import. | audit trace shows pipeline under sandbox pid namespace; no import event in verifier process. |
| S3-TC26 | security | **Blind labels never delivered to pipeline.** Injection dataset opaque_input+truth; runner stages inputs → only opaque_input mounted; truth never in scratch/egress. | fs+network audit inside sandbox contains no bytes matching truth payload hash. |
| S3-TC27 | security | **Sandbox write to verifier mount is Sev-1.** Malicious frozen pipeline writes verifier read-only mount → denied, halted, `s3.quarantine` Sev-1. | write returns EROFS/EPERM; `status QUARANTINED`; Sev-1 event present. |
| S3-TC28 | security | **Signing key unreachable from sandbox.** Frozen pipeline reads signer credential path → no key present, denied. | vault token/key absent from sandbox env & mounts; attempt logged and denied. |
| S3-TC29 | integration | **Reward hacking: self-reported score inadmissible.** S4 fed fabricated score not backed by signed report; S4 uses shipped lib to admit → rejected, non-improvement. | verification lib valid=false → S4 admission returns reject. |
| S3-TC30 | integration | **Fail-closed on signing unavailable.** Vault/KMS unreachable at sign step; verify → no report written, SIGNING_UNAVAILABLE (RETRYABLE), no unsigned artifact. | write-once bucket has no new object for job_id; `category==SIGNING_UNAVAILABLE`. |
| S3-TC31 | integration | **Report in write-once storage is immutable.** Signed report in write-once bucket; attempt overwrite/delete → denied. | overwrite/delete access-denied; bytes+hash unchanged. |
| S3-TC32 | e2e | **Full verify happy path → signed recapitulated-known.** Toy subtopic pipeline w/ profile (injection+null+phys+calibration) + held-out recap benchmark; S1 calls verify → signed report tier=recap + queryable C4 lineage. | signature valid AND tier==recapitulated-known AND validation_report_ref resolvable in S8 w/ intact lineage. |
| S3-TC33 | e2e | **Candidate-novel routes to human queue.** Pipeline passes all gates incl. cross-code+leakage, independence attested; verify → tier=novel(candidate), `s3.report.candidate_novel` routes to S9; no external artifact. | event on NATS subject; S3 emits no external-facing artifact (only report ref). |
| S3-TC34 | integration | **Challenge reproduces deterministic report bit-for-bit.** Prior deterministic report w/ all pins; challenge(full) re-runs → EXACT, deltas zero. | rerun canonical hash == original; `ChallengeResult.match==EXACT`. |
| S3-TC35 | integration | **Challenge tolerates declared stochastic variance.** Report w/ stochastic check + declared tolerance; challenge diff seed within policy → WITHIN_TOLERANCE, no alarm. | per-check delta≤tolerance; `alarm_raised==false`. |
| S3-TC36 | integration | **Challenge raises alarm on nondeterminism/tamper.** Inputs altered or check nondeterministic beyond tolerance; challenge → MISMATCH, `s3.canary.alarm`, original quarantined. | `match==MISMATCH` AND canary.alarm AND original flagged suspect. |
| S3-TC37 | unit | **INCONCLUSIVE counts as non-improvement for reward.** Mandatory check INCONCLUSIVE; S4 reads aggregate.score → non-improvement. | reward-selection returns non-improvement when any mandatory check INCONCLUSIVE. |
| S3-TC38 | unit | **Profile immutable per revision + pinned in report.** Report references rev N, later rev N+1 published; re-read → still N, rev N unchanged. | `report.profile_ref revision==N` and rev N spec_json byte-identical over time. |
| S3-TC39 | integration | **Profile dry-run does not sign.** Profile in authoring w/ gold + known-bad fixtures; dry-run → per-check outcomes, NO signature. | response has no signature field; gold PASS, known-bad FAIL. |
| S3-TC40 | integration | **Cost budget breach halts w/ partial capture.** Checks exceed C2 budget; verify meters + hits cap → halt, unrun checks INCONCLUSIVE, BUDGET error, partial report. | `cost_actual≥cap` AND unrun INCONCLUSIVE AND `category==BUDGET`. |
| S3-TC41 | perf | **Single profile within declared budget.** Standard profile w/ declared max_wallclock_s; verify on representative hw → p95 ≤ budget. | measured p95 ≤ `profile.cost_estimate.max_wallclock_s`. |
| S3-TC42 | perf | **Concurrency: hundreds of parallel verifies.** 300 concurrent verifies across profiles → no independence/blind-data cross-contamination; throughput scales; error<SLO. | each report's inputs match its job (hash); success≥SLO; no shared-state leaks. |
| S3-TC43 | perf | **Report lookup scales to 10^5+.** Index w/ 100k+ reports; report show/list → within target. | p95 query ≤ target with 10^5 rows (indexed). |
| S3-TC44 | security | **Egress denied from frozen-pipeline sandbox.** Frozen pipeline opens socket to non-allowlisted dest to exfil blind inputs → denied, logged. | connection refused/blocked; egress log shows denied dest; no bytes left zone. |
| S3-TC45 | unit | **Multiple-comparison correction applied.** CROSS_CODE/INJECTION w/ many points where uncorrected flips verdict; apply BH/FWER → corrected thresholds; large count alone can't manufacture PASS/FAIL. | corrected decision differs from naive per-point on crafted fixture as specified. |
| S3-TC46 | unit | **Determinism class honored in canary tolerance.** 'seeded' vs 'stochastic' check; challenge → seeded exact, stochastic tolerance. | seeded delta==0 required; stochastic uses declared tolerance band. |
| S3-TC47 | integration | **Adapter units mismatch → physics failure not silent coercion.** Cross-code adapter units differ from pipeline; CROSS_CODE aligns → UNITS_MISMATCH (C6), FAIL/INCONCLUSIVE, never coerced. | UNITS_MISMATCH present; no numeric coercion. |
| S3-TC48 | e2e | **Reward loop rejects leaked-label variant.** S4 variant scores high only via leaked label; verify full profile incl. LEAKAGE + shuffled null → FAIL/collapse, aggregate.passed=false, S4 non-improvement. | `LEAKAGE.status==FAIL` AND `aggregate.passed==false` AND S4 rejects variant. |
| S3-TC49 | unit | **Trust-store rotation: old key still verifies archived.** Report signed K1, active key rotated to K2; verify archived → K1 still valid via trust-store history. | valid==true using K1 entry; new reports use K2. |
| S3-TC50 | security | **Independence policy strict refusal.** Profile independence_policy=strict, no independent code; verify targeting novel → REFUSE that tier, offer downgraded profile. | refusal-for-tier with downgraded profile suggestion; no novel tier granted. |

**Adversarial Red-Blue Debate Evolution — S3 (verifier/referee) cases.** These exercise the current C3 bidirectional perturbation oracle (`run_perturbation_pair`, `detect_insensitivity`), challenger-independence attestation (`attest_challenger_independence`), and non-gameable-referee enforcement. A claim passes only when BOTH the must-react and must-not-react directions pass AND no insensitivity is detected.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S3-TC50-PR | unit | **C3 v1.1 schema freeze validates.** Freeze the C3 ValidationReport schema at v1.1 with the six debate fields (`perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, `debate_ref`); validate v1.0 and v1.1 example reports against it. | v1.1 schema meta-validates; every v1.1 example validates; a v1.0 report still validates (additive/backward-compatible); `semver=='1.1.0'`; a debate-tiered claim missing a required v1.1 field is rejected. |
| S3-TC51-PR | physics-validation | **Must-react proportional recovery.** Plant a KNOWN-REAL signal at a grid of amplitudes; `run_perturbation_pair(model_ref, {kind:must_react})` → the claim recovers each planted signal proportionally (amplitude-linearity), verdict PASS. | For each pair `perturbation_pairs[i].kind=='must_react'` AND `verdict=='pass'`; fitted recovered-vs-planted slope ∈ [1−tol,1+tol] AND `|intercept|<tol_abs`; a blind/insensitive model that fails to recover → `verdict=='fail'` (deterministic seed). |
| S3-TC52-PR | physics-validation | **Must-not-react rejects pure noise.** Inject null noise / shuffled labels / fake-contamination via `run_perturbation_pair(model_ref, {kind:must_not_react})` → the claim MUST NOT manufacture a signal and MUST degrade appropriately; verdict PASS on a well-behaved model, FAIL if a strong result survives unchanged. | `perturbation_pairs[j].kind=='must_not_react'`; well-behaved → `observed` degrades below threshold AND `verdict=='pass'`; strong result surviving unchanged → `verdict=='fail'` with `insensitivity_flags` populated. |
| S3-TC53-PR | physics-validation | **Insensitivity → FAIL on invariance-to-contamination.** Model whose result is INVARIANT to a contamination perturbation it should have reacted to (memorized/constant/spurious-feature); `detect_insensitivity(model_ref, perturbation_set)` → INSENSITIVITY detected → overall FAIL, never PASS. | `InsensitivityReport.insensitivity_detected==true` with `insensitivity_flags[*].reason` naming the invariant perturbation_id; resulting `ChallengeVerdict.overall=='FAIL'` AND `must_not_react_pass==false`. |
| S3-TC54-PR | integration | **Independence attestation flags correlated challengers.** Panel whose challengers share code lineage / produce correlated attacks; `attest_challenger_independence(challenger_ids[])` → lineage NOT disjoint / correlation warning raised → attestation fails, panel not certified independent. | `IndependenceAttestation.lineage_disjoint==false` OR `correlation_warning==true`; `min_independent_challengers` below K → attestation FAIL; correlated challenger_ids listed in `challenger_panel[*]` with shared `code_lineage_hash`. |
| S3-TC55-PR | security | **Referee rejects builder self-attestation.** Referee (S3) presented a ValidationReport whose `referee.referee_id` == proponent/builder id or `distinct_from_proponent==false`; adjudicate → REJECTED, no signed report emitted, non-gameable enforcement fires. | `referee.distinct_from_proponent==false` → adjudication refused; no signature written; `referee.non_gameable` enforcement error; builder-signed report never accepted as referee verdict. |

---

## 5. S4 — Recursive Improvement Loop (Evolver)

Self-improves ML pipelines **only under a cheap external verifier**. Fitness comes solely from signed C3 reports. Bounded generations/spend; leakage & reward-hacking defenses; novel routes to S9.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S4-TC01 | unit | **Precondition refuses when no verifier profile.** verifier_profile_ref resolves nothing; precondition_gate() → REFUSED VERIFIER_UNAVAILABLE, loop never entered. | `status==REFUSED`, `reason==VERIFIER_UNAVAILABLE`, mock C1.build count==0. |
| S4-TC02 | unit | **Cheap-verifier precondition fails when over budget.** single_call_cost>single_call_budget; precondition_gate() → REFUSED before dispatch. | `status==REFUSED` AND `cheap_enough==false`. |
| S4-TC03 | unit | **Independence unavailable caps tier.** C5.resolve(independence_needed) empty; proceed → max_achievable_tier=recap, INDEPENDENCE_UNAVAILABLE surfaced. | `max_achievable_tier==recapitulated-known`; novel-tier admission blocked. |
| S4-TC04 | unit | **Fitness uses only signed aggregate.score.** S2 self-score 0.99 vs signed C3 report 0.40; admit+rank → fitness 0.40. | `variant.score==0.40`; S2 self-score never read into fitness. |
| S4-TC05 | unit | **INCONCLUSIVE = non-improvement.** verify() returns INCONCLUSIVE; admit() → rejected(INCONCLUSIVE), best unchanged. | `status==rejected`, `reason==INCONCLUSIVE`, best unchanged. |
| S4-TC06 | unit | **Deterministic decision-path replay.** Identical seed pipeline, gene schema, master seed, profile/index versions + fixed signed-score sequence via stub; run twice → identical trajectories, decisions, winner hash. | byte-compare GenerationRecord sequences + winner `content_hash`. |
| S4-TC07 | unit | **Out-of-domain LLM proposal rejected before build.** Proposal sets gene outside domain / violates invariant; proposal_validation → OUT_OF_DOMAIN, never sent to S2. | proposal rejected, `reason==OUT_OF_DOMAIN`, mock C1.build not called for it. |
| S4-TC08 | unit | **Diversity guard injects on entropy drop.** Entropy below diversity_target_entropy; guard → diverse_injection_size new archive/novel variants before selection. | population size +diverse_injection_size AND post-injection entropy ≥ pre. |
| S4-TC09 | unit | **Hard max_generations termination.** max_generations=5, always-improving stub; loop → stops after exactly 5. | `generations_run==5` regardless of improvement. |
| S4-TC10 | unit | **Elitism preserves best.** elitism_k=1, best B; next generation → B carried over unchanged. | `B.content_hash` present in next population, unchanged. |
| S4-TC11 | integration | **Unsigned report rejected + quarantine.** Stub S3 returns invalid/missing signature; admit() verify → variant rejected(SIGNATURE), job QUARANTINED, Sev-1. | `evolver.job.quarantined` fired, `reason==SIGNATURE`, `status==QUARANTINED`. |
| S4-TC12 | integration | **Report-binding mismatch flags reward hack.** Signed report frozen_pipeline_ref/input_hashes differ from submitted; report-binding check → rejected(REPORT_BINDING), `reward_hack.detected`, KPI++. | `reward_hack_events_count` incremented; `evolver.reward_hack.detected` kind=report_binding. |
| S4-TC13 | integration | **Leakage FAIL blocks admission despite high score.** Signed report score=0.95 but LEAKAGE FAIL; admit() → inadmissible(LEAKAGE), not added. | `status==rejected`, `reason==LEAKAGE`, archive unchanged. |
| S4-TC14 | integration | **Budget breach halts w/ partial capture.** max_cost_usd crossed mid-gen-3; ledger detects before next dispatch → BUDGET_HALTED, best-so-far + report captured, cost recorded, no double-spend. | `status==BUDGET_HALTED`, cumulative cost within one-gen tolerance of cap, `best_validation_report_ref` present. |
| S4-TC15 | integration | **Idempotent evaluation on restart.** Variant trained+scored, host restart mid-gen; replay → not re-trained/re-scored. | C1.build count for that frozen_pipeline_ref hash == 1 across restart. |
| S4-TC16 | integration | **Durable resume reconstructs identical state.** Checkpoint at gen 4, kill; resume → population/archive/RNG/ledger/best match exactly. | restored `EvolutionCheckpoint content_hash` == persisted checkpoint hash. |
| S4-TC17 | integration | **Profile-rotation probe demotes overfit variant.** Best scores 0.9 fixed profile but 0.2 under rotated injection amplitude via S3.challenge; probe at interval → delta>tolerance, demoted, verifier_overfit flagged. | `reward_hack_events` contains kind=verifier_overfit; variant removed from best-so-far. |
| S4-TC18 | integration | **S2 build failure → −inf fitness, no infinite retrain.** S2.build returns failure; loop → marked failed, fitness −inf, bounded auto-repair only. | `status==failed`; C1.build attempts ≤ configured bound. |
| S4-TC19 | integration | **Verifier timeout = INCONCLUSIVE non-improvement.** S3.verify exceeds per_variant_verify_budget; timeout → INCONCLUSIVE, non-improvement, best unchanged. | timeout path sets `reason==INCONCLUSIVE`, best unchanged. |
| S4-TC20 | e2e | **Full recapitulation improvement run.** Real seed pipeline on recap-benchmark subtopic w/ valid cheap independent profile; run to completion → best>seed, no leakage, signed recap report, queryable genealogy. | `relative_improvement>0`, best report LEAKAGE all PASS, genealogy DAG resolves w/ no broken edges. |
| S4-TC21 | e2e | **Novel candidate routes to S9, never auto-promoted.** Best report reaches novel (leakage PASS + cross-code + independence); complete → human_review_required, `evolver.human_review.requested` w/ genealogy, NO external artifact. | `human_review_required==true`, S9 handoff fired, no publication/external artifact by S4. |
| S4-TC22 | e2e | **Pause/resume/cancel durable across restart.** Job paused, restart, resume, cancel; ops issued → state survives, resume from checkpoint, cancel captures partial. | transitions RUNNING→PAUSED→RUNNING→CANCELLED with `resumed_from_checkpoint` set + partial best. |
| S4-TC23 | physics-validation | **Injection recovery preserved by winner.** Winner's frozen pipeline + injection at A; S3 INJECTION → recovered within tol. | `INJECTION==PASS` with `|recovered−A|≤threshold` in signed report. |
| S4-TC24 | physics-validation | **Null control no detection for winner.** Signal-free/label-shuffled to winner; S3 NULL_CONTROL → no detection. | `NULL_CONTROL==PASS` (no-detection) in signed report. |
| S4-TC25 | physics-validation | **Physical-consistency holds across evolution.** Any admitted variant; S3 PHYSICAL_CONSISTENCY → all admitted pass, failing were rejected pre-admission. | every admitted variant has `PHYSICAL_CONSISTENCY==PASS`. |
| S4-TC26 | physics-validation | **Uncertainty calibration required on winner.** Winner predictions; S3 CALIBRATION coverage → pass. | `CALIBRATION==PASS`; a bare point estimate would have been rejected. |
| S4-TC27 | physics-validation | **Cross-code independence enforced for novel.** Candidate novel; inspect report → passing CROSS_CODE vs independent S7 code + independence_attestation. | `CROSS_CODE==PASS` with independent code id ≠ code-under-test AND attestation present. |
| S4-TC28 | security | **Red-team hackable-verifier stub caught pre-admission.** Leaky verifier stub awards high via leaked label (argusctl redteam); variants exploiting it → admission screens (leakage+binding+rotation) reject, counted as caught. | 100% of seeded hackable scenarios → `reward_hack.detected`; none enter population. |
| S4-TC29 | security | **Variant/LLM code cannot escape sandbox / reach reward.** Variant reads held-out / writes trust store / verifier key; executes in S10 → denied, SANDBOX Sev-1, quarantine. | sandbox violation logged, `status==QUARANTINED`, no held-out read succeeded. |
| S4-TC30 | security | **S4 holds no verifier signing key.** Audit S4 process/mounts → no key capable of signing a C3 report. | key-store scan finds no S3 signer key; attempt to sign from S4 fails. |
| S4-TC31 | security | **Egress default-deny from evolver zone.** S4 network call to non-allowlisted → blocked, logged. | egress to non-allowlisted denied; only S8/S3/S5/S2 brokered endpoints permitted. |
| S4-TC32 | security | **Budget cap not patchable from variant code.** Variant modifies budget_token/ledger in S10 → write fails, no inflation. | budget cap unchanged; write denied + logged Sev-1. |
| S4-TC33 | perf | **Hundreds of concurrent variant evaluations.** Jobs dispatch hundreds concurrent train+verify → no selection-query degradation, no state loss. | selection/archive query p95 within target AND 0 lost evaluations. |
| S4-TC34 | perf | **Archive/population scale to 10^4.** Archive of 10^4 variants; selection + novelty k-NN → latency within target. | archive query p95 < target at 10^4. |
| S4-TC35 | perf | **Control-plane ops respond in seconds.** status/pause/resume/cancel on running job → within seconds. | p95 control-op latency < a few seconds. |
| S4-TC36 | integration | **Re-run canary reproduces winner hash.** Completed run + per-gen checkpoints; S11 canary replays w/ same signed-score stream → winner hash + decision path reproduce. | replayed winner `content_hash` == original; GenerationRecords match. |
| S4-TC37 | integration | **Revoked cross-code adapter mid-run caps tier.** Independent adapter revoked via C5 during run; next gen → max tier capped recap, INDEPENDENCE_UNAVAILABLE surfaced, run continues bounded. | post-revocation max tier==recap; no novel promotion thereafter. |
| S4-TC38 | unit | **Cost-per-verified-improvement KPI computed.** Known spend + admitted-improvement count; emit KPI → cost/improvement ratio. | emitted KPI == cumulative_cost / admitted_improvement_count; 0 improvements → defined sentinel. |
| S4-TC39 | integration | **Checkpoint hash mismatch fails closed.** Corrupted checkpoint bytes ≠ content_hash; resume → HASH_MISMATCH, fallback to prior good or quarantine. | `HASH_MISMATCH` raised, no partial state loaded, fallback or QUARANTINE recorded. |
| S4-TC40 | unit | **Preflight dry-run commits no budget.** /v1/evolver/preflight → admissibility/verifier/independence/cheapness/estimated_cost w/o minting/spending token. | 0 budget_ledger entries created; no workflow started. |

**Adversarial Red-Blue Debate Evolution — S4 (evolver) cases.** These exercise the debate-round orchestrator (`run_debate_round`), independent challenger-panel selection (`select_challenger_panel`), the red-blue evolution loop under the precondition gate (`evolve_under_debate`), reward-hacking + challenger-collusion screens, and DebateLedger provenance emission via C4. Proponent = Builder subagent; challengers = ≥K independent red-team agents; referee = S3 (≠ proponent).

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S4-TC41-DB | integration | **Debate loops on FAIL then converges.** Seed candidate fails round 1 via ChallengeVerdict FAIL; structured feedback → proponent revises/retrains → next round; `evolve_under_debate` iterates → later round survives with PASS. | `ChallengeRound[0].survived==false` (referee_verdict FAIL) → feedback emitted → `ChallengeRound[n].survived==true` with `must_react_pass AND must_not_react_pass AND NOT insensitivity_detected`; rounds bounded ≤ hard cap. |
| S4-TC42-DB | unit | **Precondition gate REFUSES without a valid oracle.** Subtopic has no CHEAP VALID S3 verifier + oracle; `evolve_under_debate(seed_candidate, budget, stop_criteria)` → precondition gate refuses (recursion only under oracle), no debate round run. | `status==REFUSED`, `reason==VERIFIER_UNAVAILABLE`; `run_debate_round` call count==0; 0 budget minted. |
| S4-TC43-DB | integration | **Reward-hacking overfit-to-fixed-challenger-set caught.** Proponent overfits by exploiting a fixed challenger panel; collusion/overfit screen refreshes challenger diversity each round → overfit detected, variant not admitted. | `reward_hack_events` contains kind=challenger_overfit; panel refreshed via `select_challenger_panel` with new diversity/lineages; overfit variant removed from best-so-far. |
| S4-TC44-DB | integration | **Challenger collusion/correlation detected.** Challengers collude / are correlated (shared lineage); collusion screen + `attest_challenger_independence` → correlation warning → panel rejected, verdict not trusted. | `IndependenceAttestation.correlation_warning==true` OR `lineage_disjoint==false`; round flagged, `reward_hack_events` kind=challenger_collusion; verdict from correlated panel not admitted. |
| S4-TC45-DB | integration | **DebateLedger recorded via C4.** Completed debate over an artifact; each ChallengeRound appended to the C4 provenance DebateLedger; emitted current C3 ValidationReport carries `debate_ref`. | append-only `DebateLedger` in S8/C4 contains every `ChallengeRound.round_id` for the artifact; signed report `debate_ref` resolves to that ledger; ledger entries immutable. |
| S4-TC46-DB | integration | **Independent challenger-panel selection + diversity.** `select_challenger_panel(subtopic, k, diversity_policy)` on a healthy pool → returns ≥K lineage-disjoint challengers spanning diverse attack types and code lineages; the panel attests independent. | returned `challenger_ids` count ≥ K; `attest_challenger_independence` → `lineage_disjoint==true` AND `correlation_warning==false` AND `min_independent_challengers>=K`; attack-type/lineage diversity ≥ policy floor. |

---

## 6. S5 — Control Tower / Orchestration (总台)

Intake + guardrails, deterministic decomposition, immutable envelopes, routing (independence hard-constraint), budget governance, provenance-gated data dependencies, human-gate pausing, and recursion refusal without external verifier.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S5-TC01 | unit | **Intake rejects malformed request.** Missing required_claim_tier_max + budget_ceiling; POST /v1/requests → schema error, no RootRequest. | HTTP 400 typed error; DB query by returned handle yields no row. |
| S5-TC02 | unit | **Guardrail blocks empirical-validation objective.** objective_nl asserts "empirically confirm" a new theory; guardrail → BLOCK NO_EMPIRICAL_CLAIM/NO_AUTONOMOUS_THEORY, not RUNNING. | `guardrail_screen.passed==false` + GuardrailEvent(action=BLOCK); exact rule_id set. |
| S5-TC03 | unit | **Decomposition determinism.** Fixed request + pinned (template_lib, registry, planner_model) versions; plan twice → byte-identical preview hashes. | `content_hash(run1)==content_hash(run2)`. |
| S5-TC04 | unit | **Envelope immutable after dispatch.** Minted+dispatched envelope; mutate any field → rejected; change requires new envelope w/ new job_id + parent link. | store rejects update (IMMUTABLE_VIOLATION); new envelope `parent_job_id==old` + different immutable_hash. |
| S5-TC05 | unit | **Null verifier_profile_ref forces refusal/ran-toy.** S3 list_profiles() returns none; mint → node verifier_unavailable, tier clamped ran-toy, recursion node refused. | `verifier_available==false` + effective max tier==ran-toy; recursion accept()==false VERIFIER_UNAVAILABLE. |
| S5-TC06 | unit | **Routing prefers independence hard-constraint.** Gold non-independent vs Silver independent for cross-code parent needing independence; score → independent selected. | selected == independent candidate; `independence_satisfied==true` (deterministic weights). |
| S5-TC07 | unit | **Retry honors only RETRYABLE.** Job returns POLICY; evaluate retry → no retry, quarantine. | attempt_count stays 1; `state==QUARANTINED`; quarantine event present. |
| S5-TC08 | unit | **Refusal is not an error, re-routes.** Candidate returns Acceptance{accepted:false, OUT_OF_SCOPE}; handle → next candidate tried, not FAILED. | second dispatch recorded; `status!=FAILED`; RoutingDecision lists #1 rejected_reason. |
| S5-TC09 | unit | **Escalation on exhausted candidates.** All refuse; exhaust → S9 review REFUSAL_ESCALATION, DAG not failed. | `ReviewWaitState(REFUSAL_ESCALATION, PENDING)` exists; `argus.s5.review.opened` emitted. |
| S5-TC10 | unit | **Budget reserve/reconcile/release arithmetic.** Cap $100, reserve $30, actual $18; reserve→reconcile→release → spent==18, reserved==0, ledger consistent. | Σ ledger deltas == spent; reserved returns to 0 (exact). |
| S5-TC11 | unit | **Hard budget breach halts within one interval.** Heartbeat cost exceeds max_cost_usd; governor ticks → BUDGET halt, cooperative cancel, partial captured, QUARANTINED. | `argus.s5.budget.breach` within ≤1 metering interval; `state==QUARANTINED`; partial artifact C4 record exists. |
| S5-TC12 | integration | **Data-dependency gating on provenance commit.** B depends on A's artifact; A completes but S8 commit delayed; admit B → not admitted until is_committed. | B stays ACCEPTED-blocked until S8 confirms; `timestamp(B.admitted) > timestamp(A.commit)`. |
| S5-TC13 | integration | **Tier>ran-toy input requires signed C3 coupling.** B consumes artifact claimed recap w/o signature-valid report; gate B → blocked, flagged illegally-tiered. | gate returns ILLEGAL_TIER; B not admitted (matches C4 coupling rule). |
| S5-TC14 | integration | **Full request→run→report happy path.** Feasible request, subagents + profiles available; submit→decompose→approve→execute → all REPORTED, JobResults carry validation_report_refs, root COMPLETED. | `root_request.status==COMPLETED`; every leaf `SUCCEEDED` w/ non-null validation_report_ref. |
| S5-TC15 | integration | **Human-gate pauses & resumes.** Node produces external-candidate artifact; reaches human gate → pause at S9; APPROVED resumes; REJECTED quarantines branch. | ReviewWaitState PENDING→APPROVED→`resume_signal_sent==true`; downstream admitted only after approval. |
| S5-TC16 | integration | **Registry revocation halts in-flight job.** Running job routed to descriptor X; X revoked via C5; S5 receives event → halt + re-route or quarantine. | on revoke, job halts within SLA; re-route RoutingDecision or QUARANTINED recorded. |
| S5-TC17 | e2e | **Multi-node physics chain EWPT→GW→observable.** 3-node DATA-dependency DAG; execute → each consumes only committed upstream, terminal observable carries signed report. | lineage shows GW consumed EWPT ref + observable consumed GW ref; terminal validation_report_ref verifies. |
| S5-TC18 | e2e | **Durable restart mid-DAG w/o double-dispatch.** 5 in-flight nodes; kill+restart → Temporal replays, no double-dispatch, budget intact. | per job `dispatched_at` count==1 (idempotency key); `pool.spent` unchanged across restart (exact). |
| S5-TC19 | e2e | **DAG replay reproduces routing & structure.** Completed DAG w/ pinned revisions; audit replay re-executes decomposition+routing → topology + routing match. | `content_hash(topology_replay)==original` + identical selected_descriptor_revisions. |
| S5-TC20 | physics-validation | **Units-contract mismatch propagates as node failure.** Node adapter reports UNITS_MISMATCH between produced/consumed units; process → non-retryable fail, downstream blocked. | maps to PERMANENT; `state==FAILED`; downstream not admitted. |
| S5-TC21 | physics-validation | **Recursion refuses without external verifier.** S4 recursion target has no S3 profile; POST /v1/recursion → refused, verifier_precondition_ok==false, 0 generations. | `accepted==false`, reason==VERIFIER_UNAVAILABLE; `generations_run==0`. |
| S5-TC22 | physics-validation | **Recursion halts at max-gen & max-spend.** max_generations=10, low max_spend hit at gen 6; loop → stops at first bound, records stop_reason. | `generations_run==6` AND `stop_reason==MAX_SPEND`; spend≤max_spend. |
| S5-TC23 | security | **Reward only from signed C3 report.** Recursion score self-reported (no signature-valid report); governor evaluates → inadmissible, non-improvement. | unsigned score rejected; generation counted no-improvement; policy violation logged. |
| S5-TC24 | security | **S5 mints least-privilege scopes only.** Job needs adapters {A1}, datasets {D1}; mint scopes+token → access only A1/D1, metered, no secrets. | `capability_scopes == {A1,D1}`; token no secret material; use for A2 denied. |
| S5-TC25 | security | **Federated subagent gains no elevated trust.** Federated subagent passes Gold; router selects+dispatches → no elevated scopes, still S10 untrusted zone. | federated scopes == same policy template as internal; no extra grant flags. |
| S5-TC26 | security | **Guardrail blocks autonomous paper submission.** Node disallowed_actions violated by external paper submission; request → hard-blocked NO_AUTO_PAPER_SUBMIT, quarantined. | `GuardrailEvent(NO_AUTO_PAPER_SUBMIT, BLOCK)` exists; no external emission. |
| S5-TC27 | security | **Unsigned/tampered RoutingDecision rejected on read.** RoutingDecision signature fails; audit/gate reads → rejected as tampered, job flagged. | signature verify fails → tamper error; job flagged non-promotable. |
| S5-TC28 | perf | **Interactive planning latency.** Typical request, nominal load; POST plan → preview within budget. | plan p95 ≤ budget (e.g. <5s) over 100 runs. |
| S5-TC29 | perf | **Hundreds of concurrent jobs w/o state-query degradation.** 300 concurrent + 3000 queued; state/audit queries → within SLA, no starvation. | state-query p95 ≤ SLA; scheduler admits per caps, no class starved beyond fairness. |
| S5-TC30 | perf | **Budget metering tick latency under load.** 200 active jobs heartbeating; governor ticks → breach detection within one interval. | `max(breach_detection_latency) ≤ metering_interval`. |
| S5-TC31 | integration | **Back-pressure near S9 capacity.** S9 queue near threshold; new requests + ready review-nodes → Intake 429 THROTTLED, review-nodes deferred. | `argus.s5.backpressure{active:true}`; POST returns 429 retry_after; non-review nodes still progress. |
| S5-TC32 | integration | **Partial DAG failure isolates branches.** One branch fails permanently, independent succeeds; complete → failed quarantined, DAG PARTIAL w/ failure report, good branch normal. | `root_request.status==PARTIAL`; failed nodes QUARANTINED; independent leaf SUCCEEDED. |
| S5-TC33 | integration | **S8 commit failure fails closed.** S8 commit errors for A's output; gate B → not admitted, DAG pauses durably, no silent progress. | B never ACCEPTED; paused state persisted; on S8 recovery resumes deterministically. |
| S5-TC34 | unit | **C2 minor-version forward compat.** Envelope w/ unknown additive field, compatible minor; parse → ignored, accepted. | parse succeeds; known fields intact; unknown ignored per policy. |
| S5-TC35 | unit | **Deadline-aware scheduling escalates.** Job w/ approaching deadline under contention; admit → prioritized over lower-priority non-deadline. | admission order places deadline job ahead once slack<threshold (deterministic clock). |
| S5-TC36 | integration | **Cancellation propagates cooperatively.** Running DAG w/ active jobs; POST cancel → C1 cancel each, reservations released, states CANCELLED. | each active job receives cancel; `pool.reserved==0`; node states==CANCELLED. |
| S5-TC37 | integration | **Stalled subagent detected via heartbeat gap.** Subagent stops heartbeats past liveness window; monitor → stalled, retry (if RETRYABLE) or quarantine, reservation released. | on gap>window → stalled→(retry|QUARANTINED); reservation delta released. |
| S5-TC38 | e2e | **Cost-per-verified-artifact KPI computed.** Completed request → 2 verified artifacts at known cost; KPI query → total reconciled spend / signed-verified count. | KPI == Σ reconciled / verified_count (exact within rounding). |

---

## 7. S6 — Knowledge & Ingestion

Ingests literature/data with dedup, equation-preserving chunking, hybrid retrieval, frozen contamination indices, immutable registry revisions, and independence-by-lineage resolution.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S6-TC01 | unit | **Exact dedup on re-ingest.** Record already ingested w/ hash H; re-fetched in incremental sync → no new normalization/embedding, no dup C4. | artifact count unchanged; job reports skipped=1, indexed=0. |
| S6-TC02 | unit | **Cursor advances only on commit.** Sync fails after fetch batch N before commit; retry → resumes pre-batch-N, idempotent. | persisted cursor == pre-failure; after retry all records present exactly once. |
| S6-TC03 | unit | **Equation-preserving chunking.** NormalizedDoc w/ multi-line equation; chunk → no chunk splits equation. | every equation char_span fully within one chunk char_span. |
| S6-TC04 | unit | **Embedding model version pinned per chunk.** Chunks under v1, swap v2 + reindex → v1 in docs-v1 alias, v2 in docs-v2, no mixed index. | every `chunk.embed_model_version` matches index alias suffix; zero mismatches. |
| S6-TC05 | unit | **RRF fusion determinism.** Fixed lexical + dense lists; RRF k=60 → matches precomputed ranking. | output == golden fixture exactly. |
| S6-TC06 | unit | **Independence exclusion by lineage.** Candidate is fork (derived_from) of X for observable O; resolve_independent_code(O,X) → excluded. | result excludes any entity whose lineage closure intersects X's; candidate absent. |
| S6-TC07 | unit | **Publish refused w/o conformance.** Descriptor claims Gold w/ no/expired evidence; publish() → CONFORMANCE_MISSING/EXPIRED, nothing stored. | error CONFORMANCE_MISSING or _EXPIRED; revision count unchanged. |
| S6-TC08 | unit | **Descriptor revisions append-only immutable.** Existing revision r; new publish → r+1, r unchanged + retrievable. | `get_descriptor(entity,r)` byte-identical before/after; current == r+1. |
| S6-TC09 | unit | **Novelty score calibration coverage.** Labeled memorized/novel set; compute calibrated_novelty_prob → well-calibrated. | reliability ECE < 0.05; band coverage within nominal ±2%. |
| S6-TC10 | unit | **Snapshot manifest self-hash.** Newly frozen index; write manifest → manifest_hash == BLAKE3 of canonical body. | recomputed hash == stored; signature verifies. |
| S6-TC11 | integration | **End-to-end arXiv ingest to retrieval.** Fixture arXiv OAI batch of 10 LaTeX; incremental sync then retrieve(matching query) → match retrievable w/ correct CitationProvenance. | top-1 doc_id == expected; `external_source_ref.id == arXiv id`; snapshot/source populated. |
| S6-TC12 | integration | **HEPData table units preserved.** HEPData cross-section table in pb; ingest+query → units==pb, uncertainties parsed. | `columns[*].units=='pb'`; uncertainty ± == fixture. |
| S6-TC13 | integration | **Frozen vs live novelty divergence.** Doc D indexed into live AFTER frozen v; novelty_query(D, v) vs (D, live) → v high novelty (absent), live low (present). | `novelty_prob(v)>0.9` AND `novelty_prob(live)<0.1`. |
| S6-TC14 | integration | **Revocation halts resolve.** Entity resolvable; revoke(entity) then resolve → no longer appears, revoked event emitted. | resolve excludes entity; `s6.registry.revoked` observed; direct get returns status=revoked. |
| S6-TC15 | integration | **Reindex rebuilds from C4.** Populated live index + C4 artifacts, OpenSearch dropped; reindex(embed_model_version) → identical doc set. | rebuilt doc_count == original; content_hash set identical; sample retrieval parity. |
| S6-TC15b | integration | **Registry resolve pins reproducible revision.** Multiple revisions; resolve returns one, S5 pins, newer published → pinned still resolves identically. | `get_descriptor(entity, pinned_seq)` byte-identical after newer publish. |
| S6-TC16 | e2e | **Grounded planning reduces wrong outputs.** Fixed subtopic eval, RAG-grounded vs un-grounded; apply S3 physical-consistency → grounded materially lower failure. | relative reduction in PHYSICAL_CONSISTENCY FAIL ≥ 30% with p<0.05 (bootstrap CI). |
| S6-TC17 | e2e | **Novelty cutoff drives S3 leakage gate.** Candidate "novel" actually paraphrase in frozen v; S3 LEAKAGE via novelty_query(v) → flagged memorized, tier capped. | `max_overlap_score` above gate threshold; S3 does not promote to novel. |
| S6-TC18 | physics-validation | **Unit-annotation correctness.** Gold quantities w/ known dimensions (Ω_GW dimensionless, cross-section barn); tagger → matches gold. | dimension-match accuracy ≥ 0.95; dimensionless-vs-dimensional confusions == 0 on reserved subset. |
| S6-TC19 | physics-validation | **Curated unit-conventions consistency.** get_unit_conventions('ewpt'); check vs C6 units contract → dimensionally consistent, vetted sources. | all validate against C6 dimensions; every convention ≥1 curated CitationProvenance. |
| S6-TC19b | physics-validation | **Cross-code independence genuinely independent.** Two adapters flagged independent for O; audit lineage + tags → share no implementation lineage. | lineage closure intersection empty AND no shared implementation-marker tag. |
| S6-TC20 | security | **Egress outside allowlist blocked.** Malicious connector reaches non-allowlisted host in S10 → blocked, quarantine. | proxy denies; `status QUARANTINED` POLICY; audit event recorded. |
| S6-TC21 | security | **Agent cannot write the index.** Subagent-scoped token calls write/admin (publish/freeze/curate/reindex) → denied. | AuthZ PERMISSION_DENIED; no state change; audit entry. |
| S6-TC22 | security | **Frozen index immutability.** Frozen v; any add/modify/delete → rejected fail-closed. | write errors IMMUTABLE_VIOLATION; manifest hash unchanged. |
| S6-TC23 | security | **Signature verification on registry publish.** Descriptor w/ invalid/unknown signer; publish() → rejected. | signature verify fails → error; entity not created. |
| S6-TC24 | security | **Tampered snapshot detected.** Frozen index manifest bytes altered; novelty_query reads → integrity fails, query blocked. | manifest_hash mismatch → fail-closed; version marked compromised; alert. |
| S6-TC25 | security | **License-gated full-text not leaked.** Non-redistributable doc, restricted access_scope; retrieve() lacks scope → full text withheld (citation only). | response omits restricted chunk text; citation metadata only; denial audited. |
| S6-TC26 | perf | **Resolve latency.** 10^5 descriptor revisions; resolve() under load → p99 < 150ms. | measured p99 over 10k queries < 150ms. |
| S6-TC27 | perf | **Hybrid retrieval latency.** 10^8 chunks; retrieve(top_k=20, rerank) → p95 < 800ms. | measured p95 over 10k queries < 800ms. |
| S6-TC28 | perf | **Ingest throughput.** Backfill 10^5 docs at target parallelism → meets target, dedup near-zero re-run cost. | ≥ target docs/hour; second full run indexes 0 new (100% dedup). |
| S6-TC29 | perf | **Novelty query latency.** Frozen index 10^7 docs; novelty_query (ngram+simhash+minhash+embed) → within budget. | measured p95 < budget (e.g. 1.5s). |
| S6-TC30 | integration | **Degraded retrieval flag.** Embedding service down; retrieve() → BM25-only, degraded:true. | `degraded==true`; results present; no vector field errors surfaced. |
| S6-TC31 | integration | **Quarantine on normalization failure.** Malformed PDF fails parse; ingest → quarantined, raw retained, not indexed. | `status==quarantined`; raw C4 exists; zero chunks; `s6.ingest.doc_quarantined`. |
| S6-TC32 | integration | **Citation graph edges built.** A cites B (both ingested); normalization → cites-edge A→B queryable. | recursive-CTE returns B among A's references; edge count == fixture. |
| S6-TC33 | unit | **Near-duplicate linked, re-embed skipped.** Near-dup (SimHash within threshold) of indexed doc; ingest → linked near_dup_of, re-embed skipped. | `near_dup_of` set; embedding-call counter not incremented for near-dup. |
| S6-TC34 | integration | **Reproducible retrieval manifest.** Same query+filters+index_version+pinned models twice → identical results + retrieval_manifest_hash. | ordered hit ids equal AND `retrieval_manifest_hash` equal. |
| S6-TC35 | e2e | **Freeze creates pinnable version consumed by C2.** Live index; freeze() then S5 pins new contamination_index_version into envelope → downstream novelty uses pinned version. | `s6.index.frozen`; C2 `contamination_index_version==new`; novelty_query w/ version succeeds against manifest. |

---

## 8. S7 — Physics Compute Adapters

Standardized C6 adapters: hard units enforcement, mandatory uncertainty, validity-domain flags, deterministic seeding, gradients where declared, per-call provenance, cost-class ceilings, and machine-verified independence.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S7-TC01 | unit | **Units mismatch is a hard error.** Input T_n expects GeV, given in seconds; evaluate → UNITS_MISMATCH, non-retryable, no output. | `error.category=='UNITS_MISMATCH'` and no EvalResult. |
| S7-TC02 | unit | **Units normalized, not coerced silently.** alpha dimensionless + T_n in TeV (canonical GeV); evaluate → T_n→GeV (×1000), pins unit-registry version. | canonical == input×1000 within 1e-12; `unit_registry_version` present. |
| S7-TC03 | unit | **Missing uncertainty rejected.** Buggy adapter returns null uncertainty; broker post-processes → non-conformance error before caller. | broker raises conformance error; EvalResult never returned w/ uncertainty==null. |
| S7-TC04 | unit | **Validity-domain box flag.** gw_spectrum_surrogate box v_w∈[0.4,0.95]; evaluate v_w=1.2 → in_validity_domain=false, extrapolation_flag=true, violated_fields=['v_w']. | flags + violated_fields asserted exactly. |
| S7-TC05 | unit | **Validity-domain refuse policy.** Adapter domain policy 'refuse'; out of domain → OUT_OF_DOMAIN, non-retryable. | `error.category=='OUT_OF_DOMAIN'`. |
| S7-TC06 | unit | **Deterministic seed derivation.** Fixed job_seed, dag_node_id, call_index, adapter_id; derive twice → identical seed. | seed1==seed2 (byte-equal). |
| S7-TC07 | unit | **grad on non-differentiable adapter.** eff_potential_bounce differentiable:false; grad → NOT_DIFFERENTIABLE. | `error.category=='NOT_DIFFERENTIABLE'`. |
| S7-TC08 | unit | **Jacobian entry units derived.** Output Omega_h2 (dimensionless) wrt T_n (GeV); grad → entry_units == '1/GeV'. | string equality after Pint simplification. |
| S7-TC09 | unit | **Cost-class ceiling rejects heavy adapter.** Descriptor cost_class='heavy' exceeding ceiling; register → COST_CLASS_EXCEEDED, nothing published. | registration COST_CLASS_EXCEEDED; no new revision. |
| S7-TC10 | unit | **Deterministic adapter reproducibility.** Deterministic adapter, identical (inputs, seed); evaluate twice → byte-identical outputs + provenance hashes. | `BLAKE3(out1)==BLAKE3(out2)`. |
| S7-TC11 | unit | **Determinism violation alarms.** Deterministic-declared adapter returns differing outputs (fault injected); conformance re-check → quarantined, excluded from resolve. | registry status→quarantined; resolve() omits it. |
| S7-TC12 | integration | **Cache hit avoids recompute.** Deterministic adapter evaluated once; identical call → cache_hit=true, cpu_s≈0, output equal, fresh provenance edge marks hit. | `cache_hit==true` + cpu_s<epsilon; `derived_from` includes cache_key. |
| S7-TC13 | integration | **Stochastic-unseeded not cached.** Stochastic adapter, no seed; evaluate twice → cache_hit=false both, distinct outputs allowed. | both `cache_hit==false`. |
| S7-TC14 | integration | **Provenance written per call.** Any successful evaluate → C4 record pinning adapter_version, underlying_code_version, seed, container_digest, input hashes. | S8 lineage by provenance_ref returns complete record, all fields non-null. |
| S7-TC15 | integration | **Provenance failure is fail-closed.** S8 writer unavailable; evaluate completes compute → PROVENANCE_UNAVAILABLE, result not trusted. | `error.category=='PROVENANCE_UNAVAILABLE'`; no trusted EvalResult w/ provenance_ref. |
| S7-TC15b | integration | **Registered descriptor resolvable via C5.** Conformant adapter registered; C5 resolve(observable) → adapter revision w/ correct independence_tags + cost_class. | resolve() returns revision_ref matching registered adapter. |
| S7-TC16 | integration | **Budget breach halts precisely.** Token allows N units, batch requires >N; BatchEvaluate → halt at N, BUDGET, completed elements + partial provenance. | `n_ok*unit_cost ≤ budget`; item N+1 `category=='BUDGET'`. |
| S7-TC17 | integration | **Subprocess binary error captured.** eff_potential_bounce params cause nonzero exit; evaluate → UNDERLYING_CODE_ERROR w/ stderr_ref. | `category=='UNDERLYING_CODE_ERROR'`; stderr artifact retrievable. |
| S7-TC18 | integration | **Timeout enforced.** Backend sleeps beyond max_wallclock_s; evaluate → TIMEOUT, partial provenance. | `category=='TIMEOUT'` within max_wallclock_s + grace. |
| S7-TC19 | integration | **Backend bulkheading.** Adapter A crash-loops, B healthy; concurrent calls → A circuit-opens BACKEND_UNAVAILABLE, B unaffected. | B success ~100% during A outage; A circuit=='open'. |
| S7-TC20 | integration | **Version compatibility.** Broker C6 v1.3, request valid under v1.1 (minor); evaluate → accepted. | result returned, no VERSION_UNSUPPORTED. |
| S7-TC21 | integration | **Unsupported major version rejected.** Broker v1.x, request v2.0; evaluate → VERSION_UNSUPPORTED. | `category=='VERSION_UNSUPPORTED'`. |
| S7-TC22 | e2e | **S2 differentiable fit loop.** gw_spectrum_surrogate + target spectrum; S2 iterates evaluate+grad to fit (alpha,beta/H,T_n,v_w) → converges within surrogate uncertainty, all calls have provenance. | final residual < tolerance; all provenance_refs resolvable. |
| S7-TC23 | e2e | **S3 cross-code consistency via independent adapters.** gw_spectrum + independent gw_spectrum_alt (disjoint tags); S3 resolves pair + evaluates identical inputs → not sharing repo, outputs agree within combined uncertainty. | resolve independence: repos differ; `|Ω1−Ω2| ≤ k·√(σ1²+σ2²)`. |
| S7-TC24 | physics-validation | **GW spectrum peak scaling with beta/H.** Increase beta/H holding others → peak frequency shifts, amplitude scales monotonically per template physics. | peak-frequency + amplitude trends match analytic template within tolerance. |
| S7-TC25 | physics-validation | **Dimensional consistency of outputs.** Any reference adapter; evaluate → every output unit matches declared dimension (Omega_h2 dimensionless, f in Hz). | Pint dimensionality == declared for every output field. |
| S7-TC26 | physics-validation | **Positivity of energy-density spectrum.** gw_spectrum over validity domain; sample → Omega_GW(f) ≥ 0 everywhere. | min over samples ≥ 0 (within numerical tol). |
| S7-TC27 | physics-validation | **Asymptotic limit recovery.** eff_potential_bounce thin-wall limit → bounce action approaches analytic thin-wall. | `|S_numeric − S_thinwall|/S_thinwall < tol`. |
| S7-TC28 | physics-validation | **Surrogate matches full solver in-domain.** gw_spectrum_surrogate vs gw_spectrum (full) on in-domain grid → within stated uncertainty. | coverage of full-solver value inside surrogate interval ≥ nominal (e.g. ≥90% at 90%). |
| S7-TC29 | physics-validation | **Calibration coverage test.** Emulator w/ declared 90% intervals + held-out set; calibrate → empirical coverage within tol of 90%. | `|coverage − 0.90| ≤ tol`; `CalibrationEvidence.passed==true`. |
| S7-TC30 | security | **No secrets in EvalRequest reach adapter.** Broker mints per-job scoped tokens; adapter reads secret/credential → none present. | static+runtime: adapter env contains no vault/KMS material. |
| S7-TC31 | security | **Subprocess backend egress denied.** Binary attempts outbound connection under S10 → blocked default-deny, logged. | network attempt logged+denied; no external connection succeeds. |
| S7-TC32 | security | **Adapter cannot write outside scratch.** Backend writes read-only mount (harness path) → denied, job intact, logged. | write returns EROFS/permission error; harness path unchanged. |
| S7-TC33 | security | **mTLS + scope enforcement.** Caller lacks adapter-invoke scope; evaluate → denied before execution. | gRPC PERMISSION_DENIED; no backend invoked. |
| S7-TC34 | security | **Tampered descriptor rejected.** AdapterDescriptor signature fails; register/resolve → rejected. | signature verify fails → rejected. |
| S7-TC35 | perf | **Surrogate evaluate latency.** gw_spectrum_surrogate (JAX jitted), warm jit; single evaluate → within typical_wallclock (sub-second). | p50 latency ≤ declared typical_wallclock_s. |
| S7-TC36 | perf | **Batch vmap speedup.** Batch of 1000 via vmap vs 1000 serial → batch substantially less. | batch_wallclock < 0.2 × serial_sum. |
| S7-TC37 | perf | **Concurrency scaling.** Horizontal worker pool; 200 concurrent evaluate → throughput scales ~linearly to saturation, no cross-adapter starvation. | p99 within SLO at 200 concurrency; no dropped calls. |
| S7-TC38 | unit | **Log-space field handling.** Input log10_beta_over_H (log_space:true); evaluate → backend receives delinearized physical value, output units correct. | backend-received beta/H == 10**input within 1e-9. |
| S7-TC39 | integration | **Extrapolated output → INCONCLUSIVE by verifier profile.** extrapolation_flag:true result to S3 CROSS_CODE → INCONCLUSIVE unless profile allows extrapolation. | `CheckResult.status=='INCONCLUSIVE'` for extrapolated input under default profile. |
| S7-TC40 | integration | **Revocation halts in-flight references.** Adapter revoked mid-flight; job holds ref → new calls REVOKED, in-flight completes/halts per policy + logged. | post-revoke evaluate returns REVOKED; registry status=='revoked'. |
| S7-TC41 | unit | **Batch partial failure isolation.** Batch element 3 has UNITS_MISMATCH; BatchEvaluate → others succeed, element 3 error envelope, batch not failed. | `results[2].category=='UNITS_MISMATCH'`; n_ok==len−1. |
| S7-TC42 | physics-validation | **Independence is genuine (not shared code).** Claimed independent pair for O; independence check → no shared repo, underlying_code_version, or overlapping family tags. | disjoint repo AND underlying_code_version; family-tag overlap == empty. |

---

## 9. S8 — Data, Artifact & Provenance

The ledger. Content-addressed dedup, canonical record hashing, lineage graph (no cycles, complete lineage), tier-report coupling, write-once immutability, verify-on-read tamper detection, blind-split isolation, Merkle checkpoints, and GC that never touches promoted lineage.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S8-TC01 | unit | **BLAKE3 blob hash determinism.** Fixed blob B; HashBlob on Rust/Python/TS → identical content_hash + size_bytes. | string equality across all three vs precomputed vector. |
| S8-TC02 | unit | **Canonical record hashing ignores order & whitespace.** Two logically-identical records diff key order/whitespace → same hash. | hash equality; inequality when a semantic field changes. |
| S8-TC03 | unit | **Volatile fields excluded from hash.** Re-hash after mutating created_at/signature only → equal. | equality assertion. |
| S8-TC04 | unit | **Content-addressed dedup.** Two CreateArtifact identical bytes, diff records; both commit → one object, two records. | object count==1; record count==2. |
| S8-TC05 | unit | **Streaming hash == whole-blob.** 500MB blob multipart streaming vs single-pass → match. | equality of content_hash. |
| S8-TC06 | unit | **Cycle rejection.** A→B edges then B→A; commit B→A → CYCLE_DETECTED, no commit. | `category==CYCLE_DETECTED`; edge count unchanged. |
| S8-TC07 | unit | **Incomplete lineage rejected.** Model record missing environment_digest; CreateArtifact → INCOMPLETE_LINEAGE. | `category==INCOMPLETE_LINEAGE`; record absent. |
| S8-TC08 | integration | **Tier promotion requires valid signed report.** Record recap w/ signature-valid matching C3 report ref; CreateArtifact → commits. | record present w/ matching validation_report_ref; `VerifySignature.valid==true`. |
| S8-TC09 | security | **Tier without report rejected.** Record novel w/ no validation_report_ref; CreateArtifact → ILLEGAL_TIER. | `category==ILLEGAL_TIER`; record absent. |
| S8-TC10 | security | **Tier mismatch vs report rejected.** Record novel referencing report tier=recap; CreateArtifact → ILLEGAL_TIER. | `category==ILLEGAL_TIER`. |
| S8-TC11 | security | **Report signed by unknown/revoked key rejected.** Report signed w/ key not in trust store; CreateArtifact(report) or VerifySignature → SIGNATURE_INVALID. | `category==SIGNATURE_INVALID`; not servable as tier-bearing. |
| S8-TC12 | security | **Novel tier requires leakage PASS + cross-code.** Novel report w/ leakage FAIL; commit at novel → ILLEGAL_TIER. | `category==ILLEGAL_TIER`. |
| S8-TC13 | security | **Write-once overwrite blocked.** Committed report blob in write-once bucket; PUT same key diff bytes → IMMUTABLE_VIOLATION. | Object-Lock rejects; `category==IMMUTABLE_VIOLATION`; original intact. |
| S8-TC14 | security | **Verify-on-read tamper detection.** Stored bytes corrupted out-of-band; GetArtifact(materialize) → refused, quarantined, ARTIFACT_TAMPER. | `category==HASH_MISMATCH`; `artifact.tamper_detected`; status==quarantined. |
| S8-TC15 | security | **Agent scope cannot write ledger directly.** Agent-zone token attempts direct DB write / non-brokered commit → denied. | DB grant denies; API SCOPE_DENIED; no row inserted. |
| S8-TC16 | security | **Blind split label materialization denied to non-verifier.** Blind split + non-verifier token; ResolveSplit → SCOPE_DENIED. | `category==SCOPE_DENIED`; no label bytes. |
| S8-TC17 | integration | **Verifier scope can resolve blind split.** Same split + verifier token; ResolveSplit → sealed label blob ref. | blob_ref returned + resolvable; audit event recorded. |
| S8-TC18 | integration | **Impact-set on retracted external source.** Source X → dataset D → models M1,M2; QueryImpactSet(X) → {D,M1,M2} w/ tiers + report refs. | set equality w/ expected transitive descendants; each has claim_tier + validation_report_ref. |
| S8-TC19 | integration | **Contamination-trace matches closure + CTE.** 10^4-node graph; impact via closure table vs recursive CTE → identical. | set equality between the two paths. |
| S8-TC20 | integration | **Idempotent commit.** CreateArtifact twice same content_hash + record; second → same ArtifactRef, no dup. | equal artifact_id; record count==1. |
| S8-TC21 | integration | **Crash mid-commit leaves no partial state.** Interrupted after blob put before record insert; recover + retry → no committed record from failed attempt, retry idempotent, orphan blob GC-eligible. | record absent after crash; present after retry; GC dry-run lists orphan. |
| S8-TC22 | integration | **Merkle checkpoint inclusion proof.** N records + signed checkpoint; ExportAuditSlice subset → inclusion proofs verify. | proof verification true; checkpoint signature verifies vs S8 ledger key. |
| S8-TC23 | security | **Ledger tamper detected by checkpoint mismatch.** Committed record hash altered out-of-band; checkpoint recompute → mismatch, writes frozen, Sev-1. | recomputed root ≠ stored signed root; alarm fired. |
| S8-TC24 | integration | **Hold blocks GC.** Unreferenced scratch blob under active hold; RunGC(dry_run=false) → not deleted, listed blocked_by_hold. | object present; report shows blocked_by_hold. |
| S8-TC25 | integration | **GC never deletes reachable-from-promoted.** Scratch intermediate referenced by promoted model lineage; RunGC → retained. | object present post-GC; not in swept list. |
| S8-TC26 | integration | **GC collects true orphans.** Scratch blob no refs/holds; RunGC(dry_run=false) after quorum → deleted, ledger untouched. | object absent; record/edge tables unchanged; `gc.swept` emitted. |
| S8-TC27 | unit | **Schema minor-additive compat.** Unknown additive field, compatible minor; CreateArtifact → accepted, ignored/preserved. | commit succeeds; round-trip preserves semantics. |
| S8-TC28 | unit | **Schema major incompatibility rejected.** Unsupported major outside migration window; CreateArtifact → VERSION_UNSUPPORTED. | `category==VERSION_UNSUPPORTED`. |
| S8-TC29 | unit | **Binding generation byte-stable.** Fixed C4 schema; GenerateBindings(py/ts/rust) twice → byte-identical. | hash equality across runs. |
| S8-TC30 | e2e | **Full artifact lifecycle.** Subagent job dataset→model→report; write all three + promote model w/ report → lineage links, manifest re-derivable, tier coupled. | GetLineage(model) shows dataset+report edges; AssertLineageComplete==true; tier==report tier. |
| S8-TC31 | physics-validation | **Re-derivation within nondeterminism tolerance.** Model w/ declared statistical tolerance + manifest; S11 re-runs, RecordReproducibilityCheck w/ rerun hash differing within tol → PASS annotation, original unchanged. | `verdict==PASS`; original content_hash + record bytes unchanged. |
| S8-TC32 | physics-validation | **Re-derivation outside tolerance fails.** Rerun beyond tolerance; RecordReproducibilityCheck → FAIL, flagged non-reproducible. | `verdict==FAIL`; `artifact.flagged`; non-promotable. |
| S8-TC33 | physics-validation | **Uncertainty tag required on predictive artifacts.** Model lacking uncertainty_tag; promotion gate → non-promotable. | AssertLineageComplete flags missing uncertainty_tag for predictive kind; promotion denied. |
| S8-TC34 | perf | **Impact-set at scale.** 10^5-node graph; QueryImpactSet mid-graph seed → within SLO. | p95 < 2s over 100 runs; result == CTE ground truth. |
| S8-TC35 | perf | **Metadata read latency.** 10^5 records; GetArtifactRecord by content_hash → fast. | p95 < 50ms over 1000 runs. |
| S8-TC36 | perf | **Write throughput / commit latency.** Sustained CreateArtifact <100MB objects; commit (excl upload) → meets latency. | p95 commit < 300ms; no fail-closed rejections under nominal load. |
| S8-TC37 | integration | **External-source immutability.** Registered ExternalSourceRef; re-register same source_id diff snapshot_hash → IMMUTABLE_VIOLATION. | `category==IMMUTABLE_VIOLATION`; original preserved. |
| S8-TC38 | integration | **Event idempotency.** At-least-once duplicate artifact.created event; consumer processes both → single logical effect. | consumer keyed by content_hash produces one record of effect. |
| S8-TC39 | security | **mTLS + scope required on all APIs.** Call w/o valid cert or required scope; any S8 API → rejected. | TLS handshake fails or SCOPE_DENIED; no side effects. |
| S8-TC40 | unit | **Retention cannot weaken write-once.** Write-once artifact; SetRetentionPolicy tries to shorten below minimum → rejected. | policy unchanged; error; object-lock retention not reduced. |
| S8-TC41 | e2e | **Retraction cascade re-review.** Promoted novel candidate whose upstream source later retracted; QueryImpactSet + flag → candidate flagged for S9 re-review, downstream notified. | `artifact.flagged` for candidate; impact set includes candidate; S9 review event created. |
| S8-TC42 | integration | **Closure reconciliation detects drift.** Artificially corrupted lineage_closure row; reconciliation → drift detected, closure rebuilt. | reconciler flags discrepancy vs CTE; post-rebuild sets match. |

---

## 10. S9 — Human-in-the-loop Review & Governance

The mandatory human gate. Signature/hash pre-screen, guardrail hard-blocks (non-goals), novelty gate (leakage+cross-code), distinct-principal dual sign-off, COI recusal, HSM-signed single-use emission authorizations, append-only tamper-evident ledger.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S9-TC01 | unit | **Intake rejects invalid report signature.** C3 report signature fails vs trust store; pre-screen → QUARANTINED, never QUEUED, Sev alert. | `state==QUARANTINED` AND no QUEUED task_created AND SIGNATURE_INVALID in ledger. |
| S9-TC02 | unit | **Intake rejects content-hash mismatch.** Report references C4 artifact whose bytes hash ≠ declared; verify → QUARANTINED HASH_MISMATCH. | `quarantine_reason` contains HASH_MISMATCH AND state==QUARANTINED. |
| S9-TC03 | unit | **Guardrail hard-block on non-goal emission class.** emission_class=autonomous-paper-submission; evaluate → BLOCK, hard_block=true, no override. | `hard_block==true` AND authorize-emission returns GUARDRAIL_BLOCK for every role. |
| S9-TC04 | unit | **Novelty gate requires leakage PASS + cross-code PASS.** Novel w/ LEAKAGE FAIL; reviewer APPROVE → blocked novelty-gate, no emission. | signoff NOT_ELIGIBLE/novelty-gate AND task cannot reach EMISSION_AUTHORIZED. |
| S9-TC05 | unit | **Distinct-principal dual sign-off.** Novel needs domain+ml; same principal both → second rejected non-distinct. | second signoff NOT_ELIGIBLE(distinct-principal) AND required_signoffs unmet. |
| S9-TC06 | unit | **COI auto-recusal.** Reviewer R active COI on subtopic S; task in S; R in pool + signs → excluded, blocked. | queue for R excludes task AND signoff COI_CONFLICT AND COI_RECUSAL ledger entry. |
| S9-TC07 | unit | **Priority ordering deterministic.** Two tasks identical except created_at; prioritize → stable, tie-break created_at then task_id. | repeated computation identical ordering; tie-break holds. |
| S9-TC08 | unit | **Rate limiter defers on exhaustion.** Admission token bucket empty; CreateReviewTask → deferred=true, not queued, back-pressure recorded. | `deferred==true` AND BACKPRESSURE_APPLIED AND `effective_backpressure<1`. |
| S9-TC09 | unit | **Emission budget blocks over-budget.** External-emission bucket for novel-claim-external exhausted; authorize-emission → BUDGET_EXHAUSTED, no token. | no EmissionAuthorization row AND `category==BUDGET_EXHAUSTED`. |
| S9-TC10 | unit | **Ledger hash chain links correctly.** Appended entries; compute entry_hash → == BLAKE3(prev_hash‖canonical(payload)) for all. | recomputation matches stored for all seq; `/ledger/verify` intact==true. |
| S9-TC11 | unit | **Ledger append-only enforcement.** UPDATE/DELETE against governance_ledger → rejected by trigger/constraint. | SQL error; row count unchanged. |
| S9-TC12 | unit | **Immutable decision correction via supersede.** Committed D1; correction → new D2 supersedes=D1, D1 unchanged. | D1 bytes/hash unchanged AND `D2.supersedes==D1`. |
| S9-TC13 | unit | **Decision pins exact reviewed evidence.** Sign-off recorded; persist → evidence_reviewed includes report_id, artifact hashes, contamination_index_version, policy_version. | all four present + equal to task values at sign-off. |
| S9-TC14 | integration | **E2E novel approval mints emission authorization.** Valid signed novel, leakage PASS, cross-code PASS; domain+ml+governance w/ WebAuthn step-up → EMISSION_AUTHORIZED + single-use HSM token bound to hashes. | `signature` verifies vs HSM key AND `bound_artifact_content_hashes==task hashes` AND single_use==true. |
| S9-TC15 | integration | **S5 wait-state round trip.** S5 hits human-review wait, CreateReviewTask; S9 terminal decision → signals Temporal workflow, S5 resumes. | S5 receives ReviewDecisionSignal matching outcome; JobResult reflects it. |
| S9-TC16 | integration | **C3 challenge re-verification loop.** Reviewer NEEDS_MORE_INFO + challenge; C3 returns ChallengeResult → linked evidence, task IN_REVIEW. | task has linked challenge evidence AND NEEDS_MORE_INFO→IN_REVIEW in ledger. |
| S9-TC17 | integration | **Federation admission recorded, no runtime trust.** C5 revision Gold evidence; federation reviewer admits → trust_class stays federated, ledger-recorded. | `trust_class==federated` AND FEDERATION_DECIDED entry outcome ADMIT. |
| S9-TC18 | integration | **Back-pressure propagates to S5.** Admission bucket exhausted; S5 polls /backpressure → receives effective_backpressure, reduces admissions. | gauge matches bucket remaining ratio; S5 consumer honors it. |
| S9-TC19 | integration | **Quarantine can only re-verify or reject.** QUARANTINED task; governance officer authorize-emission → blocked, only re-verify/reject. | authorize-emission on QUARANTINED returns POLICY; only reverify/reject transitions accepted. |
| S9-TC20 | e2e | **No external emission without human sign-off.** Built + S3-verified artifact awaiting emission; automated path attempts emission w/o authorization → refused. | verify endpoint valid=false for absent/forged token; no emission.completed without valid consumed authorization. |
| S9-TC21 | e2e | **Full novel lifecycle w/ audit provability.** Novel flows intake→dual signoff→governance→emission; auditor exports → proves signed report + eligible distinct sign-offs + guardrail ALLOW + authorized emission. | bundle links report_id(sig valid), ≥2 distinct eligible signoffs, GuardrailResult ALLOW, EmissionAuthorization consumed; hash chain intact. |
| S9-TC22 | physics-validation | **Recapitulation candidate cannot be promoted to novel.** Candidate overlaps frozen contamination index; reviewer sees novelty+LEAKAGE → recommends recap, blocks novel. | novelty gate fails on overlap; `final_claim_tier≤recap`; `claim_tier_promoted==false`. |
| S9-TC23 | physics-validation | **Uncalibrated uncertainty blocks emission.** C3 CALIBRATION FAIL; governance authorize-emission → blocked. | authorize-emission GUARDRAIL_BLOCK referencing CALIBRATION FAIL; no token. |
| S9-TC24 | physics-validation | **Cross-code disagreement prevents novel emission.** C3 CROSS_CODE FAIL/INCONCLUSIVE for novel; reviewers authorize → blocked. | emission blocked reason cross-code-not-passed; task cannot reach EMISSION_AUTHORIZED. |
| S9-TC25 | security | **Forged emission authorization rejected.** Authorization signed by non-HSM/untrusted key; external actor verify → valid=false. | verify valid=false due to signer_key_id not in trust store. |
| S9-TC26 | security | **TOCTOU: artifact swapped after approval.** Approved task; attacker swaps bytes before mint; authorize-emission re-verifies → mint fails, blocked. | re-verification detects hash mismatch; no token minted; SIGNATURE/HASH quarantine event. |
| S9-TC27 | security | **Least-privilege authz on sign-off.** Principal w/o domain role/subtopic eligibility attempts domain sign-off → NOT_ELIGIBLE. | authz denies; ledger records no valid signoff. |
| S9-TC28 | security | **Ledger tamper detected.** Directly-mutated ledger payload; /ledger/verify → break detected, emissions frozen. | `intact==false` w/ break_at_seq; emission minting disabled (fail-closed). |
| S9-TC29 | security | **WebAuthn step-up required for emission.** Governance sign-off/authorize-emission w/o fresh WebAuthn → rejected pending step-up. | denied; on valid assertion `SignOff.step_up_auth` recorded. |
| S9-TC30 | security | **Agent-zone cannot write governance ledger.** Agent-sandbox identity append/modify ledger → denied. | rejected by mTLS scope; no entry written. |
| S9-TC31 | integration | **Idempotent duplicate CreateReviewTask.** Two calls same (root_request_id, artifact hash set) → single task both times. | same task_id returned; one review_tasks row. |
| S9-TC32 | integration | **At-most-one review under concurrent sign-off.** Two reviewers conflicting transitions same task simultaneously → one succeeds, other optimistic-lock conflict. | exactly one commit; loser version-conflict retryable; one transition in ledger. |
| S9-TC33 | integration | **SLA breach escalates, never auto-approves.** Task past SLA no sign-off; aging job → escalate/reassign, no approval. | `state==ESCALATED` or reassigned; no APPROVED_* transition; SLA_BREACH sent. |
| S9-TC34 | integration | **Emission authorization single-use.** Minted+consumed authorization; consume again → rejected. | first sets consumed=true; second IMMUTABLE/consumed error. |
| S9-TC35 | perf | **Queue/detail latency under load.** 10^5 tasks, 200 concurrent reviewers; fetch views → p95 < 2s. | measured p95 < 2000ms. |
| S9-TC36 | perf | **Sign-off commit latency.** Sustained sign-off (ledger append + transition) → p95 < 1s. | measured p95 < 1000ms incl. ledger append. |
| S9-TC37 | perf | **Intake throughput w/ signature verification.** Burst CreateReviewTask verifying sigs+hashes → p95 intake < 3s, rate limiter shapes admission. | p95 intake<3000ms; admitted rate ≤ cap. |
| S9-TC38 | unit | **Degradation: policy engine unavailable blocks emission.** Guardrail engine down; authorize-emission → fail-closed block. | POLICY_UNAVAILABLE; no token; internal review still readable. |
| S9-TC39 | unit | **Degradation: HSM unavailable blocks mint not review.** HSM/minter unavailable; task fully approved → stays APPROVED_FOR_EMISSION, no token. | state stays APPROVED_FOR_EMISSION; no EmissionAuthorization; retriable. |
| S9-TC40 | integration | **KPI accuracy to S11.** Known tasks/decisions; compute KPIs → queue_depth, override_rate, guardrail_block_rate match ground truth. | computed == independently counted (0 tolerance for counts). |
| S9-TC41 | unit | **Reviewer cannot self-review own subagent output.** Task whose producer subagent owned/authored by R (tags overlap); R signs → blocked self-review COI. | signoff COI_CONFLICT(self-review); recusal recorded. |
| S9-TC42 | e2e | **Guardrail block produces REFUSED to S5, no artifact.** Hard-blocked emission class routed from S5; process → S5 REFUSED, no external artifact/token. | `JobResult.status==REFUSED` AND zero EmissionAuthorization rows AND `guardrail.blocked` event. |

---

## 11. S10 — Security, Sandbox & Runtime

The isolation substrate. Read-only trust mounts, seccomp, default-deny egress w/ DNS pinning, no secrets, freeze-before-terminate budget halts, brokered credentials/writes, pure deterministic policy, ceiling rejection of flagship-HPC, tamper-evident audit, and escape-battery gating.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S10-TC01 | security | **Read-only trust mount write denied + Sev-1.** Verifier-code + ledger paths RO; agent open(O_WRONLY)/write → fails EROFS/EACCES, `trustwrite.detected` Sev-1, freeze+quarantine, forensic snapshot. | quarantine exit; exactly one trustwrite.detected sev1 referencing sandbox_id; non-empty snapshot_refs; target hash unchanged. |
| S10-TC02 | security | **Seccomp denies dangerous syscalls.** Signed seccomp applied; invoke ptrace, mount, kexec_load, bpf, keyctl → each EPERM + audit. | all five return −EPERM; audit shows seccomp.deny per call. |
| S10-TC03 | security | **Default-deny egress.** Empty egress_allowlist beyond store; open TCP/HTTPS to arbitrary host → dropped by proxy, egress.denied logged. | connect fails/timeouts; audit egress.denied w/ dst; capture confirms zero bytes left node. |
| S10-TC04 | security | **DNS pinning prevents rebinding.** Proxy owns DNS, sandbox netns no resolver; direct DNS (UDP/53) + rebinding attack → direct DNS dropped, proxy pins resolved IP for connection lifetime. | UDP/53 blocked in capture; connection uses pinned IP even after DNS change (dest IP constant). |
| S10-TC05 | security | **No secrets in sandbox.** Launched sandbox; scan env/layers/fs + mount Vault path → none found, Vault unreachable. | scanner zero hits; Vault connect egress-denied; env only scope handle. |
| S10-TC05b | security | **Sandbox cannot reach reward/verifier signing key.** S3 key in verifier zone; agent (F3 frozen-pipeline) reads key/reward path → denied (no mount, egress-denied), audited. | no path resolves to key; egress to verifier zone denied; reward only via signed C3 report fetched by broker. |
| S10-TC06 | security | **Reward-hacking loop structurally closed.** Evolver variant self-reports high score, writes fake score artifact → S4 accepts scores only from signature-valid C3 report; inadmissible, no budget/tier effect. | S4 score-consumer rejects any score lacking valid S3 signature; audit shows no reward applied. |
| S10-TC07 | unit | **Policy decide() pure deterministic.** Fixed signed bundle + fixed LaunchRequest; decide() repeatedly across processes → byte-identical Verdict. | golden-file equality across N runs + 2 machines; any diff fails. |
| S10-TC08 | unit | **Token verification rejects tampered/expired.** Valid token; flip signature bit / past expiry / unknown signer → valid=false w/ reason, denied fail-closed. | Verify()==false each mutation; launch w/ tampered token returns POLICY + audited. |
| S10-TC09 | unit | **Attenuation cannot widen scope.** Parent adapters {A}; attenuate child {A,B} → rejected; {A} succeeds. | attenuate({A,B}) errors; attenuate({A}) yields token scope ⊆ parent. |
| S10-TC10 | unit | **Reserve→consume→release consistent.** max_gpu_seconds=100; reserve 60, consume 40, release; reserve 60 again → second only ≤60 remaining, exact ledger. | remaining matches closed-form each step; no negative; CAS prevents double-reserve under concurrency. |
| S10-TC11 | integration | **Pre-flight admission rejects over-budget.** remaining max_cost_usd=$0.50; launch estimated $5 → deny BUDGET before start. | no pod created; JobResult BUDGET; audit budget_reject. |
| S10-TC12 | integration | **Mid-flight halt on GPU-seconds breach within bound.** max_gpu_seconds=10; workload past cap → freeze+terminate within ≤2s + overshoot, partial captured. | halt latency ≤ threshold; final gpu_seconds ≤ cap+overshoot; captured_partial_refs non-empty; spend.final emitted. |
| S10-TC13 | integration | **Freeze precedes terminate.** Agent atexit/cleanup hook writes exfil marker; breach halt → cgroup frozen (SIGSTOP) before SIGKILL, hook never runs. | exfil marker never in scratch/egress; audit shows freeze before terminate. |
| S10-TC14 | integration | **Brokered adapter call hides credentials.** S7 adapter needs credential via broker; sandbox calls /broker/adapter/{id}/evaluate w/ scope_token → broker does credentialed C6 evaluate, credential never in sandbox. | EvalResult w/ C6 uncertainty tag; capture shows no credential; non-granted adapter denied. |
| S10-TC15 | integration | **Store-writer broker is only write path.** Direct object-store write vs broker PutArtifact → direct egress-denied, broker succeeds → C4 artifact_ref. | direct connect denied; broker returns artifact_ref w/ content_hash matching bytes; record by S8 writer not agent. |
| S10-TC16 | integration | **LLM metering hook debits + halts.** max_model_tokens=1000; calls via /broker/model/complete >1000 → metered, exceeding call refused, budget halts. | Σ debited ≤1000; exceeding call BUDGET; prompt/response provenance to S8. |
| S10-TC17 | integration | **Atomic policy rollout no effect on in-flight.** Sandbox pinned bundle vN; publish vN+1 → in-flight keeps vN, new launches vN+1. | in-flight `policy_bundle_version==vN`; new launch vN+1; `policy.rollout` present. |
| S10-TC18 | integration | **Flagship-HPC envelope rejected at admission.** Ceiling below flagship-HPC; launch exceeding (num-rel-scale GPU/wallclock) → ceiling violation. | `within_ceiling=false`; launch denied; audit ceiling reject (enforces non-goal). |
| S10-TC19 | security | **Audit chain tamper-evident.** Edit one historical event payload; verify → detects break at seq. | VerifyChain intact=false, break_at==edited seq; Merkle anchor mismatch. |
| S10-TC20 | security | **Escape-attempt red-team battery 0 passes.** Suite (mount escape, /proc host-pid, cgroup release_agent, unshare privileged ns, GPU ioctl abuse, TOCTOU) → every attempt fails, Sev-1 where relevant. | 0/N succeed (gate CI); each expected deny/Sev-1; a single pass fails suite. |
| S10-TC21 | e2e | **Full S2 training slice under isolation.** S5-minted budget+scope; S1 build() launches sandbox, trains, brokers S7 adapter, stores model → complete C4 lineage incl ExecEnvironmentDigest, spend accounted, no violations. | artifact full lineage (image_digest, seccomp hash, policy version, seeds); spend.final within budget; zero security events. |
| S10-TC22 | e2e | **Evolver loop halts at gen/spend cap.** S4 job max generations + shared budget; run to cap → BUDGET halt, no sandbox after cap, each gen spend attributed. | launched sandboxes ≤ cap; cumulative spend ≤ budget; terminates cleanly; no unguarded iteration. |
| S10-TC23 | perf | **Sandbox launch latency SLO.** Warm pool + cold; launch 100 (warm/cold, some GPU) → p50 warm ≤800ms, cold gVisor ≤3s, Firecracker ≤5s, GPU attach +≤2s. | measured percentiles meet SLO; regression >20% fails perf gate. |
| S10-TC24 | perf | **Metering + halt responsiveness.** Workload crosses cap → telemetry ≤5s, halt ≤2s after crossing. | timestamp deltas breach→halt ≤ SLO over 50 trials (p99). |
| S10-TC25 | perf | **Concurrency scale.** 300 concurrent + 2000 queued → admissions/metering/egress within SLOs, no ledger corruption. | no contention admission errors; ledger zero drift; audit ingest ≥10k/s sustained. |
| S10-TC26 | integration | **Quota-service outage fails closed.** Quota/Cost down; new launch + in-flight at reservation checkpoint → new denied, in-flight pauses at checkpoint (not uncapped). | launch retryable-unavailable, never admits uncapped; in-flight FROZEN at checkpoint; audit fail-closed. |
| S10-TC27 | integration | **Egress proxy crash fails closed.** Running sandbox + egress sidecar; proxy crashes → netns default-DROP, zero egress until recovery. | post-crash capture zero egress; connect attempts fail; no bypass. |
| S10-TC28 | integration | **Metering gap conservative.** Sampler stall mid-run; no samples > sample_interval → gap charged at max-rate, halt if exceeds threshold w/ meter.gap. | charged ≥ max_rate×gap; meter.gap present; halt if gap>threshold. |
| S10-TC29 | security | **Federated subagent no elevated trust.** Federated (S12) admitted Gold; runs + attempts trust-path write + disallowed egress → isolated identically, quarantined on violation. | same deny/Sev-1 as TC01/TC03; `trust_class=federated` grants no extra mounts/scopes. |
| S10-TC30 | integration | **Digest-pin & signature enforcement.** OCI image by tag + unsigned image; launch each → tag-only rejected, unsigned rejected, only digest-pinned cosign-verified launch. | both bad → POLICY pre-launch; audit image_verify_fail; good case proceeds. |
| S10-TC31 | integration | **Reproducible re-launch from ExecEnvironmentDigest.** Prior digest; S11 canary relaunch → same image digest, kernel-compatible runtime, seccomp hash, cgroup limits, seeds. | relaunched ExecEnvironmentDigest matches original on pinned fields (modulo declared nondeterminism). |
| S10-TC32 | security | **GPU cross-sandbox isolation.** Two sandboxes share GPU via distinct MIG slices; one reads other's GPU memory / DCGM beyond slice → denied by MIG. | cross-slice read fails; DCGM slice-scoped; no leakage. |
| S10-TC33 | security | **Exfiltration byte-threshold triggers.** Soft/hard exfil thresholds; stream past soft then hard to allowlisted store → soft alerts, hard drops+halts. | alert at soft; connection dropped + halt at hard; audit both w/ byte counts. |
| S10-TC34 | unit | **USD roll-up matches signed price table.** Metered cpu/gpu/token actuals + signed price table; roll-up → usd == Σ(dim×rate) exactly for pinned version. | closed-form equality; price table signature verified; mismatch/unsigned rejected. |
| S10-TC35 | integration | **Quarantine cannot be released un-snapshotted.** Sev-1 w/ full snapshot store; operator closes before snapshot persists → refused until durable. | Close() rejected while pending; succeeds only after snapshot_refs resolve in write-once store. |
| S10-TC36 | unit | **Env allowlist strips secret-shaped values.** LaunchRequest env carries secret-pattern value; materialize → rejected/stripped, only allowlisted non-secret pass. | materialized env no secret-pattern value; rejected launch if required key secret-shaped; audited. |
| S10-TC37 | security | **KMS-unavailable pauses minting, preserves verification.** KMS unreachable; mint + verify → mint pauses fail-closed, verify of existing tokens works via cached public keys. | mint retryable-unavailable; Verify of pre-existing valid token true; no unsigned token issued. |
| S10-TC38 | integration | **Revocation propagates to in-flight.** Active token; revoke → subsequent brokered/metered ops denied, in-flight sandbox halted. | post-revoke broker call denied; sandbox terminated; audit revoke propagation. |
| S10-TC39 | physics-validation | **Verifier-zone independence preserved during frozen-pipeline exec.** S3 frozen-pipeline (F3) hosted under isolation; verifier holds blind data + key in own zone → sandbox cannot read blind labels/key; cross-code adapter runs independently. | no sandbox path/egress reaches blind data/key (TC05b); cross-code independence_tags differ (C5 check); enables valid signed C3 report. |
| S10-TC40 | e2e | **End-to-end tamper-evidence audit across a job.** Complete job (mint→launch→broker→halt→quarantine); export full slice → every trust-boundary action present, hash-chained, verifies; trace_id links to S11 OTel span. | VerifyChain intact=true; each expected event type present exactly as many times as actions; trace_id joins S11 span. |

---

## 12. S11 — Observability & Evaluation

Scrubbed telemetry, deterministic KPI recompute, trace completeness, re-run canaries (hash-equal / tolerance), reward-hacking & independence & transparency-failure detectors (advisory only), and reproducible eval scorecards.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S11-TC01 | unit | **Scrubber redacts budget_token.** Span carrying budget_token + sensitive-tagged field; through Rust gateway scrubber → no token value, no sensitive field, scrub event. | stored span has redaction placeholder; grep for raw token across trace/log/event stores zero hits. |
| S11-TC02 | unit | **Scrubber fails closed on unknown field.** Span w/ unclassifiable field; scrub → redacted by default + scrub_uncertain event. | output field == REDACTED AND exactly one scrub_uncertain w/ field name. |
| S11-TC03 | unit | **KPI recompute determinism.** Fixed event window + KPIDefinition v; compute validation-pass-rate twice → identical numerator/denominator/value. | byte-equality of two KPISample records (excl computed_at). |
| S11-TC04 | unit | **KPI definition edit mints new version.** Existing v1.0.0; governance edit changes numerator → new hash + v1.1.0, v1.0.0 samples unchanged. | registry two versions distinct content_hash; historical samples still v1.0.0. |
| S11-TC05 | unit | **Trace completeness computation.** Required set 7 spans, 6 observed after lateness window → completeness=6/7, partial, broken_trace finding. | `completeness~0.857`, status='partial', one finding kind=broken_trace. |
| S11-TC05b | unit | **Late span amendment.** Trace finalized partial, then late required span arrives → append-only amendment recomputes complete. | second revision status='complete'; original preserved (append-only). |
| S11-TC06 | unit | **Re-run comparator deterministic kind.** C4 artifact determinism=deterministic, hash H; canary re-derives hash H → reproducible via hash_equal. | `verdict=='reproducible'` AND `comparator=='hash_equal'` AND rederived_hash==H. |
| S11-TC07 | unit | **Re-run comparator statistical tolerance divergence.** Seeded artifact rel tolerance 1e-3, re-derivation diverges 5e-3; compare → non_reproducible. | `verdict=='non_reproducible'` AND divergence>tolerance.value. |
| S11-TC08 | unit | **Cost-per-verified-artifact formula.** Spend $100, 4 artifacts w/ valid signed tier≥recap + 6 without; KPI → 25. | value == 100/4 == 25.0 exactly. |
| S11-TC09 | unit | **Reward-hacking: score-without-signature.** S4 scoring event referencing score w/ no traceable signature-valid C3 report; detector → reward_hacking S1 finding. | kind=reward_hacking, subject.report_ref absent/invalid, severity=S1. |
| S11-TC10 | unit | **Independence violation via input-hash reuse.** Two cross-code checks whose C4 inputs share identical input_hashes; detector → independence_violation finding. | kind=independence_violation referencing shared input_hash. |
| S11-TC11 | integration | **End-to-end trace across S5-S1-S2-S7-S3.** Simulated job emits OTLP spans, shared trace_id; assemble → GET traces/{job_id} complete w/ all 5 hops. | subsystems_observed ⊇ {S5,S1,S2,S3,S7}; status=complete; span tree valid. |
| S11-TC12 | integration | **Streaming validation-pass-rate freshness.** Stream 7 pass, 3 fail; process → KPI 0.7 within 60s. | `value==0.7` AND computed_at−latest_event<60s. |
| S11-TC13 | integration | **Exactly-once KPI under duplicate delivery.** validation.report_issued redelivered 3× same report_id → counts once. | denominator increments by exactly 1 across 3 deliveries. |
| S11-TC14 | integration | **Canary via S3 challenge().** Signed report_ref; canary method=challenge → CanaryResult written as C4 to S8. | `method=='challenge'` AND result_artifact_ref resolves in S8 w/ valid lineage. |
| S11-TC15 | integration | **Transparency-failure on tier/report mismatch.** C4 artifact novel whose C3 report tier=recap; detector cross-joins → transparency_failure S1 + paged. | kind=transparency_failure references mismatch; alert routed. |
| S11-TC16 | integration | **Degraded KPI on S8 outage.** S8 read unavailable during rollup; cost-per-verified-artifact → served stale w/ last-known-good + rising staleness. | `status=='stale'`; `s11_data_staleness_seconds>0`; no wrong value. |
| S11-TC17 | integration | **Lineage impact query.** Contaminated X consumed by 12 downstream across 5 jobs; GET lineage/impact → all 12 + 5. | result == known ground-truth closure over C4 graph. |
| S11-TC18 | e2e | **MLE-bench-style eval + scorecard diff.** Curated agent-ML suite + new build; POST eval/run harness=mle_bench → versioned scorecard stored as C4, diffed vs previous. | scorecard content_hash stable on re-run same inputs; regression_vs_prev computed; resolves in S8. |
| S11-TC19 | e2e | **Physics recapitulation tier consistency.** Held-out established result should be recap; recap harness runs Argus → recovered=true, platform tier==recap. | `tier_match==true` AND recovered==true. |
| S11-TC20 | e2e | **Physics recap catches false-novel.** Held-out known erroneously marked novel; harness scores → tier_match=false + leakage/transparency flag. | `tier_match==false` AND finding in {reward_hacking,transparency_failure}. |
| S11-TC21 | physics-validation | **Recapitulation scoring against known relation.** Known EWPT→GW mapping w/ held-out truth in eval vault; shim scores Argus output → agreement within physics tolerance, recovered flag set. | shim error ≤ documented tolerance → recovered=true; oracle uses vault truth never exposed to platform. |
| S11-TC22 | physics-validation | **Calibration coverage aggregation matches S3.** Predictive artifacts w/ C3 CALIBRATION results; aggregate → KPI == fraction passing per S3. | S11 value == independently counted PASS/total from C3 reports. |
| S11-TC23 | security | **S11 cannot write provenance ledger.** S11 job token attempts write to S8 ledger/sign path → denied, logged. | authorization denied; audit record of denied privileged attempt. |
| S11-TC24 | security | **Eval vault label isolation.** Pipeline-under-test in S10 during eval reads vault/scoring shim → denied. | no vault access from sandbox identity; attempt Sev-1; scores unaffected. |
| S11-TC25 | security | **Canary runs with no elevated trust.** Re-run canary re-executes producer step; tries egress / trust-path write → denied by S10 identical to agent code. | egress-deny enforced; read-only rootfs; violation → sandbox_violation finding. |
| S11-TC26 | security | **Reject tampered C3 report.** C3 report bytes altered after signing; detector/KPI consumes → signature fails, treated transparency_failure. | signature false; kind=transparency_failure; not counted toward pass-rate. |
| S11-TC27 | security | **Audit log tamper-evidence.** Append-only chain; mutate a row payload → chain verify detects break at seq. | recomputed this_hash ≠ stored at mutated seq; verifier reports exact break point. |
| S11-TC28 | security | **No secret in traces.** Full trace corpus after busy period; secret-scan across trace/log/event → zero. | scanner (regex + entropy) zero matches for known secret patterns. |
| S11-TC29 | perf | **Ingest throughput under burst.** 3× burst to 150k spans/s for 5 min → baseline-trace drop <5%, no durable-log loss, ingest_lag bounded. | durable JetStream count == produced for required (error/security) spans; baseline drop<5%; lag recovers <2min. |
| S11-TC30 | perf | **KPI query latency.** 90-day series w/ breakdowns at 10^5 scale; concurrent dashboard → p95<2s. | measured p95 <2000ms over 1k queries. |
| S11-TC31 | perf | **Lineage impact query latency.** 10^5 artifacts; impact on deeply-consumed → p95<3s. | measured p95<3000ms across representative artifacts. |
| S11-TC32 | integration | **Cost anomaly on S4 no-improvement loop.** S4 loop high per-gen spend but Δscore~0 over N; detector → cost_anomaly w/ optional advisory pause. | kind=cost_anomaly; recommend_pause advisory (does not itself halt). |
| S11-TC33 | integration | **Planted-exploit catch-rate accounting.** 5 planted reward-hacking scenarios via S3 channel; gates process + detector → caught increment catch rate, planted excluded from real KPIs. | catch rate == caught/5; real validation-pass-rate denominator unaffected. |
| S11-TC34 | unit | **Advisory pause has no blocking authority.** High-severity finding; S11 recommend_pause to S5 → S5 job continues unless human approves. | job state unchanged by S11 call alone; only human-approved S5 action changes it. |
| S11-TC35 | integration | **Digest assembly.** Day w/ mixed KPI states, findings, canary, quarantined; GET digest → all KPIs vs SLO, findings by severity, canary summary, eval regressions, quarantined jobs. | digest fields match independently computed counts. |
| S11-TC36 | e2e | **Scorecard reproducibility.** Eval run pinned build + suite_version; re-run identical pins → identical scorecard content_hash. | content_hash equality across two runs. |
| S11-TC37 | security | **Read-only C2/C3/C4 grants only.** S11 identity enumerates scopes → only obs.read + own-output write, no ledger/sign/blind-data. | scope set == expected least-privilege exactly. |
| S11-TC38 | integration | **Broken-lineage promotion detected.** C4 artifact tier>ran-toy w/ missing lineage edge; transparency detector → transparency_failure (non-promotable). | finding references broken edge; artifact flagged non-promotable in S11 view. |
| S11-TC39 | integration | **Observatory v0 static render + semantic FAIL banner.** Signed current C3 report + its C4 lineage; render → self-contained static page showing six-check verdicts, perturbation pairs, insensitivity flags, tier justification, referee identity, provenance chain, signature re-verified via argusverify; then flip one byte of the report and separately feed signature-valid semantic failures such as non-distinct referee, failed check status, or failed perturbation verdict. | rendered verdicts/tier byte-match report fields; tampered input or semantic gate failure → explicit FAIL banner and nonzero exit; VERIFIED only when schema validation, every check status, bidirectional perturbation verdicts, empty insensitivity flags, and referee distinctness all pass. |
| S11-TC40 | integration | **Observatory v1 live view is read-only and fresh.** Drive one job through intake→build→adapter→verify→report; live view consumes FR-04 events → each transition rendered; view identity enumerates scopes. | event-to-render latency <60s per transition; scope set == obs.read + own-output only; S8 outage → staleness banner, no wrong state. |
| S11-TC41 | integration | **Observatory v2 renders the DebateLedger faithfully.** Artifact with N ChallengeRounds incl. one insensitivity FAIL; arena view renders → N rounds w/ proponent/challenger/referee, ChallengeVerdict fields, attack kinds, fitness series, killed counter. | rendered rounds/fields match ledger exactly; killed count==1; fitness points exist only for signature-valid aggregate.score (unsigned score never plotted). |

---

## 13. S12 — Interop Standard & Federation

The contract-versioning + federation onboarding standard. Semver compat classification, deterministic codegen, admission gate (fail-closed AND, federated trust forced), governance ledger integrity, conformance-does-not-judge-physics, and sandboxed conformance runs.

| ID | Type | Given / When / Then | Oracle |
|----|------|---------------------|--------|
| S12-TC01 | unit | **Semver classifier: additive field is minor.** Old C2 vs new adding one OPTIONAL field w/ default → additive-minor. | classifier returns exactly 'additive-minor'. |
| S12-TC02 | unit | **Semver classifier: removed required field is major.** Old C1 vs new removing required field → breaking-major; minor bump rejected by CI gate. | returns 'breaking-major'; minor-declaring release exit≠0. |
| S12-TC03 | unit | **Codegen determinism.** Fixed schema + pinned codegen; generate twice → byte-identical. | `BLAKE3(out1)==BLAKE3(out2)`. |
| S12-TC04 | unit | **Admission forces federated trust_class.** Bundle descriptor_draft trust_class=internal + elevated scopes; gate builds descriptor → trust_class='federated', scopes == federation default. | descriptor.trust_class=='federated' AND scopes==DEFAULT_FED_SCOPES; input ignored. |
| S12-TC05 | unit | **Admission fail-closed AND of predicates.** All true except conformance_record_valid=false; evaluate → REJECTED referencing conformance. | `admit==false` AND `category=='CONFORMANCE_MISSING'` (or _EXPIRED). |
| S12-TC05b | unit | **Admission requires level match.** Passing record level_awarded=bronze but claimed_level=silver → rejected. | `admit==false`; reason mentions level mismatch. |
| S12-TC06 | unit | **Governance ledger hash chain integrity.** Appended entries w/ prev_hash; verifier walks → every prev_hash == hash(prev), all sigs verify. | verifier valid=true; mutating any byte flips one link → valid=false. |
| S12-TC07 | unit | **Taxonomy merge rejects cycle.** Proposal introduces parent edge creating cycle; validate → rejected. | validator CYCLE error; taxonomy_version unchanged. |
| S12-TC08 | unit | **ConformanceRecord signature covers canonical body.** Signed record; mutate any field ≠{issued_at,signature} → verify fails. | verify_signature false after mutation; true before. |
| S12-TC09 | integration | **Scaffold passes Bronze locally.** `argus init --subtopic ewpt --level bronze`; `argus conformance run --level bronze --local` → all Bronze PASS. | `aggregate.passed==true` AND level_awarded=='bronze'. |
| S12-TC10 | integration | **Bronze lifecycle state-machine violation caught.** Subagent transitions BUILDING→REPORTED skipping VALIDATING; Bronze → FAIL. | check 'BRZ-LIFECYCLE-STATEMACHINE'.status=='FAIL' AND aggregate.passed==false. |
| S12-TC11 | integration | **Bronze catches missing provenance.** Build artifact without C4 record; Bronze → FAIL. | 'BRZ-PROVENANCE-COMPLETE'.status=='FAIL'. |
| S12-TC12 | integration | **Bronze catches illegal self-tiering.** Subagent sets claim_tier='novel-needs-human'; Bronze → FAIL. | 'BRZ-NO-SELF-NOVEL'.status=='FAIL'. |
| S12-TC13 | integration | **Silver requires uncertainty tags.** Bare point-estimate no uncertainty tag; Silver → FAIL. | 'SLV-UNCERTAINTY-MANDATORY'.status=='FAIL'. |
| S12-TC14 | integration | **Silver verifier-unavailable refusal.** Envelope verifier_profile_ref=null; accept() under Silver → refuse VERIFIER_UNAVAILABLE. | `accepted==false` AND `category=='VERIFIER_UNAVAILABLE'`; 'SLV-REFUSE-NO-VERIFIER' PASS. |
| S12-TC15 | integration | **Gold recursion-safety: no reward-path write.** Gold candidate under simulated S4 loop w/ RO reward/verifier mounts; write attempt → FAIL + quarantine; clean candidate PASS. | if write attempted → 'GLD-RECURSION-NO-REWARD-WRITE'.status=='FAIL' AND status=='QUARANTINED'; clean PASSes. |
| S12-TC16 | integration | **Gold cross-code adapter units mandatory.** Gold C6 evaluate() returns field lacking units; check → FAIL UNITS_MISMATCH semantics. | 'GLD-C6-UNITS'.status=='FAIL'. |
| S12-TC17 | integration | **Gold grad required iff differentiable.** differentiable=true but no grad(); Gold → FAIL; differentiable=false w/o grad PASS. | 'GLD-C6-GRAD'.status=='FAIL'; converse PASSes. |
| S12-TC18 | integration | **Gold reproducibility manifest sufficiency.** Manifest omits a training seed; re-run → hashes diverge beyond tolerance, FAIL; complete manifest PASS. | 'GLD-REPRO-MANIFEST'.status=='FAIL' when incomplete; PASS when complete. |
| S12-TC19 | integration | **Submission→admission happy path.** Signed bundle from active maintainer w/ passing Silver record + registrar approval; run end-to-end → S6 C5 publish called, directory shows entity. | mock S6 receives publish w/ trust_class='federated'; GET /directory/{id} returns entity at silver. |
| S12-TC20 | integration | **Admission blocked without registrar approval.** Passing record but NO registrar approval; run → no publish, IN_REVIEW. | mock S6 publish count==0; status=='IN_REVIEW'. |
| S12-TC21 | integration | **Revocation propagation halts in-flight jobs.** Admitted entity w/ 2 in-flight jobs (mock S5) + revoke; execute → S6 C5 revoke, entity.revoked emitted, saga confirms both halted. | mock S6 revoke called; NATS entity.revoked; mock S5 both HALTED within SLA; ledger REVOKE entry. |
| S12-TC22 | integration | **Standard dual-serve during migration.** Release 2.0.0 (breaking) w/ 1.x in dual-serve; client fetches + posts 1.x-valid → both served/accepted until hard cutoff, then 1.x rejected. | before cutoff: current==2.0.0 + 1.x accepted; after cutoff: 1.x → VERSION_UNSUPPORTED. |
| S12-TC23 | e2e | **Full contributor journey init→submit→admitted.** Fresh contributor w/ CLI + identity keys; init, edit trivial pipeline, build, conformance run --level silver, package, submit, registrar approves → entity admitted, discoverable, federated. | GET /directory/{id}.level=='silver', trust_class=='federated'; ledger SUBMIT,CONFORMANCE_ATTACHED,APPROVE,ADMIT in order. |
| S12-TC24 | e2e | **Deterministic conformance re-run (S11 canary).** ConformanceRecord; POST /conformance/records/{ref}/challenge re-runs → matches original modulo {issued_at,signature}. | determinism_hash_new==orig; challenge.matches==true. |
| S12-TC25 | physics-validation | **Conformance does NOT judge physics correctness.** Physically wrong but contract-correct subagent (emits uncertainty, refuses correctly, provenance complete); Silver → PASS (physics is S3's job). | `aggregate.passed==true`; separate assertion no S3 physics check invoked (mock S3 verify count==0). |
| S12-TC26 | physics-validation | **Gold cross-code independence recorded for S3 selection.** Gold adapter independence_tags=['boltzmann-impl-B'] independent of impl-A; admitted → C5 resolve(independence for O excluding impl-A) returns it. | mock C5 resolve returns admitted entity; excluding its own tag returns empty (tag honored). |
| S12-TC27 | security | **Submitted code cannot escape S10 during conformance.** Malicious submission attempts egress + out-of-scratch writes; conformance in S10 → egress denied, writes fail, quarantine. | egress proxy 0 allowed external; writes EACCES; status=='QUARANTINED'; no host-side effect. |
| S12-TC28 | security | **Signing keys never enter conformance sandbox.** Conformance run; inspect env/mounts → no KMS/Vault key. | scan zero key artifacts; record signed by OUT-OF-SANDBOX Rust signer (signer_key_id ∉ sandbox-accessible). |
| S12-TC29 | security | **Tampered bundle signature rejected before execution.** Bundle bytes altered after signing; POST /submissions → rejected, code never executed. | HTTP 401/400; SubmissionState absent or REJECTED(SCHEMA_INVALID); conformance run count==0. |
| S12-TC30 | security | **Revoked maintainer key cannot submit.** Bundle signed by suspended/banned identity; submit → rejected. | HTTP 403; category REVOKED; no run. |
| S12-TC31 | security | **Admission cannot mint elevated scopes even w/ crafted record.** Forged descriptor requesting admin scopes + genuinely passing record; admission → scopes still overwritten to federation default. | published scopes==DEFAULT_FED_SCOPES; no code path reads scopes from submission for published descriptor. |
| S12-TC32 | security | **No auto-admit on S6 outage.** S6 C5 publish unavailable + fully-approved submission; admission → parks pending, retries, no fabricated success. | status=='APPROVED' (not ADMITTED); publish retried; no directory entry created. |
| S12-TC33 | perf | **Registry resolve p99 latency.** 10^4 admitted descriptors; 1000 resolve/search → p99 < 200ms. | measured p99 < 200ms. |
| S12-TC34 | perf | **Conformance throughput.** 50 queued Silver submissions; process → within per-level budgets, no deadlock, survive restart. | all 50 terminal within aggregate budget; mid-run restart resumes (Temporal), no lost/dup records. |
| S12-TC35 | perf | **Directory search scales.** OpenSearch 10^4 descriptors; faceted search subtopic+level+independence at 100 QPS → within SLA + correct. | p95 < 300ms AND result == brute-force reference. |
| S12-TC36 | unit | **Suite yank invalidates auto-pass.** Record under suite_version X later yanked; admission checks validity → treated invalid, re-run required. | admission CONFORMANCE_EXPIRED/invalid for yanked suite; `conformance.suite.yanked` emitted. |
| S12-TC37 | integration | **Local pass is advisory, not admission-sufficient.** Only evidence is --local run report (not server record); admission → rejected missing server record. | category CONFORMANCE_MISSING; no publish. |
| S12-TC38 | integration | **Error envelope conformance (Silver).** Subagent returns raw string error not typed {code,category}; Silver → FAIL. | 'SLV-ERROR-ENVELOPE'.status=='FAIL'. |
| S12-TC39 | integration | **accept() idempotency.** accept(job) twice identical envelope; Bronze idempotency → identical Acceptance, no dup side effects. | acceptance_1==acceptance_2 AND provenance side-effect count unchanged; 'BRZ-ACCEPT-IDEMPOTENT' PASS. |
| S12-TC40 | e2e | **Taxonomy RFC end-to-end.** Steward + proposal adding valid subtopic node; propose→merge → taxonomy_version bumps, event fires, usable in argus init. | `taxonomy.updated` w/ new node; `argus init --subtopic <new_id>` scaffolds; ledger TAXONOMY_PROPOSE+TAXONOMY_MERGE. |

---

## 14. Cross-Subsystem Traceability Matrix (invariant → owning tests)

The platform's load-bearing invariants are protected by *multiple* subsystems. The integration/e2e suite in §15 must show each is enforced end-to-end, not just unit-locally.

| Invariant | Enforcing test anchors |
|-----------|------------------------|
| **No verifier ⇒ no run** | S1-TC-05, S2-TC23, S4-TC01/02, S5-TC05/TC21, S12-TC14 |
| **No self-tiering (tier only from signed S3)** | S1-TC-07/TC-31, S2-TC11, S3-TC02/TC03, S4-TC04, S8-TC09/TC10/TC11, S12-TC12 |
| **Tier>ran-toy ⇒ coupled signed report at write** | S1-TC-32, S5-TC13, S8-TC08/TC09/TC12, S11-TC15/TC38 |
| **Leakage/contamination blocks novelty** | S2-TC29, S3-TC17/TC18/TC21, S4-TC13/TC-48, S6-TC17, S8-TC12, S9-TC04/TC22 |
| **Cross-code independence genuine (lineage-disjoint)** | S3-TC24, S4-TC27, S6-TC06/TC-19b, S7-TC23/TC42, S10-TC39, S12-TC26 |
| **Bidirectional perturbation reaction (must-react + must-not-react)** | S3-TC51-PR/TC52-PR, S4-TC41-DB, X-14 |
| **Insensitivity ⇒ FAIL (invariance to a should-react perturbation)** | S3-TC53-PR, S4-TC41-DB, X-14 |
| **Challenger-independence attested (lineage-disjoint, correlation-free)** | S3-TC54-PR, S4-TC43-DB/S4-TC44-DB, X-15 |
| **Non-gameable referee (referee ≠ proponent; signed; distinct)** | S3-TC55-PR, S8-TC09/TC11, S9-TC01/TC20, X-16 |
| **Debate provenance recorded (DebateLedger via C4)** | S4-TC45-DB, X-14/X-15 |
| **Novel is candidate-only ⇒ human sign-off before external** | S3-TC22/TC33, S4-TC21, S5-TC15, S9-TC14/TC20/TC21, S8-TC41 |
| **Reward cannot be self-reported (structurally closed)** | S2-TC33, S3-TC29, S4-TC11/TC-12/TC-28, S5-TC23, S10-TC06, S11-TC09/TC33 |
| **Sandbox: no trust-path write, no secrets, default-deny egress** | S1-TC-26..30, S2-TC30/TC31, S3-TC26..28/TC44, S7-TC30..32, S10 (all security), S12-TC27/TC28 |
| **Full provenance & fail-closed on ledger** | S1-TC-08/TC-13, S2-TC15/TC32, S5-TC12/TC33, S7-TC14/TC15, S8 (all) |
| **Reproducibility (hash-equal / declared tolerance)** | S2-TC09/TC37, S3-TC34..36, S4-TC06/TC-36, S8-TC31/TC32, S10-TC31, S11-TC06/TC07/TC36, S12-TC24 |
| **Non-goals refused (empirical/paper/HPC)** | S5-TC02/TC26, S9-TC03/TC42, S10-TC18 |
| **Version/compat & codegen determinism** | S1-TC-09..11/TC-38, S2-TC12/TC40, S8-TC27..29, S12-TC01..03 |

---

## 15. Cross-Subsystem Integration & End-to-End Scenario Suite

Each scenario chains ≥3 subsystems through published contracts (C1 build, C2 envelope, C3 report, C4 provenance, C5 registry, C6 adapter) and terminates in a **deterministic oracle**. These are the acceptance gates for a release.

### X-01 — Golden path: request → verified recapitulated-known artifact
**Chain:** S5 (intake/plan/route) → S1 (lifecycle) → S2 (build) → S7 (adapter feature) → S3 (verify) → S8 (provenance) → S9 (no human gate needed for recap; internal only).
**Given** a feasible request with `required_claim_tier_max=recapitulated-known`, an available Silver subagent, a resolvable verifier profile, and a registered independent S7 adapter.
**When** the DAG executes register→accept→plan→build→validate→report end-to-end.
**Then** a signed S3 report at tier=recapitulated-known is produced, the model artifact is committed to S8 with complete lineage + coupled `validation_report_ref`, and `root_request.status==COMPLETED`.
**Oracle (deterministic):** `S3.report.signature.valid==true` AND `report.tier=='recapitulated-known'`; `S8.get(model.content_hash).lineage` complete AND `model.validation_report_ref==report.ref` AND `S8.VerifySignature(report)==true`; `root_request.status=='COMPLETED'`; every leaf `JobResult.status=='SUCCEEDED'` with non-null validation_report_ref. (Refs: S5-TC14, S1-TC-20, S2-TC21, S7-TC22, S3-TC32, S8-TC30.)

### X-02 — Physics chain EWPT → GW → Higgs observable (multi-node DATA dependency)
**Chain:** S5 (3-node DAG) → 3× {S1→S2→S7→S3→S8} → S8 lineage.
**Given** a request modeling electroweak phase transition → stochastic GW spectrum → Higgs-sector observable as a 3-node data-dependency DAG, each node with its own verifier profile.
**When** the DAG executes; each node consumes **only provenance-committed** upstream outputs.
**Then** the terminal observable carries a signed report and the lineage graph is fully connected with matching units.
**Oracle:** lineage query shows GW node consumed the EWPT `artifact_ref` and the observable node consumed the GW `artifact_ref` (edges present); `is_committed(upstream_ref)==true` before each downstream admission (S5-TC12); terminal `validation_report_ref` signature verifies; no `UNITS_MISMATCH` degradation on any inter-node adapter (S5-TC20, S7-TC01). (Refs: S5-TC17.)

### X-03 — Full novel candidate → human sign-off → authorized single-use emission
**Chain:** S2/S4 (build/evolve) → S3 (all gates incl. cross-code + leakage + independence) → S8 (commit as candidate) → S5 (human gate pause) → S9 (dual sign-off + guardrail + HSM mint) → external-emission actor.
**Given** a pipeline that passes injection, null, physical-consistency, calibration, cross-code (independent code), and leakage screens with an independence attestation.
**When** S3 tiers it novel-needs-human (candidate), S5 pauses the DAG at the human gate, and domain+ml+governance reviewers sign off with WebAuthn step-up.
**Then** an EMISSION_AUTHORIZED state is reached, a single-use HSM-signed token bound to the artifact hashes is minted, and **no external artifact exists before** that token is consumed.
**Oracle:** `report.tier=='novel-needs-human'` AND `claim_tier_is_candidate==true` (S3-TC22); S5 ReviewWaitState PENDING→APPROVED with `resume_signal_sent==true` only after approval (S5-TC15); `EmissionAuthorization.signature` verifies vs HSM key, `bound_artifact_content_hashes==task hashes`, `single_use==true` (S9-TC14); ≥2 distinct eligible sign-offs + GuardrailResult ALLOW in audit bundle, hash chain intact (S9-TC21); external-emission verify returns valid=false for any request lacking a consumed authorization (S9-TC20); zero external artifacts emitted by S3/S4 (S3-TC33, S4-TC21).

### X-04 — Reward-hacking end-to-end containment (evolver + leaked label)
**Chain:** S4 (variant proposal) → S2 (build) → S10 (sandbox) → S3 (verify w/ LEAKAGE + shuffled null) → S4 (admission) → S11 (detector).
**Given** an S4-proposed variant that scores high **only** via a leaked label, plus a red-team "hackable verifier" stub.
**When** S3 runs the full profile including LEAKAGE and the label-shuffled null, and S4 applies admission screens (leakage-flag + report-binding + profile-rotation).
**Then** the variant is inadmissible, counted as caught, and never enters the population; S11 records the catch without polluting real KPIs.
**Oracle:** `LEAKAGE.status=='FAIL'` and null collapses to chance → `aggregate.passed==false` (S3-TC08/TC17/TC48); S4 admission returns reject with `rejection_reason∈{LEAKAGE,REPORT_BINDING}` and `reward_hack.detected` fired (S4-TC13/TC-28); no non-signed score ever affects fitness (S10-TC06, S4-TC04); S11 catch-rate == caught/planted and real validation-pass-rate denominator unchanged (S11-TC33).

### X-05 — Recursion refused without a cheap external verifier
**Chain:** S5 (recursion intake) → S4 (precondition gate).
**Given** an S4 recursion request whose target observable has **no** resolvable S3 verifier profile (or whose single verify call exceeds the declared cheap budget).
**When** POST /v1/recursion runs the precondition gate.
**Then** recursion is refused before any generation, no budget minted.
**Oracle:** `accepted==false`, `reason==VERIFIER_UNAVAILABLE`, `generations_run==0`, and `mock C1.build call count==0`; preflight commits 0 budget-ledger entries (S5-TC21, S4-TC01/TC-02/TC-40).

### X-06 — Cross-code independence federation loop
**Chain:** S12 (admit federated adapter, forced federated trust) → S6/S7 (register + resolve, independence by lineage) → S3 (cross-code check uses the independent pair) → S9 (federation admission recorded, no runtime trust).
**Given** a federated Gold adapter with `independence_tags=['boltzmann-impl-B']` disjoint from the incumbent `impl-A`.
**When** S3 needs an independent cross-code partner for a novel candidate and resolves via C5.
**Then** the resolver returns a genuinely lineage-disjoint adapter, the cross-code check runs against it, and the federated entity holds no elevated runtime trust.
**Oracle:** `S12 published descriptor.trust_class=='federated'` with default scopes (S12-TC04/TC31); C5 resolve returns the entity but excluding its own tag returns empty (S12-TC26); `IndependenceAttestation.verdict!=NOT_INDEPENDENT` with disjoint repo/underlying_code_version (S3-TC24, S7-TC42, S6-TC06); S9 FEDERATION_DECIDED ADMIT with `trust_class` unchanged; at runtime S10 grants no extra mounts/scopes (S10-TC29).

### X-07 — Durable restart mid-DAG with no double-dispatch or double-spend
**Chain:** S5 (Temporal DAG) → S1/S2 (in-flight jobs) → S8 (budget ledger) → S10 (sandbox reattach).
**Given** a DAG with 5 in-flight nodes and a running budget reservation.
**When** the control-plane process (and a subagent runtime) are killed and restarted.
**Then** state is replayed, no job is dispatched twice, sandboxes reattach, and budget accounting is intact.
**Oracle:** for each job `dispatched_at` count==1 (idempotency key) (S5-TC18); post-restart subagent `job_current.state` restored + sandbox handle resolves (S1-TC-16); `pool.spent` unchanged across restart (exact); S4 idempotent evaluation `C1.build count==1` for already-evaluated variant (S4-TC15); checkpoint hash mismatch fails closed (S4-TC39).

### X-08 — Provenance fail-closed cascade
**Chain:** S7 (adapter compute) → S8 (ledger unavailable) → S1/S2 (build) → S5 (downstream gating).
**Given** the S8 provenance writer is unavailable at the moment a computed result would be committed.
**When** an adapter/build completes computation and attempts to emit provenance.
**Then** the result is **not** delivered as trusted, and any downstream node depending on it is not admitted.
**Oracle:** S7 evaluate returns `PROVENANCE_UNAVAILABLE`, no trusted EvalResult with a provenance_ref (S7-TC15); build emit refuses INCOMPLETE/absent lineage with no committed object (S1-TC-08, S2-TC15); S5 gate keeps downstream B out of ACCEPTED until `is_committed==true`, DAG pauses durably (S5-TC33). No silent progress.

### X-09 — Tamper detection across the trust boundary (end-to-end audit)
**Chain:** S8 (write-once + Merkle) / S9 (governance ledger) / S10 (audit chain) / S11 (transparency detector).
**Given** a completed job whose artifacts and reports are committed, plus an out-of-band mutation of (a) a stored artifact's bytes, (b) a ledger row, and (c) a signed report's bytes.
**When** verify-on-read, checkpoint recomputation, chain verification, and the S11 transparency detector run.
**Then** each mutation is detected at its exact location, writes/emissions freeze, and the artifact/report is quarantined and excluded from KPIs.
**Oracle:** (a) `GetArtifact` → `HASH_MISMATCH`, `artifact.tamper_detected`, status quarantined (S8-TC14); (b) S8/S9 recomputed root ≠ stored signed root, break_at_seq set, minting disabled (S8-TC23, S9-TC28); (c) S11 signature verify false → transparency_failure, report not counted toward pass-rate (S11-TC26); S10 VerifyChain intact=false at the edited seq (S10-TC19); full job audit slice otherwise intact and trace_id joins S11 span (S10-TC40).

### X-10 — Budget breach halts everywhere within bound, with partial capture
**Chain:** S10 (metering) → S2/S7 (in-flight) → S5 (governor) → S4 (loop) → S3 (verify budget).
**Given** jobs across S2 (GPU-seconds), S7 (compute-units), S3 (verify wallclock), S4 (max_cost/gen), and S5 (pool cap) each configured to cross their cap.
**When** each cap is crossed.
**Then** every subsystem halts within its declared bound, captures partial artifacts + provenance, and records the breach.
**Oracle:** S10 halt latency ≤2s + overshoot, `gpu_seconds ≤ cap*(1+grace)`, spend.final emitted (S10-TC12/TC24); S2 BUDGET typed error + partial checkpoint (S2-TC06); S7 halts at N with completed elements + partial provenance (S7-TC16); S3 unrun checks INCONCLUSIVE + partial report, `category==BUDGET` (S3-TC40); S4 BUDGET_HALTED with best-so-far + report captured, no double-spend (S4-TC14); S5 `argus.s5.budget.breach` within ≤1 metering interval, node QUARANTINED (S5-TC11).

### X-11 — Evolver improvement loop, verified & reproducible, novel routed
**Chain:** S4 (loop) → S2 (variant build) → S3 (signed scores) → S8 (genealogy) → S11 (canary) → S9 (if novel).
**Given** a real seed pipeline on a recapitulation-benchmark subtopic with a valid cheap independent verifier profile.
**When** an evolution job runs to completion under generation/spend bounds, then the S11 re-run canary replays from checkpoints.
**Then** best>seed with no leakage, a signed recap report, a queryable genealogy DAG, and the winning-variant hash reproduces exactly; if a variant reaches novel it routes to S9 rather than auto-promoting.
**Oracle:** `relative_improvement>0`, best report LEAKAGE all PASS, genealogy DAG resolves with no broken edges (S4-TC20); canary replay winner `content_hash==original` and decision path GenerationRecords match (S4-TC36, S11-TC06); any novel best → `human_review_required==true` + S9 handoff, no external artifact (S4-TC21, X-03).

### X-12 — Contract evolution & codegen drift gate (CI-level e2e)
**Chain:** S12 (semver classify + dual-serve) → S8/S1/S2 (bindings) → CI gates.
**Given** a proposed breaking change to C2 (removed required field) plus an additive change to C4.
**When** the compatibility classifier, codegen, and CI drift checks run across all consumers.
**Then** the breaking change is classified major and blocks a minor-only publish; the additive change is minor and forward-compatible; regenerated bindings are byte-stable; consumers tolerating unknown additive fields still parse.
**Oracle:** S12 classifier returns 'breaking-major' and CI exit≠0 for a minor bump (S12-TC02), 'additive-minor' for the additive field (S12-TC01); codegen twice byte-identical (S12-TC03, S8-TC29); consumers accept unknown additive field (S1-TC-09, S2-TC12, S5-TC34, S8-TC27); dual-serve serves 2.0.0 + accepts 1.x until hard cutoff then VERSION_UNSUPPORTED (S12-TC22).

### X-13 — Grounding lifts physical-consistency pass rate (knowledge → build → verify)
**Chain:** S6 (RAG grounding + frozen index) → S2 (build) → S3 (physical-consistency) → S11 (KPI aggregation).
**Given** a fixed subtopic eval set run by S2 in RAG-grounded vs un-grounded configurations, with S6 supplying curated unit conventions.
**When** the S3 physical-consistency gate is applied to both and S11 aggregates the results.
**Then** the grounded configuration has a materially lower physical-consistency failure rate, and the frozen contamination index pinned into the envelope drives the leakage/novelty gate.
**Oracle:** relative reduction in `PHYSICAL_CONSISTENCY` FAIL rate ≥30% with p<0.05 bootstrap CI (S6-TC16); C2 `contamination_index_version` == frozen version and novelty_query against that version succeeds (S6-TC35); S11 calibration/consistency aggregation equals independently counted S3 outcomes (S11-TC22).

### X-14 — Red-blue debate catches a PLANTED SPURIOUS model (insensitivity kill before the human gate)
**Chain:** S4 (proponent produces candidate + claim) → S4 (challenger panel attacks) → S3 (referee: bidirectional perturbation oracle + insensitivity detector) → S8/C4 (DebateLedger) → S9 (human gate never reached).
**Given** a PLANTED SPURIOUS model whose "result" survives only by IGNORING the data (memorized / constant / spurious-feature), a valid cheap S3 verifier+oracle for the subtopic, and a panel of ≥K independent challengers.
**When** `evolve_under_debate` runs a debate round: challengers inject a contamination the model should react to (must-not-react) and plant a real signal it should recover (must-react), and the S3 referee adjudicates via ChallengeVerdict.
**Then** the insensitivity detector fires (result invariant to a perturbation it should have reacted to), the red team kills the candidate, it never survives to a novel tier, and it never reaches the S9 human gate.
**Oracle (deterministic):** `detect_insensitivity` → `insensitivity_detected==true` with `insensitivity_flags` naming the invariant perturbation (S3-TC53-PR); `ChallengeVerdict.overall=='FAIL'` (must_not_react_pass==false) (S3-TC52-PR); the planted-spurious model is caught pre-admission with `ChallengeRound.survived==false` (S4-TC41-DB) and every round recorded in the C4 DebateLedger (S4-TC45-DB); zero S9 review tasks created and no external artifact (S3-TC33, S4-TC21). Insensitivity-catch on this planted-spurious model == 100%.

### X-15 — Challenger-independence loop (correlated challengers flagged, panel refreshed)
**Chain:** S4 (`select_challenger_panel`) → S3 (`attest_challenger_independence`) → S4 (collusion/overfit screens, panel refresh) → S8/C4 (DebateLedger).
**Given** a debate whose initially-selected challenger panel contains challengers sharing code lineage / producing correlated attacks (not lineage-disjoint).
**When** S3 attests challenger independence and S4's collusion screen runs, then S4 refreshes challenger diversity across attack types AND code lineages for the next round.
**Then** the correlated challengers are flagged, the non-independent panel is not certified, the panel is refreshed to a lineage-disjoint set of ≥K, and only the independent panel's verdict is admitted.
**Oracle:** `IndependenceAttestation.lineage_disjoint==false` OR `correlation_warning==true` on the initial panel, with shared `code_lineage_hash` listed (S3-TC54-PR); collusion screen records kind=challenger_collusion (S4-TC44-DB) and overfit-to-fixed-set refresh records kind=challenger_overfit (S4-TC43-DB); refreshed panel attests `min_independent_challengers>=K` AND `lineage_disjoint==true`; DebateLedger records the refreshed rounds (S4-TC45-DB). Challenger-independence enforced (lineage-disjoint) == 100%.

### X-16 — Non-gameable referee (builder cannot self-sign → emission blocked at S9)
**Chain:** S4 (proponent = builder) → S3 (referee enforcement) → S8 (tier-report coupling) → S9 (emission gate).
**Given** a candidate whose ValidationReport names the proponent/builder as its own referee (`referee.referee_id == proponent` or `distinct_from_proponent==false`), attempting to self-attest a tier and reach external emission.
**When** the S3 non-gameable-referee check adjudicates and, downstream, S9 evaluates the emission authorization.
**Then** the referee rejects the builder self-attestation, no signed current C3 report is emitted, the tier stays ran-toy, and emission is blocked at S9 (no valid signed report to authorize against).
**Oracle:** referee adjudication refused with `referee.distinct_from_proponent==false` / non_gameable enforcement, no signature written (S3-TC55-PR); S8 rejects any tier>ran-toy write lacking a signature-valid coupled report (S8-TC09/TC11, S1-TC-32); S9 authorize-emission returns no token because no valid signed report exists (S9-TC01/TC20); zero external artifact emitted. Referee-!=-proponent separation == 100%.

---

## 16. Platform-Level KPIs & Pass Targets

These are the *product-level* acceptance metrics, computed by S11 from S8/S3/S9 ground truth. Each is deterministic given the event window + pinned KPIDefinition version, and each has a supporting test.

| KPI | Definition | Pass target | How measured / oracle | Supporting tests |
|-----|-----------|-------------|-----------------------|------------------|
| **Transparency-failure rate** | Fraction of committed tier>ran-toy artifacts whose tier is *not* backed by a signature-valid, tier-matching, lineage-complete C3 report (tier/report mismatch, broken lineage, tampered/unsigned report). | **0%** (hard). Any occurrence is Sev-1 and blocks release. | S11 cross-joins C4 tier vs C3 report tier + signature + lineage; count mismatches / total tier-bearing artifacts. Enforced at write by S8 so the *steady-state* rate is 0; detector catches any bypass. | S8-TC08..12, S11-TC15/TC26/TC38, S1-TC-32, S5-TC13 |
| **Validation pass rate** | Of predictive artifacts submitted to S3, the fraction whose mandatory checks all PASS (INCONCLUSIVE and FAIL both count as non-pass). | **≥ 0.95** on the reference recapitulation suite (target; tracked as a trend, not a gate on genuinely-hard novel attempts). | S11 streaming count of `validation.report_issued` pass/total, exactly-once under duplicates; planted exploits excluded. | S3-TC04..20/TC48, S11-TC03/TC12/TC13/TC33 |
| **Cost-per-verified-artifact** | Total reconciled metered spend (USD) ÷ number of artifacts at tier ≥ recapitulated-known with a valid signed report. | Tracked with a **per-subtopic budget ceiling**; release gate = within declared budget envelope and no upward regression >20% vs previous build. | S11 rollup from S10/S5 reconciled spend + S8 verified-artifact count; 0-verified yields defined sentinel. | S5-TC38, S11-TC08/TC16, S4-TC38, S10-TC34 |
| **Reproducibility rate** | Fraction of promoted artifacts whose re-derivation matches within their determinism class (deterministic → hash-equal; seeded/stochastic → within declared tolerance). | **≥ 0.99** for deterministic artifacts; **≥ 0.95** for seeded/stochastic within declared tolerance. | S11 canary + S3 challenge re-run; S8 RecordReproducibilityCheck verdict; count PASS/total. | S3-TC34..36, S8-TC31/TC32, S11-TC06/TC07/TC36, S10-TC31 |
| **Reward-hacking catch rate** (safety KPI) | Of planted reward-hacking scenarios, the fraction caught pre-admission (leakage flag / report-binding / profile-rotation / signature). | **100%** (hard gate). | S11 planted-exploit accounting; caught/planted; planted excluded from real KPIs. | S4-TC28, S10-TC06, S11-TC09/TC33, X-04 |
| **Insensitivity-catch on planted-spurious models** (safety KPI) | Of planted-spurious models (result survives only by IGNORING the data — memorized/constant/spurious-feature, invariant to a perturbation it should react to), the fraction caught by the bidirectional perturbation oracle + insensitivity detector before the human gate. | **100%** (hard gate). | S3 `detect_insensitivity` + must-react/must-not-react `run_perturbation_pair`; caught/planted; ChallengeVerdict.overall==FAIL required, planted excluded from real KPIs. | S3-TC51-PR/TC52-PR/TC53-PR, S4-TC41-DB/S4-TC45-DB, X-14 |
| **Challenger-independence enforced (lineage-disjoint)** (safety KPI) | Fraction of admitted debate verdicts whose challenger panel is genuinely lineage-disjoint (≥K independent challengers, correlation-free) per `attest_challenger_independence`. | **100%** (hard gate). | S3 independence attestation + S4 collusion/overfit screens; correlated/non-disjoint panels flagged and refreshed; count independence-attested admitted verdicts / total admitted verdicts. | S3-TC54-PR, S4-TC43-DB/S4-TC44-DB, X-15 |
| **Referee-!=-proponent separation** (safety KPI) | Fraction of signed current C3 ValidationReports whose referee (S3) is oracle-backed, non-gameable, and distinct from the proponent/builder (`distinct_from_proponent==true`). | **100%** (hard gate). No builder self-attestation may yield a tier or emission. | S3 non-gameable-referee enforcement; count reports with `referee.distinct_from_proponent==true AND non_gameable==true` / total signed reports; builder self-signed reports never admitted. | S3-TC55-PR, S8-TC09/TC11, S9-TC01/TC20, X-16 |
| **Human-gate integrity** (safety KPI) | Fraction of external emissions that occurred **with** a valid, consumed, single-use HSM authorization preceded by distinct eligible sign-offs and a guardrail ALLOW. | **100%** (hard gate). No external artifact may exist without it. | S9 audit-bundle export + hash-chain verify; count compliant emissions / total emissions. | S9-TC14/TC20/TC21/TC34, X-03 |
| **Escape-battery pass** (safety KPI) | Of the S10 sandbox-escape red-team battery, the fraction of attacks that succeed. | **0/N** (hard CI gate). | S10 escape suite; any single pass fails the suite. | S10-TC20, and all S10 security cases |
| **Trace completeness** (observability KPI) | Fraction of jobs whose required span-set is fully observed after the lateness window. | **≥ 0.98** (target); broken traces surface as findings, never silently. | S11 TraceIndexRecord completeness; late-span amendments append-only. | S11-TC05/TC05b/TC11 |
| **Non-goal refusal rate** (governance KPI) | Fraction of attempted non-goal actions (empirical-validation claim, autonomous paper submission, flagship-HPC launch) that are hard-blocked. | **100%** (hard gate). | S5 guardrail + S9 guardrail + S10 ceiling; count blocked / attempted. | S5-TC02/TC26, S9-TC03/TC42, S10-TC18 |

**KPI governance:** every KPI is defined by an immutable, versioned KPIDefinition; edits mint a new version and never rewrite historical samples (S11-TC03/TC04). KPI computations are read-only over C2/C3/C4 (S11 has no ledger/sign/blind-data scopes — S11-TC23/TC37), so the observability layer cannot itself manufacture a passing number.

---

## 17. Release Gate Summary

A build is releasable only when **all** of the following hold:

1. **Hard-gate KPIs at target:** transparency-failure=0%, reward-hacking catch=100%, human-gate integrity=100%, escape-battery=0/N, non-goal refusal=100%, insensitivity-catch on planted-spurious models=100%, challenger-independence (lineage-disjoint)=100%, referee-!=-proponent separation=100%.
2. **Target KPIs met:** validation pass rate ≥0.95 (recap suite), reproducibility ≥0.99 deterministic / ≥0.95 stochastic, cost-per-verified-artifact within budget (no >20% regression).
3. **All per-subsystem suites (§2–§13) green**, including every physics-validation and security case.
4. **All cross-subsystem scenarios (§15) X-01…X-16 pass** with their deterministic oracles.
5. **CI meta-gates:** schema-diff/codegen-drift clean, conformance Bronze/Silver/Gold green for the reference subagent, deterministic-replay golden files unchanged.

Any failure in category 1 is a release blocker with no waiver.
