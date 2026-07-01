# Project Argus — Milestone Roadmap

> **Part of the Project Argus design set.** Start at README.md for the doc map and reading order. Related docs: Architecture.md, PRD.md, TechDesign.md, Backlog-and-Interfaces.md, TestPlan.md, Roadmap.md.

**Document owner:** Delivery Lead
**Status:** Complete build plan (not an MVP). Covers 100% of the decoupled backlog across all 12 subsystems.
**Scope of this roadmap:** ordered milestones M0..M6, each with goal, entry/exit criteria, the explicit set of included subtask IDs, the cross-subsystem integration deliverable, a concrete demo/acceptance test, and the parallelizable tracks. Followed by the critical path and decoupling notes.

---

## 0. How this roadmap is sequenced

Argus's whole architecture is a bet on **decoupling through published contracts**. The sequencing rules that follow directly from the dependency graph and the design principles are:

1. **Contracts first, foundations first.** The six contracts (C1..C6) are frozen as versioned JSON Schemas in M0, and the only two zero-dependency subsystems — **S8 (Data/Artifact/Provenance, owner of C4)** and **S10 (Security/Sandbox/Runtime)** — are stood up in M0. Every trust, reproducibility, and isolation guarantee rests on these. Freezing the schemas is what lets all 12 tracks proceed in parallel against stable seams.
2. **The load-bearing verifier (S3) lands early, and becomes a non-gameable referee.** Argus's central thesis is *verify-before-trust*. A minimal but real S3 (injection + null + physical-consistency, producing a **signed** ValidationReport) is delivered in **M1** on a single vertical slice, and S3 is then hardened progressively (cross-code, calibration, leakage, challenge/canary) through M2–M4. Starting in M1, S3 also acts as the **non-gameable REFEREE** of the adversarial red-blue debate: it runs **bidirectional perturbation pairs** (a MUST-REACT probe that plants a known-real signal and requires proportional, amplitude-linear recovery, and a MUST-NOT-REACT probe that injects noise / shuffled labels / fake-contamination and requires appropriate degradation), and an **insensitivity detector** that FAILs any claim invariant to a perturbation it should have reacted to (memorized / constant / spurious-feature results). The referee is oracle-backed and structurally `distinct_from_proponent` (referee != builder). Nothing downstream (S4 recursion, S9 promotion) is unblocked until the oracle it depends on exists.
3. **Prove one vertical slice before scaling breadth.** M1 wires C1/C3/C4/C6 together on one subtopic end-to-end. Breadth rollout (many subagents) waits until M4, honoring *breadth-over-depth* only after the single-slice mechanics are de-risked.
4. **Orchestration and provenance-at-scale before volume.** S5 (owner of C2) and full S8 lineage/audit land in M2, because durable governed execution and provable reproducibility are prerequisites for trusting anything at volume.
5. **Contamination control before novelty judgments.** S6 (knowledge, registry/C5, frozen contamination index) lands in M3, because the field is presumptively contaminated; without the frozen index and leakage screens the platform cannot responsibly separate *recapitulated-known* from *novel*.
6. **Human governance keeps pace with breadth.** S9 (mandatory human gate) is delivered alongside the breadth rollout in M4 so nothing external can escape without sign-off.
7. **Recursion only under a proven oracle — as adversarial red-blue debate.** S4 (the Evolver) is enabled in M5 — after the verifier, provenance, sandbox, and budget controls are all proven — and runs *only* where a cheap valid S3 verifier + oracle exists. In M5 the self-improvement loop is reframed as **Adversarial Red-Blue Debate Evolution**: the Builder subagent is the PROPONENT (candidate model + claim), a panel of >=K INDEPENDENT (lineage-disjoint, cross-code) red-team agents are the CHALLENGERS that attack the claim with evidence, and S3 is the REFEREE that adjudicates via a ChallengeVerdict (require `must_react_pass` AND `must_not_react_pass` AND NOT `insensitivity_detected`). Reward-hacking and challenger-collusion screens, hard round bounds, and per-round challenger-diversity refresh keep the debate honest; every round is recorded append-only in the C4 DebateLedger.
8. **Federation/standard (S12) lands last.** The SLHA-for-agents standard, SDK/CLI, conformance suite, and community registry open in M6, once internal subagents are proven and the contract, sandbox, and registry are mature enough for outsiders to run code in the federation.

**Backlog accounting.** The backlog contains **377 subtasks** (S1:30, S2:26, S3:38, S4:31, S5:33, S6:35, S7:32, S8:27, S9:25, S10:35, S11:35, S12:30). This includes the **11 new Adversarial Red-Blue Debate Evolution subtasks** (S3-TPR1..S3-TPR5 = 5; S4-TDB1..S4-TDB6 = 6) that embed multi-agent adversarial peer-review (proponent / challenger panel / non-gameable referee) into S3 verification and S4 evolution. Every subtask ID appears in **exactly one** milestone below. Section 9 provides the full coverage ledger.

**A note on intra-milestone ordering.** Within a milestone, subtasks are still gated by their own `depends_on` edges (schema authoring before codegen, base classes before hooks, etc.). Assignment to a milestone means "must be complete by that milestone's exit," not "started on day one." Where a subsystem's schema-authoring/codegen root task is a hard prerequisite for many later tasks, that root is pulled as early as possible (M0 for the six contract owners).

---

## M0 — Spine & Contracts First

**Goal.** Freeze C1..C6 as versioned draft-2020-12 JSON Schemas with multi-language bindings; stand up the two foundational zero-dependency subsystems — the S8 data/provenance plane and the S10 sandbox/runtime/security substrate — so all 12 teams build against stable, tested seams. Nothing agent-authored can execute or persist an artifact except through S10 and S8. **C3 is frozen at v1.1** (additive, backward-compatible) from M0 — pre-implementation, so there is no migration — carrying the six new ValidationReport fields (`perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, `debate_ref`) that the M1 perturbation oracle and the M5 red-blue debate will populate.

**Entry criteria.**
- Base infra available: Postgres, object store (S3/MinIO with Object-Lock), Redis, NATS JetStream, KMS/Vault, an OCI registry, gVisor/Firecracker-capable nodes, a schema registry, and a codegen toolchain (pydantic v2 / TypeScript / Rust serde).
- Contract owners (S1→C1, S5→C2, S3→C3, S8→C4, S6+S12→C5, S7→C6) named and staffed.

**Exit criteria.**
- All six contract schemas (C1..C6) are authored, meta-validated, semver-1.0.0 tagged, published to the schema registry, and have compiling round-trip bindings in Python/TS/Rust with a CI drift gate. **C3 is frozen at v1.1** with the six new ValidationReport fields (`perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, `debate_ref`), meta-validated and round-trip-bound like the rest (S3-TPR1); consumers tolerate the additive fields with no migration.
- S8 can commit a content-addressed C4 ArtifactRecord with complete lineage, fail-closed on incomplete lineage or illegal tier coupling, enforce append-only/write-once, and answer ancestor/descendant/impact-set lineage queries; Merkle audit chain verifiable.
- S10 can mint/verify budget+scope tokens, meter a running sandbox against a budget and halt on breach, launch a digest-pinned cosign-verified image under gVisor/Firecracker with default-deny egress via the proxy, broker credentialed calls with zero secrets in the sandbox, and emit launch provenance to S8.
- Cross-language hashing/canonicalization agree byte-for-byte.

**Included subtask IDs.**

*Contract schema roots + bindings (the "seams"):*
`S1-T01, S1-T03, S1-T25, S1-T30` (C1 schema, semver diff gate, error envelope, C1 spec+migration policy),
`S2-T01` (C1/C2/C4/C6-bound models + version tolerance),
`S3-T01, S3-TPR1` (C3 schemas + bindings; C3 frozen at v1.1 with the six new ValidationReport fields),
`S5-T01, S5-T31` (C2 schema + version-compat/dual-serve),
`S7-T01, S7-T02` (C6 schemas + bindings),
`S8-T01, S8-T02, S8-T04, S8-T27` (C4 schema, canonicalization spec, bindings+generator, schema registry service).

*S8 foundational data/provenance plane (owner of C4):*
`S8-T03, S8-T05, S8-T06, S8-T07, S8-T08, S8-T09, S8-T10, S8-T11, S8-T12, S8-T13, S8-T14, S8-T15, S8-T16, S8-T17, S8-T18, S8-T19, S8-T20, S8-T21, S8-T22, S8-T23, S8-T24, S8-T25, S8-T26`.

*S10 foundational sandbox/runtime/security substrate:*
`S10-T01, S10-T02, S10-T02b, S10-T03, S10-T04, S10-T04b, S10-T05, S10-T06, S10-T07, S10-T08, S10-T09, S10-T09b, S10-T10, S10-T11, S10-T12, S10-T13, S10-T14, S10-T15, S10-T16, S10-T17, S10-T18, S10-T19, S10-T20, S10-T21, S10-T22, S10-T23, S10-T24, S10-T25, S10-T26, S10-T27, S10-T30, S10-T31`.

**Cross-subsystem integration deliverable.**
The **Spine Integration Slice**: a scripted flow that mints a budget+scope token (S10-T02), launches a digest-pinned image in a gVisor sandbox with default-deny egress (S10-T06/T08/T09/T20), writes a small artifact through the store-writer broker (S10-T14) which lands a complete, hashed, lineage-linked C4 ArtifactRecord in S8 (S8-T07), and emits launch provenance (S10-T19 → S8-T07). The C4 record is then read back with verify-on-read (S8-T21) and its lineage queried (S8-T12). All six contract binding packages are consumable from a fresh checkout with the CI drift gate green.

**Demo / acceptance test.**
"Foundations are trustworthy and the seams are stable." Run: (a) meta-validate + round-trip all six schemas across three languages, including C3 v1.1 with its six new ValidationReport fields present and additive-compatible (CI drift gate green; S3-TPR1); (b) attempt a write with incomplete lineage → rejected fail-closed (S8-TC07); (c) attempt to overwrite a write-once artifact → blocked (S8-TC13); (d) tamper with a committed record → detected via Merkle chain (S8-TC22/TC23); (e) run the red-team escape battery in the sandbox → 0/N escapes (S10-TC20/TC26); (f) run a sandbox past its budget → halt within SLA with partial capture (S10-TC12/TC13); (g) confirm no secret-shaped value reaches the sandbox and direct bucket writes are egress-denied (S10-TC05/TC15/TC36).

**Parallel tracks.**
- **Track A (Contracts):** the six schema-authoring roots (S1-T01/T03/T25/T30, S3-T01/S3-TPR1, S5-T01/T31, S7-T01/T02, S8-T01/T02/T04/T27, S2-T01) — independent per contract; only cross-touch is C4 being consumed by others' bindings. C3 is authored directly at v1.1 (six new fields) so no later migration is needed.
- **Track B (S8 data plane):** all remaining S8 tasks — depends only on the C4 schema root + base infra.
- **Track C (S10 substrate):** all S10 M0 tasks — depends only on the S10 schema root + base infra.
Tracks B and C are fully independent of each other except at the two integration touchpoints (store-writer broker → S8 writer; launch provenance → S8), which are wired last in M0.

---

## M1 — One Vertical Slice, Oracle-Gated

**Goal.** Prove *verify-before-trust* on one real subtopic end-to-end: a single C1 subagent (S1 runtime) driving an S2 classical/tabular baseline build, calling one or two S7 physics adapters for physics-aware features/targets, and handing a frozen pipeline to a minimal S3 verifier (injection + null + physical-consistency) that returns a **signed** ValidationReport. The minimal S3 verifier now explicitly includes the **bidirectional perturbation oracle**: a MUST-REACT / MUST-NOT-REACT perturbation-pair runner (S3-TPR2), an **insensitivity detector** that FAILs any claim invariant to a perturbation it should have reacted to (S3-TPR3), and **non-gameable referee enforcement** — the referee is oracle-backed, signed, and `distinct_from_proponent` (referee != builder) (S3-TPR4). Claim-tiering is wired end-to-end to `ran-toy` / `recapitulated-known`, with structural prevention of self-promotion and self-attestation.

**Entry criteria.**
- M0 exit met: C1..C6 frozen; S8 and S10 operational.
- A target subtopic chosen with an established result available for recapitulation and at least one independent physics code for the adapter set.

**Exit criteria.**
- The full C1 lifecycle (REGISTERED→…→REPORTED) runs for one reference subagent, executing only in S10 and emitting fail-closed C4 provenance for every artifact.
- S2 builds a deterministic frozen inference pipeline (features + model + calibration) with mandatory uncertainty, capped at `ran-toy`, with no self-grading path.
- At least two S7 reference adapters (a bounce/effective-potential wrapper + a GW-spectrum solver, one with an independent twin) are registered, units/uncertainty/domain-tagged, and callable via the broker with per-call provenance.
- S3 runs INJECTION, NULL_CONTROL, and PHYSICAL_CONSISTENCY over a blind-data vault against the frozen pipeline in a nested sandbox, assembles a canonicalized, signed, write-once ValidationReport, and assigns a tier deterministically. The subagent's `report()` sources tier **only** from that signed report.
- S3 runs **bidirectional perturbation pairs** via `run_perturbation_pair(model_ref, perturbation_spec)`: a MUST-REACT probe plants a known-real signal and requires proportional, amplitude-linear recovery (no recovery → FAIL); a MUST-NOT-REACT probe injects noise / shuffled labels / fake-contamination and requires appropriate degradation (a strong result surviving unchanged → FAIL). Results populate `perturbation_pairs` on the C3 v1.1 ValidationReport (S3-TPR2).
- S3's **insensitivity detector** (`detect_insensitivity(model_ref, perturbation_set)`) flags any claim invariant to a perturbation it should have reacted to (memorized / constant / spurious-feature) and populates `insensitivity_flags`; a claim passes only when BOTH perturbation directions pass AND no insensitivity is detected (S3-TPR3).
- **Non-gameable referee enforcement**: the referee is S3 (oracle-backed), signs the report, and is structurally `distinct_from_proponent` — the builder cannot self-attest; the `referee` field records `referee_id`, `non_gameable`, `signed_by`, and `distinct_from_proponent` (S3-TPR4).

**Included subtask IDs.**

*S1 subagent framework/runtime (full — the contract's reference implementation):*
`S1-T02, S1-T04, S1-T05, S1-T06, S1-T07, S1-T08, S1-T09, S1-T10, S1-T11, S1-T12, S1-T13, S1-T14, S1-T15, S1-T16, S1-T17, S1-T18, S1-T19, S1-T20, S1-T21, S1-T22, S1-T23, S1-T24, S1-T26, S1-T27, S1-T28, S1-T29`.
*(S1-T01/T03/T25/T30 were delivered in M0.)*

*S2 ML builder (baseline path sufficient for one slice; deep/advanced families deferred to M4):*
`S2-T02, S2-T03, S2-T04, S2-T05, S2-T06, S2-T07, S2-T08, S2-T10, S2-T11, S2-T12, S2-T13, S2-T15, S2-T16, S2-T17, S2-T18, S2-T19, S2-T20, S2-T22, S2-T23, S2-T24`.
*(S2-T01 in M0; deep families S2-T09, HPO S2-T14, Evolver-facing build_variant S2-T21, conformance/perf hooks S2-T25/T26 deferred.)*

*S7 physics adapters (SDK, backends, broker, provenance, two+ reference adapters):*
`S7-T03, S7-T04, S7-T05, S7-T06, S7-T07, S7-T08, S7-T09, S7-T10, S7-T11, S7-T12, S7-T13, S7-T14, S7-T15, S7-T16, S7-T17, S7-T19, S7-T20, S7-T21, S7-T22, S7-T23, S7-T24, S7-T27, S7-T28, S7-T32`.
*(Independence resolution S7-T18, determinism and security hardening are T19/T21-in-M1; multi-adapter breadth S7-T25, CLI S7-T26, version/revocation S7-T29/T30, perf S7-T31 deferred to M3/M4.)*

*S3 minimal-but-real verifier (schema in M0; core service + three check families + tiering + signing + bidirectional perturbation oracle + insensitivity detector + non-gameable referee):*
`S3-T02, S3-T03, S3-T04, S3-T05, S3-T06, S3-T07, S3-T08, S3-T09, S3-T10, S3-T11, S3-T12, S3-T13, S3-T15, S3-T16, S3-T17, S3-T19, S3-T22, S3-T23, S3-T26, S3-T30, S3-TPR2, S3-TPR3, S3-TPR4`.
*(Cross-code S3-T18, leakage S3-T20, calibration S3-T21, recap-benchmark S3-T24, challenge/canary S3-T25, independence resolver S3-T14, cost metering S3-T27, author tooling S3-T28, observability S3-T29, reward-for-recursion contract S3-T31, perf S3-T32, security audit S3-T33, and challenger-independence attestation S3-TPR5 land in M2/M3/M4/M5.)*

**Cross-subsystem integration deliverable.**
The **Oracle-Gated Vertical Slice**: S5 is not yet present, so the slice is driven via the S1 CLI / a thin harness. One reference subagent accepts a job, S2 builds a frozen pipeline using S7 adapter-derived features (with propagated uncertainty), S1 freezes and hands the blind pipeline handle to S3, S3 runs the three checks in a verifier-zone sandbox against the blind vault, and returns a signed ValidationReport whose tier flows back through `report()` into a C4-coupled artifact. `recapitulated-known` is achievable only when the subtopic's established result is recovered under injection + null + physical-consistency.

**Demo / acceptance test.**
"One subtopic, verified, tiered, and un-self-promotable." (a) Recapitulate the chosen established result and obtain a **signed** `recapitulated-known` ValidationReport (S3-TC32 e2e signed report; S1-TC15/T15b/T31 blind handoff). (b) Verify the signature offline via the shipped library (S3-TC02/TC03). (c) Confirm the subagent has no `set_claim_tier` and cannot self-promote (S1-TC07/TC24; S2-TC11/TC33). (d) Confirm the frozen pipeline runs in an egress-denied sandbox with labels never delivered and any sandbox write raising Sev-1 (S3-TC25/TC26/TC27/TC44). (e) Confirm the independent-twin GW adapter agrees within uncertainty on a grid (S7-TC26). (f) MUST-REACT: plant a known-real signal and confirm the claim recovers it proportionally (amplitude-linear); a blind/insensitive claim FAILs (S3-TC51-PR). (g) MUST-NOT-REACT: feed pure noise / shuffled labels and confirm the claim manufactures no signal and degrades appropriately (S3-TC52-PR). (h) Insensitivity → FAIL: a claim invariant to a contamination it should have reacted to is caught by the insensitivity detector (S3-TC53-PR). (i) Referee != builder: a builder self-attestation is rejected — the referee must be `distinct_from_proponent` and signed (S3-TC55-PR).

**Parallel tracks.**
- **Track A (S1 runtime):** the entire S1 stack — depends on M0 C1 schema + S8/S10.
- **Track B (S7 adapters):** SDK/backends/broker + reference adapters — depends on M0 C6 schema + S8/S10; independent of S1 except the reference example test (S1-T28) consumes a C6 adapter.
- **Track C (S2 builder):** baseline build path — depends on S1 (lifecycle) and S7 (forward-model injector S2-T05) at integration time; internal S2 work (units, features, zoo, training, UQ, freezer) proceeds against mocks until S1/S7 land.
- **Track D (S3 verifier):** core service + checks + bidirectional perturbation oracle + insensitivity detector + non-gameable referee — depends on M0 C3 v1.1 schema + S8/S10 and on S7 for the cross-code check (deferred), so the three M1 checks (injection/null/physical) and the perturbation-pair/insensitivity/referee machinery (S3-TPR2/TPR3/TPR4) have no hard S2/S7 runtime dependency and can be built against a stub frozen pipeline; final wiring consumes the real S1-frozen pipeline and S7 adapters. The referee!=builder separation (S3-TPR4) is a structural precondition for the M5 red-blue debate.

---

## M2 — Orchestration & Provenance at Scale

**Goal.** Turn the single slice into a governed multi-job platform: stand up the Control Tower (S5, owner of C2) with durable DAG execution, budget/concurrency governance, routing, retries, and human-gate wait-state plumbing; complete the S8 provenance-at-scale surfaces; and stand up the S11 observability spine with the re-run reproducibility canary that proves artifacts are reproducible.

**Entry criteria.**
- M1 exit met: a signed ValidationReport is produced on one slice; S1/S2/S3/S7 baseline operational.
- C2 frozen (M0). S9 not yet built — S5 wires *coordinator wait states* against an S9 stub/mock this milestone; the live S9 gate lands in M4.

**Exit criteria.**
- S5 accepts a request, plans an inspectable deterministic DAG bound to verifier profiles, mints immutable envelopes + least-privilege scopes + metered budget tokens, routes to subagents via C5 (against the M3 registry once available; against a registry stub until then), executes durable restart-safe DAGs mapped to the C1 lifecycle, gates downstream nodes on provenance-commit + tier/report coupling, meters spend with hard-breach halt, and handles refusals/retries/typed errors/cancellation.
- S8 provenance-at-scale surfaces (retraction cascade, impact-set at 10^5 nodes, reproducibility manifests) validated under load.
- S11 telemetry gateway, trace assembly, KPI registry/streaming, transparency-failure + reward-hacking detectors (read-only), and the **re-run reproducibility canary** operate against live S3/S8/S10; scorecards/canary verdicts written as C4 artifacts.

**Included subtask IDs.**

*S5 Control Tower (full):*
`S5-T02, S5-T02b, S5-T03, S5-T04, S5-T05, S5-T06, S5-T07, S5-T08, S5-T09, S5-T10, S5-T11, S5-T12, S5-T13, S5-T14, S5-T15, S5-T16, S5-T17, S5-T18, S5-T19, S5-T20, S5-T21, S5-T22, S5-T23, S5-T24, S5-T25, S5-T26, S5-T27, S5-T28, S5-T29, S5-T30, S5-T32`.
*(S5-T01/T31 delivered in M0. Note: S5-T21 Recursion Governor and S5-T18/T19 human-gate plumbing are built here but exercised end-to-end only once S4 (M5) and S9 (M4) are live; they are tested against mocks/stubs in M2.)*

*S8 remaining provenance-at-scale surfaces held for load context:*
*(All S8 tasks were delivered in M0 as the foundational plane; the retraction-cascade + perf harnesses S8-T25/T26 are re-run here as scale-acceptance gates rather than new development. No new S8 IDs are introduced in M2 — S8 is 100% covered in M0.)*

*S11 observability spine + reproducibility canary (core):*
`S11-T01, S11-T02, S11-T03, S11-T04, S11-T05, S11-T06, S11-T07, S11-T08, S11-T09, S11-T10, S11-T11, S11-T12, S11-T13, S11-T14, S11-T16, S11-T22, S11-T23, S11-T24, S11-T25, S11-T26, S11-T28, S11-T29, S11-T30, S11-T31, S11-T33, S11-T34, S11-T35`.
*(Eval/benchmark harnesses S11-T15/T17/T18/T19/T20/T21/T27/T32 land in M5 with the benchmark theme; T21 scorecard-C4-writer is pulled to M5 with the harnesses it serves.)*

**Cross-subsystem integration deliverable.**
The **Governed DAG**: S5 decomposes a two-node request (build→verify), obtains human/mock approval, mints envelopes and budget tokens, routes to the M1 subagent, executes the durable DAG, gates the verify node on the build's provenance commit, collects a signed S3 report, and event-sources every transition to S8. In parallel, S11 assembles the end-to-end trace (S5→S1→S2→S7→S3), and the re-run canary independently re-executes the frozen pipeline in S10 (and/or issues an S3 `challenge`) to confirm bit-exact/within-tolerance reproduction, writing a `CanaryResult` C4 artifact.

**Demo / acceptance test.**
"A governed, reproducible, budgeted job." (a) Submit a request; watch S5 produce a deterministic DAG preview, require approval before any spend, and execute it durably across a forced worker restart with no double-dispatch (S5-TC18). (b) Force a budget breach and observe halt-within-interval + partial capture + quarantine (S5-TC11/TC30). (c) Feed an illegal-tier input downstream → blocked (S5-TC12/TC13/TC33). (d) The re-run canary reproduces the M1 artifact and flags a deliberately perturbed pipeline as non-reproducible (S11-TC06/TC07/TC14/TC25). (e) The transparency-failure detector flags a synthetic tier-without-report record (S11-TC15/TC26).

**Parallel tracks.**
- **Track A (S5 core execution):** intake→planner→envelope→router→executor→gating→budget→scheduler — internal to S5, built against C1/C3/C4/C5 stubs from the S5 test harness (S5-T32), then wired to live S1/S3/S8.
- **Track B (S11 observability):** gateway→collector→storage→consumers→trace-assembly→KPIs→detectors→canary — depends on S8/S3/S5 events; read-only, so it never blocks A.
- **Track C (S8 scale hardening):** retraction-cascade + 10^5-node perf re-runs — independent, gated only by M0 S8 completion.
These three tracks share only the NATS event contracts and C4 read paths, which are frozen from M0.

---

## M3 — Knowledge, Registry & Contamination Control

**Goal.** Stand up S6 (bulk ingest of arXiv/GitHub/HEPData, curated-doc RAG, the registry/C5, and the frozen contamination index), and complete the S3 checks that depend on it (leakage/novelty). This unlocks registry-driven routing in S5, cross-code independence resolution, and the ability to responsibly separate `recapitulated-known` from `novel`. It also adds **challenger-independence attestation** (S3-TPR5): `attest_challenger_independence(challenger_ids[]) -> IndependenceAttestation`, verifying that a challenger panel is **lineage-disjoint cross-code** (min independent challengers, `lineage_disjoint`, `correlation_warning`) — the independence guarantee the M5 red-blue debate panel depends on.

**Entry criteria.**
- M2 exit met: S5 orchestration + S11 canary live (routing currently against a registry stub).
- C5 schema frozen (M0). S3 core live (M1).

**Exit criteria.**
- S6 ingests and normalizes arXiv/GitHub/HEPData into content-addressed C4 artifacts under S10 isolation with egress allowlists; produces a hybrid (lexical+vector) RAG that measurably lowers plausible-but-wrong rates on a fixed eval set; serves the registry (publish/get/resolve/deprecate/revoke) with immutable signed C5 revisions and independence resolution; and freezes an immutable, signed, integrity-verified **contamination index** snapshot.
- S3 LEAKAGE, CALIBRATION, CROSS_CODE, recap-benchmark, and independence-resolution checks are live and consume the S6 frozen index and S7 independent adapters; S3 challenge/canary + cost metering + author tooling + observability + reward-for-recursion contract + perf/security hardening complete.
- S3 **challenger-independence attestation** (S3-TPR5) is live: `attest_challenger_independence(challenger_ids[])` produces an IndependenceAttestation (`min_independent_challengers`, `lineage_disjoint`, `correlation_warning`) and populates the C3 v1.1 `challenger_panel` + `independence_attestation_debate` fields; correlated / lineage-overlapping challengers are flagged so the M5 debate panel can be refreshed.
- S5 router now resolves real C5 descriptors and honors independence + revocation.
- S7 completes independence metadata, the remaining reference adapter breadth, CLI, version negotiation/revocation, and perf.

**Included subtask IDs.**

*S6 knowledge/ingestion/registry/contamination (full):*
`S6-T01, S6-T02, S6-T03, S6-T04, S6-T05, S6-T06, S6-T07, S6-T08, S6-T09, S6-T10, S6-T11, S6-T12, S6-T13, S6-T14, S6-T15, S6-T16, S6-T17, S6-T18, S6-T19, S6-T20, S6-T21, S6-T22, S6-T23, S6-T24, S6-T25, S6-T26, S6-T27, S6-T28, S6-T29, S6-T30, S6-T31, S6-T32, S6-T33, S6-T34, S6-T35`.

*S3 contamination-dependent + hardening checks + challenger-independence attestation (completing S3):*
`S3-T14, S3-T18, S3-T20, S3-T21, S3-T24, S3-T25, S3-T27, S3-T28, S3-T29, S3-T31, S3-T32, S3-T33, S3-TPR5`.
*(S3 is now 100% covered: M0=T01,TPR1; M1=T02..T13,T15,T16,T17,T19,T22,T23,T26,T30,TPR2,TPR3,TPR4; M3=T14,T18,T20,T21,T24,T25,T27,T28,T29,T31,T32,T33,TPR5.)*

*S7 completion (independence, breadth, CLI, versioning, perf):*
`S7-T18, S7-T25, S7-T26, S7-T29, S7-T30, S7-T31`.
*(S7 now 100% covered.)*

**Cross-subsystem integration deliverable.**
The **Contamination-Aware Novelty Gate**: S6 freezes a contamination-index snapshot and registers it as a C5 entity; S3's LEAKAGE plugin queries that frozen index (read-only, pinned version) and, together with CROSS_CODE (via S3-T14 independence resolver + S7 independent twin) and CALIBRATION, gates any promotion above `recapitulated-known`. The recap-benchmark gate (S3-T24) is required before `recapitulated-known` for known subtopics. S5's router (S5-T08/T17) now consumes real C5 descriptors and halts on revocation.

**Demo / acceptance test.**
"Contamination is presumed and screened; routing is registry-driven." (a) Show the curated-RAG A/B harness delivering ≥30% relative reduction in physical-consistency-gate failures with p<0.05 (S6-TC16/S6-T34). (b) Freeze the contamination index, tamper with the snapshot, and confirm fail-closed detection on read (S6-TC24/S6-T26). (c) Run LEAKAGE against a planted train/test overlap → FAIL blocks novelty (S3-TC17/TC18/TC48). (d) Resolve an independent cross-code that excludes the code-under-test (S3-TC24; S6-TC06/TC19b) and run CROSS_CODE agreement (S3-TC09/TC10/TC11/TC47). (e) Revoke a descriptor and watch S5 halt in-flight jobs referencing it (S5-TC16; S6-TC14). (f) Attest a challenger panel: a lineage-disjoint cross-code panel passes, while a panel with correlated / lineage-overlapping challengers is flagged (`correlation_warning`, `lineage_disjoint=false`) (S3-TC54-PR).

**Parallel tracks.**
- **Track A (S6 ingestion+RAG):** connectors→orchestrator→normalizer→chunker→embedder→index→retrieval→curation — depends on S8/S10 only; the registry and contamination sub-tracks branch off internally.
- **Track B (S6 registry/C5 + contamination index):** publish/resolve/revoke + freeze/novelty/integrity — depends on S8/S10 and the C5 schema; feeds S3 and S5.
- **Track C (S3 contamination-dependent checks + hardening + challenger-independence attestation):** LEAKAGE/CROSS_CODE/CALIBRATION/recap/challenge/independence + challenger-independence attestation (S3-TPR5) — depends on S6 Track B (frozen index, independence resolve) and S7 independence metadata; the challenger-independence attestation reuses the cross-code lineage machinery and feeds the M5 debate panel.
- **Track D (S7 completion):** independence metadata, adapter breadth, CLI, versioning, perf — depends on S6 registry for resolve support, otherwise independent.
Tracks A and B run concurrently; C waits on B's frozen-index + resolve endpoints; D waits on B's registry.

---

## M4 — Breadth Rollout & Human Governance

**Goal.** Deliver the core value proposition — cover the long tail of subtopics that have no ML today — by onboarding many subtopic subagents (breadth-over-depth), while standing up the mandatory, non-bypassable human gate: S9 review queues, claim-tier review UI, publication guardrails, emission authorization, and rate-limits sized to human review capacity. Complete the S2 deep/physics-informed families and HPO that breadth requires.

**Entry criteria.**
- M3 exit met: S6 knowledge/registry/contamination live; S3 fully hardened; S5 routing registry-driven.
- S11 KPIs live (M2) to feed S9 evidence panels and back-pressure sizing.

**Exit criteria.**
- S9 is live as the sole (with S3) promoter of `novel-needs-human`: intake with signature/hash verification and guardrail pre-screen, review-task state machine with single/dual/quorum sign-off and COI enforcement, hash-chained governance ledger, HSM-signed single-use emission authorizations, rate limits + emission budgets + back-pressure gauge published to S5, review UI (queue + claim-tier detail + governance/admin consoles), WebAuthn step-up, S5-Temporal wait-state integration, federation-admission review flow, and full degradation/fail-closed handling.
- S5's human-gate wait states (S5-T18/T19), external-emission rate limiting, and non-goal guardrails are now exercised end-to-end against live S9.
- S2 deep/physics-informed families, HPO, Evolver-facing `build_variant`, and conformance/perf hooks complete — enabling breadth of model classes and readiness for M5 recursion.
- Many subtopic subagents onboarded (breadth), each conforming to C1 and gated by S3.

**Included subtask IDs.**

*S9 human-in-the-loop review & governance (full):*
`S9-T01, S9-T02, S9-T03, S9-T04, S9-T05, S9-T06, S9-T07, S9-T08, S9-T09, S9-T10, S9-T11, S9-T12, S9-T13, S9-T14, S9-T15, S9-T16, S9-T17, S9-T18, S9-T19, S9-T20, S9-T21, S9-T22, S9-T23, S9-T24, S9-T25`.

*S2 completion (deep families, HPO, build_variant, conformance/perf hooks):*
`S2-T09, S2-T14, S2-T21, S2-T25, S2-T26`.
*(S2 now 100% covered: M0=T01; M1=T02..T08,T10..T13,T15..T20,T22,T23,T24; M4=T09,T14,T21,T25,T26. Note: S2-T21 build_variant and S2-T25 recursion-safe hooks are delivered here as prerequisites for S4 in M5.)*

**Cross-subsystem integration deliverable.**
The **Human Gate + Breadth Fleet**: multiple subtopic subagents run through S5, each producing S3-signed reports; when S3 assigns `novel-needs-human`, S5 (S5-T18) pauses the DAG on a Temporal wait state and opens an S9 review task carrying the signed report, C4 lineage, S6 novelty context (vs frozen index), and S11 calibration view (S9-T15). A reviewer signs off under COI/quorum rules; only then does S9 mint a single-use, scope-bound, HSM-signed emission authorization (S9-T09), and S5 resumes. External-emission rate limiting + back-pressure (S5-T19 ↔ S9-T10) keep intake sized to review capacity.

**Demo / acceptance test.**
"Nothing external escapes without human sign-off; breadth is real." (a) A `novel-needs-human` candidate pauses the DAG, appears in the review queue with all four evidence sources pinned by content hash, and cannot be emitted until a fresh WebAuthn-stepped-up sign-off mints a single-use emission token (S9-TC14/TC19/TC26/TC29). (b) A non-goal emission class is hard-blocked non-overridably at intake and execution (S9-TC03/TC22/TC23; S5-TC26). (c) Drive many subagents concurrently across distinct subtopics, each gated by S3, with back-pressure engaging near S9 capacity (S5-TC31; S9-TC08/TC09). (d) Tamper with a report at intake → rejected (S9-TC01/TC02); forge/replay an emission token → rejected (S9-TC20/TC25/TC34).

**Parallel tracks.**
- **Track A (S9 core gate):** contract binding→ledger storage→signature module→intake→state machine→sign-off→emission minter — depends on S8/S3/S6/S11 read surfaces; internal to S9.
- **Track B (S9 UI + admin + WebAuthn + notifications + audit):** review UI, governance/admin consoles, step-up, SLA/escalation, audit export — depends on Track A APIs.
- **Track C (S5↔S9 integration):** Temporal wait-state adapters, rate-limit/back-pressure coupling, federation-admission flow — the only cross-subsystem seam; S5 side already built in M2 against mocks, now wired live.
- **Track D (S2 completion):** deep families, HPO, build_variant, conformance hooks — independent of S9 entirely; gated only by M1 S2 baseline.
Track D runs fully parallel to A/B/C; the breadth onboarding of subagents proceeds against S1/S2/S3/S5/S6 already live from prior milestones.

---

## M5 — Adversarial Red-Blue Debate Evolution (recursion under oracle)

**Goal.** Enable the Evolver (S4) — Argus's highest-leverage and highest-risk capability — as **Adversarial Red-Blue Debate Evolution**: the self-improvement loop becomes a multi-agent adversarial peer-review embedded in evolution. The Builder subagent is the **PROPONENT** (candidate model + claim); a panel of **>=K INDEPENDENT** (lineage-disjoint, cross-code) red-team agents are the **CHALLENGERS** that attack the claim with evidence (signal-injection, null-noise, label-shuffle, data-contamination, alt-analysis); and S3 is the oracle-backed, non-gameable **REFEREE** (`distinct_from_proponent`) that adjudicates via a ChallengeVerdict requiring `must_react_pass` AND `must_not_react_pass` AND NOT `insensitivity_detected`. The loop runs with hard bounds, diversity control, and reward-hacking + challenger-collusion defenses, **only** where a cheap valid S3 verifier + oracle exists (precondition gate), scoring **only** from a signed S3 report, and records every ChallengeRound append-only in the C4 **DebateLedger**. Add the S11 benchmark/eval harnesses (MLE-bench-style agent-ML + physics held-out recapitulation + planted-exploit reward-hacking canary) **plus a planted-spurious-model detection harness** (S11) that seeds models which survive only by ignoring data, to confirm the insensitivity detector + red team kill them before the human gate.

**Entry criteria.**
- M4 exit met: verifier fully hardened (M3), provenance/audit at scale (M2/M8-plane), sandbox+budget controls (M0), human gate (M4), and S2 `build_variant` + recursion-safe hooks (M4) all proven.
- S5 Recursion Governor (S5-T21) live and coupled to S3's reward-for-recursion contract (S3-T31, M3).
- The referee machinery is proven: bidirectional perturbation oracle + insensitivity detector + referee!=builder (S3-TPR2/TPR3/TPR4, M1) and challenger-independence attestation (S3-TPR5, M3) are all live — the red-blue debate consumes them directly.

**Exit criteria.**
- **Precondition gate (S4-TDB3):** S4 refuses to enter the loop absent a cheap, applicable, signer-trusted S3 verifier + oracle and independent cross-code (tier-capping enforced) — recursion only under an oracle.
- **Debate-round orchestrator (S4-TDB1):** `run_debate_round(candidate_ref, challenger_pool, referee) -> ChallengeRound` drives the proponent / challenger / referee loop: the proponent produces a candidate; each challenger runs Attacks (`signal_injection` / `null_noise` / `label_shuffle` / `data_contamination` / `alt_analysis`); the referee (S3, != proponent, signed) adjudicates via ChallengeVerdict; every ChallengeRound is recorded.
- **Independent challenger-panel selection + diversity policy (S4-TDB2):** `select_challenger_panel(subtopic, k, diversity_policy) -> challenger_ids[]` selects >=K challengers, lineage-disjoint, diverse across attack types AND code lineages; independence is attested via S3-TPR5.
- **Red-blue evolution loop under the precondition gate (S4-TDB3):** `evolve_under_debate(seed_candidate, budget, stop_criteria) -> EvolutionResult` runs a durable, deterministic, replayable loop delegating training to S2 (in S10) and refereeing to S3; admits fitness **only** from signature-valid, report-bound scores (INCONCLUSIVE = non-improvement); halts on hard budget/generation/round bounds with partial capture; quarantines fail-loud on any anomaly.
- **Reward-hacking + challenger-collusion screens (S4-TDB4):** detect proponent overfitting to a fixed challenger set (profile-invariance probe), detect challenger correlation / collusion, detect referee tampering; refresh challenger diversity each round; the red-team suite catches 100% of seeded scenarios.
- **DebateLedger provenance emission via C4 (S4-TDB5):** every ChallengeRound is appended to the C4 DebateLedger for the artifact, and the signed C3 v1.1 ValidationReport carries a `debate_ref` pointer into it; claim tier is set by survival.
- **Feedback -> revise -> retrain step (S4-TDB6):** on FAIL the referee emits structured feedback; the proponent revises/retrains and enters the next round under refreshed challenger diversity.
- S4 hands `novel-needs-human` results to S9 via S5 without self-promotion or external emission; the builder cannot self-sign (referee!=proponent), so emission is blocked at S9 if attempted.
- S11 benchmark/eval harnesses (agent-ML MLE-bench-style, physics held-out recapitulation, planted-exploit canary) **plus the planted-spurious-model detection harness** run with label isolation and write scorecards as C4 artifacts; planted-spurious models (survive only by ignoring data) are caught by the insensitivity detector + red team pre-human-gate at 100%. Platform KPIs (cost-per-verified-artifact, reward-hacking-catch rate, insensitivity-catch rate, challenger-independence-enforced rate, referee-!=-proponent separation, reproducibility rate) live in the daily Trust Digest.

**Included subtask IDs.**

*S4 recursive improvement loop / Evolver — Adversarial Red-Blue Debate Evolution (full):*
`S4-T01, S4-T02, S4-T03, S4-T04, S4-T05, S4-T06, S4-T07, S4-T08, S4-T09, S4-T10, S4-T11, S4-T12, S4-T13, S4-T14, S4-T15, S4-T16, S4-T17, S4-T18, S4-T19, S4-T20, S4-T21, S4-T22, S4-T23, S4-T24, S4-T25, S4-TDB1, S4-TDB2, S4-TDB3, S4-TDB4, S4-TDB5, S4-TDB6`.
*(S4-TDB1 debate-round orchestrator; S4-TDB2 independent challenger-panel selection + diversity policy; S4-TDB3 red-blue evolution loop under the precondition gate; S4-TDB4 reward-hacking + challenger-collusion screens; S4-TDB5 DebateLedger provenance emission via C4; S4-TDB6 feedback -> revise -> retrain step.)*

*S11 evaluation/benchmark harnesses + planted-exploit canary + planted-spurious-model detection harness + digest (completing S11):*
`S11-T15, S11-T17, S11-T18, S11-T19, S11-T20, S11-T21, S11-T27, S11-T32`.
*(S11 now 100% covered: M2=T01..T14,T16,T22,T23,T24,T25,T26,T28,T29,T30,T31,T33,T34,T35; M5=T15,T17,T18,T19,T20,T21,T27,T32. The planted-spurious-model detection harness is added to the S11 benchmark suite — S11-T19/T20 physics-held-out + planted-exploit tracks are extended to seed spurious models that survive only by ignoring data.)*

**Cross-subsystem integration deliverable.**
The **Oracle-Gated Red-Blue Debate + Benchmark Loop**: S5's Recursion Governor schedules bounded generations as child jobs; the S4-TDB3 precondition gate refuses to run without a cheap valid S3 verifier + oracle. Per generation, the proponent (Builder) produces a candidate (typed operators + LLM proposer, both untrusted, running only in S10) and trains it via C1.build→S2 (idempotent by frozen-pipeline hash); S4-TDB2 selects an independent, lineage-disjoint, attack-diverse challenger panel (independence attested via S3-TPR5); each challenger runs its Attacks (signal_injection / null_noise / label_shuffle / data_contamination / alt_analysis); the referee (S3, != proponent, signed) adjudicates via C1.validate→C3.verify + `run_perturbation_pair` + `detect_insensitivity`, emitting a ChallengeVerdict that requires `must_react_pass` AND `must_not_react_pass` AND NOT `insensitivity_detected`. Fitness is admitted only from the signed report (Rust sig-verify hot path). On FAIL (S4-TDB6) the referee emits structured feedback, the proponent revises/retrains, and the next round runs under refreshed challenger diversity. Reward-hacking + collusion screens (S4-TDB4) catch proponent-overfit-to-fixed-panel, challenger correlation/collusion, and referee tampering. Every ChallengeRound is appended to the C4 DebateLedger (S4-TDB5) and referenced by `debate_ref` in the emitted C3 v1.1 ValidationReport. In parallel, S11's harnesses run the whole platform against held-out physics and agent-ML benchmarks, and the planted-exploit canary + planted-spurious-model detection harness (coordinated with S3's injection channel, no blind labels to S11) confirm the reward-hacking-catch and insensitivity-catch rates.

**Demo / acceptance test.**
"Self-improvement that is verified through adversarial debate, not reckless." (a) Point S4 at a subtopic with no verifier/oracle → immediate REFUSED at the precondition gate, loop never entered (S4-TC01/TC02; S4-TC42-DB; S4-TDB3). (b) Run a real recapitulation benchmark; S4 improves the incumbent only on signature-valid, report-bound gains, with unsigned/tampered/replayed reports rejected (S4-TC04/TC05/TC11/TC12/TC13/TC25). (c) The red-team harness registers deliberately hackable verifier stubs (leaked label, replayable report, verifier-quirk-overfit) and S4 catches 100% pre-admission (S4-TC12/TC13/TC17/TC28). (d) Breach the budget mid-run → halt within one generation, partial capture, ledger no double-spend (S4-TC14/TC32/TC38). (e) Replay a completed run from checkpoints → identical winning-variant hash (S4-TC36; S4-TC16/TC22/TC39). (f) The physics held-out harness rediscovers established results and flags any false-novel (S11-TC19/TC20/TC21); planted exploits are excluded from real KPI denominators (S11-TC33). (g) The debate loop FAILs a candidate, feeds structured feedback, and converges over rounds (S4-TC41-DB). (h) A **planted-spurious model** (survives only by ignoring data) is killed by the insensitivity detector + red team before the human gate (X-14; S4-TC41-DB; S11 planted-spurious-model harness). (i) A challenger panel with correlated / lineage-overlapping challengers is detected and the panel is refreshed (S4-TC44-DB; S3-TC54-PR). (j) A proponent overfitting to a fixed challenger set is caught by the reward-hacking screen (S4-TC43-DB). (k) The DebateLedger is recorded in C4 and referenced by `debate_ref` (S4-TC45-DB).

**Parallel tracks.**
- **Track A (S4 decision core):** data models→precondition/cost/independence gates→gene/operators→population/archive→selector→workflow→checkpointer→provenance/genealogy→control APIs→quarantine — internal to S4; depends on S2 (build_variant), S3 (verify + reward contract), S5 (recursion governor), S8/S10.
- **Track B (S4 red-blue debate + reward defense):** debate-round orchestrator (S4-TDB1), independent challenger-panel selection + diversity policy (S4-TDB2), red-blue evolution loop under the precondition gate (S4-TDB3), reward-hacking + challenger-collusion screens (S4-TDB4), DebateLedger provenance emission via C4 (S4-TDB5), feedback→revise→retrain (S4-TDB6), plus the admission gate / profile-invariance probe / physics-validation suite — depends on Track A workflow + S3 (referee, perturbation oracle, insensitivity detector, challenger-independence attestation from M1/M3).
- **Track C (S11 benchmark harnesses):** eval vault + scoring shim (label isolation), MLE-bench-style + physics held-out harnesses, planted-exploit canary, **planted-spurious-model detection harness**, scorecard C4 writer, digest — depends on S11 core (M2) + S3 injection channel; read/drive-only, so independent of S4 internals except the planted-exploit / planted-spurious coordination.
Tracks A and C run concurrently; B depends on A's workflow and on the S3-TPR* referee machinery but not on C.

---

## M6 — Federation & Interop Standard

**Goal.** Publish the SLHA-for-agents specification (S12), ship the contribution SDK/CLI and the Bronze/Silver/Gold conformance suite, and open the community registry/governance so external physicists build compliant subagents that gain **no elevated trust**. Deliberately last: it requires the contract, conformance suite, sandbox, and registry to all be mature and trustworthy before outsiders run code in the federation.

**Entry criteria.**
- M5 exit met: internal subagents proven across breadth (M4) and recursion (M5); C1 and C5 mature; S6 registry and S10 sandbox hardened; S3 conformance-relevant checks stable.

**Exit criteria.**
- S12 publishes immutable, signed StandardReleases with a semver compatibility checker + dual-serve/deprecation calendar; ships deterministic multi-language codegen, the `argus-sdk` (C1 lifecycle + C6 adapter surface), the `argus` CLI, and a signed, immutable, deterministic Bronze/Silver/Gold conformance suite executed in S10 with hermetic mocks.
- A Registry Gateway + admission gate publishes admitted entities to S6/C5 with `trust_class=federated` (no elevation), behind a hash-chained governance ledger, federation identity service, registrar review UI, revocation-propagation saga, versioned taxonomy service, public directory/discovery, appeals/abuse handling, security hardening, observability/KPIs, and re-run canary integration.
- External submissions run only in S10 with egress-deny; conformance evidence is signed and stored as C4; conformance auto-pass is invalidated on suite yank.

**Included subtask IDs.**

*S12 interop standard & federation (full):*
`S12-T01, S12-T02, S12-T03, S12-T04, S12-T05, S12-T06, S12-T07, S12-T08, S12-T09, S12-T10, S12-T11, S12-T12, S12-T13, S12-T14, S12-T15, S12-T16, S12-T17, S12-T18, S12-T19, S12-T20, S12-T21, S12-T22, S12-T23, S12-T24, S12-T25, S12-T26, S12-T27, S12-T28, S12-T29, S12-T30`.

**Cross-subsystem integration deliverable.**
The **Open Federation**: an external contributor scaffolds a subagent with the `argus` CLI, runs the local conformance shim (S10-equivalent offline), submits a signed bundle to the Registry Gateway, which verifies the signature/SBOM (out-of-sandbox KMS), runs the Bronze/Silver/Gold battery in S10 via the Conformance Service, emits a signed write-once ConformanceRecord, requires registrar approval through the governance engine (every action ledgered), and on approval publishes a `trust_class=federated` descriptor to S6/C5 — after which S5 can route to it exactly as an internal subagent, with S3 still gating every artifact and S9 still gating every external emission. Revocation propagates via the saga to S6/C5 and halts in-flight S5 jobs within SLA.

**Demo / acceptance test.**
"Outsiders can contribute; the trust model holds." (a) An external subagent completes REGISTERED→REPORTED via the SDK, passes Bronze/Silver/Gold in S10, and is admitted only after registrar sign-off, published as `federated` with no elevated scopes (S12-TC04/TC05/TC19/TC20; scopes always federation-default). (b) A tampered/unsigned bundle or a suspended identity is rejected pre-execution (S12-TC28/TC29/TC30). (c) Any trust-path write attempt during conformance quarantines the run and pages Sev-1 (S12-TC27/TC28/TC31). (d) Revoke a federated entity → C5 revoke + saga halts in-flight jobs or escalates within SLA (S12-TC21). (e) Yank a conformance suite → auto-pass invalidated, event emitted (S12-TC36); a flaky check disagreement quarantines and can trigger a yank via the S11 canary hook (S12-TC24). (f) An under-declared semver bump fails the CI gate (S12-TC01/TC02).

**Parallel tracks.**
- **Track A (S12 standard + SDK + CLI + codegen):** StandardRelease model→semver checker→codegen→standard service→docs→SDK→CLI — depends on C1/C4/C6 + S6 registry; internal to S12.
- **Track B (S12 conformance):** hermetic mocks→Bronze/Silver/Gold batteries→conformance service (S10 execution)→suite authoring→signer/SBOM→canary integration→security hardening — depends on S10 + C2/C3/C4/C6; the batteries reuse S1/S7 conformance semantics.
- **Track C (S12 governance/federation):** identity→registry gateway/admission→governance ledger/engine→revocation saga→taxonomy→directory→registrar UI→appeals/abuse→independence-recording→observability — depends on S6/C5 + S9 governance patterns.
Tracks A/B/C are internal to S12 and touch the rest of Argus only through frozen contracts (C1/C4/C5/C6), the S10 sandbox, and the S6 registry — all mature by M6.

---

## 7. Critical path

The critical path is the longest chain of milestones that cannot be compressed, each gating the next:

**M0 → M1 → M2 → M3 → M4 → M5 → M6**

Rationale for each edge:

- **M0 → M1.** The vertical slice cannot run without the frozen contracts, the S8 provenance plane, and the S10 sandbox. (S1/S2/S3/S7 all list S8+S10 as dependencies; S3 additionally needs S8's signed-report storage and blind vault built on S8/S10.)
- **M1 → M2.** S5 orchestrates *proven* subagents and gates on *signed* reports; it needs a working C1 subagent (S1) and a working C3 verifier (S3) to route to and gate on. S11's canary needs real artifacts + reports to reproduce.
- **M2 → M3.** S6's registry unlocks S5's registry-driven routing (already stubbed in M2), and S3's leakage/novelty/cross-code checks need S6's frozen contamination index and independence resolution. Building S6 after S5/S11 lets those consume it immediately.
- **M3 → M4.** S9's novelty gate needs S6's frozen index for novelty context and S3's fully-hardened cross-code/calibration/leakage gates to judge `novel-needs-human`; breadth rollout needs registry-driven routing (M3).
- **M4 → M5.** Recursion is enabled only after the verifier, provenance, sandbox, budget, human gate, and S2 `build_variant` are all proven. S4 structurally refuses to run without these. The Adversarial Red-Blue Debate Evolution loop additionally requires the referee machinery to exist first: the non-gameable referee (referee!=builder, S3-TPR4, M1), the bidirectional perturbation oracle + insensitivity detector (S3-TPR2/TPR3, M1), and the challenger-independence attestation (S3-TPR5, M3) — all delivered before M5 — so S4-TDB1..S4-TDB6 have a proven referee and an attestable independent challenger panel to build on.
- **M5 → M6.** Federation opens to outsiders only after internal subagents are proven across breadth and recursion and the conformance-relevant contract/sandbox/registry surfaces are mature.

**Longest single-subsystem chains inside milestones (the true schedule risk):** S8's `T01→T05→T07→T12` (data plane) and S10's `T01→T05→T08→T11` (sandbox/halt) in M0; S3's `T01/TPR1→T03→T09→T16/17/19→T22→T23` plus the perturbation-oracle branch `TPR1→TPR2→TPR3→TPR4` (M1) feeding `→TPR5` (M3) (verifier + referee machinery) in M1/M3; S5's `T01→T06→T10→T11` (durable executor) in M2; S4's `T01→T05/T07/T08/T09/T11→T12` (Temporal decision core, XL) and the red-blue debate branch `TDB3(precondition gate)→TDB2(panel)→TDB1(round orchestrator)→TDB4(reward/collusion screens)→TDB6(feedback→retrain)→TDB5(DebateLedger)` in M5; S12's `T13→T14` (Gold battery → conformance service, both XL) in M6. These are the tasks to staff most heavily.

---

## 8. Decoupling notes — how work streams stay independent

The architecture's premise is that teams communicate **only through published contracts**. The roadmap preserves that:

1. **Schemas are frozen in M0, before any consumer builds against them.** All six contract roots (C1..C6) plus each subsystem's schema/codegen root are front-loaded. A CI drift gate (S1-T02, S7-T02, S8-T04, S12-T02/T03) makes any incompatible change fail loudly, so downstream teams never chase a moving seam. Version negotiation + dual-serve (S5-T31, S7-T29, S8-T27, S12-T04) means a major bump never breaks in-flight consumers within the migration window.

2. **Every subsystem is built against hermetic mocks of its dependencies, then wired to the real thing at the milestone integration point.** S5 ships a full mock harness (S5-T32) for C1/C3/C4/C5/S8/S9; S12 ships hermetic C2/C3/C4/C6 mocks (S12-T10); S3's three M1 checks run against a stub frozen pipeline before the real S1 pipeline exists. This is what lets, e.g., the S5 executor (M2) and the S9 gate (M4) be developed in parallel with their eventual counterparts and only *coupled* at the integration seam.

3. **The dependency graph is a DAG rooted at S8 and S10.** Nothing depends on the graders it produces: S3 deliberately does **not** depend on S2/S4 (independence of the oracle); S8 and S10 depend on nothing in Argus (trust boundary at the bottom). The milestone order respects this — foundations (M0), then producers/verifier (M1), then meta-layer (M2), then knowledge (M3), then human layer (M4), then recursion (M5), then federation (M6) — so no milestone ever requires a subsystem that a later milestone owns.

4. **Read-only observers never block producers.** S11 (M2/M5) observes rather than participates; it holds only `obs.read` + own-output-write scopes (S11-T30) and can be developed and deployed without gating any producer. Its only "authority" (pause recommendation, non-promotable flag) is advisory and human-gated (S11-T31/T14).

5. **Cross-subsystem seams are explicit and few.** The load-bearing seams — store-writer-broker→S8 (M0), S1-frozen-pipeline→S3 (M1), S5-router→C5 (M2/M3), S5-wait-state↔S9 (M4), S4→S2/S3 (M5), S12-gateway→C5 (M6) — are each a single contract boundary, wired at the *end* of the relevant milestone. Everything before that wiring is independent internal work. The M5 red-blue debate seam is S4→S3-as-referee: S4-TDB1's debate-round orchestrator drives S3's `run_perturbation_pair` / `detect_insensitivity` / referee-adjudication over the frozen C3 v1.1 report contract, and S4-TDB2's challenger panel consumes S3-TPR5's `attest_challenger_independence` — both across the already-frozen C3 v1.1 boundary, so S4's debate internals and S3's referee internals stay decoupled.

6. **Tasks staged into later milestones are pulled by dependency, not by subsystem.** A subsystem is not necessarily "finished" in one milestone: S2 baseline lands in M1 but its deep families/HPO/`build_variant` land in M4 (pulled forward only when breadth and recursion need them); S3's core lands in M1 but its contamination-dependent checks land in M3 (they *cannot* exist before S6's frozen index); S7's core lands in M1 but independence metadata + breadth land in M3. The Adversarial Red-Blue Debate Evolution subtasks follow the same rule: S3's referee machinery is split across M0 (schema freeze at C3 v1.1, S3-TPR1), M1 (perturbation oracle + insensitivity detector + referee!=builder, S3-TPR2/TPR3/TPR4), and M3 (challenger-independence attestation, S3-TPR5, which reuses the M3 cross-code lineage machinery), while S4's debate loop (S4-TDB1..S4-TDB6) lands in M5 because it *cannot* run before its referee and independent-challenger prerequisites exist. This keeps each milestone's critical path minimal while still covering 100% of the backlog.

---

## 9. Coverage ledger (every subtask appears exactly once)

| Subsystem | Total | M0 | M1 | M2 | M3 | M4 | M5 | M6 |
|---|---|---|---|---|---|---|---|---|
| **S1** (30) | 30 | T01,T03,T25,T30 (4) | T02,T04–T24,T26–T29 (26) | — | — | — | — | — |
| **S2** (26) | 26 | T01 (1) | T02–T08,T10–T13,T15–T20,T22,T23,T24 (20) | — | — | T09,T14,T21,T25,T26 (5) | — | — |
| **S3** (38) | 38 | T01,TPR1 (2) | T02–T13,T15,T16,T17,T19,T22,T23,T26,T30,TPR2,TPR3,TPR4 (23) | — | T14,T18,T20,T21,T24,T25,T27,T28,T29,T31,T32,T33,TPR5 (13) | — | — | — |
| **S4** (31) | 31 | — | — | — | — | — | T01–T25,TDB1,TDB2,TDB3,TDB4,TDB5,TDB6 (31) | — |
| **S5** (33) | 33 | T01,T31 (2) | — | T02,T02b,T03–T30,T32 (31) | — | — | — | — |
| **S6** (35) | 35 | — | — | — | T01–T35 (35) | — | — | — |
| **S7** (32) | 32 | T01,T02 (2) | T03–T17,T19,T20,T21,T22,T23,T24,T27,T28,T32 (24) | — | T18,T25,T26,T29,T30,T31 (6) | — | — | — |
| **S8** (27) | 27 | T01–T27 (27) | — | — | — | — | — | — |
| **S9** (25) | 25 | — | — | — | — | T01–T25 (25) | — | — |
| **S10** (35) | 35 | T01–T32 + T02b,T04b,T09b (35) | — | — | — | — | — | — |
| **S11** (35) | 35 | — | — | T01–T14,T16,T22–T26,T28–T31,T33,T34,T35 (27) | — | — | T15,T17,T18,T19,T20,T21,T27,T32 (8) | — |
| **S12** (30) | 30 | — | — | — | — | — | — | T01–T30 (30) |
| **TOTAL** | **377** | **73** | **93** | **58** | **54** | **30** | **39** | **30** |

Sum of milestone columns: 73 + 93 + 58 + 54 + 30 + 39 + 30 = **377** = full backlog. Every subtask ID is assigned to exactly one milestone. The **11 new Adversarial Red-Blue Debate Evolution subtasks** land as: S3-TPR1 [M0]; S3-TPR2/TPR3/TPR4 [M1]; S3-TPR5 [M3]; S4-TDB1..S4-TDB6 [M5].

*Coverage notes:* S8 (all 27) and S10 (all 35) are complete in M0 as the foundations. S5-T18/T19/T21 are **built** in M2 against mocks but only **exercised end-to-end** once S9 (M4) and S4 (M5) are live — they remain assigned to M2 for delivery. S2-T21/T25 (build_variant, recursion-safe hooks) are delivered in M4 as prerequisites for S4 in M5. The Adversarial Red-Blue Debate Evolution subtasks are staged by dependency: the referee machinery (S3-TPR1 schema in M0; S3-TPR2/TPR3/TPR4 perturbation oracle + insensitivity detector + referee!=builder in M1; S3-TPR5 challenger-independence attestation in M3) is delivered ahead of the S4 debate loop (S4-TDB1..S4-TDB6 in M5), which consumes it — recursion runs as adversarial debate only after the non-gameable referee and independent challenger panel exist.

---

## 10. Milestone summary (one-line goals)

- **M0 — Spine & Contracts First:** freeze C1..C6 as versioned schemas with bindings and stand up the zero-dependency foundations S8 (data/provenance) and S10 (sandbox/runtime) so all 12 teams build against stable seams.
- **M1 — One Vertical Slice, Oracle-Gated:** prove verify-before-trust on one subtopic end-to-end — one C1 subagent + S2 baseline builder + S7 adapters + minimal S3 verifier producing a signed ValidationReport with claim-tiering.
- **M2 — Orchestration & Provenance at Scale:** stand up the Control Tower (S5) with durable DAG execution, budget/concurrency governance, and routing, plus S8 lineage-at-scale and the S11 re-run reproducibility canary.
- **M3 — Knowledge, Registry & Contamination Control:** bulk-ingest arXiv/GitHub/HEPData (S6), ship curated RAG + the registry/C5 + the frozen contamination index, and complete S3's leakage/cross-code/calibration gates on top of it.
- **M4 — Breadth Rollout & Human Governance:** onboard many subtopic subagents and stand up the mandatory human gate (S9) — review queues, claim-tier UI, guardrails, emission authorization, and review-capacity rate limits — plus S2 deep families/HPO.
- **M5 — Adversarial Red-Blue Debate Evolution (recursion under oracle):** enable the Evolver (S4) as a proponent / independent-challenger-panel / non-gameable-referee debate loop with hard bounds, challenger diversity, and reward-hacking + collusion defenses, running only under a cheap valid S3 verifier + oracle, recording every ChallengeRound in the C4 DebateLedger, and add the S11 benchmark/eval + planted-exploit + planted-spurious-model harnesses.
- **M6 — Federation & Interop Standard:** publish the SLHA-for-agents standard, SDK/CLI, and Bronze/Silver/Gold conformance suite (S12), and open the community registry/governance so external physicists contribute subagents that gain no elevated trust.
