# Project Argus — Design Set README

> **Part of the Project Argus design set.** You are at the canonical entry point. Start here for the doc map and reading order. Related docs: [Architecture.md](Architecture.md), [PRD.md](PRD.md), [TechDesign.md](TechDesign.md), [Backlog-and-Interfaces.md](Backlog-and-Interfaces.md), [TestPlan.md](TestPlan.md), [Roadmap.md](Roadmap.md).

This README is the **consolidation index** for the six-document Project Argus design set. Read it first, then follow the reading order below.

---

## 1. Thesis

Argus is a **verifier-gated, agent-operated ML foundry** for fragmented theoretical particle physics and particle cosmology. Its operating principle is **verify-before-trust**: every agent-executed unit is presumed untrusted — potentially reward-hacking, leaked, or spurious — until an external oracle proves otherwise. The agents do **not** autonomously discover physics; they are automated ML researchers that **BUILD, VALIDATE, and ITERATE** ML models for each physics subtopic, supplying the scarce "ML-engineer half" of the domain-expert-plus-ML-engineer pairing. Nothing carries a claim tier above `ran-toy`, and **nothing is emitted externally**, without (a) a cryptographically **signed C3 ValidationReport (v1.1)** from the S3 verifier — a non-gameable referee that is never the same agent as the proponent — and (b) the mandatory **human gate S9**. Recursive self-improvement (S4) is permitted **only** under a cheap, valid external verifier, structurally defeating reward hacking by construction rather than by instruction.

---

## 2. Document map

| Doc | Purpose | When an implementer should read it |
|-----|---------|------------------------------------|
| [Architecture.md](Architecture.md) | System overview & core thesis, design principles P1–P12, glossary, default tech stack, global NFRs N1–N14, security model, and the **six shared contracts C1..C6 in full**, plus the subsystem dependency graph and milestone themes. | **First and always open.** The authoritative source for contract shapes, principles, and cross-subsystem seams. Consult before touching any interface. |
| [PRD.md](PRD.md) | Product overview, cross-cutting thesis and non-goals (NG-A..NG-D), claim tiering, then **one PRD per subsystem S1–S12** with goals, personas, user stories, and functional/non-functional requirement tables. | When you need to know **what** a subsystem must do and why — its requirements, personas, and acceptance intent. |
| [TechDesign.md](TechDesign.md) | Per-subsystem **technical design**: architecture overviews, components, key algorithms, sequence flows, data models (pydantic v2 / JSON-Schema), and public APIs. | When you need to know **how** to build a subsystem — concrete types, algorithms, and API signatures. |
| [Backlog-and-Interfaces.md](Backlog-and-Interfaces.md) | The consolidated **380-subtask backlog**, cross-subsystem dependency analysis, and the **interface registry** (producer ↔ consumer reconciliation, mismatch count). | When picking up work: your **task list**, its dependencies, and the exact interfaces you produce/consume. |
| [TestPlan.md](TestPlan.md) | Physics-validation philosophy (the six oracles), per-subsystem test batteries, the cross-subsystem integration suite (X-01..X-16), the traceability matrix, and platform KPIs / release gates. | When defining **done**: the acceptance cases and KPIs your work must satisfy before it can pass a gate. |
| [Roadmap.md](Roadmap.md) | The **milestone sequence M0–M6**, critical path, decoupling notes, and the coverage ledger mapping every subtask to exactly one milestone. | When planning **sequence**: which milestone your subtask lives in and what must precede it. |

---

## 3. Reading order (for a downstream coding agent, e.g. Codex)

Read the set in dependency order — contracts and principles first, sequence last:

1. **[Architecture.md](Architecture.md)** — the frozen contracts C1..C6 and load-bearing principles. Everything else assumes these.
2. **[PRD.md](PRD.md)** — *what* each subsystem must do (requirements, non-goals, claim tiering).
3. **[TechDesign.md](TechDesign.md)** — *how* to build it (components, algorithms, data models, APIs).
4. **[Backlog-and-Interfaces.md](Backlog-and-Interfaces.md)** — the *task list* and the exact producer/consumer *interfaces*.
5. **[TestPlan.md](TestPlan.md)** — the *acceptance* criteria, integration scenarios, and KPIs.
6. **[Roadmap.md](Roadmap.md)** — the *sequence*: milestone order and critical path.

---

## 4. Contract catalog (C1..C6)

The six contracts are the decoupling seams: subsystems couple **only** through them, never through another subsystem's internals (principle P6). Canonical JSON Schema (draft 2020-12) with generated pydantic / TypeScript / Rust-serde bindings; semver with additive-minor / breaking-major semantics. Consumer lists below are **post-fix** (interface-registry mismatch count = 0).

| Contract | Name | Owner | Consumers (post-fix) |
|----------|------|-------|----------------------|
| **C1** | Subagent Contract ("SLHA-for-agents") | S1 | S5, S2, S3, S4, S11, S12 *(S9 removed — was over-declared)* |
| **C2** | Task / Job Envelope | S5 | S1, S2, S3, S4, S7, S9, S10, S11, S12 *(S6, S8 removed — were over-declared)* |
| **C3** (**v1.1**) | Verifier Interface + Validation Report | S3 | S1, S2, S4, S5, S7, S8, S9, S11, S12 |
| **C4** | Artifact + Provenance Record | S8 | S1, S2, S3, S4, S5, S6, S7, S9, S10, S11, S12 |
| **C5** | Registry / Capability Descriptor | S6 / S12 | S1, S2, S3, S4, S5, S7, S9, S10, S11 |
| **C6** | Compute-Adapter Tool Interface | S7 | S1, S2, S3, S5, S6, S10, S11, S12 *(S4 removed — C5-mediated, not direct; S12 added — was omitted)* |

**C3 is at v1.1** (additive, backward-compatible; frozen at v1.1 from M0 — pre-implementation, no migration). v1.1 folds **Adversarial Red-Blue Debate Evolution** into verification and adds six ValidationReport fields: `perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, and `debate_ref` (a pointer into the C4 provenance `DebateLedger`). C3 also documents the **C3↔S7 extrapolation reciprocity**: S7 emits an extrapolation / out-of-validity flag in its C6 tool result, and S3 consumes that flag and sets the affected check to `INCONCLUSIVE`.

---

## 5. Subsystem roster (S1..S12)

| ID | Subsystem | One-liner | Owns |
|----|-----------|-----------|------|
| **S1** | Subagent Framework & Contract | The subagent SDK/runtime and the SLHA-for-agents lifecycle. | **C1** |
| **S2** | ML Builder Engine | AutoML core inside a subagent: features, model synthesis/selection, HPO, training, auto-repair. Builds candidates; never self-grades. | — |
| **S3** | Physics Validation & Verifier Framework | The external oracle; runs the checks and signs the Validation Report; acts as the non-gameable **referee**. | **C3** |
| **S4** | Recursive Improvement Loop (Evolver) | Oracle-gated self-improvement via proponent / challenger-panel / referee **red-blue debate**. Owns the debate data models. | — |
| **S5** | Control Tower / Orchestration (总台) | Meta-orchestrator: intake, DAG decomposition, routing, budget/concurrency governance. | **C2** |
| **S6** | Knowledge & Ingestion | arXiv/GitHub/HEPData ingest, RAG, registry co-owner, frozen contamination index. | **C5** (co-owned with S12) |
| **S7** | Physics Compute Adapters | Uncertainty-tagged forward-model tools; emits the extrapolation flag S3 consumes. | **C6** |
| **S8** | Data, Artifact & Provenance | Foundational data plane; content-addressed artifacts and lineage. | **C4** |
| **S9** | Human-in-the-loop Review & Governance | Mandatory human gate before any external artifact. | — |
| **S10** | Security, Sandbox & Runtime | Isolation, secrets, egress control, cost governance. | — |
| **S11** | Observability & Evaluation | Traces, metrics, KPIs, re-run canary, benchmark/planted-exploit harnesses. | — |
| **S12** | Interop Standard & Federation | Publishes the SLHA-for-agents spec, conformance suite, community registry. | **C5** (co-owned with S6) |

---

## 6. Milestone summary (M0..M6)

| Milestone | Theme | Highlights |
|-----------|-------|------------|
| **M0** | Spine & Contracts First | Freeze C1..C6 as versioned schemas with bindings; **C3 frozen at v1.1 with the six new fields** (adds `S3-TPR1`); stand up zero-dependency S8 + S10. |
| **M1** | One Vertical Slice, Oracle-Gated | Prove verify-before-trust on one subtopic end-to-end. Minimal S3 now includes the **bidirectional perturbation oracle** (must-react + must-not-react), the **insensitivity detector**, and **referee!=builder** enforcement (adds `S3-TPR2`, `S3-TPR3`, `S3-TPR4`). |
| **M2** | Orchestration & Provenance at Scale | Control Tower (S5) durable DAG execution, budget/concurrency/routing; S8 lineage-at-scale; S11 re-run reproducibility canary. *(theme unchanged)* |
| **M3** | Knowledge, Registry & Contamination Control | Bulk ingest (S6), curated RAG + C5 registry + frozen contamination index; S3 leakage/cross-code/calibration gates; **challenger-independence attestation** (lineage-disjoint cross-code, adds `S3-TPR5`). |
| **M4** | Breadth Rollout & Human Governance | Onboard many subtopic subagents; stand up the mandatory human gate (S9); S2 deep families/HPO. *(theme unchanged)* |
| **M5** | **Adversarial Red-Blue Debate Evolution (recursion under oracle)** *(retheme)* | Evolver (S4) as a proponent / independent-challenger-panel / non-gameable-referee **debate loop** with hard bounds, challenger diversity, and reward-hacking + collusion defenses — running only under a cheap valid S3 verifier + oracle, recording every `ChallengeRound` in the C4 `DebateLedger`; S11 gains a planted-spurious-model detection harness (adds `S4-TDB1..S4-TDB6`). |
| **M6** | Federation & Interop Standard | Publish the SLHA-for-agents standard, SDK/CLI, and Bronze/Silver/Gold conformance suite (S12); open the community registry — federated subagents gain no elevated trust. *(theme unchanged)* |

---

## 7. How to build against these docs (for Codex)

- **Build against the frozen contracts.** C1..C6 are the only coupling surface; never import another subsystem's internal types (principle P6). C3 is at **v1.1** — target the v1.1 schema from the start.
- **Every artifact needs a signed C3 v1.1 ValidationReport.** No output carries a claim tier above `ran-toy` without a signature-valid report from an S3 verifier key; verify signatures at every consumption point.
- **Enforce claim-tiering.** `ran-toy` < `recapitulated-known` < `novel-needs-human`. A subagent may self-report at most `ran-toy`; `recapitulated-known` is set only by a signed S3 report; `novel-needs-human` is an S3 *candidate* finalized only by S9. Tiers are monotone.
- **Recursion (S4) runs ONLY under a valid S3 oracle.** The Evolver's precondition gate refuses to start unless a cheap, valid external verifier + oracle exists for the subtopic. No verifier, no loop — refuse rather than run unguarded.
- **Referee != proponent.** The S3 referee is non-gameable and is never the same agent as the S2/builder proponent; the ValidationReport's `referee.distinct_from_proponent` MUST be true and the report must be signed. Challenger panels must be ≥K independent, lineage-disjoint agents.
- **Nothing emits without S9.** No external-facing artifact leaves Argus without a recorded human sign-off; surviving the red-blue debate never bypasses the S9 gate.
- **Implement in milestone order.** Follow M0→M6; respect the critical path and coverage ledger in the Roadmap.
- **Each subtask has acceptance criteria in the Backlog and cases in the TestPlan.** Do not consider a subtask done until its Backlog acceptance criteria pass and its TestPlan cases (including the relevant `-PR` / `-DB` semantic cases and integration scenarios X-14..X-16) are green.
- **Keep the design set mechanically consistent.** Run `python3 scripts/validate_docs.py` after editing the docs; it checks roadmap coverage, estimate accounting, contract consumer maps, and stable test IDs.

---

## 8. Change log — Adversarial Red-Blue Debate Evolution update

This update folded **Adversarial Red-Blue Debate Evolution** into the self-improvement loop (S3 verifier + S4 evolver) as a multi-agent adversarial peer review: a Builder **proponent**, a panel of ≥K independent **challengers**, and the S3 **referee** (non-gameable, never the proponent). Concretely:

- **Semantic upgrade in S3/S4.** Verification became a bidirectional perturbation oracle — a **must-react** probe (plant a known-real signal that must be recovered proportionally) and a **must-not-react** probe (inject noise / shuffled labels / fake contamination that must not manufacture a signal) — plus an **insensitivity** screen (invariance to a perturbation it should have reacted to ⇒ FAIL). A claim passes only when both directions pass and no insensitivity is detected.
- **C3 bumped to v1.1** (additive, backward-compatible; frozen at v1.1 from M0). Added six ValidationReport fields: `perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, `debate_ref`. New S4-owned data models: `ChallengeRound`, `Attack`, `ChallengeVerdict`, `DebateLedger` (the C4-provenance record).
- **11 new subtasks added** — backlog grew **366 → 377**: `S3-TPR1` [M0], `S3-TPR2`/`S3-TPR3`/`S3-TPR4` [M1], `S3-TPR5` [M3], and `S4-TDB1..S4-TDB6` [M5]. The Roadmap coverage ledger now totals 377, each id in exactly its tagged milestone.
- **New integration tests added:** `X-14` (red-blue debate catches a planted spurious model via the insensitivity detector before the human gate), `X-15` (challenger-independence loop: correlated challengers flagged, panel refreshed), `X-16` (non-gameable referee: builder cannot self-sign → emission blocked at S9). Plus per-subsystem semantic `-PR` / `-DB` cases and hard KPIs (insensitivity-catch = 100%, challenger-independence lineage-disjoint = 100%, referee-!=-proponent separation = 100%).
- **Five interface mismatches fixed** (interface-registry mismatch count now **0**): C1 consumers drop S9; C2 consumers drop S6 and S8; C6 consumers drop S4 (C5-mediated) and add S12; and the **C3↔S7 extrapolation reciprocity** is documented in C3, S3, and S7 (S7 emits an out-of-validity flag; S3 consumes it and sets the affected check to `INCONCLUSIVE`).
