# Argus — Architecture & Shared Contracts

> **Part of the Project Argus design set.** Start at README.md for the doc map and reading order. Related docs: Architecture.md, PRD.md, TechDesign.md, Backlog-and-Interfaces.md, TestPlan.md, Roadmap.md.

> **Status:** Complete implementation design (not an MVP).
> **Scope of this document:** System overview and core thesis, design principles, glossary, default tech stack, global non-functional requirements (NFRs), the security model, the six shared contracts **C1..C6** in full, and the subsystem dependency graph. Milestone themes are included as context for the phased build.

---

## Table of Contents

1. [System Overview & Core Thesis](#1-system-overview--core-thesis)
2. [Design Principles](#2-design-principles)
3. [Glossary](#3-glossary)
4. [Default Tech Stack](#4-default-tech-stack)
5. [Global Non-Functional Requirements (NFRs)](#5-global-non-functional-requirements-nfrs)
6. [Security Model](#6-security-model)
7. [Shared Contracts C1..C6](#7-shared-contracts-c1c6)
   - [C1 — Subagent Contract (SLHA-for-agents)](#c1--subagent-contract-slha-for-agents)
   - [C2 — Task/Job Envelope](#c2--taskjob-envelope)
   - [C3 — Verifier Interface + Validation Report](#c3--verifier-interface--validation-report)
   - [C4 — Artifact + Provenance Record](#c4--artifact--provenance-record)
   - [C5 — Registry / Capability Descriptor](#c5--registry--capability-descriptor)
   - [C6 — Compute-Adapter Tool Interface](#c6--compute-adapter-tool-interface)
8. [Subsystem Dependency Graph](#8-subsystem-dependency-graph)
9. [Milestone Themes (Phased Build)](#9-milestone-themes-phased-build)
10. [Subsystem & Contract Cross-Reference Index](#10-subsystem--contract-cross-reference-index)

---

<a id="1-system-overview--core-thesis"></a>
## 1. System Overview & Core Thesis

**Argus** is a verifier-gated, agent-operated ML foundry for fragmented theoretical particle physics and particle cosmology. Its wager is that in this field the machine-learning signal — information humans cannot extract by inspection — is the real prize, while an unaided agent only automates human labor. Argus therefore does not aim its agents at *discovering* physics; it aims them at being **automated ML researchers** that build, train, validate, and iterate ML models for each physics subtopic. It supplies the "ML-engineer half" of the scarce person who is both a domain expert and an ML engineer.

The architecture is a **federation**: each subtopic is served by a domain **subagent** conforming to a single standardized interface ("SLHA-for-agents", contract [C1](#c1--subagent-contract-slha-for-agents)), orchestrated by a **Control Tower** (总台, S5). Everything an agent produces is presumed untrusted until an external **Physics Verifier** (S3) signs a **Validation Report** — injection recovery, held-out/null controls, cross-code consistency, physical-consistency gates, and leakage screens — and every claim is tiered *ran-toy / recapitulated-known / novel-needs-human*. **Recursion** (self-improvement of a pipeline, S4) is permitted **only** when a cheap external verifier exists to score it, structurally defeating reward hacking.

The strategy is **breadth-over-depth**: cover the long tail of subtopics that today have no ML at all, rather than trying to beat the flagship specialist on the flagship problem. Autonomy stops at hard non-goals — no autonomous discovery of new fundamental theory, no autonomous paper submission, no autonomous flagship-HPC execution, no claim of empirical validation (the empirical arbiter is a real experiment, out-of-band and years away). Human sign-off is mandatory before any external artifact.

The six shared contracts **C1..C6** are the decoupling seams that let twelve subsystem teams build in parallel against stable interfaces rather than against each other's code.

### 1.1 Illustrative physics pipeline

A representative research chain Argus targets:

> electroweak phase transition → stochastic gravitational-wave background → Higgs-sector observables

Each link in such a chain is a candidate subtopic served by its own subagent.

### 1.2 Subsystem roster (S1..S12)

| ID | Subsystem | One-line role |
|----|-----------|---------------|
| **S1** | Subagent Framework & Contract | The subagent SDK/runtime; defines and hosts [C1](#c1--subagent-contract-slha-for-agents). |
| **S2** | ML Builder Engine | AutoML core inside a subagent: features, model synthesis/selection, HPO, training, auto-repair. |
| **S3** | Physics Validation & Verifier Framework | The external oracle; runs the checks and signs the Validation Report ([C3](#c3--verifier-interface--validation-report)). |
| **S4** | Recursive Improvement Loop (Evolver) | Oracle-gated self-improvement of pipelines. |
| **S5** | Control Tower / Orchestration (总台) | Meta-orchestrator; owns the Job Envelope ([C2](#c2--taskjob-envelope)). |
| **S6** | Knowledge & Ingestion | arXiv/GitHub/HEPData ingest, RAG, registry co-owner, frozen contamination index. |
| **S7** | Physics Compute Adapters | Uncertainty-tagged forward-model tools; owns [C6](#c6--compute-adapter-tool-interface). |
| **S8** | Data, Artifact & Provenance | Foundational data plane; owns [C4](#c4--artifact--provenance-record). |
| **S9** | Human-in-the-loop Review & Governance | Mandatory human gate before any external artifact. |
| **S10** | Security, Sandbox & Runtime | Isolation, secrets, egress control, cost governance. |
| **S11** | Observability & Evaluation | Traces, metrics, KPIs, re-run canary, benchmark harness. |
| **S12** | Interop Standard & Federation | Publishes the SLHA-for-agents spec, conformance suite, community registry. |

### 1.3 Non-goals (explicitly out of scope)

- Autonomous discovery/confirmation of new fundamental theory.
- Autonomous submission of papers to venues.
- Autonomous configuration/execution of flagship HPC simulations (numerical relativity, large hydro). Compute is scoped to **lightweight solvers, emulators, differentiable surrogates, and ML training**.
- Claiming empirical validation (the empirical arbiter is a real experiment/observation, which is out-of-band and years away).

These non-goals are enforced as hard guardrails in S9/S5 (see [§6](#6-security-model)), not left to agent judgment.

---

<a id="2-design-principles"></a>
## 2. Design Principles

These principles are load-bearing; each is referenced throughout the contracts and NFRs.

| # | Principle | Statement |
|---|-----------|-----------|
| **P1** | Oracle-gated autonomy (adversarial, bidirectional) | No ML artifact, claim, or recursion step is trusted until an **external** verifier (S3) — code the agent cannot see or modify — signs it. Agents may propose; only the oracle may accept. The oracle is a **non-gameable referee** that is **never the same agent as the proponent** (referee != proponent; the S3 referee != the S2/builder proponent). Verification is a **bidirectional perturbation oracle**: a **must-react** probe plants a known-real signal that the claim MUST recover proportionally, and a **must-not-react** probe injects noise / shuffled labels / fake contamination that the claim MUST NOT amplify into a signal; invariance to a perturbation it should have reacted to is an **insensitivity** failure. A claim passes only when both directions pass and no insensitivity is detected. |
| **P2** | Verify-before-trust, presumptive contamination | Treat every dataset, label, and literature match as potentially leaked/contaminated until a leakage screen and provenance chain say otherwise. The frozen contamination index (S6) is the default null hypothesis. |
| **P3** | Claim-tiering is mandatory and monotone | Every output is stamped *ran-toy* < *recapitulated-known* < *novel-needs-human*. Tier can only be raised by passing a defined gate; a subagent may never self-assign 'novel'. Only S3+S9 promote to novel. |
| **P4** | Full provenance and bit-level reproducibility | Every artifact is content-addressed and carries a complete lineage (inputs, code version, container digest, seeds, config, adapter versions). If it cannot be re-derived, it does not exist. |
| **P5** | Structural, not behavioral, safety | The harness/verifier/reward path is physically unreachable from agent-executed code (separate process, separate credentials, read-only mounts, egress-denied). We assume reward-hacking and self-modification and prevent them by construction, not by instruction. |
| **P6** | Decoupled subsystems, contract-only coupling | Subsystems communicate **only** through the six published contracts C1..C6. No subsystem imports another's internal types. Contracts are versioned with explicit compatibility semantics. |
| **P7** | Breadth-over-depth near-term | Maximize coverage of subtopics that have no ML today; do not attempt to beat the domain specialist on the flagship numerical problem. Value is in the long tail and in standardization. |
| **P8** | Human-in-the-loop is a hard gate, not advice | No external-facing artifact leaves Argus without a recorded human sign-off (S9). Autonomy is sized to human review throughput, not the reverse. |
| **P9** | Cheap-verifier precondition for recursion | The Evolver (S4) refuses to start unless a valid, cheap-to-evaluate external verifier exists for the target. No verifier, no loop — reject rather than run unguarded. |
| **P10** | Uncertainty is first-class | Every forward-model call (S7) and every model prediction carries a calibrated uncertainty tag; a bare point estimate is an incomplete result and is rejected by downstream gates. |
| **P11** | Physics priors are injected, not hoped for | Units/dimensions, symmetries, positivity, unitarity, and known limits are encoded as explicit constraints and post-hoc gates (S2/S3), not left for the model to rediscover. |
| **P12** | Fail loud and quarantine | Any gate failure, adapter disagreement, or budget breach halts the job into a quarantined, fully-logged state for review rather than degrading silently. |

---

<a id="3-glossary"></a>
## 3. Glossary

| Term | Definition |
|------|------------|
| <a id="g-argus"></a>**Argus** | The verifier-gated, agent-built ML foundry described here: a federation of domain subagents orchestrated by a control tower, gated by a physics verifier. |
| <a id="g-subagent"></a>**Subagent** | A domain-scoped automated ML researcher for one physics subtopic (e.g. electroweak phase transition), implementing the [C1](#c1--subagent-contract-slha-for-agents) Subagent Contract lifecycle: register, accept, plan, build, validate, report. |
| <a id="g-control-tower"></a>**Control Tower (总台, S5)** | The meta-orchestrator that intakes a research request, decomposes it into a job DAG, routes jobs to subagents, and governs concurrency, budget, retries, and workflow composition. |
| <a id="g-slha"></a>**SLHA-for-agents** | Argus's standardized subagent interface, named by analogy to the SUSY Les Houches Accord: a single stable contract ([C1](#c1--subagent-contract-slha-for-agents)) every domain subagent implements so subagents are interchangeable and federated. |
| <a id="g-verifier"></a>**Physics Verifier (S3)** | The load-bearing external oracle that runs injection, null/negative-control, cross-code, physical-consistency, and leakage tests and emits a signed Validation Report. It is the reward signal for recursion and is unreachable from agent code. |
| <a id="g-validation-report"></a>**Validation Report** | The signed [C3](#c3--verifier-interface--validation-report) artifact recording which verifier checks ran, their outcomes, the assigned claim tier, calibrated metrics, and a cryptographic signature. The unit of trust in Argus. |
| <a id="g-injection"></a>**Injection test** | A verifier check that injects a known synthetic signal of known amplitude into the pipeline input and confirms the model recovers it within tolerance; the primary guard against a model that learns nothing real. |
| <a id="g-null"></a>**Null / negative-control test** | A verifier check that runs the pipeline on signal-free or label-shuffled data and confirms it reports no detection; guards against a model that hallucinates signal from noise or leakage. |
| <a id="g-cross-code"></a>**Cross-code consistency** | A verifier check that compares a result against one or more **independent** physics codes/emulators (S7) and requires agreement within stated uncertainty; guards against single-implementation bias. |
| <a id="g-physical-consistency"></a>**Physical-consistency gate** | A verifier check enforcing hard physics: dimensional/unit correctness, positivity, unitarity bounds, known symmetries, and correct asymptotic limits. |
| <a id="g-leakage"></a>**Leakage / contamination screen** | A verifier check that detects train/test overlap, target leakage, and overlap with the frozen literature/contamination index (S6) so 'novel' cannot be a memorized result. |
| <a id="g-claim-tier"></a>**Claim tier** | The monotone trust label on any output: *ran-toy* (executed a toy/self-consistency), *recapitulated-known* (matched an established result held out from the model), or *novel-needs-human* (a candidate new result requiring mandatory human review). Never self-assignable to novel. |
| <a id="g-evolver"></a>**Evolver (S4)** | The recursive improvement loop: propose pipeline variant → train (S2) → score via verifier (S3) → select/mutate, under hard bounds, diversity control, and reward-hacking defenses. Refuses to run without a valid external verifier. |
| <a id="g-ml-builder"></a>**ML Builder Engine (S2)** | The AutoML core inside a subagent: physics-aware feature engineering, model synthesis/selection, hyperparameter optimization, training orchestration, and failure diagnosis/auto-repair. |
| <a id="g-compute-adapter"></a>**Compute Adapter (S7)** | A standardized, uncertainty-tagged tool-wrapper exposing a domain physics code, emulator, or differentiable surrogate as a callable forward model with normalized I/O, per contract [C6](#c6--compute-adapter-tool-interface). |
| <a id="g-job-envelope"></a>**Job envelope (C2)** | The standardized task/job message that flows from the control tower to a subagent and back: problem spec, budget, constraints, provenance handles, and required verifier profile. |
| <a id="g-capability-descriptor"></a>**Capability descriptor (C5)** | The machine-readable declaration of what a subagent (or code/tool) can do — subtopics, required adapters, resource envelope, conformance level — used by the registry for routing and by federation for admission. |
| <a id="g-artifact-provenance"></a>**Artifact + Provenance record (C4)** | The content-addressed record of any produced object (dataset, model, report, plot) with its full lineage graph, seeds, versions, and environment digest. |
| <a id="g-conformance-suite"></a>**Conformance suite** | The executable test battery (S12) an external subagent must pass to be admitted to the federation at a declared conformance level (Bronze/Silver/Gold). |
| <a id="g-frozen-index"></a>**Frozen contamination index** | A version-pinned, immutable snapshot of literature/data (S6) used as the reference for novelty and recall discrimination, so 'novel' means 'absent from this frozen corpus at this date'. |
| <a id="g-surrogate"></a>**Differentiable surrogate** | A fast, gradient-providing approximation of an expensive physics forward model, exposed via [C6](#c6--compute-adapter-tool-interface), enabling gradient-based fitting and cheap verifier evaluation. |
| <a id="g-reward-hacking"></a>**Reward hacking** | An agent optimizing the measured score without achieving the intended physics result (e.g. exploiting a leaked label or a verifier bug). Structurally prevented by external, held-out, signed verifiers and blind test data. |
| <a id="g-recap-benchmark"></a>**Recapitulation benchmark** | A held-out established physics result the platform can be scored against to prove a pipeline rediscovers known physics before any novel claim is entertained. |

---

<a id="4-default-tech-stack"></a>
## 4. Default Tech Stack

These are platform **defaults**; a subsystem may deviate only by declaring the deviation in its capability descriptor ([C5](#c5--registry--capability-descriptor)) and passing conformance. The contracts (C1..C6) are language-neutral wire specs so teams are not locked to these choices.

### 4.1 Languages

- **Python 3.11+** — primary language for subagents, ML Builder (S2), verifier checks (S3), and adapters (S7). Non-negotiable because the scientific/ML ecosystem (NumPy/SciPy, JAX, PyTorch, scikit-learn) and the physics community both live here. Typed with `pydantic` v2 models generated from the contract schemas.
- **Rust** — for the security-critical, hot, or trust-boundary components: the sandbox supervisor / syscall broker (S10), the content-hashing + provenance ledger writer (S8), and the egress proxy. Chosen for memory safety and performance at the trust boundary where a Python bug is a security bug.
- **TypeScript** — the Human-in-the-loop review UI (S9) and observability dashboards (S11), on **React + Next.js**.

### 4.2 ML / numerics

- **JAX** as the default for differentiable surrogates, emulators, and physics-aware models where gradients through the forward model matter (S2, S7 surrogates); **PyTorch** supported for imported community models.
- **scikit-learn / XGBoost / LightGBM** for tabular/classical baselines (often the right tool for breadth-first subtopics).
- **Optuna** for HPO/AutoML search; **Ray Tune** for distributed trials.
- *Rationale:* JAX's `grad`/`vmap`/`jit` and functional purity align with reproducibility and with differentiable-surrogate-based verification.

### 4.3 Physics interop

- Adapters (S7) wrap community codes (effective-potential / bounce / GW-spectrum solvers, collider fast-sim chains, Boltzmann/transport solvers, emulators) behind the **[C6](#c6--compute-adapter-tool-interface)** interface. Wrappers may shell out to C++/Fortran binaries inside pinned containers.
- **HEPData**, **LHAPDF**-style conventions honored where relevant. Uncertainty tagging is mandatory.

### 4.4 Storage & data plane

- **PostgreSQL 16** — system of record for registries, job state, review queues, and the lineage/audit graph (using recursive CTEs or the `pgrouting`/graph extensions; a dedicated graph DB is deferred until scale demands it).
- **Object store (S3-compatible: MinIO on-prem / AWS S3 cloud)** — content-addressed artifact store (S8); objects keyed by BLAKE3 digest. **Immutable, write-once buckets** for signed Validation Reports and the frozen contamination index.
- **OpenSearch** — full-text + vector index for Knowledge/Ingestion (S6) RAG over arXiv/GitHub/HEPData and the contamination index. Vectors via a domain-appropriate embedding model served internally.
- **Redis** — ephemeral queues, rate-limits, and short-lived coordination only (never a system of record).

### 4.5 Messaging / orchestration

- **Temporal** — durable workflow engine for the Control Tower (S5) DAG execution, retries, timeouts, and human-in-the-loop wait states. Chosen because research jobs are long-running, must survive restarts, and mix automated steps with human-approval waits — exactly Temporal's model.
- **NATS JetStream** — lightweight event bus for observability events, registry change notifications, and cross-subsystem pub/sub.

### 4.6 Execution & isolation (S10)

- **gVisor** (or **Firecracker** microVMs for the strongest boundary) to sandbox all agent-executed code, with a **seccomp** + read-only rootfs + **network-egress-deny-by-default** policy through a mediating proxy.
- **OCI containers** (built reproducibly, pinned by digest) are the unit of execution. **Kubernetes** for scheduling with hard `ResourceQuota`/`LimitRange`; **Kata**-style isolation where the platform runs multi-tenant.
- **Sigstore/cosign**-style signing for Validation Reports and container images; secrets via a **vault** (HashiCorp Vault or cloud KMS), never mounted into agent sandboxes.

### 4.7 LLM / agent layer

- Subagent reasoning and the ML-Builder planner are driven by **Claude (Anthropic API)** via the Agent SDK, with tool-use restricted to the C1/C6 tool surface. Model calls are logged and cost-metered (S11). Prompt/response provenance is captured (S8). Any model can be swapped since the agent only ever acts through contracts.

### 4.8 Cross-cutting

- **OpenTelemetry** for tracing/metrics/logs (S11), exported to **Prometheus + Grafana + Tempo/Jaeger**.
- **JSON Schema** (draft 2020-12) is the canonical contract IDL; language bindings (pydantic, TypeScript types, Rust serde) are **generated** from it so all subsystems share one source of truth.
- **CBOR** optional as a compact wire encoding; JSON is the interoperable default. Versioning via **semver** with a schema registry.

---

<a id="5-global-non-functional-requirements-nfrs"></a>
## 5. Global Non-Functional Requirements (NFRs)

| # | NFR | Requirement |
|---|-----|-------------|
| **N1** | Reproducibility | Any signed artifact ([C4](#c4--artifact--provenance-record)) MUST be bit-for-bit (or, where nondeterministic kernels are unavoidable, statistically within a declared tolerance) re-derivable from its lineage record: pinned container digest, code commit, adapter versions, seeds, config, and input hashes. Re-derivation is tested continuously by a re-run canary (S11). |
| **N2** | Isolation guarantee (hard) | Agent-executed code MUST run with no write access to the harness, verifier, reward path, provenance ledger, or its own supervisor; network egress denied by default; CPU/GPU/memory/wallclock/cost caps enforced by the runtime (S10), not by the agent. A sandbox escape is a **Sev-1**. |
| **N3** | Trust integrity | No output may carry a claim tier above *ran-toy* without a Validation Report ([C3](#c3--verifier-interface--validation-report)) signed by an S3 verifier key; signatures are verified at every consumption point; an unsigned or tamper-detected report is treated as a failure and quarantined. |
| **N4** | Verifier independence | Cross-code checks MUST use at least one physics code implemented independently of the one under test; the verifier process MUST NOT share code, credentials, or memory with the subagent it grades. |
| **N5** | Provenance completeness | 100% of externally-visible artifacts and 100% of claim-tier promotions have a complete, queryable lineage graph; an artifact with a broken lineage edge is non-promotable and flagged. |
| **N6** | Human-throughput sizing | The platform enforces a global cap on items entering the human review queue (S9) per unit time and back-pressures the Control Tower; no external artifact is emitted without a recorded human sign-off, with full audit trail. |
| **N7** | Availability & durability | Control-plane services target **99.5%** availability; signed Validation Reports, provenance ledger, and the frozen contamination index are stored write-once with **≥ 99.999999999% (11 nines)** durability and are immutable/append-only. |
| **N8** | Cost governance | Every job carries a hard budget (compute + model tokens); the runtime meters spend in near-real-time, halts on breach, and reports cost-per-verified-artifact as a first-class KPI. No unbounded loops: S4 has a hard max-generations and max-spend. |
| **N9** | Latency expectations | Interactive control-tower planning responds within seconds; a single verifier check profile completes within its declared budget (typically minutes); long training/evolution jobs are asynchronous and durable via Temporal, surviving restarts. |
| **N10** | Scalability | Horizontally scalable to hundreds of concurrent subagent jobs and thousands of queued jobs; the registry and lineage graph scale to 10^5+ artifacts without query degradation. |
| **N11** | Calibration | Every predictive artifact and forward-model call reports calibrated uncertainty; verifier gates reject results whose stated uncertainty fails a calibration check (e.g. coverage test). |
| **N12** | Security & secrets | Secrets never enter agent sandboxes; all inter-subsystem calls are mutually authenticated (mTLS) and authorized by least-privilege scopes; every trust-boundary action is audit-logged and tamper-evident. |
| **N13** | Contract compatibility | A subsystem MUST accept any message valid under a compatible minor version of a contract; breaking changes require a major-version bump and a documented migration window during which both versions are served. |
| **N14** | Observability completeness | Every job emits a distributed trace spanning control tower → subagent → builder → adapters → verifier; the platform-level KPIs (transparency-failure rate, validation pass rate, cost-per-verified-artifact, reward-hacking-catch rate) are always queryable. |

---

<a id="6-security-model"></a>
## 6. Security Model

### 6.1 Threat model (assume the worst of our own agents)

Argus treats every agent-executed unit — subagent reasoning steps, ML-Builder-generated training code, Evolver-proposed variants — as potentially adversarial or reward-hacking. The primary adversary is not an outside attacker but **the optimizer itself**: it will, if structurally able, read held-out labels, edit the verifier, patch its own budget cap, spoof a signature, or exfiltrate data to inflate a score. The security model exists to make those moves physically impossible rather than merely disallowed.

### 6.2 Trust zones (strictly separated)

1. **Untrusted zone — agent execution (S10 sandbox).** All model-generated code and all training runs execute here inside gVisor/Firecracker isolation: read-only rootfs, no write access outside a scratch volume, egress-deny-by-default through a mediating proxy, seccomp-restricted syscalls, and hard CPU/GPU/mem/wallclock/cost quotas enforced by the supervisor. This zone holds **NO secrets, NO verifier code, NO reward path, NO ledger credentials**.
2. **Verifier zone (S3).** The physics verifier runs as a separate service with its own identity and signing key, on inputs it fetches itself from content-addressed storage. It never imports subagent code and never runs inside the agent sandbox. It holds blind/held-out test data the subagent cannot see. Only this zone possesses a key that can sign a Validation Report.
3. **Control / provenance zone (S5/S8/S9).** Orchestration, the append-only provenance ledger, registries, and the human-review plane. The ledger is write-once/append-only; provenance writes go through the Rust ledger writer, not through agents.
4. **Human governance zone (S9).** Sign-off, publication guardrails, and audit review. Physically gates every external artifact.

### 6.3 Key security invariants

- **No self-modification of the trust path.** The harness, verifier, reward function, sandbox supervisor, and budget enforcer are on read-only mounts unreachable from the untrusted zone. Any write attempt is a **Sev-1** event, halts the job, and quarantines the sandbox image for forensics.
- **Reward comes only from a signed oracle.** The Evolver (S4) and any scoring consumer accept a score **ONLY** from a C3 Validation Report whose signature verifies against an S3 verifier key registered in the trust store. Self-reported scores are inadmissible. This closes the classic reward-hacking loop by construction.
- **Blind test data.** Held-out/injection/null test sets live in the verifier zone and are delivered to the subagent only as opaque inputs (or via the verifier running the subagent's frozen pipeline), never as labeled data the optimizer can memorize. Leakage screens (S3) plus the frozen contamination index (S6) detect memorization masquerading as novelty.
- **Egress control & exfiltration defense.** Default-deny network egress; the only permitted destinations are the content-addressed store and declared adapter endpoints, via an allowlisting proxy that logs every request. Ingest of external corpora (S6) happens in a separate pipeline, not from inside agent sandboxes.
- **Secrets isolation.** All secrets live in a vault/KMS; short-lived, least-privilege, audience-scoped tokens are minted per job for the specific resources a job needs; tokens never enter the untrusted zone (adapters that need credentials run as brokered services outside the sandbox).
- **Authn/authz between subsystems.** mTLS everywhere; every contract call is authorized by least-privilege capability scopes; the registry ([C5](#c5--registry--capability-descriptor)) admission of a federated subagent (S12) requires passing the conformance suite and does not grant it any elevated trust — external subagents run in the same untrusted zone.
- **Tamper-evidence & provenance.** Content addressing (BLAKE3) plus signed reports make artifacts self-verifying; the lineage graph is append-only and auditable; any hash mismatch invalidates the artifact everywhere.
- **Human gate is non-bypassable.** No pathway emits an external-facing artifact (publication text, dataset release, 'novel' claim) without a recorded S9 human sign-off; rate limits cap external emissions independently of agent throughput.

### 6.4 Explicitly out of scope by policy (enforced, not just documented)

Autonomous discovery/confirmation of new fundamental theory, autonomous submission of papers, autonomous configuration/execution of flagship HPC simulations, and any claim of empirical validation. These are encoded as hard guardrails in S9/S5, not left to agent judgment.

---

<a id="7-shared-contracts-c1c6"></a>
## 7. Shared Contracts C1..C6

The six contracts are the decoupling seams of Argus. All are canonical **JSON Schema (draft 2020-12)** with generated bindings (pydantic / TypeScript / Rust serde). All are versioned via **semver** with the compatibility semantics in [N13](#5-global-non-functional-requirements-nfrs).

### 7.0 Contract summary

| Contract | Name | Owner | Consumers |
|----------|------|-------|-----------|
| [C1](#c1--subagent-contract-slha-for-agents) | Subagent Contract (SLHA-for-agents) | S1 | S5, S2, S3, S4, S11, S12 |
| [C2](#c2--taskjob-envelope) | Task/Job Envelope | S5 | S1, S2, S3, S4, S7, S9, S10, S11 |
| [C3](#c3--verifier-interface--validation-report) | Verifier Interface + Validation Report | S3 | S1, S2, S4, S5, S8, S9, S11 |
| [C4](#c4--artifact--provenance-record) | Artifact + Provenance Record | S8 | S1, S2, S3, S4, S5, S6, S7, S9, S10, S11, S12 |
| [C5](#c5--registry--capability-descriptor) | Registry / Capability Descriptor | S6 / S12 | S1, S5, S7, S9, S11, S12 |
| [C6](#c6--compute-adapter-tool-interface) | Compute-Adapter Tool Interface | S7 | S1, S2, S3, S5, S8, S11, S12 |

---

<a id="c1--subagent-contract-slha-for-agents"></a>
### C1 — Subagent Contract ("SLHA-for-agents")

**Owner:** S1 · **Consumers:** S5, S2, S3, S4, S11, S12

The single interface every domain subagent implements. Language-neutral (JSON Schema canonical); reference bindings in Python (pydantic) and TypeScript. Transport: gRPC or HTTP/JSON; all calls mTLS-authenticated and scoped by least-privilege capability tokens.

#### Versioning

- `contract_version: string` (semver, e.g. `1.3.0`). Minor = additive/back-compatible; major = breaking, dual-served during a migration window. Subagent declares `min_supported`/`max_supported` in its [C5](#c5--registry--capability-descriptor) descriptor.

#### Lifecycle (state machine)

`REGISTERED → ACCEPTED → PLANNING → BUILDING → VALIDATING → REPORTED` with terminal `FAILED`, `REJECTED`, `QUARANTINED`. Transitions are event-sourced to the provenance ledger ([C4](#c4--artifact--provenance-record)).

#### Methods

1. `register() -> CapabilityDescriptor(C5)` — advertise identity, supported subtopics, required adapters ([C6](#c6--compute-adapter-tool-interface)), resource envelope, conformance level, contract version range.
2. `accept(JobEnvelope C2) -> Acceptance{accepted:bool, reason?, estimated_cost, plan_eta}` — subagent MAY refuse (out-of-scope, missing adapter, budget too small, no valid verifier available). Refusal is a first-class, non-error outcome.
3. `plan(JobEnvelope) -> Plan{steps:[Step], adapters_required:[adapter_ref], datasets_required:[dataset_ref], verifier_profile_ref, budget_breakdown, risk_notes}` — produces an inspectable plan BEFORE any execution.
4. `build(Plan) -> BuildResult{artifact_refs:[C4], training_log_ref, diagnostics}` — runs inside S10 sandbox; invokes S2. MUST emit provenance for every artifact. Auto-repair attempts are bounded and logged.
5. `validate(BuildResult) -> ValidationRequest` — hands the frozen pipeline + artifacts to S3; does NOT self-grade. Subagent may pre-run cheap physical-consistency self-checks but these are advisory only.
6. `report() -> SubagentReport{job_id, artifact_refs, validation_report_ref(C3), claim_tier, uncertainty_summary, cost_actual, reproducibility_manifest}` — final deliverable to the control tower.
7. `cancel(job_id, reason)` / `heartbeat() -> Health{status, progress, spend_so_far}` — cooperative cancellation and liveness.

#### Required fields on every method envelope

`job_id (uuid)`, `subagent_id`, `trace_id (OTel)`, `budget_token`, `provenance_context`, `capability_scopes[]`.

#### Conformance requirements

- MUST NOT self-assign a claim tier above `recapitulated-known`; `novel-needs-human` is assigned only by S3+S9.
- MUST run all code through the S10 sandbox; MUST NOT attempt egress outside declared adapters.
- MUST emit a complete reproducibility manifest for every artifact.
- MUST implement `accept` as potentially-refusing and idempotent.
- MUST pass the S12 conformance suite at a declared level (**Bronze:** lifecycle + provenance; **Silver:** + injection/null self-checks + uncertainty tagging; **Gold:** + recursion-safe under S4 + cross-code participation).

#### Error semantics

Errors use a typed envelope `{code, category(RETRYABLE|PERMANENT|BUDGET|POLICY|VERIFIER_UNAVAILABLE|SANDBOX), message, retry_after?, provenance_ref}`. `POLICY` and `SANDBOX` errors are non-retryable and quarantine the job. `VERIFIER_UNAVAILABLE` blocks any tier promotion and (for S4) aborts the loop.

---

<a id="c2--taskjob-envelope"></a>
### C2 — Task/Job Envelope

**Owner:** S5 · **Consumers:** S1, S2, S3, S4, S7, S9, S10, S11

The standardized message the Control Tower (S5) emits to route work to a subagent, and the shape the whole platform meters against. Canonical JSON Schema; immutable once dispatched (a change = a new envelope with a new `job_id` linked via `parent_job_id`).

#### Versioning

`envelope_version: semver`. Additive fields under minor; consumers ignore unknown fields (forward-compatible). Breaking changes bump major.

#### Core fields

- `job_id: uuid`, `parent_job_id?: uuid`, `root_request_id: uuid` (ties to the originating human research request), `dag_node_id`.
- `problem_spec: { subtopic: string, objective: string, target_observable, inputs_schema, success_criteria, required_claim_tier_max }` — what to model and what 'done' means.
- `verifier_profile_ref: ref(C3 profile)` — **REQUIRED**. Which verifier check-suite must pass. If null/unavailable, subagents MUST refuse (no verifier, no run).
- `budget: { max_compute_units, max_gpu_seconds, max_model_tokens, max_wallclock_s, max_cost_usd }` — hard caps; `budget_token` is the minted, metered credential.
- `constraints: { physics_priors[], units_contract, allowed_adapters:[adapter_ref C6], allowed_datasets:[dataset_ref C4], disallowed_actions[] }`.
- `provenance_context: { root_lineage_ref, contamination_index_version }` — pins the frozen index (S6) used for novelty.
- `scheduling: { priority, deadline?, concurrency_class, retry_policy{max_attempts, backoff, retry_categories[]} }`.
- `routing: { candidate_subagents?[], routing_strategy }`.
- `capability_scopes[]` — least-privilege grants for this job (S10).

#### Result envelope (`JobResult`)

`{ job_id, status(SUCCEEDED|FAILED|REFUSED|QUARANTINED|CANCELLED), subagent_report_ref(C1), validation_report_ref(C3), artifacts[](C4), cost_actual, claim_tier, trace_id }`.

#### DAG semantics

Envelopes compose into a DAG; an edge declares data dependency (produces/consumes `artifact_ref`) or ordering. S5 executes via a durable workflow engine; a node's outputs are addressable by downstream nodes only after they are provenance-committed.

#### Error semantics

Shares the C1 typed error envelope. `BUDGET` breach → immediate halt + partial-result capture. `REFUSED` is not an error (routes to an alternative subagent or escalates to human). Retries honor `retry_categories` only; `POLICY`/`SANDBOX`/`VERIFIER_UNAVAILABLE` are never auto-retried.

---

<a id="c3--verifier-interface--validation-report"></a>
### C3 — Verifier Interface + Validation Report

**Owner:** S3 · **Consumers:** S1, S2, S4, S5, S8, S9, S11

The oracle contract. Defines how work is submitted for verification and the shape of the **signed** Validation Report that is the ONLY admissible source of a claim tier > *ran-toy* and the ONLY admissible reward signal for S4.

**Contract version: v1.1** (additive, backward-compatible; frozen at v1.1 from **M0** — since Argus is pre-implementation there is no migration). v1.1 folds **Adversarial Red-Blue Debate Evolution** into verification: the verifier acts as a **non-gameable REFEREE** (never the same agent as the PROPONENT/builder) adjudicating a panel of ≥K INDEPENDENT CHALLENGERS via **bidirectional perturbation probes** (`must_react` + `must_not_react`) and an **insensitivity** screen. The new data models — **ChallengeRound**, **Attack**, **ChallengeVerdict**, and the C4-provenance **DebateLedger** — are owned by S4 and referenced here and in [C4](#c4--artifact--provenance-record).

#### Versioning

`verifier_contract_version: semver` (**v1.1**); `check_suite_version` and `contamination_index_version` are pinned into every report for reproducibility. The six new ValidationReport fields below are additive (minor bump) and default-empty for legacy readers.

#### Verifier interface

1. `list_profiles() -> [VerifierProfile{profile_ref, applicable_subtopics, checks[], cost_estimate, independence_guarantees}]`.
2. `verify(VerificationRequest) -> ValidationReport` where `VerificationRequest = { job_id, frozen_pipeline_ref(C4), artifact_refs[](C4), profile_ref, blind_dataset_handle, budget_token, trace_id }`. The verifier fetches inputs itself from content-addressed storage; it never runs subagent code in-process.
3. `challenge(report_ref) -> ChallengeResult` — re-run/audit a prior report for the re-run canary (S11).

#### Check taxonomy

Each check returns `{check_id, type, status(PASS|FAIL|INCONCLUSIVE), metric, threshold, evidence_ref, uncertainty}`:

| Type | Purpose |
|------|---------|
| `INJECTION` | Inject known signal of known amplitude; require recovery within tolerance. |
| `NULL_CONTROL` | Signal-free / label-shuffled input; require no detection. |
| `CROSS_CODE` | Compare vs ≥1 independent physics code (S7); require agreement within uncertainty. |
| `PHYSICAL_CONSISTENCY` | Units/dimensions, positivity, unitarity, symmetry, asymptotic-limit gates. |
| `LEAKAGE` | Train/test overlap, target leakage, and overlap with the frozen contamination index (S6). |
| `CALIBRATION` | Coverage/calibration of stated uncertainties. |

#### ValidationReport (signed)

```json
{
  "report_id": "...", "job_id": "...", "verifier_id": "...", "verifier_contract_version": "...",
  "profile_ref": "...", "check_suite_version": "...", "contamination_index_version": "...",
  "checks": ["[CheckResult]"],
  "aggregate": { "passed": true, "score": 0.0, "score_definition": "..." },
  "claim_tier": "ran-toy | recapitulated-known | novel-needs-human",
  "claim_tier_justification": "...", "uncertainty_summary": "...",
  "frozen_pipeline_ref": "...", "input_hashes": ["..."], "environment_digest": "...",
  "independence_attestation": "...",

  "perturbation_pairs": [
    { "perturbation_id": "...", "kind": "must_react | must_not_react",
      "expected": "...", "observed": "...", "verdict": "PASS | FAIL | INCONCLUSIVE" }
  ],
  "insensitivity_flags": [ { "perturbation_id": "...", "reason": "..." } ],
  "challenger_panel": [
    { "challenger_id": "...", "code_lineage_hash": "...", "independence_class": "..." }
  ],
  "independence_attestation_debate": {
    "min_independent_challengers": 0, "lineage_disjoint": true, "correlation_warning": false
  },
  "referee": {
    "referee_id": "...", "non_gameable": true, "signed_by": "...", "distinct_from_proponent": true
  },
  "debate_ref": "pointer into the C4 provenance DebateLedger",

  "issued_at": "...", "signature": "over the canonicalized report", "signer_key_id": "..."
}
```

The six v1.1 additions:
- **`perturbation_pairs`** — the bidirectional probe results. `must_react` plants a KNOWN-REAL signal that MUST be recovered proportionally (amplitude-linearity); `must_not_react` injects noise / shuffled labels / fake contamination that MUST NOT manufacture a signal and MUST degrade appropriately.
- **`insensitivity_flags`** — records where the claim was INVARIANT to a perturbation it should have reacted to (memorized / constant / spurious-feature). Any flag ⇒ FAIL.
- **`challenger_panel`** — the ≥K red-team CHALLENGERS with `code_lineage_hash` and `independence_class` (see S4 **ChallengeRound** / **Attack**).
- **`independence_attestation_debate`** — `min_independent_challengers`, `lineage_disjoint`, `correlation_warning`; emitted by `attest_challenger_independence`.
- **`referee`** — the non-gameable REFEREE identity; `distinct_from_proponent` MUST be true (referee != builder; signed).
- **`debate_ref`** — pointer into the C4 provenance **DebateLedger** (the append-only record of all **ChallengeRound**s and their **ChallengeVerdict**s for the artifact).

A claim passes only when the **ChallengeVerdict** has `must_react_pass` AND `must_not_react_pass` AND NOT `insensitivity_detected`.

- `claim_tier` is set by the verifier per fixed rules and is **monotone**: `novel-needs-human` additionally **REQUIRES** all leakage checks PASS and cross-code agreement, and even then only marks a *candidate* that S9 must review before it is external.
- The report is written to a write-once bucket; the signature covers a canonical serialization; consumers MUST verify the signature and reject unsigned/tampered reports.

#### Reward-for-recursion semantics

S4 reads `aggregate.score` ONLY from a signature-valid report. `INCONCLUSIVE` counts as non-improvement (never as reward). Any attempt to source reward elsewhere is a policy violation.

#### Extrapolation reciprocity with S7 (C3 ↔ C6)

Verification and forward models form a reciprocal contract on out-of-validity use: **S7 MUST emit an extrapolation / out-of-validity flag** in its [C6](#c6--compute-adapter-tool-interface) tool result (`in_validity_domain:false` / `extrapolation_flag:true`), and **S3 MUST consume that flag and set the affected check to `INCONCLUSIVE`** unless the active profile explicitly permits extrapolated outputs. An extrapolated forward-model call can therefore never silently upgrade a claim tier. This reciprocity is documented symmetrically in [C6](#c6--compute-adapter-tool-interface) (S7 side) and in the S7/S3 subsystem specs.

#### Error semantics

`{code, category(RETRYABLE|BUDGET|PROFILE_UNSUPPORTED|INDEPENDENCE_UNAVAILABLE|INPUT_MISSING), ...}`. `INDEPENDENCE_UNAVAILABLE` (no independent cross-code) downgrades the max achievable tier and is surfaced, not hidden.

---

<a id="c4--artifact--provenance-record"></a>
### C4 — Artifact + Provenance Record

**Owner:** S8 · **Consumers:** S1, S2, S3, S4, S5, S6, S7, S9, S10, S11, S12

The universal record for anything Argus produces (dataset, trained model, Validation Report, plot, config, log). Everything is content-addressed and carries a complete lineage edge set. This is what makes reproducibility and contamination-auditing possible.

#### Versioning

`record_version: semver`. Records are immutable; a 'change' produces a new record with a new `content_hash` and a `derived_from` edge to the prior.

#### ArtifactRecord

```json
{
  "artifact_id": "uuid",
  "content_hash": "string (BLAKE3, also the storage key)",
  "kind": "dataset | model | report | figure | config | log | container | notebook",
  "media_type": "...", "size_bytes": 0, "storage_uri": "...",
  "producer": { "job_id": "...", "subagent_id | verifier_id | adapter_id": "...", "step_id": "..." },
  "lineage": {
    "inputs": [ { "role": "...", "artifact_ref | external_source_ref": "..." } ],
    "derived_from": ["artifact_ref"],
    "code": { "repo": "...", "commit": "...", "dirty": false },
    "environment_digest": "string (container image digest)",
    "adapters_used": [ { "adapter_ref": "...", "adapter_version": "..." } ],
    "seeds": { "global": 0, "per_library": {} },
    "config_hash": "...", "params_hash": "..."
  },
  "claim_tier?": "ran-toy | recapitulated-known | novel-needs-human",
  "validation_report_ref?": "ref(C3)",
  "uncertainty_tag?": { "representation": "...", "value": "..." },
  "contamination_index_version?": "string",
  "created_at": "...", "retention_policy": "...", "access_scope": "..."
}
```

#### Guarantees

- **Reproducibility manifest** = the `lineage` block; MUST be sufficient to re-derive the artifact (subject to declared nondeterminism tolerance). Enforced by S11's re-run canary.
- **Lineage graph**: `derived_from` + `inputs` form a DAG; queries like 'what consumed contaminated dataset X?' MUST be answerable. Append-only, tamper-evident.
- **Tiering coupling**: an artifact's `claim_tier` may exceed `ran-toy` ONLY if `validation_report_ref` points to a signature-valid C3 report whose tier matches. S8 rejects records that violate this.
- **Contamination provenance**: any dataset ingested from S6 records its `contamination_index_version` and source URIs so novelty questions are answerable against a frozen reference.

#### External source refs

For ingested (non-Argus-produced) inputs, `external_source_ref = { source: arxiv|github|hepdata|other, id, url, snapshot_hash, ingested_at, license }`.

#### Error semantics

Writing a record with a missing required lineage field, a hash mismatch, or an illegal tier/report coupling fails with `{code, category(HASH_MISMATCH|INCOMPLETE_LINEAGE|ILLEGAL_TIER|IMMUTABLE_VIOLATION)}` and does NOT commit (fail-closed). Consumers reject any artifact whose `content_hash` does not match its bytes.

---

<a id="c5--registry--capability-descriptor"></a>
### C5 — Registry / Capability Descriptor

**Owner:** S6 / S12 · **Consumers:** S1, S5, S7, S9, S11, S12

The machine-readable declaration of what a subagent, physics code, or tool can do, plus the registry API that stores and serves these for routing (S5) and federation admission (S12).

#### Versioning

`descriptor_version: semver`. The registry is versioned and append-only per entity (each publish is a new immutable revision; `current` pointer moves forward). Consumers pin a revision for reproducible routing.

#### CapabilityDescriptor

```json
{
  "entity_id": "...", "entity_type": "subagent | physics_code | adapter | dataset | verifier",
  "name": "...", "owner": "...", "maintainer_contact": "...",
  "contract_versions": { "c1?": "...", "c6?": "...", "min": "...", "max": "..." },
  "subtopics": [ { "taxonomy_id": "...", "description": "..." } ],
  "capabilities": [ { "verb": "...", "target_observable": "...", "io_schema_ref": "..." } ],
  "required_adapters": ["adapter_ref(C6)"],
  "required_datasets": ["dataset_ref"],
  "resource_envelope": { "cpu": "...", "gpu": "...", "mem": "...", "typical_wallclock": "...", "cost_class": "..." },
  "uncertainty_support": true,
  "conformance": { "level": "bronze|silver|gold", "suite_version": "...", "passed_at": "...", "evidence_ref": "...", "expires_at": "..." },
  "independence_tags": ["..."],
  "trust_class": "internal | federated",
  "provenance_ref": "C4", "signature": "...", "signer_key_id": "...", "status": "active|deprecated|revoked"
}
```

> `independence_tags` are used for cross-code verification eligibility.

#### Registry API

- `publish(descriptor) -> revision_ref` (requires valid conformance evidence for the claimed level).
- `resolve(query{subtopic, required_verifier, min_conformance, independence_needed}) -> [descriptor_revision]` — used by S5 routing and by S3 to find an **independent** cross-code.
- `deprecate(entity_id, revision)` / `revoke(entity_id, reason)` — revocation propagates: in-flight jobs referencing a revoked entity are halted.
- `subscribe(filter) -> stream` — registry change events (NATS) for caches and observability.

#### Federation semantics (S12)

- External entities enter as `trust_class: federated`; admission REQUIRES a passing conformance record (C5 `conformance` block) but grants **no elevated runtime trust** — federated subagents execute in the same S10 untrusted zone.
- The community registry governance (approvals, revocations, taxonomy evolution) is an S12 responsibility and is fully audited.

#### Independence for cross-code (critical)

`independence_tags` + `code.repo`/`derived_from` let S3 select a cross-check code that is genuinely independent of the code under test; the registry MUST be able to answer 'give me an independent implementation of observable O'.

#### Error semantics

`{code, category(CONFORMANCE_MISSING|CONFORMANCE_EXPIRED|SCHEMA_INVALID|REVOKED|VERSION_UNSUPPORTED)}`. Publishing without valid conformance, or resolving a revoked entity, fails closed.

---

<a id="c6--compute-adapter-tool-interface"></a>
### C6 — Compute-Adapter Tool Interface

**Owner:** S7 · **Consumers:** S1, S2, S3, S5, S8, S11, S12

The uniform, uncertainty-tagged interface that exposes any domain physics code, emulator, or differentiable surrogate as a callable forward model, so subagents (S2) and the verifier (S3) invoke forward models identically. Standardized, normalized I/O with units.

#### Versioning

`adapter_contract_version: semver`; each adapter also carries `adapter_version` and the pinned `underlying_code_version` (e.g. the wrapped solver/binary version) in its descriptor ([C5](#c5--registry--capability-descriptor)) and in every output's provenance ([C4](#c4--artifact--provenance-record)).

#### Adapter descriptor (registered via C5)

```json
{ "adapter_id": "...", "exposes": "physics_code | emulator | surrogate",
  "observable": "...", "differentiable": false,
  "input_schema": "typed + UNITS per field", "output_schema": "typed + UNITS",
  "validity_domain": { "param ranges": "...", "applicability_notes": "..." },
  "uncertainty_model": { "kind": "analytic|emulator_gp|ensemble|declared", "calibration_ref": "..." },
  "determinism": "deterministic | seeded | stochastic",
  "independence_tags": ["..."],
  "resource_envelope": "...", "cost_class": "..." }
```

#### Methods

1. `describe() -> AdapterDescriptor`.
2. `evaluate(EvalRequest) -> EvalResult` where `EvalRequest = { inputs (units-tagged), fidelity?, seed?, budget_token, trace_id }` and `EvalResult = { outputs (units-tagged), uncertainty (REQUIRED: interval|covariance|samples), in_validity_domain: bool, extrapolation_flag: bool, cost, provenance_ref(C4) }`.
3. `grad(EvalRequest) -> Jacobian` — **REQUIRED iff** `differentiable:true` (enables gradient-based fitting and cheap differentiable verification).
4. `batch_evaluate([EvalRequest]) -> [EvalResult]`.

#### Guarantees / semantics

- **Units are mandatory** on every input/output field; a units mismatch is a hard error, not a coercion. This backstops the S3 dimensional-consistency gate.
- **Uncertainty is mandatory** on every output; a bare point estimate is non-conformant.
- **Validity domain (extrapolation reciprocity with S3)**: out-of-domain inputs return `in_validity_domain:false` + `extrapolation_flag:true` (or refuse per policy). S7 **MUST** emit this extrapolation / out-of-validity flag in the C6 result, and S3 **MUST** consume it and set the affected check to `INCONCLUSIVE` unless a profile allows extrapolated outputs — a reciprocal contract documented symmetrically in [C3](#c3--verifier-interface--validation-report).
- **Independence**: `independence_tags` let S3 pick a cross-code adapter independent of the one under test (see [C5](#c5--registry--capability-descriptor)).
- **Scope guard**: adapters are for lightweight solvers, emulators, differentiable surrogates, and emulated fast-sim — **NOT** flagship HPC (numerical relativity, large hydro); an adapter whose `cost_class` exceeds the platform ceiling is rejected at registration (enforces the non-goal).
- Every `evaluate`/`grad` emits a C4 provenance record pinning adapter + underlying-code versions and seeds.

#### Error semantics

`{code, category(OUT_OF_DOMAIN|UNITS_MISMATCH|NOT_DIFFERENTIABLE|BUDGET|UNDERLYING_CODE_ERROR|TIMEOUT)}`. `OUT_OF_DOMAIN` and `UNITS_MISMATCH` are non-retryable; `UNDERLYING_CODE_ERROR` captures stderr into provenance for diagnosis (S2 auto-repair).

---

<a id="8-subsystem-dependency-graph"></a>
## 8. Subsystem Dependency Graph

The graph is rooted at two **zero-dependency foundations** — **S8** (data/provenance) and **S10** (security/sandbox) — on which all trust and reproducibility guarantees rest.

### 8.1 Dependency table

| Subsystem | Depends on | Rationale |
|-----------|-----------|-----------|
| **S1** Subagent Framework & Contract | S8, S10 | The SDK/runtime must emit provenance (C4/S8) for every artifact and can only execute agent code inside the sandbox (S10). It defines C1 but consumes the artifact and isolation primitives. Deliberately does NOT depend on S5/S3 (they depend on it), keeping the contract at the bottom of the stack. |
| **S2** ML Builder Engine | S1, S7, S8, S10, S6 | Runs inside the S1 lifecycle and S10 sandbox, calls physics forward models via S7/C6 for physics-aware features and training targets, writes artifacts to S8/C4, and pulls curated docs/priors from S6 to reduce plausible-but-wrong rates. It produces trained models but never grades them. |
| **S3** Physics Validation & Verifier Framework | S7, S8, S6, S1 | The oracle needs independent physics codes (S7/C6) for cross-code checks, content-addressed inputs and signed-report storage (S8/C4), the frozen contamination index (S6) for leakage/novelty screens, and the C1 pipeline handles to fetch frozen pipelines. It must NOT depend on S2/S4 (those it grades) to preserve independence. |
| **S4** Recursive Improvement Loop (Evolver) | S2, S3, S8, S10, S5 | Each iteration proposes a variant, trains via S2, and scores ONLY via a signed S3 report; it persists lineage to S8, executes in the S10 sandbox under hard bounds, and is scheduled/budget-governed by S5. It structurally refuses to run absent a valid S3 verifier. |
| **S5** Control Tower / Orchestration (总台) | S1, S6, S8, S9, S10, S11 | Owns C2 and routes jobs to subagents (S1) using registry lookups (S6/C5), executes durable DAGs writing state/lineage to S8, inserts human-review wait states (S9), enforces budget/concurrency via S10, and emits traces to S11. It is the meta-layer, so it sits above most subsystems. |
| **S6** Knowledge & Ingestion | S8, S10 | Bulk ingest and indexing of arXiv/GitHub/HEPData, RAG, the registry (co-owner of C5), and the frozen contamination index all materialize as content-addressed artifacts (S8/C4) and run ingestion in isolated pipelines (S10). Low in the stack because many subsystems read from it. |
| **S7** Physics Compute Adapters | S8, S10, S6 | Adapters (owner of C6) wrap physics codes/emulators as uncertainty-tagged tools, execute wrapped binaries under sandbox/resource limits (S10), emit provenance per call (S8/C4), and register their descriptors in the registry (S6/C5). They are leaf tools consumed by S2/S3/S4. |
| **S8** Data, Artifact & Provenance | — | The foundational data plane and owner of C4. Content-hashing, artifact store, lineage graph, and reproducibility pinning depend on nothing else in Argus (only on base infra), which is why every other subsystem can safely depend on it. It is the bedrock of the dependency graph. |
| **S9** Human-in-the-loop Review & Governance | S8, S3, S6, S11 | Review queues render Validation Reports (S3/C3) and artifact lineage (S8/C4), use the frozen index (S6) to judge novelty, and surface KPIs (S11). It is the mandatory non-bypassable gate before any external artifact and the sole promoter (with S3) of the novel-needs-human tier. |
| **S10** Security, Sandbox & Runtime | — | The isolation, secrets, egress-control, and cost-governance substrate. Like S8 it depends only on base infrastructure so it can be the trust boundary underneath everything; nothing agent-executed can reach beneath it. Foundational. |
| **S11** Observability & Evaluation | S8, S3, S5 | Consumes traces/metrics from all subsystems and reads artifacts (S8), Validation Reports (S3), and job state (S5) to compute platform KPIs and run the re-run canary and benchmark/eval harness. It observes rather than participates, so it depends on the data it measures without being on the critical trust path. |
| **S12** Interop Standard & Federation | S1, S6, S8, S10 | Publishes the SLHA-for-agents spec (C1, co-owner of C5), ships the contribution SDK/CLI and conformance suite, and runs the community registry/governance. It depends on S1 (the contract it standardizes), the registry (S6/C5), provenance for conformance evidence (S8), and the sandbox that federated subagents run in (S10). Federated entities gain no elevated trust. |

### 8.2 Layered view

```
Layer 0 (foundations, zero-dependency):   S8   S10
Layer 1 (read from foundations):          S1   S6   S7
Layer 2 (build/verify):                   S2   S3
Layer 3 (orchestration & governance):     S5   S9   S4
Layer 4 (observation & federation):       S11  S12
```

*(Layering is by longest dependency chain; several subsystems span layers via multiple edges — see the table for exact edges.)*

---

<a id="9-milestone-themes-phased-build"></a>
## 9. Milestone Themes (Phased Build)

| ID | Theme | Rationale |
|----|-------|-----------|
| **M0** | **Spine & Contracts First** — freeze C1..C6 as versioned JSON Schemas (**C3 is frozen at v1.1**, including the 6 new ValidationReport fields — `perturbation_pairs`, `insensitivity_flags`, `challenger_panel`, `independence_attestation_debate`, `referee`, `debate_ref` — via **S3-TPR1**), stand up the foundational data plane (S8) and sandbox/runtime (S10), and generate language bindings so all 12 teams build against stable seams. | S8 and S10 are the only zero-dependency foundations; every trust and reproducibility guarantee rests on them. Freezing the six contracts first — with C3 already at v1.1 so the adversarial-debate fields need no later migration — is what lets the teams decouple and work in parallel, the entire premise of the architecture. |
| **M1** | **One Vertical Slice, Oracle-Gated** — a single real subtopic end-to-end: one C1 subagent, S2 builder on a classical/tabular baseline, one or two S7 adapters, and a minimal S3 verifier that now explicitly includes the **bidirectional perturbation oracle** (must-react + must-not-react, **S3-TPR2**), the **insensitivity detector** (**S3-TPR3**), and **referee != builder** enforcement (**S3-TPR4**) — on top of injection + null + physical-consistency — producing a signed v1.1 Validation Report, with claim-tiering wired to ran-toy/recapitulated-known. | Proves the load-bearing claim of Argus (verify-before-trust) works on a real problem before scaling breadth. A signed report, a recapitulation, and a non-gameable bidirectional oracle on one subtopic de-risk the oracle layer, which is the whole thesis, and exercise C1/C3/C4/C6 together. |
| **M2** | **Orchestration & Provenance at Scale** — the Control Tower (S5) with durable DAG execution, budget/concurrency governance, and retries over C2; full lineage/audit graph queries in S8; and the re-run canary in S11 proving reproducibility. | Turns a single slice into a governed multi-job platform. Durable orchestration and provable reproducibility are prerequisites for trusting anything at volume and for cost governance, which the thesis flags as the scarce-resource discipline. |
| **M3** | **Knowledge, Registry & Contamination Control** — bulk ingest of arXiv/GitHub/HEPData (S6), curated-doc RAG that measurably lowers plausible-but-wrong rates, the registry/capability descriptors (C5), the frozen contamination index feeding S3 leakage/novelty screens, and **challenger-independence attestation** (lineage-disjoint cross-code, **S3-TPR5**). | Contamination is presumptive in this field; without the frozen index and leakage screens the platform cannot responsibly distinguish recapitulated-known from novel. The registry also unlocks routing (S5), independence attestation for the challenger panel, and, later, federation (S12). |
| **M4** | **Breadth Rollout & Human Governance** — onboard many subtopic subagents (breadth-over-depth), stand up the S9 review queues, claim-tier review UI, publication guardrails, and rate-limits sized to human review capacity; strengthen S3 with cross-code consistency and calibration gates. | Delivers the core value proposition — covering the long tail of subtopics that have no ML today — while ensuring the mandatory human gate and cross-code independence keep pace so nothing external escapes without sign-off. |
| **M5** | **Adversarial Red-Blue Debate Evolution (recursion under oracle)** — enable the Evolver (S4) as a **proponent / challenger / referee** debate loop with hard bounds, challenger diversity, and reward-hacking + collusion defenses, running ONLY where a cheap valid S3 verifier + oracle exists: debate-round orchestrator (**S4-TDB1**), independent challenger-panel selection + diversity policy (**S4-TDB2**), the red-blue evolution loop under the precondition gate (**S4-TDB3**), reward-hacking + challenger-collusion screens (**S4-TDB4**), DebateLedger provenance emission via C4 (**S4-TDB5**), and the feedback → revise → retrain step (**S4-TDB6**); S11 gains a **planted-spurious-model detection harness** alongside the MLE-bench-style + physics held-out benchmark harness and platform KPIs. | Self-improvement is the highest-leverage and highest-risk capability, so it comes only after the verifier, provenance, sandbox, and budget controls are proven. Making recursion an adversarial debate — gated on a signed external reward, attacked by an independent red team, and adjudicated by a non-gameable referee != proponent — is what makes it safe rather than reckless. |
| **M6** | **Federation & Interop Standard** — publish the SLHA-for-agents specification (S12), ship the contribution SDK/CLI and conformance suite (Bronze/Silver/Gold), and open the community registry/governance so external physicists build compliant subagents. | The network effect — external domain experts contributing subagents under a shared contract — is the long-term moat. It is deliberately last because it requires the contract, conformance suite, sandbox, and registry to all be mature and trustworthy before outsiders run code in the federation. |

---

<a id="10-subsystem--contract-cross-reference-index"></a>
## 10. Subsystem & Contract Cross-Reference Index

### 10.1 Contract ownership & consumption

| Contract | Owner | Consumed by |
|----------|-------|-------------|
| [C1](#c1--subagent-contract-slha-for-agents) | S1 | S5, S2, S3, S4, S11, S12 |
| [C2](#c2--taskjob-envelope) | S5 | S1, S2, S3, S4, S7, S9, S10, S11 |
| [C3](#c3--verifier-interface--validation-report) | S3 | S1, S2, S4, S5, S8, S9, S11 |
| [C4](#c4--artifact--provenance-record) | S8 | S1, S2, S3, S4, S5, S6, S7, S9, S10, S11, S12 |
| [C5](#c5--registry--capability-descriptor) | S6 / S12 | S1, S5, S7, S9, S11, S12 |
| [C6](#c6--compute-adapter-tool-interface) | S7 | S1, S2, S3, S5, S8, S11, S12 |

### 10.2 Principle → enforcement map

| Principle | Primarily enforced by |
|-----------|-----------------------|
| P1 Oracle-gated autonomy | S3 (C3 signed reports), N3 |
| P2 Verify-before-trust / presumptive contamination | S6 frozen index, S3 LEAKAGE check, N5 |
| P3 Claim-tiering monotone | C3 tier rules, S9 promotion, N3 |
| P4 Full provenance / reproducibility | S8 (C4), N1, N5, S11 re-run canary |
| P5 Structural safety | S10 sandbox, §6 security model, N2 |
| P6 Contract-only coupling | C1..C6, N13 |
| P7 Breadth-over-depth | M4, C6 scope guard |
| P8 Human-in-the-loop hard gate | S9, N6 |
| P9 Cheap-verifier precondition for recursion | S4 refusal, C2 `verifier_profile_ref` REQUIRED |
| P10 Uncertainty first-class | C6 mandatory uncertainty, S3 CALIBRATION, N11 |
| P11 Physics priors injected | S2/S3 PHYSICAL_CONSISTENCY, C2 `physics_priors` |
| P12 Fail loud and quarantine | typed error envelopes, QUARANTINED states, N8 |

---

*End of Architecture & Shared Contracts document.*
