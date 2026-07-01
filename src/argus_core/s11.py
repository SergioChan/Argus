"""S11 observability, KPI, detector, and re-run canary core semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from decimal import Decimal
from typing import Any

from .c3 import C3ReportVerifier
from .hashing import hash_json
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


class S11Error(Exception):
    """Base class for S11 observability failures."""


@dataclass(frozen=True)
class TelemetrySpan:
    trace_id: str
    span_id: str
    name: str
    subsystem: str
    attributes: dict[str, Any]


@dataclass(frozen=True)
class ScrubbedTelemetry:
    span: TelemetrySpan
    redacted_fields: tuple[str, ...]
    scrub_uncertain_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str
    subject_ref: str
    reason: str
    confidence: str = "confirmed"


@dataclass(frozen=True)
class TraceSummary:
    trace_id: str
    required_spans: tuple[str, ...]
    observed_spans: tuple[str, ...]
    completeness: float
    status: str
    findings: tuple[Finding, ...] = ()
    revision: int = 1


@dataclass(frozen=True)
class PlatformEvent:
    event_id: str
    kind: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class KPISample:
    name: str
    definition_hash: str
    numerator: Decimal
    denominator: Decimal
    value: Decimal | None
    status: str = "fresh"


@dataclass(frozen=True)
class CanaryResult:
    artifact_ref: str
    verdict: str
    comparator: str
    expected_hash: str | None = None
    rederived_hash: str | None = None
    tolerance: Decimal | None = None
    divergence: Decimal | None = None
    method: str = "rerun"


@dataclass(frozen=True)
class EvalTask:
    task_id: str
    harness: str
    input_ref: str
    expected_value: Decimal
    tolerance: Decimal
    expected_tier: str = "recapitulated-known"
    planted: bool = False


@dataclass(frozen=True)
class BlindEvalPayload:
    task_id: str
    harness: str
    input_ref: str


@dataclass(frozen=True)
class EvalTaskResult:
    task_id: str
    score: Decimal
    passed: bool
    recovered: bool
    expected_tier: str
    observed_tier: str
    finding: Finding | None = None


@dataclass(frozen=True)
class EvalScorecard:
    scorecard_id: str
    harness: str
    suite_version: str
    platform_build: str
    run_id: str
    task_results: tuple[EvalTaskResult, ...]
    aggregate_score: Decimal
    regression_vs_prev: Decimal | None
    input_refs: tuple[str, ...]


@dataclass(frozen=True)
class PlantedExploitRecord:
    scenario_id: str
    kind: str
    caught: bool
    excluded_from_real_kpis: bool = True


@dataclass(frozen=True)
class SpuriousModelProbe:
    scenario_id: str
    candidate_ref: str
    insensitivity_detected: bool
    survived_pre_human_gate: bool


@dataclass(frozen=True)
class SpuriousModelResult:
    scenario_id: str
    caught: bool
    finding: Finding | None


@dataclass(frozen=True)
class AdvisoryPauseRecommendation:
    subject_ref: str
    finding_kind: str
    recommended: bool
    authority: str = "advisory_only"


@dataclass(frozen=True)
class TrustDigest:
    digest_date: str
    kpis: tuple[KPISample, ...]
    findings_by_severity: dict[str, int]
    canary_summary: dict[str, int]
    eval_regressions: tuple[str, ...]
    quarantined_jobs: tuple[str, ...]


class TelemetryScrubber:
    """Fail-closed span scrubber for S11 ingest."""

    _SENSITIVE_FIELDS = frozenset({"budget_token", "scope_token", "secret", "authorization"})

    def __init__(self, *, allowed_attribute_fields: tuple[str, ...]) -> None:
        self._allowed = set(allowed_attribute_fields)

    def scrub(self, span: TelemetrySpan) -> ScrubbedTelemetry:
        attributes: dict[str, Any] = {}
        redacted: list[str] = []
        uncertain: list[str] = []
        for key, value in span.attributes.items():
            if key in self._SENSITIVE_FIELDS:
                attributes[key] = "REDACTED"
                redacted.append(key)
            elif key not in self._allowed:
                attributes[key] = "REDACTED"
                redacted.append(key)
                uncertain.append(key)
            else:
                attributes[key] = value
        return ScrubbedTelemetry(
            span=replace(span, attributes=attributes),
            redacted_fields=tuple(sorted(redacted)),
            scrub_uncertain_fields=tuple(sorted(uncertain)),
        )


class TraceAssembler:
    """Computes S11 trace completeness over a required span set."""

    def __init__(self, *, required_spans: tuple[str, ...]) -> None:
        if not required_spans:
            raise S11Error("required_spans cannot be empty")
        self._required_spans = tuple(required_spans)

    def assemble(self, *, trace_id: str, spans: tuple[TelemetrySpan, ...], revision: int = 1) -> TraceSummary:
        observed = tuple(sorted({span.name for span in spans if span.trace_id == trace_id}))
        observed_set = set(observed)
        missing = tuple(name for name in self._required_spans if name not in observed_set)
        completeness = (len(self._required_spans) - len(missing)) / len(self._required_spans)
        findings = ()
        if missing:
            findings = (
                Finding(
                    kind="broken_trace",
                    severity="S2",
                    subject_ref=trace_id,
                    reason="missing spans: " + ",".join(missing),
                ),
            )
        return TraceSummary(
            trace_id=trace_id,
            required_spans=self._required_spans,
            observed_spans=observed,
            completeness=completeness,
            status="complete" if not missing else "partial",
            findings=findings,
            revision=revision,
        )

    def amend(self, previous: TraceSummary, *, spans: tuple[TelemetrySpan, ...]) -> TraceSummary:
        return self.assemble(trace_id=previous.trace_id, spans=spans, revision=previous.revision + 1)


class KPIProcessor:
    """Deterministic S11 KPI computations over immutable platform events."""

    def validation_pass_rate(self, events: tuple[PlatformEvent, ...], *, exclude_planted: bool = True) -> KPISample:
        seen_report_ids: set[str] = set()
        passed = Decimal("0")
        total = Decimal("0")
        for event in sorted(events, key=lambda item: item.event_id):
            if event.kind != "validation.report_issued":
                continue
            if exclude_planted and event.payload.get("planted") is True:
                continue
            report_id = str(event.payload["report_id"])
            if report_id in seen_report_ids:
                continue
            seen_report_ids.add(report_id)
            total += Decimal("1")
            if event.payload.get("passed") is True:
                passed += Decimal("1")
        return KPISample(
            name="validation_pass_rate",
            definition_hash=hash_json({"name": "validation_pass_rate", "version": "1.0.0"}),
            numerator=passed,
            denominator=total,
            value=(passed / total) if total else None,
        )

    def cost_per_verified_artifact(
        self,
        *,
        spend_usd: Decimal | int | str,
        verified_artifact_count: int,
    ) -> KPISample:
        spend = spend_usd if isinstance(spend_usd, Decimal) else Decimal(str(spend_usd))
        denominator = Decimal(verified_artifact_count)
        return KPISample(
            name="cost_per_verified_artifact",
            definition_hash=hash_json({"name": "cost_per_verified_artifact", "version": "1.0.0"}),
            numerator=spend,
            denominator=denominator,
            value=(spend / denominator) if denominator else None,
        )


class EvalVault:
    """Label-isolated eval vault and scoring shim."""

    def __init__(self, tasks: tuple[EvalTask, ...]) -> None:
        self._tasks = {task.task_id: task for task in tasks}

    def blind_payload(self, task_id: str) -> BlindEvalPayload:
        task = self._tasks[task_id]
        return BlindEvalPayload(task_id=task.task_id, harness=task.harness, input_ref=task.input_ref)

    def sandbox_label_read(self, *, task_id: str, sandbox_identity: str) -> Finding:
        return Finding(
            kind="eval_vault_access_denied",
            severity="S1",
            subject_ref=f"{sandbox_identity}:{task_id}",
            reason="sandbox identity cannot read held-out labels or scoring shim",
        )

    def score(self, *, task_id: str, observed_value: Decimal | int | str) -> Decimal:
        task = self._tasks[task_id]
        observed = observed_value if isinstance(observed_value, Decimal) else Decimal(str(observed_value))
        error = abs(observed - task.expected_value)
        if task.tolerance == 0:
            return Decimal("1") if error == 0 else Decimal("0")
        return max(Decimal("0"), Decimal("1") - (error / task.tolerance))

    def task(self, task_id: str) -> EvalTask:
        return self._tasks[task_id]


class EvalHarness:
    """Deterministic MLE-bench and physics-recap scorecard runner."""

    def __init__(self, *, vault: EvalVault) -> None:
        self._vault = vault

    def run_scorecard(
        self,
        *,
        harness: str,
        suite_version: str,
        platform_build: str,
        run_id: str,
        outputs: dict[str, Decimal | int | str],
        observed_tiers: dict[str, str] | None = None,
        previous: EvalScorecard | None = None,
    ) -> EvalScorecard:
        observed_tiers = observed_tiers or {}
        results: list[EvalTaskResult] = []
        input_refs: list[str] = []
        for task_id in sorted(outputs):
            task = self._vault.task(task_id)
            if task.harness != harness:
                continue
            score = self._vault.score(task_id=task_id, observed_value=outputs[task_id])
            observed = outputs[task_id] if isinstance(outputs[task_id], Decimal) else Decimal(str(outputs[task_id]))
            recovered = abs(observed - task.expected_value) <= task.tolerance
            observed_tier = observed_tiers.get(task_id, task.expected_tier)
            finding = _tier_finding(task, observed_tier) if recovered and observed_tier != task.expected_tier else None
            results.append(
                EvalTaskResult(
                    task_id=task_id,
                    score=score,
                    passed=recovered and finding is None,
                    recovered=recovered,
                    expected_tier=task.expected_tier,
                    observed_tier=observed_tier,
                    finding=finding,
                )
            )
            input_refs.append(task.input_ref)
        if not results:
            raise S11Error("scorecard has no task results")
        aggregate = sum((result.score for result in results), Decimal("0")) / Decimal(len(results))
        regression = (aggregate - previous.aggregate_score) if previous is not None else None
        scorecard_id = hash_json(
            {
                "harness": harness,
                "suite_version": suite_version,
                "platform_build": platform_build,
                "run_id": run_id,
                "results": [_eval_result_payload(result) for result in results],
                "previous": previous.scorecard_id if previous else None,
            }
        )
        return EvalScorecard(
            scorecard_id=scorecard_id,
            harness=harness,
            suite_version=suite_version,
            platform_build=platform_build,
            run_id=run_id,
            task_results=tuple(results),
            aggregate_score=aggregate,
            regression_vs_prev=regression,
            input_refs=tuple(input_refs),
        )

    def write_scorecard(
        self,
        *,
        store: InMemoryArtifactStore,
        scorecard: EvalScorecard,
        producer_version: str = "0.0.0",
    ) -> ArtifactRecord:
        return store.create_artifact(
            kind="eval_scorecard",
            payload=_scorecard_payload(scorecard),
            producer=Producer(subsystem="S11", version=producer_version),
            lineage=Lineage(
                input_refs=scorecard.input_refs,
                code_ref="git:s11-eval-harness",
                environment_digest="oci:s11-eval-harness",
            ),
        )


class ReRunCanary:
    """Compares re-derived outputs and records CanaryResult artifacts."""

    def compare_hash(self, *, artifact_ref: str, expected_hash: str, rederived_hash: str) -> CanaryResult:
        return CanaryResult(
            artifact_ref=artifact_ref,
            verdict="reproducible" if expected_hash == rederived_hash else "non_reproducible",
            comparator="hash_equal",
            expected_hash=expected_hash,
            rederived_hash=rederived_hash,
        )

    def compare_tolerance(
        self,
        *,
        artifact_ref: str,
        expected_value: Decimal | int | str,
        rederived_value: Decimal | int | str,
        tolerance: Decimal | int | str,
    ) -> CanaryResult:
        expected = expected_value if isinstance(expected_value, Decimal) else Decimal(str(expected_value))
        rederived = rederived_value if isinstance(rederived_value, Decimal) else Decimal(str(rederived_value))
        tol = tolerance if isinstance(tolerance, Decimal) else Decimal(str(tolerance))
        divergence = abs(rederived - expected)
        return CanaryResult(
            artifact_ref=artifact_ref,
            verdict="reproducible" if divergence <= tol else "non_reproducible",
            comparator="statistical_tolerance",
            tolerance=tol,
            divergence=divergence,
        )

    def write_result(
        self,
        *,
        store: InMemoryArtifactStore,
        result: CanaryResult,
        producer_version: str = "0.0.0",
    ) -> ArtifactRecord:
        payload = asdict(result)
        if result.tolerance is not None:
            payload["tolerance"] = str(result.tolerance)
        if result.divergence is not None:
            payload["divergence"] = str(result.divergence)
        return store.create_artifact(
            kind="canary_result",
            payload=payload,
            producer=Producer(subsystem="S11", version=producer_version),
            lineage=Lineage(
                input_refs=(result.artifact_ref,),
                code_ref="git:s11-canary",
                environment_digest="oci:s11-canary",
            ),
        )


class TransparencyDetector:
    """Read-only detector for promoted artifacts lacking valid C3 coupling."""

    def __init__(self, *, report_verifier: C3ReportVerifier | None = None) -> None:
        self._report_verifier = report_verifier

    def detect(
        self,
        *,
        record: ArtifactRecord,
        report_payload: dict[str, Any] | None,
    ) -> Finding | None:
        if record.claim_tier == "ran-toy":
            return None
        if not record.lineage.code_ref or not record.lineage.environment_digest:
            return self._finding(record, "broken promoted lineage")
        if not record.validation_report_ref or report_payload is None:
            return self._finding(record, "missing validation report")
        if self._report_verifier is not None:
            verification = self._report_verifier.verify(report_payload)
            if not verification.valid:
                return self._finding(record, f"invalid validation report signature: {verification.reason}")
            if verification.claim_tier != record.claim_tier:
                return self._finding(record, "validation report tier mismatch")
            if verification.aggregate_passed is not True:
                return self._finding(record, "validation report did not pass")
        elif report_payload.get("claim_tier") != record.claim_tier:
            return self._finding(record, "validation report tier mismatch")
        return None

    @staticmethod
    def _finding(record: ArtifactRecord, reason: str) -> Finding:
        return Finding(
            kind="transparency_failure",
            severity="S1",
            subject_ref=record.artifact_ref,
            reason=reason,
        )


def detect_reward_hacking(*, score_ref: str, report_ref: str | None, signature_valid: bool) -> Finding | None:
    if report_ref and signature_valid:
        return None
    return Finding(
        kind="reward_hacking",
        severity="S1",
        subject_ref=score_ref,
        reason="score lacks signature-valid C3 report",
    )


def planted_exploit_catch_rate(records: tuple[PlantedExploitRecord, ...]) -> KPISample:
    caught = Decimal(sum(1 for record in records if record.caught))
    total = Decimal(len(records))
    return KPISample(
        name="planted_exploit_catch_rate",
        definition_hash=hash_json({"name": "planted_exploit_catch_rate", "version": "1.0.0"}),
        numerator=caught,
        denominator=total,
        value=(caught / total) if total else None,
    )


def run_planted_spurious_model_harness(
    probes: tuple[SpuriousModelProbe, ...],
) -> tuple[tuple[SpuriousModelResult, ...], KPISample]:
    results = tuple(_spurious_result(probe) for probe in probes)
    caught = Decimal(sum(1 for result in results if result.caught))
    total = Decimal(len(results))
    return (
        results,
        KPISample(
            name="insensitivity_catch_rate",
            definition_hash=hash_json({"name": "insensitivity_catch_rate", "version": "1.0.0"}),
            numerator=caught,
            denominator=total,
            value=(caught / total) if total else None,
        ),
    )


def detect_cost_anomaly(
    *,
    subject_ref: str,
    cost_usd: Decimal | int | str,
    score_delta: Decimal | int | str,
    min_cost_usd: Decimal | int | str,
    max_score_delta: Decimal | int | str,
) -> Finding | None:
    cost = cost_usd if isinstance(cost_usd, Decimal) else Decimal(str(cost_usd))
    delta = score_delta if isinstance(score_delta, Decimal) else Decimal(str(score_delta))
    cost_floor = min_cost_usd if isinstance(min_cost_usd, Decimal) else Decimal(str(min_cost_usd))
    delta_ceiling = max_score_delta if isinstance(max_score_delta, Decimal) else Decimal(str(max_score_delta))
    if cost < cost_floor or abs(delta) > delta_ceiling:
        return None
    return Finding(
        kind="cost_anomaly",
        severity="S2",
        subject_ref=subject_ref,
        reason="high spend with near-zero verified score delta",
    )


def recommend_pause(finding: Finding) -> AdvisoryPauseRecommendation:
    return AdvisoryPauseRecommendation(
        subject_ref=finding.subject_ref,
        finding_kind=finding.kind,
        recommended=finding.severity in {"S1", "S2"},
    )


def assemble_trust_digest(
    *,
    digest_date: str,
    kpis: tuple[KPISample, ...],
    findings: tuple[Finding, ...],
    canaries: tuple[CanaryResult, ...],
    scorecards: tuple[EvalScorecard, ...],
    quarantined_jobs: tuple[str, ...],
) -> TrustDigest:
    findings_by_severity: dict[str, int] = {}
    for finding in findings:
        findings_by_severity[finding.severity] = findings_by_severity.get(finding.severity, 0) + 1
    canary_summary: dict[str, int] = {}
    for canary in canaries:
        canary_summary[canary.verdict] = canary_summary.get(canary.verdict, 0) + 1
    regressions = tuple(
        scorecard.scorecard_id
        for scorecard in scorecards
        if scorecard.regression_vs_prev is not None and scorecard.regression_vs_prev < 0
    )
    return TrustDigest(
        digest_date=digest_date,
        kpis=kpis,
        findings_by_severity=findings_by_severity,
        canary_summary=canary_summary,
        eval_regressions=regressions,
        quarantined_jobs=tuple(sorted(quarantined_jobs)),
    )


def _tier_finding(task: EvalTask, observed_tier: str) -> Finding:
    kind = "transparency_failure" if observed_tier == "novel-needs-human" else "reward_hacking"
    return Finding(
        kind=kind,
        severity="S1",
        subject_ref=task.task_id,
        reason=f"expected tier {task.expected_tier}, observed {observed_tier}",
    )


def _spurious_result(probe: SpuriousModelProbe) -> SpuriousModelResult:
    caught = probe.insensitivity_detected and not probe.survived_pre_human_gate
    finding = None
    if not caught:
        finding = Finding(
            kind="spurious_model_escape",
            severity="S1",
            subject_ref=probe.candidate_ref,
            reason="planted spurious model survived pre-human gate",
        )
    return SpuriousModelResult(scenario_id=probe.scenario_id, caught=caught, finding=finding)


def _scorecard_payload(scorecard: EvalScorecard) -> dict[str, Any]:
    return {
        "scorecard_id": scorecard.scorecard_id,
        "harness": scorecard.harness,
        "suite_version": scorecard.suite_version,
        "platform_build": scorecard.platform_build,
        "run_id": scorecard.run_id,
        "task_results": [_eval_result_payload(result) for result in scorecard.task_results],
        "aggregate_score": str(scorecard.aggregate_score),
        "regression_vs_prev": str(scorecard.regression_vs_prev) if scorecard.regression_vs_prev is not None else None,
        "input_refs": scorecard.input_refs,
    }


def _eval_result_payload(result: EvalTaskResult) -> dict[str, Any]:
    payload = {
        "task_id": result.task_id,
        "score": str(result.score),
        "passed": result.passed,
        "recovered": result.recovered,
        "expected_tier": result.expected_tier,
        "observed_tier": result.observed_tier,
    }
    if result.finding is not None:
        payload["finding"] = asdict(result.finding)
    return payload
