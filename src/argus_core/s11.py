"""S11 observability, KPI, detector, and re-run canary core semantics."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from decimal import Decimal
from functools import lru_cache
from html import escape
import json
import os
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from argusverify import C3ReportVerifier
from .hashing import hash_json
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, LineageEdge, LineageGraph, Producer


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


OBSERVATORY_SIX_CHECKS = (
    "INJECTION",
    "NULL_CONTROL",
    "CROSS_CODE",
    "PHYSICAL_CONSISTENCY",
    "LEAKAGE",
    "CALIBRATION",
)


@dataclass(frozen=True)
class ObservatoryLineageBundle:
    subject_ref: str
    report_ref: str
    graph: LineageGraph


@dataclass(frozen=True)
class ObservatoryVerification:
    trusted: bool
    failures: tuple[str, ...]
    signature_valid: bool
    signature_key_id: str | None
    subject_ref: str
    report_ref: str


@dataclass(frozen=True)
class ObservatoryRenderResult:
    html: str
    verification: ObservatoryVerification


def render_observatory_v0_html(
    *,
    report_payload: dict[str, Any],
    lineage: ObservatoryLineageBundle,
    report_verifier: C3ReportVerifier,
) -> ObservatoryRenderResult:
    verification = verify_observatory_v0(
        report_payload=report_payload,
        lineage=lineage,
        report_verifier=report_verifier,
    )
    return ObservatoryRenderResult(
        html=_observatory_v0_html(report_payload=report_payload, lineage=lineage, verification=verification),
        verification=verification,
    )


def verify_observatory_v0(
    *,
    report_payload: dict[str, Any],
    lineage: ObservatoryLineageBundle,
    report_verifier: C3ReportVerifier,
) -> ObservatoryVerification:
    failures: list[str] = []
    failures.extend(_c3_validation_report_schema_failures(report_payload))
    signature = report_verifier.verify(report_payload)
    if not signature.valid:
        failures.append(f"signature verification failed: {signature.reason or signature.error_code or 'unknown'}")
    nodes_by_ref = _nodes_by_ref(lineage.graph.nodes, failures)
    subject = nodes_by_ref.get(lineage.subject_ref)
    report_record = nodes_by_ref.get(lineage.report_ref)
    if subject is None:
        failures.append(f"lineage missing subject record: {lineage.subject_ref}")
    if report_record is None:
        failures.append(f"lineage missing report record: {lineage.report_ref}")

    if report_record is not None:
        report_hash = hash_json(report_payload)
        if report_record.content_hash != report_hash:
            failures.append(
                "validation report content hash mismatch: "
                f"record={report_record.content_hash} computed={report_hash}"
            )
    if subject is not None:
        if subject.validation_report_ref != lineage.report_ref:
            failures.append(
                "subject validation_report_ref mismatch: "
                f"record={subject.validation_report_ref or '<missing>'} expected={lineage.report_ref}"
            )
        report_tier = _string_field(report_payload, "claim_tier")
        if report_tier and subject.claim_tier != report_tier:
            failures.append(f"subject tier mismatch: record={subject.claim_tier} report={report_tier}")

    aggregate = report_payload.get("aggregate")
    if not isinstance(aggregate, Mapping) or aggregate.get("passed") is not True:
        failures.append("validation report aggregate.passed is not true")

    checks = _check_map(report_payload)
    for check_name in OBSERVATORY_SIX_CHECKS:
        if check_name not in checks:
            failures.append(f"missing six-check verdict: {check_name}")
            continue
        status = _string_field(checks[check_name], "status")
        if status != "PASS":
            failures.append(f"six-check verdict is not PASS: {check_name}={status or '<missing>'}")

    perturbation_pairs = _sequence_field(report_payload, "perturbation_pairs")
    if not perturbation_pairs:
        failures.append("validation report perturbation_pairs is empty or missing")
    else:
        seen_perturbation_kinds: set[str] = set()
        for index, pair in enumerate(perturbation_pairs):
            if not isinstance(pair, Mapping):
                failures.append(f"perturbation pair {index} is not an object")
                continue
            kind = _string_field(pair, "kind")
            verdict = _string_field(pair, "verdict")
            if kind:
                seen_perturbation_kinds.add(kind)
            if verdict != "pass":
                identifier = _string_field(pair, "perturbation_id") or str(index)
                failures.append(f"perturbation pair verdict is not pass: {identifier}={verdict or '<missing>'}")
        for required_kind in ("must_react", "must_not_react"):
            if required_kind not in seen_perturbation_kinds:
                failures.append(f"missing perturbation kind: {required_kind}")

    insensitivity_flags = _sequence_field(report_payload, "insensitivity_flags")
    if insensitivity_flags:
        failures.append("validation report has insensitivity flags")

    referee = report_payload.get("referee")
    if not isinstance(referee, Mapping):
        failures.append("validation report referee block is missing")
    elif referee.get("distinct_from_proponent") is not True:
        failures.append("validation report referee.distinct_from_proponent is not true")

    profile_ref = _string_field(report_payload, "profile_ref")
    pipeline_ref = _string_field(report_payload, "frozen_pipeline_ref")
    for ref_name, ref in (("profile_ref", profile_ref), ("frozen_pipeline_ref", pipeline_ref)):
        if not ref:
            failures.append(f"report missing {ref_name}")
        elif ref not in nodes_by_ref:
            failures.append(f"lineage missing report {ref_name}: {ref}")

    if report_record is not None and profile_ref and not _has_edge(
        lineage.graph.edges,
        source_ref=profile_ref,
        target_ref=lineage.report_ref,
        edge_type="input",
    ):
        failures.append(f"lineage missing profile input edge: {profile_ref} -> {lineage.report_ref}")
    if report_record is not None and pipeline_ref and not _has_edge(
        lineage.graph.edges,
        source_ref=pipeline_ref,
        target_ref=lineage.report_ref,
        edge_type="input",
    ):
        failures.append(f"lineage missing frozen-pipeline input edge: {pipeline_ref} -> {lineage.report_ref}")
    if subject is not None and report_record is not None and not _has_edge(
        lineage.graph.edges,
        source_ref=lineage.report_ref,
        target_ref=lineage.subject_ref,
        edge_type="validation_report",
    ):
        failures.append(f"lineage missing validation-report edge: {lineage.report_ref} -> {lineage.subject_ref}")

    return ObservatoryVerification(
        trusted=not failures,
        failures=tuple(failures),
        signature_valid=signature.valid,
        signature_key_id=signature.key_id,
        subject_ref=lineage.subject_ref,
        report_ref=lineage.report_ref,
    )


def _c3_validation_report_schema_failures(report_payload: Mapping[str, Any]) -> tuple[str, ...]:
    validator = _c3_validation_report_validator()
    errors = sorted(validator.iter_errors(report_payload), key=lambda error: list(error.path))
    return tuple(
        f"validation report schema violation at {_json_path(error.path)}: {error.message}" for error in errors
    )


@lru_cache(maxsize=1)
def _c3_validation_report_validator() -> Draft202012Validator:
    schema_path = _schema_path("contracts", "c3.validation-report.schema.json")
    with schema_path.open(encoding="utf-8") as handle:
        c3_schema = json.load(handle)
    report_schema = dict(c3_schema["$defs"]["ValidationReport"])
    report_schema["$schema"] = c3_schema["$schema"]
    report_schema["$id"] = c3_schema["$id"] + "#/$defs/ValidationReport"
    report_schema["$defs"] = c3_schema["$defs"]
    return Draft202012Validator(report_schema)


def _schema_path(*parts: str) -> Path:
    candidates: list[Path] = []
    env_root = os.environ.get("ARGUS_SCHEMA_ROOT")
    if env_root:
        candidates.append(Path(env_root).joinpath(*parts))
    candidates.extend(
        (
            Path(__file__).resolve().parents[2] / "schemas" / Path(*parts),
            Path.cwd() / "schemas" / Path(*parts),
        )
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    attempted = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(f"schema file not found: {Path(*parts)}; attempted: {attempted}")


def _json_path(path: Any) -> str:
    parts = ["$"]
    for part in path:
        if isinstance(part, int):
            parts.append(f"[{part}]")
        else:
            parts.append(f".{part}")
    return "".join(parts)


def observatory_lineage_bundle_from_json(payload: Mapping[str, Any]) -> ObservatoryLineageBundle:
    nodes = tuple(_artifact_record_from_json(item) for item in _sequence_field(payload, "nodes"))
    edges = tuple(_lineage_edge_from_json(item) for item in _sequence_field(payload, "edges"))
    return ObservatoryLineageBundle(
        subject_ref=_required_string(payload, "subject_ref"),
        report_ref=_required_string(payload, "report_ref"),
        graph=LineageGraph(nodes=nodes, edges=edges),
    )


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


def _observatory_v0_html(
    *,
    report_payload: dict[str, Any],
    lineage: ObservatoryLineageBundle,
    verification: ObservatoryVerification,
) -> str:
    title = f"Argus Observatory v0 - {_string_field(report_payload, 'report_id') or lineage.report_ref}"
    status_class = "ok" if verification.trusted else "fail"
    status_label = "VERIFIED" if verification.trusted else "FAIL"
    failures = (
        "<p class=\"quiet\">No verification failures.</p>"
        if verification.trusted
        else "<ul>" + "".join(f"<li>{escape(item)}</li>" for item in verification.failures) + "</ul>"
    )
    return "\n".join(
        (
            "<!doctype html>",
            "<html lang=\"en\">",
            "<head>",
            "  <meta charset=\"utf-8\">",
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            f"  <title>{escape(title)}</title>",
            "  <style>",
            _observatory_css(),
            "  </style>",
            "</head>",
            "<body>",
            "  <main>",
            f"    <section class=\"banner {status_class}\" data-verdict=\"{status_label}\">",
            f"      <div><span class=\"eyebrow\">Argus Observatory v0</span><h1>{escape(status_label)} verified-run report</h1></div>",
            f"      <p>{escape(lineage.subject_ref)}</p>",
            "    </section>",
            "    <section>",
            "      <h2>Verification Gate</h2>",
            f"      {failures}",
            "    </section>",
            "    <section>",
            "      <h2>Report Summary</h2>",
            _summary_table(report_payload=report_payload, verification=verification),
            "    </section>",
            "    <section>",
            "      <h2>Six Checks</h2>",
            _checks_table(report_payload),
            "    </section>",
            "    <section>",
            "      <h2>Perturbation Pairs</h2>",
            _perturbation_table(report_payload),
            "    </section>",
            "    <section>",
            "      <h2>Insensitivity Flags</h2>",
            _insensitivity_table(report_payload),
            "    </section>",
            "    <section>",
            "      <h2>Tier Justification</h2>",
            _tier_justification(report_payload),
            "    </section>",
            "    <section>",
            "      <h2>Referee</h2>",
            _referee_table(report_payload),
            "    </section>",
            "    <section>",
            "      <h2>Provenance Chain</h2>",
            _lineage_table(lineage.graph),
            "    </section>",
            "  </main>",
            "</body>",
            "</html>",
            "",
        )
    )


def _observatory_css() -> str:
    return """
    :root {
      color-scheme: light;
      --ink: #17202a;
      --muted: #5a6472;
      --line: #cfd8e3;
      --ok: #146c43;
      --ok-bg: #e8f5ed;
      --fail: #b42318;
      --fail-bg: #fff0ee;
      --panel: #ffffff;
      --page: #f5f7fa;
      --accent: #2454a6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--page);
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 15px;
      line-height: 1.45;
    }
    main {
      width: min(1180px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 24px 0 48px;
    }
    section {
      margin-top: 18px;
      padding: 18px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      overflow: hidden;
    }
    .banner {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: end;
      color: var(--ink);
      border-width: 2px;
    }
    .banner.ok { background: var(--ok-bg); border-color: var(--ok); }
    .banner.fail { background: var(--fail-bg); border-color: var(--fail); }
    .banner p { margin: 0; color: var(--muted); overflow-wrap: anywhere; }
    .eyebrow {
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    h1, h2 { margin: 0; letter-spacing: 0; }
    h1 { font-size: 30px; line-height: 1.1; }
    h2 { font-size: 18px; margin-bottom: 12px; }
    h3 { font-size: 15px; margin: 12px 0 8px; }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    th, td {
      padding: 10px 8px;
      border-top: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      width: 24%;
    }
    .pill {
      display: inline-block;
      padding: 2px 7px;
      border: 1px solid var(--line);
      border-radius: 999px;
      font-weight: 700;
      font-size: 12px;
    }
    .pill.pass, .pill.verified { color: var(--ok); border-color: var(--ok); }
    .pill.fail, .pill.missing { color: var(--fail); border-color: var(--fail); }
    .quiet { color: var(--muted); }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
    @media (max-width: 700px) {
      main { width: min(100vw - 20px, 1180px); padding-top: 10px; }
      .banner { align-items: start; flex-direction: column; }
      h1 { font-size: 24px; }
      th, td { display: block; width: 100%; }
      td { border-top: 0; padding-top: 0; }
    }
    """


def _summary_table(*, report_payload: dict[str, Any], verification: ObservatoryVerification) -> str:
    aggregate = report_payload.get("aggregate") if isinstance(report_payload.get("aggregate"), Mapping) else {}
    rows = (
        ("Report ID", _string_field(report_payload, "report_id")),
        ("Report Ref", verification.report_ref),
        ("Subject Ref", verification.subject_ref),
        ("Profile Ref", _string_field(report_payload, "profile_ref")),
        ("Frozen Pipeline Ref", _string_field(report_payload, "frozen_pipeline_ref")),
        ("Claim Tier", _string_field(report_payload, "claim_tier")),
        ("Aggregate Passed", str(aggregate.get("passed"))),
        ("Aggregate Score", _json_cell(aggregate.get("score"))),
        ("Signature", "valid" if verification.signature_valid else "invalid"),
        ("Signature Key", verification.signature_key_id or ""),
    )
    return _key_value_table(rows)


def _checks_table(report_payload: dict[str, Any]) -> str:
    checks = _check_map(report_payload)
    rows = []
    for check_name in OBSERVATORY_SIX_CHECKS:
        check = checks.get(check_name, {})
        status = _string_field(check, "status") if isinstance(check, Mapping) else ""
        rows.append(
            "<tr>"
            f"<td>{escape(check_name)}</td>"
            f"<td>{_status_pill(status or 'MISSING')}</td>"
            f"<td><code>{escape(_json_cell(check.get('metrics') if isinstance(check, Mapping) else None))}</code></td>"
            f"<td>{escape(', '.join(_string_items(check.get('evidence_refs') if isinstance(check, Mapping) else ())))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Check</th><th>Status</th><th>Metrics</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _perturbation_table(report_payload: dict[str, Any]) -> str:
    pairs = _sequence_field(report_payload, "perturbation_pairs")
    if not pairs:
        return "<p class=\"quiet\">No perturbation pairs recorded.</p>"
    rows = []
    for pair in pairs:
        if not isinstance(pair, Mapping):
            continue
        details = {k: v for k, v in pair.items() if k not in {"perturbation_id", "kind", "verdict"}}
        rows.append(
            "<tr>"
            f"<td>{escape(str(pair.get('perturbation_id', '')))}</td>"
            f"<td>{escape(str(pair.get('kind', '')))}</td>"
            f"<td>{_status_pill(str(pair.get('verdict', '')))}</td>"
            f"<td><code>{escape(_json_cell(details))}</code></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>ID</th><th>Kind</th><th>Verdict</th><th>Details</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _insensitivity_table(report_payload: dict[str, Any]) -> str:
    flags = _sequence_field(report_payload, "insensitivity_flags")
    if not flags:
        return "<p class=\"quiet\">No insensitivity flags recorded.</p>"
    rows = []
    for flag in flags:
        if not isinstance(flag, Mapping):
            continue
        rows.append(
            "<tr>"
            f"<td>{escape(str(flag.get('perturbation_id', '')))}</td>"
            f"<td>{escape(str(flag.get('severity', '')))}</td>"
            f"<td>{escape(str(flag.get('reason', '')))}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>Perturbation</th><th>Severity</th><th>Reason</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _tier_justification(report_payload: dict[str, Any]) -> str:
    aggregate = report_payload.get("aggregate") if isinstance(report_payload.get("aggregate"), Mapping) else {}
    independence = (
        report_payload.get("independence_attestation_debate")
        if isinstance(report_payload.get("independence_attestation_debate"), Mapping)
        else {}
    )
    rows = (
        ("Claim Tier", _string_field(report_payload, "claim_tier")),
        ("Aggregate Passed", str(aggregate.get("passed"))),
        ("Aggregate Score", _json_cell(aggregate.get("score"))),
        ("Lineage Disjoint", str(independence.get("lineage_disjoint"))),
        ("Correlation Warning", str(independence.get("correlation_warning"))),
        ("Min Independent Challengers", _json_cell(independence.get("min_independent_challengers"))),
    )
    return _key_value_table(rows)


def _referee_table(report_payload: dict[str, Any]) -> str:
    referee = report_payload.get("referee") if isinstance(report_payload.get("referee"), Mapping) else {}
    rows = (
        ("Referee ID", _string_field(referee, "referee_id")),
        ("Non-gameable", str(referee.get("non_gameable"))),
        ("Signed By", _string_field(referee, "signed_by")),
        ("Distinct From Proponent", str(referee.get("distinct_from_proponent"))),
    )
    return _key_value_table(rows)


def _lineage_table(graph: LineageGraph) -> str:
    node_rows = [
        "<tr>"
        f"<td>{escape(record.artifact_ref)}</td>"
        f"<td>{escape(record.kind)}</td>"
        f"<td>{escape(record.producer.subsystem)}</td>"
        f"<td><code>{escape(record.content_hash)}</code></td>"
        f"<td>{escape(record.lineage.code_ref)}</td>"
        "</tr>"
        for record in graph.nodes
    ]
    edge_rows = [
        "<tr>"
        f"<td>{escape(edge.source_ref)}</td>"
        f"<td>{escape(edge.edge_type)}</td>"
        f"<td>{escape(edge.target_ref)}</td>"
        "</tr>"
        for edge in graph.edges
    ]
    return (
        "<h3>Nodes</h3>"
        "<table><thead><tr><th>Artifact</th><th>Kind</th><th>Producer</th><th>Content Hash</th><th>Code Ref</th></tr></thead><tbody>"
        + "".join(node_rows)
        + "</tbody></table>"
        "<h3>Edges</h3>"
        "<table><thead><tr><th>Source</th><th>Type</th><th>Target</th></tr></thead><tbody>"
        + "".join(edge_rows)
        + "</tbody></table>"
    )


def _key_value_table(rows: tuple[tuple[str, str], ...]) -> str:
    return "<table><tbody>" + "".join(f"<tr><th>{escape(key)}</th><td>{escape(value)}</td></tr>" for key, value in rows) + "</tbody></table>"


def _status_pill(value: str) -> str:
    label = value or "UNKNOWN"
    css = label.lower().replace("_", "-")
    return f"<span class=\"pill {escape(css)}\">{escape(label)}</span>"


def _json_cell(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _check_map(report_payload: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    checks = report_payload.get("checks")
    if not isinstance(checks, list):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for check in checks:
        if isinstance(check, Mapping) and isinstance(check.get("check"), str):
            result[check["check"]] = check
    return result


def _nodes_by_ref(records: tuple[ArtifactRecord, ...], failures: list[str]) -> dict[str, ArtifactRecord]:
    nodes: dict[str, ArtifactRecord] = {}
    for record in records:
        if record.artifact_ref in nodes:
            failures.append(f"duplicate lineage node: {record.artifact_ref}")
        nodes[record.artifact_ref] = record
    return nodes


def _has_edge(edges: tuple[LineageEdge, ...], *, source_ref: str, target_ref: str, edge_type: str) -> bool:
    return any(
        edge.source_ref == source_ref and edge.target_ref == target_ref and edge.edge_type == edge_type
        for edge in edges
    )


def _artifact_record_from_json(payload: Any) -> ArtifactRecord:
    if not isinstance(payload, Mapping):
        raise ValueError("lineage node must be an object")
    producer = payload.get("producer")
    lineage = payload.get("lineage")
    if not isinstance(producer, Mapping):
        raise ValueError("lineage node producer must be an object")
    if not isinstance(lineage, Mapping):
        raise ValueError("lineage node lineage must be an object")
    return ArtifactRecord(
        artifact_ref=_required_string(payload, "artifact_ref"),
        kind=_required_string(payload, "kind"),
        content_hash=_required_string(payload, "content_hash"),
        size_bytes=int(payload.get("size_bytes", 0)),
        producer=Producer(
            subsystem=_required_string(producer, "subsystem"),
            version=_required_string(producer, "version"),
            actor_id=_optional_string(producer, "actor_id"),
            job_id=_optional_string(producer, "job_id"),
        ),
        lineage=Lineage(
            input_refs=tuple(_string_items(lineage.get("input_refs", ()))),
            code_ref=_required_string(lineage, "code_ref"),
            environment_digest=_required_string(lineage, "environment_digest"),
            seeds=tuple(_string_items(lineage.get("seeds", ()))),
            actor_id=_optional_string(lineage, "actor_id"),
            job_id=_optional_string(lineage, "job_id"),
            contamination_index_version=_optional_string(lineage, "contamination_index_version"),
        ),
        claim_tier=str(payload.get("claim_tier", "ran-toy")),
        validation_report_ref=_optional_string(payload, "validation_report_ref"),
        created_at=str(payload.get("created_at", "")),
    )


def _lineage_edge_from_json(payload: Any) -> LineageEdge:
    if not isinstance(payload, Mapping):
        raise ValueError("lineage edge must be an object")
    return LineageEdge(
        source_ref=_required_string(payload, "source_ref"),
        target_ref=_required_string(payload, "target_ref"),
        edge_type=_required_string(payload, "edge_type"),
    )


def _sequence_field(payload: Mapping[str, Any], field_name: str) -> tuple[Any, ...]:
    value = payload.get(field_name, ())
    if value is None:
        return ()
    if not isinstance(value, list | tuple):
        raise ValueError(f"{field_name} must be an array")
    return tuple(value)


def _required_string(payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
    return value


def _optional_string(payload: Mapping[str, Any], field_name: str) -> str | None:
    value = payload.get(field_name)
    return value if isinstance(value, str) else None


def _string_field(payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    return value if isinstance(value, str) else ""


def _string_items(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str))
