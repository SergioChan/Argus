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

    def validation_pass_rate(self, events: tuple[PlatformEvent, ...]) -> KPISample:
        seen_report_ids: set[str] = set()
        passed = Decimal("0")
        total = Decimal("0")
        for event in sorted(events, key=lambda item: item.event_id):
            if event.kind != "validation.report_issued":
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
