"""S3 verifier, perturbation oracle, and signed report core semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from uuid import uuid4

from .c3 import C3ReportSigner


class S3Error(Exception):
    """Base class for S3 verifier failures."""


class RefereePolicyError(S3Error):
    """Raised when the S3 referee is not distinct from the proponent."""


@dataclass(frozen=True)
class CheckResult:
    check: str
    status: str
    metrics: dict[str, Any] | None = None


@dataclass(frozen=True)
class PerturbationResult:
    perturbation_id: str
    kind: str
    verdict: str
    amplitude_linearity: dict[str, float] | None = None
    observed_degradation: dict[str, float] | None = None


@dataclass(frozen=True)
class InsensitivityFlag:
    perturbation_id: str
    reason: str
    severity: str = "fail"


@dataclass(frozen=True)
class PerturbationPairOutcome:
    perturbation_pairs: tuple[PerturbationResult, ...]
    insensitivity_flags: tuple[InsensitivityFlag, ...]


class S3Verifier:
    """Minimal non-gameable S3 referee that emits signed C3 reports."""

    def __init__(self, *, verifier_id: str, signer_key_id: str, signer: C3ReportSigner) -> None:
        self.verifier_id = verifier_id
        self.signer_key_id = signer_key_id
        self.signer = signer

    def build_report(
        self,
        *,
        profile_ref: str,
        frozen_pipeline_ref: str,
        checks: tuple[CheckResult, ...],
        proponent_id: str,
        perturbation_outcome: PerturbationPairOutcome | None = None,
        challenger_ids: tuple[str, ...] = (),
        debate_ref: str = "c4://debate/not-run",
    ) -> dict[str, Any]:
        referee = build_referee_block(
            referee_id=self.verifier_id,
            signer_key_id=self.signer_key_id,
            proponent_id=proponent_id,
        )
        perturbation_outcome = perturbation_outcome or PerturbationPairOutcome((), ())
        aggregate_passed = _aggregate_passed(checks, perturbation_outcome)
        claim_tier = tier_from_checks(checks) if aggregate_passed else "ran-toy"
        report = {
            "report_id": str(uuid4()),
            "profile_ref": profile_ref,
            "frozen_pipeline_ref": frozen_pipeline_ref,
            "checks": [_check_to_contract(check) for check in checks],
            "aggregate": {
                "passed": aggregate_passed,
                "score": _aggregate_score(checks),
            },
            "claim_tier": claim_tier,
            "claim_tier_is_candidate": claim_tier == "novel-needs-human",
            "signature": {
                "algorithm": "placeholder",
                "key_id": "placeholder",
                "value": "placeholder",
            },
            "perturbation_pairs": [asdict(pair) for pair in perturbation_outcome.perturbation_pairs],
            "insensitivity_flags": [asdict(flag) for flag in perturbation_outcome.insensitivity_flags],
            "challenger_panel": {
                "challenger_ids": list(challenger_ids),
                "min_required": len(challenger_ids) if challenger_ids else 1,
            },
            "independence_attestation_debate": {
                "min_independent_challengers": len(set(challenger_ids)),
                "lineage_disjoint": len(set(challenger_ids)) == len(challenger_ids),
                "correlation_warning": len(set(challenger_ids)) != len(challenger_ids),
            },
            "referee": referee,
            "debate_ref": debate_ref,
        }
        return self.signer.sign(report)


def run_perturbation_pair(
    *,
    perturbation_id: str,
    must_react_expected: float,
    must_react_observed: float,
    must_not_react_observed: float,
    unperturbed_headline: float,
    perturbed_headline: float,
    relative_tolerance: float = 0.1,
    null_abs_tolerance: float = 0.05,
    sensitivity_floor: float = 0.05,
) -> PerturbationPairOutcome:
    must_react_error = abs(must_react_observed - must_react_expected)
    allowed_error = max(abs(must_react_expected) * relative_tolerance, sensitivity_floor)
    must_react_pass = must_react_error <= allowed_error
    must_not_react_pass = abs(must_not_react_observed) <= null_abs_tolerance

    flags: list[InsensitivityFlag] = []
    if abs(unperturbed_headline) > sensitivity_floor and abs(unperturbed_headline - perturbed_headline) <= sensitivity_floor:
        flags.append(
            InsensitivityFlag(
                perturbation_id=perturbation_id,
                reason="headline_result_invariant_under_should-react_perturbation",
            )
        )

    return PerturbationPairOutcome(
        perturbation_pairs=(
            PerturbationResult(
                perturbation_id=perturbation_id,
                kind="must_react",
                verdict="pass" if must_react_pass else "fail",
                amplitude_linearity={
                    "expected": must_react_expected,
                    "observed": must_react_observed,
                    "absolute_error": must_react_error,
                },
            ),
            PerturbationResult(
                perturbation_id=perturbation_id,
                kind="must_not_react",
                verdict="pass" if must_not_react_pass else "fail",
                observed_degradation={
                    "observed_signal": must_not_react_observed,
                    "absolute_tolerance": null_abs_tolerance,
                },
            ),
        ),
        insensitivity_flags=tuple(flags),
    )


def build_referee_block(*, referee_id: str, signer_key_id: str, proponent_id: str) -> dict[str, Any]:
    if referee_id == proponent_id:
        raise RefereePolicyError("referee must be distinct from proponent")
    return {
        "referee_id": referee_id,
        "non_gameable": True,
        "signed_by": signer_key_id,
        "distinct_from_proponent": True,
    }


def tier_from_checks(checks: tuple[CheckResult, ...]) -> str:
    statuses = {check.check: check.status for check in checks}
    recap_required = ("INJECTION", "NULL_CONTROL", "PHYSICAL_CONSISTENCY", "CALIBRATION")
    if not all(statuses.get(check) == "PASS" for check in recap_required):
        return "ran-toy"
    if statuses.get("CROSS_CODE") == "PASS" and statuses.get("LEAKAGE") == "PASS":
        return "novel-needs-human"
    return "recapitulated-known"


def _aggregate_passed(checks: tuple[CheckResult, ...], perturbation_outcome: PerturbationPairOutcome) -> bool:
    return (
        all(check.status == "PASS" for check in checks)
        and all(pair.verdict == "pass" for pair in perturbation_outcome.perturbation_pairs)
        and len(perturbation_outcome.insensitivity_flags) == 0
    )


def _aggregate_score(checks: tuple[CheckResult, ...]) -> float:
    if not checks:
        return 0.0
    return sum(1.0 for check in checks if check.status == "PASS") / len(checks)


def _check_to_contract(check: CheckResult) -> dict[str, Any]:
    payload = {
        "check": check.check,
        "status": check.status,
    }
    if check.metrics is not None:
        payload["metrics"] = check.metrics
    return payload
