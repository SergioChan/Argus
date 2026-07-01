"""S4 adversarial red-blue evolver core semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal
from typing import Any

from .c3 import C3SignatureVerification
from .s3 import attest_challenger_independence
from .s6 import CapabilityDescriptor, IndependenceAttestation
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


class S4Error(Exception):
    """Base class for S4 evolver failures."""


class ChallengerPanelError(S4Error):
    """Raised when a challenger panel cannot satisfy independence and diversity."""


@dataclass(frozen=True)
class EvolverBounds:
    max_generations: int
    max_debate_rounds: int
    max_spend_usd: Decimal | str | int | float
    per_round_cost_usd: Decimal | str | int | float = Decimal("1.0")
    max_consecutive_panel_reuse: int = 2

    def __post_init__(self) -> None:
        if self.max_generations < 1:
            raise ValueError("max_generations must be positive")
        if self.max_debate_rounds < 1:
            raise ValueError("max_debate_rounds must be positive")
        if self.max_consecutive_panel_reuse < 1:
            raise ValueError("max_consecutive_panel_reuse must be positive")
        object.__setattr__(self, "max_spend_usd", _decimal(self.max_spend_usd))
        object.__setattr__(self, "per_round_cost_usd", _decimal(self.per_round_cost_usd))


@dataclass(frozen=True)
class EvolverPreflight:
    status: str
    reason: str | None
    verifier_available: bool
    oracle_available: bool
    signer_trusted: bool
    cheap_enough: bool
    independence_available: bool
    estimated_cost_usd: Decimal
    single_call_budget_usd: Decimal
    max_achievable_tier: str
    budget_committed: bool = False


@dataclass(frozen=True)
class DiversityPolicy:
    min_attack_types: int = 2
    min_code_lineages: int = 2


@dataclass(frozen=True)
class ChallengerPanel:
    challenger_ids: tuple[str, ...]
    descriptors: tuple[CapabilityDescriptor, ...]
    attack_types: tuple[str, ...]
    code_lineages: tuple[str, ...]
    attestation: IndependenceAttestation


@dataclass(frozen=True)
class Attack:
    attack_id: str
    challenger_id: str
    attack_type: str
    code_lineage: str
    evidence_ref: str | None = None


@dataclass(frozen=True)
class ChallengeVerdict:
    must_react_pass: bool
    must_not_react_pass: bool
    insensitivity_detected: bool
    overall: str
    reason: str | None = None


@dataclass(frozen=True)
class RewardHackEvent:
    kind: str
    detail: str
    round_id: str | None = None


@dataclass(frozen=True)
class ChallengeRound:
    round_id: str
    candidate_ref: str
    proponent_id: str
    challenger_ids: tuple[str, ...]
    attacks: tuple[Attack, ...]
    verdict: ChallengeVerdict
    survived: bool
    feedback: tuple[str, ...]
    referee_report_ref: str
    reward_hack_events: tuple[RewardHackEvent, ...] = ()


@dataclass(frozen=True)
class DebateLedger:
    artifact_ref: str
    subject_artifact_ref: str
    round_ids: tuple[str, ...]


@dataclass(frozen=True)
class RewardAdmission:
    admitted: bool
    reason: str | None
    candidate_ref: str
    validation_report_ref: str
    score: float | None
    claim_tier: str | None
    human_review_required: bool
    quarantine_required: bool = False


@dataclass(frozen=True)
class RefereeRoundEvidence:
    report_ref: str
    report: dict[str, Any]
    verification: C3SignatureVerification
    candidate_ref: str | None = None
    challenger_panel: ChallengerPanel | None = None


@dataclass(frozen=True)
class EvolutionResult:
    status: str
    reason: str | None
    generations_run: int
    rounds_run: int
    cost_actual_usd: Decimal
    best_candidate_ref: str | None
    best_validation_report_ref: str | None
    best_score: float | None
    human_review_required: bool
    debate_ref: str | None
    challenge_rounds: tuple[ChallengeRound, ...]
    reward_hack_events: tuple[RewardHackEvent, ...] = ()


def precondition_gate(
    *,
    verifier_available: bool,
    oracle_available: bool,
    signer_trusted: bool,
    estimated_cost_usd: Decimal | str | int | float,
    single_call_budget_usd: Decimal | str | int | float,
    independence_attestation: IndependenceAttestation | None = None,
    require_independence: bool = False,
) -> EvolverPreflight:
    estimate = _decimal(estimated_cost_usd)
    budget = _decimal(single_call_budget_usd)
    cheap_enough = estimate <= budget
    independence_available = _independence_available(independence_attestation)
    max_tier = "novel-needs-human" if independence_available else "recapitulated-known"

    reason = None
    if not verifier_available:
        reason = "VERIFIER_UNAVAILABLE"
    elif not oracle_available:
        reason = "ORACLE_UNAVAILABLE"
    elif not signer_trusted:
        reason = "SIGNER_UNTRUSTED"
    elif not cheap_enough:
        reason = "VERIFIER_TOO_EXPENSIVE"
    elif require_independence and not independence_available:
        reason = "INDEPENDENCE_UNAVAILABLE"

    return EvolverPreflight(
        status="REFUSED" if reason else "ACCEPTED",
        reason=reason,
        verifier_available=verifier_available,
        oracle_available=oracle_available,
        signer_trusted=signer_trusted,
        cheap_enough=cheap_enough,
        independence_available=independence_available,
        estimated_cost_usd=estimate,
        single_call_budget_usd=budget,
        max_achievable_tier=max_tier,
        budget_committed=False,
    )


def select_challenger_panel(
    *,
    challengers: tuple[CapabilityDescriptor, ...],
    subtopic: str,
    k: int,
    diversity_policy: DiversityPolicy,
) -> ChallengerPanel:
    if k < 1:
        raise ValueError("k must be positive")
    pool = tuple(
        challenger
        for challenger in sorted(challengers, key=lambda item: item.entity_id)
        if challenger.kind == "subagent"
        and challenger.status == "active"
        and subtopic in challenger.subtopics
        and "challenge" in challenger.capability_scopes
    )
    selected: list[CapabilityDescriptor] = []
    used_tags: set[str] = set()
    while True:
        candidate = _next_best_challenger(pool=pool, selected=tuple(selected), used_tags=used_tags)
        if candidate is None:
            break
        selected.append(candidate)
        used_tags.update(candidate.independence_tags)
        if len(selected) >= k and _panel_diversity_satisfied(tuple(selected), diversity_policy):
            break

    attestation = attest_challenger_independence(challengers=tuple(selected), min_independent=k)
    if len(selected) < k or not attestation.lineage_disjoint or attestation.correlation_warning:
        raise ChallengerPanelError("independent challenger panel unavailable")
    if not _panel_diversity_satisfied(tuple(selected), diversity_policy):
        raise ChallengerPanelError("challenger panel diversity floor unavailable")

    return ChallengerPanel(
        challenger_ids=tuple(challenger.entity_id for challenger in selected),
        descriptors=tuple(selected),
        attack_types=_panel_attack_types(tuple(selected)),
        code_lineages=_panel_code_lineages(tuple(selected)),
        attestation=attestation,
    )


def admit_signed_reward(
    *,
    candidate_ref: str,
    report: dict[str, Any],
    verification: C3SignatureVerification,
    validation_report_ref: str,
    expected_pipeline_ref: str | None = None,
    candidate_self_score: float | None = None,
) -> RewardAdmission:
    del candidate_self_score
    if not verification.valid:
        return RewardAdmission(
            admitted=False,
            reason="SIGNATURE",
            candidate_ref=candidate_ref,
            validation_report_ref=validation_report_ref,
            score=None,
            claim_tier=verification.claim_tier,
            human_review_required=False,
            quarantine_required=True,
        )
    if expected_pipeline_ref is not None and report.get("frozen_pipeline_ref") != expected_pipeline_ref:
        return RewardAdmission(
            admitted=False,
            reason="REPORT_BINDING",
            candidate_ref=candidate_ref,
            validation_report_ref=validation_report_ref,
            score=None,
            claim_tier=verification.claim_tier,
            human_review_required=False,
            quarantine_required=True,
        )
    rejection = _aggregate_rejection_reason(report, verification)
    if rejection is not None:
        return RewardAdmission(
            admitted=False,
            reason=rejection,
            candidate_ref=candidate_ref,
            validation_report_ref=validation_report_ref,
            score=None,
            claim_tier=verification.claim_tier,
            human_review_required=False,
            quarantine_required=rejection in {"SIGNATURE", "REPORT_BINDING", "LEAKAGE"},
        )

    score = _report_score(report)
    claim_tier = verification.claim_tier
    return RewardAdmission(
        admitted=True,
        reason=None,
        candidate_ref=candidate_ref,
        validation_report_ref=validation_report_ref,
        score=score,
        claim_tier=claim_tier,
        human_review_required=claim_tier == "novel-needs-human",
    )


def challenge_verdict_from_report(
    *,
    report: dict[str, Any],
    verification: C3SignatureVerification,
    proponent_id: str,
) -> ChallengeVerdict:
    referee = report.get("referee")
    if not isinstance(referee, dict):
        return ChallengeVerdict(False, False, False, "FAIL", "REFEREE_MISSING")
    if referee.get("referee_id") == proponent_id or referee.get("distinct_from_proponent") is not True:
        return ChallengeVerdict(False, False, False, "FAIL", "REFEREE_TAMPERED")
    if not verification.valid:
        return ChallengeVerdict(False, False, False, "FAIL", "SIGNATURE")

    pairs = report.get("perturbation_pairs")
    pair_items = pairs if isinstance(pairs, list) else []
    must_react_pairs = [pair for pair in pair_items if pair.get("kind") == "must_react"]
    must_not_react_pairs = [pair for pair in pair_items if pair.get("kind") == "must_not_react"]
    must_react_pass = bool(must_react_pairs) and all(pair.get("verdict") == "pass" for pair in must_react_pairs)
    must_not_react_pass = bool(must_not_react_pairs) and all(pair.get("verdict") == "pass" for pair in must_not_react_pairs)
    flags = report.get("insensitivity_flags")
    insensitivity_detected = bool(flags)
    overall = (
        "PASS"
        if verification.aggregate_passed is True
        and must_react_pass
        and must_not_react_pass
        and not insensitivity_detected
        else "FAIL"
    )
    reason = None if overall == "PASS" else _verdict_failure_reason(must_react_pass, must_not_react_pass, insensitivity_detected)
    return ChallengeVerdict(
        must_react_pass=must_react_pass,
        must_not_react_pass=must_not_react_pass,
        insensitivity_detected=insensitivity_detected,
        overall=overall,
        reason=reason,
    )


def run_debate_round(
    *,
    round_id: str,
    candidate_ref: str,
    proponent_id: str,
    challenger_panel: ChallengerPanel,
    referee_report: dict[str, Any],
    report_verification: C3SignatureVerification,
    report_ref: str,
) -> ChallengeRound:
    verdict = challenge_verdict_from_report(
        report=referee_report,
        verification=report_verification,
        proponent_id=proponent_id,
    )
    reward_hacks = screen_challenger_collusion(challenger_panel.attestation)
    if reward_hacks:
        verdict = ChallengeVerdict(
            must_react_pass=verdict.must_react_pass,
            must_not_react_pass=verdict.must_not_react_pass,
            insensitivity_detected=verdict.insensitivity_detected,
            overall="FAIL",
            reason="CHALLENGER_COLLUSION",
        )
    return ChallengeRound(
        round_id=round_id,
        candidate_ref=candidate_ref,
        proponent_id=proponent_id,
        challenger_ids=challenger_panel.challenger_ids,
        attacks=_default_attacks(challenger_panel),
        verdict=verdict,
        survived=verdict.overall == "PASS",
        feedback=_feedback_from_verdict(verdict),
        referee_report_ref=report_ref,
        reward_hack_events=reward_hacks,
    )


def evolve_under_debate(
    *,
    seed_candidate_ref: str,
    proponent_id: str,
    bounds: EvolverBounds,
    preflight: EvolverPreflight,
    challenger_panel: ChallengerPanel,
    round_evidence: tuple[RefereeRoundEvidence, ...],
    artifact_store: InMemoryArtifactStore | None = None,
) -> EvolutionResult:
    if preflight.status != "ACCEPTED":
        return _evolution_result(
            status="REFUSED",
            reason=preflight.reason,
            cost=Decimal("0"),
            rounds=(),
        )

    rounds: list[ChallengeRound] = []
    reward_hacks: list[RewardHackEvent] = []
    cost = Decimal("0")
    best: RewardAdmission | None = None
    max_rounds = min(bounds.max_generations, bounds.max_debate_rounds)
    current_candidate_ref = seed_candidate_ref

    for index, evidence in enumerate(round_evidence[:max_rounds], start=1):
        if cost + bounds.per_round_cost_usd > bounds.max_spend_usd:
            return _evolution_result(
                status="BUDGET_HALTED",
                reason="BUDGET_BREACH",
                cost=cost,
                rounds=tuple(rounds),
                best=best,
                reward_hacks=tuple(reward_hacks),
            )

        panel = evidence.challenger_panel or challenger_panel
        candidate_ref = evidence.candidate_ref or current_candidate_ref
        round_result = run_debate_round(
            round_id=f"round-{index}",
            candidate_ref=candidate_ref,
            proponent_id=proponent_id,
            challenger_panel=panel,
            referee_report=evidence.report,
            report_verification=evidence.verification,
            report_ref=evidence.report_ref,
        )
        rounds.append(round_result)
        reward_hacks.extend(round_result.reward_hack_events)
        reward_hacks.extend(_fixed_panel_overfit_events(tuple(rounds), bounds.max_consecutive_panel_reuse))
        cost += bounds.per_round_cost_usd

        if reward_hacks:
            return _evolution_result(
                status="QUARANTINED",
                reason=reward_hacks[-1].kind.upper(),
                cost=cost,
                rounds=tuple(rounds),
                best=best,
                reward_hacks=tuple(dict.fromkeys(reward_hacks)),
            )

        if not round_result.survived:
            current_candidate_ref = f"{candidate_ref}:revision-{index}"
            continue

        admission = admit_signed_reward(
            candidate_ref=candidate_ref,
            report=evidence.report,
            verification=evidence.verification,
            validation_report_ref=evidence.report_ref,
            expected_pipeline_ref=candidate_ref,
        )
        if not admission.admitted:
            return _evolution_result(
                status="QUARANTINED" if admission.quarantine_required else "STOPPED",
                reason=admission.reason,
                cost=cost,
                rounds=tuple(rounds),
                best=best,
                reward_hacks=tuple(reward_hacks),
            )
        best = admission
        debate_ref = None
        if artifact_store is not None:
            debate_ref = write_debate_ledger(
                artifact_store=artifact_store,
                subject_artifact_ref=seed_candidate_ref,
                rounds=tuple(rounds),
            ).artifact_ref
        return _evolution_result(
            status="COMPLETED",
            reason=None,
            cost=cost,
            rounds=tuple(rounds),
            best=best,
            debate_ref=debate_ref,
            reward_hacks=tuple(reward_hacks),
        )

    reason = "MAX_ROUNDS" if len(rounds) >= max_rounds else "NO_PASSING_ROUND"
    return _evolution_result(
        status="STOPPED",
        reason=reason,
        cost=cost,
        rounds=tuple(rounds),
        best=best,
        reward_hacks=tuple(reward_hacks),
    )


def write_debate_ledger(
    *,
    artifact_store: InMemoryArtifactStore,
    subject_artifact_ref: str,
    rounds: tuple[ChallengeRound, ...],
) -> DebateLedger:
    payload = {
        "subject_artifact_ref": subject_artifact_ref,
        "rounds": [_challenge_round_payload(round_result) for round_result in rounds],
    }
    record = artifact_store.create_artifact(
        kind="debate_ledger",
        payload=payload,
        producer=Producer(subsystem="S4", version="0.0.0"),
        lineage=Lineage(
            input_refs=(subject_artifact_ref,) + tuple(round_result.referee_report_ref for round_result in rounds),
            code_ref="git:s4-evolver",
            environment_digest="oci:s4-evolver",
        ),
    )
    return DebateLedger(
        artifact_ref=record.artifact_ref,
        subject_artifact_ref=subject_artifact_ref,
        round_ids=tuple(round_result.round_id for round_result in rounds),
    )


def screen_challenger_collusion(attestation: IndependenceAttestation) -> tuple[RewardHackEvent, ...]:
    if attestation.lineage_disjoint and not attestation.correlation_warning:
        return ()
    return (
        RewardHackEvent(
            kind="challenger_collusion",
            detail="challenger panel failed lineage-disjoint independence attestation",
        ),
    )


def _evolution_result(
    *,
    status: str,
    reason: str | None,
    cost: Decimal,
    rounds: tuple[ChallengeRound, ...],
    best: RewardAdmission | None = None,
    debate_ref: str | None = None,
    reward_hacks: tuple[RewardHackEvent, ...] = (),
) -> EvolutionResult:
    return EvolutionResult(
        status=status,
        reason=reason,
        generations_run=len(rounds),
        rounds_run=len(rounds),
        cost_actual_usd=cost,
        best_candidate_ref=best.candidate_ref if best else None,
        best_validation_report_ref=best.validation_report_ref if best else None,
        best_score=best.score if best else None,
        human_review_required=best.human_review_required if best else False,
        debate_ref=debate_ref,
        challenge_rounds=rounds,
        reward_hack_events=reward_hacks,
    )


def _aggregate_rejection_reason(report: dict[str, Any], verification: C3SignatureVerification) -> str | None:
    if verification.aggregate_passed is not True:
        checks = report.get("checks")
        if isinstance(checks, list):
            statuses = {
                check.get("check"): check.get("status")
                for check in checks
                if isinstance(check, dict) and isinstance(check.get("check"), str)
            }
            if "INCONCLUSIVE" in statuses.values():
                return "INCONCLUSIVE"
            if statuses.get("LEAKAGE") == "FAIL":
                return "LEAKAGE"
        return "AGGREGATE_FAILED"
    return None


def _report_score(report: dict[str, Any]) -> float:
    aggregate = report.get("aggregate")
    if not isinstance(aggregate, dict):
        raise S4Error("report aggregate is required")
    score = aggregate.get("score")
    if not isinstance(score, int | float):
        raise S4Error("report aggregate.score must be numeric")
    return float(score)


def _verdict_failure_reason(
    must_react_pass: bool,
    must_not_react_pass: bool,
    insensitivity_detected: bool,
) -> str:
    if insensitivity_detected:
        return "INSENSITIVITY"
    if not must_react_pass:
        return "MUST_REACT_FAILED"
    if not must_not_react_pass:
        return "MUST_NOT_REACT_FAILED"
    return "AGGREGATE_FAILED"


def _feedback_from_verdict(verdict: ChallengeVerdict) -> tuple[str, ...]:
    if verdict.overall == "PASS":
        return ()
    feedback: list[str] = []
    if not verdict.must_react_pass:
        feedback.append("recover planted signal proportionally under must-react perturbations")
    if not verdict.must_not_react_pass:
        feedback.append("degrade on null-noise, label-shuffle, and contamination controls")
    if verdict.insensitivity_detected:
        feedback.append("remove invariant or spurious behavior flagged by insensitivity probe")
    if verdict.reason in {"SIGNATURE", "REFEREE_TAMPERED", "REFEREE_MISSING", "CHALLENGER_COLLUSION"}:
        feedback.append(f"round rejected by policy: {verdict.reason}")
    return tuple(feedback)


def _default_attacks(panel: ChallengerPanel) -> tuple[Attack, ...]:
    attacks: list[Attack] = []
    for index, descriptor in enumerate(panel.descriptors):
        attack_type = sorted(_descriptor_attack_types(descriptor))[0]
        lineage = _descriptor_lineage(descriptor)
        attacks.append(
            Attack(
                attack_id=f"{descriptor.entity_id}:{attack_type}",
                challenger_id=descriptor.entity_id,
                attack_type=attack_type,
                code_lineage=lineage,
            )
        )
        if index + 1 == len(panel.challenger_ids):
            break
    return tuple(attacks)


def _fixed_panel_overfit_events(rounds: tuple[ChallengeRound, ...], max_reuse: int) -> tuple[RewardHackEvent, ...]:
    if not rounds:
        return ()
    last_panel = rounds[-1].challenger_ids
    reuse = 0
    for round_result in reversed(rounds):
        if round_result.challenger_ids != last_panel:
            break
        reuse += 1
    if reuse <= max_reuse:
        return ()
    return (
        RewardHackEvent(
            kind="challenger_overfit",
            detail="same challenger panel reused beyond diversity refresh bound",
            round_id=rounds[-1].round_id,
        ),
    )


def _challenge_round_payload(round_result: ChallengeRound) -> dict[str, Any]:
    return {
        "round_id": round_result.round_id,
        "candidate_ref": round_result.candidate_ref,
        "proponent_id": round_result.proponent_id,
        "challenger_ids": round_result.challenger_ids,
        "attacks": tuple(asdict(attack) for attack in round_result.attacks),
        "verdict": asdict(round_result.verdict),
        "survived": round_result.survived,
        "feedback": round_result.feedback,
        "referee_report_ref": round_result.referee_report_ref,
        "reward_hack_events": tuple(asdict(event) for event in round_result.reward_hack_events),
    }


def _next_best_challenger(
    *,
    pool: tuple[CapabilityDescriptor, ...],
    selected: tuple[CapabilityDescriptor, ...],
    used_tags: set[str],
) -> CapabilityDescriptor | None:
    selected_ids = {descriptor.entity_id for descriptor in selected}
    current_attack_types = set(_panel_attack_types(selected))
    current_lineages = set(_panel_code_lineages(selected))
    candidates = []
    for descriptor in pool:
        if descriptor.entity_id in selected_ids:
            continue
        tags = set(descriptor.independence_tags)
        if not tags or not tags.isdisjoint(used_tags):
            continue
        attack_types = _descriptor_attack_types(descriptor)
        lineage = _descriptor_lineage(descriptor)
        candidates.append(
            (
                len(attack_types - current_attack_types),
                1 if lineage not in current_lineages else 0,
                descriptor.entity_id,
                descriptor,
            )
        )
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1], item[2]))[3]


def _panel_diversity_satisfied(
    selected: tuple[CapabilityDescriptor, ...],
    policy: DiversityPolicy,
) -> bool:
    return (
        len(_panel_attack_types(selected)) >= policy.min_attack_types
        and len(_panel_code_lineages(selected)) >= policy.min_code_lineages
    )


def _panel_attack_types(descriptors: tuple[CapabilityDescriptor, ...]) -> tuple[str, ...]:
    attack_types: set[str] = set()
    for descriptor in descriptors:
        attack_types.update(_descriptor_attack_types(descriptor))
    return tuple(sorted(attack_types))


def _panel_code_lineages(descriptors: tuple[CapabilityDescriptor, ...]) -> tuple[str, ...]:
    return tuple(sorted({_descriptor_lineage(descriptor) for descriptor in descriptors}))


def _descriptor_attack_types(descriptor: CapabilityDescriptor) -> set[str]:
    attack_types = {
        scope.removeprefix("attack:")
        for scope in descriptor.capability_scopes
        if scope.startswith("attack:") and scope.removeprefix("attack:")
    }
    return attack_types or {"generic"}


def _descriptor_lineage(descriptor: CapabilityDescriptor) -> str:
    return "|".join(sorted(descriptor.independence_tags)) if descriptor.independence_tags else descriptor.entity_id


def _independence_available(attestation: IndependenceAttestation | None) -> bool:
    return (
        attestation is not None
        and attestation.lineage_disjoint
        and not attestation.correlation_warning
        and len(attestation.selected_entity_ids) >= attestation.min_independent
    )


def _decimal(value: Decimal | str | int | float) -> Decimal:
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))
