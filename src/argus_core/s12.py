"""S12 federation, conformance, and standard-release core semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import hmac
from typing import Any

from .canonical import canonical_json_bytes
from .hashing import hash_bytes, hash_json
from .s6 import CapabilityDescriptor, InMemoryRegistry
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer
from .schema_compat import BREAKING_MAJOR, classify_json_schema_change, schema_version_declares_change


FEDERATION_DEFAULT_SCOPES = (
    "c1.accept",
    "c1.plan",
    "c1.build",
    "c1.validate",
    "c1.report",
)

CONFORMANCE_LEVEL_ORDER = {"bronze": 1, "silver": 2, "gold": 3}


class S12Error(Exception):
    """Base class for S12 federation failures."""


class SemverCompatibilityError(S12Error):
    """Raised when a release under-declares its compatibility impact."""


class BundleSignatureError(S12Error):
    """Raised when a submitted bundle cannot be trusted."""


@dataclass(frozen=True)
class StandardRelease:
    version: str
    schemas: dict[str, dict[str, Any]]
    docs_ref: str
    bindings_ref: str
    deprecation_calendar: dict[str, str]
    signer_key_id: str
    signature: str = ""


@dataclass(frozen=True)
class ConformanceCheck:
    check_id: str
    status: str
    oracle_spec: str
    reason: str | None = None


@dataclass(frozen=True)
class ConformanceSuiteVersion:
    suite_version: str
    standard_release_ref: str
    levels: tuple[str, ...] = ("bronze", "silver", "gold")
    yanked: bool = False
    reason: str | None = None


@dataclass(frozen=True)
class ConformanceRecord:
    record_id: str
    submission_id: str
    entity_id: str
    level_awarded: str
    suite_version: str
    standard_release_ref: str
    checks: tuple[ConformanceCheck, ...]
    aggregate_passed: bool
    determinism_hash: str
    signer_key_id: str
    signature: str = ""


@dataclass(frozen=True)
class SubmissionBundle:
    submission_id: str
    entity_id: str
    maintainer_id: str
    key_id: str
    descriptor_draft: CapabilityDescriptor
    claimed_level: str
    code_ref: str
    container_digest: str
    sbom_hash: str
    signature: str = ""
    lifecycle_valid: bool = True
    provenance_complete: bool = True
    attempted_claim_tier: str = "ran-toy"
    uncertainty_tagged: bool = True
    refuses_without_verifier: bool = True
    typed_error_envelope: bool = True
    reward_path_write_attempt: bool = False
    c6_units_present: bool = True
    differentiable: bool = False
    grad_implemented: bool = False
    reproducibility_manifest_complete: bool = True
    egress_attempt: bool = False
    trust_path_write_attempt: bool = False
    signing_key_visible_in_sandbox: bool = False


@dataclass(frozen=True)
class FederationIdentity:
    maintainer_id: str
    key_id: str
    standing: str = "active"


@dataclass(frozen=True)
class SubmissionDecision:
    accepted: bool
    status: str
    category: str | None = None


@dataclass(frozen=True)
class AdmissionDecision:
    admit: bool
    status: str
    category: str | None
    descriptor: CapabilityDescriptor | None = None


@dataclass(frozen=True)
class GovernanceLedgerEntry:
    sequence: int
    action: str
    entity_id: str
    actor_id: str
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str


@dataclass(frozen=True)
class GovernanceVerification:
    valid: bool
    break_sequence: int | None = None


@dataclass(frozen=True)
class RevocationResult:
    entity_id: str
    registry_revoked: bool
    halted_job_ids: tuple[str, ...]
    escalated: bool


@dataclass(frozen=True)
class ConformanceChallenge:
    matches: bool
    quarantined: bool
    reason: str | None = None


@dataclass(frozen=True)
class TaxonomyVersion:
    version: int
    parents: dict[str, str | None]


class StandardService:
    """Immutable StandardRelease storage and dual-serve lookup."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore) -> None:
        self._artifact_store = artifact_store
        self._releases: dict[str, ArtifactRecord] = {}
        self._current_version: str | None = None

    def publish(self, release: StandardRelease) -> ArtifactRecord:
        signed = release if release.signature else sign_standard_release(release, secret=b"standard-release-dev-key")
        record = self._artifact_store.create_artifact(
            kind="standard_release",
            payload=asdict(signed),
            producer=Producer(subsystem="S12", version="0.0.0"),
            lineage=Lineage(
                input_refs=tuple(sorted((signed.docs_ref, signed.bindings_ref))),
                code_ref="git:s12-standard",
                environment_digest="oci:s12-standard",
            ),
        )
        self._releases[signed.version] = record
        self._current_version = _latest_semver(tuple(self._releases))
        return record

    def current(self) -> ArtifactRecord:
        if self._current_version is None:
            raise S12Error("no standard release published")
        return self._releases[self._current_version]

    def get(self, version: str) -> ArtifactRecord:
        return self._releases[version]

    def supports(self, version: str) -> bool:
        if version in self._releases:
            return True
        major = _semver(version)[0]
        return any(_semver(release)[0] == major for release in self._releases)


class BundleTrustStore:
    """Out-of-sandbox maintainer key trust store."""

    def __init__(self) -> None:
        self._keys: dict[str, tuple[bytes, FederationIdentity]] = {}

    def register_identity(self, identity: FederationIdentity, secret: bytes) -> None:
        self._keys[identity.key_id] = (secret, identity)

    def suspend(self, key_id: str) -> None:
        secret, identity = self._keys[key_id]
        self._keys[key_id] = (secret, replace(identity, standing="suspended"))

    def get(self, key_id: str) -> tuple[bytes, FederationIdentity] | None:
        return self._keys.get(key_id)


class ConformanceService:
    """Hermetic Bronze/Silver/Gold conformance runner."""

    def __init__(self, *, suite: ConformanceSuiteVersion, signer_key_id: str, signer_secret: bytes) -> None:
        self._suite = suite
        self._signer_key_id = signer_key_id
        self._signer_secret = signer_secret

    def run(self, bundle: SubmissionBundle, *, level: str) -> ConformanceRecord:
        checks = _conformance_checks(bundle, level)
        aggregate = all(check.status == "PASS" for check in checks)
        level_awarded = level if aggregate else _previous_level(level)
        body = ConformanceRecord(
            record_id="",
            submission_id=bundle.submission_id,
            entity_id=bundle.entity_id,
            level_awarded=level_awarded,
            suite_version=self._suite.suite_version,
            standard_release_ref=self._suite.standard_release_ref,
            checks=tuple(checks),
            aggregate_passed=aggregate,
            determinism_hash=hash_json(
                {
                    "submission_id": bundle.submission_id,
                    "entity_id": bundle.entity_id,
                    "level": level,
                    "checks": tuple(asdict(check) for check in checks),
                }
            ),
            signer_key_id=self._signer_key_id,
        )
        body = replace(body, record_id=hash_json(_record_unsigned_payload(body)))
        return sign_conformance_record(body, secret=self._signer_secret)

    def write_record(self, *, store: InMemoryArtifactStore, record: ConformanceRecord) -> ArtifactRecord:
        return store.create_artifact(
            kind="conformance_record",
            payload=asdict(record),
            producer=Producer(subsystem="S12", version="0.0.0"),
            lineage=Lineage(
                input_refs=(record.standard_release_ref,),
                code_ref="git:s12-conformance",
                environment_digest="oci:s12-conformance",
            ),
        )


class GovernanceLedger:
    """Append-only hash-chained governance ledger."""

    def __init__(self) -> None:
        self._entries: list[GovernanceLedgerEntry] = []

    @property
    def entries(self) -> tuple[GovernanceLedgerEntry, ...]:
        return tuple(self._entries)

    def append(self, *, action: str, entity_id: str, actor_id: str, payload: dict[str, Any]) -> GovernanceLedgerEntry:
        previous_hash = self._entries[-1].entry_hash if self._entries else _zero_hash()
        sequence = len(self._entries) + 1
        entry_hash = hash_json(
            {
                "sequence": sequence,
                "action": action,
                "entity_id": entity_id,
                "actor_id": actor_id,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        )
        entry = GovernanceLedgerEntry(
            sequence=sequence,
            action=action,
            entity_id=entity_id,
            actor_id=actor_id,
            payload=payload,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def verify(self, entries: tuple[GovernanceLedgerEntry, ...] | None = None) -> GovernanceVerification:
        previous_hash = _zero_hash()
        for entry in entries or self.entries:
            expected = hash_json(
                {
                    "sequence": entry.sequence,
                    "action": entry.action,
                    "entity_id": entry.entity_id,
                    "actor_id": entry.actor_id,
                    "payload": entry.payload,
                    "previous_hash": previous_hash,
                }
            )
            if entry.previous_hash != previous_hash or entry.entry_hash != expected:
                return GovernanceVerification(valid=False, break_sequence=entry.sequence)
            previous_hash = entry.entry_hash
        return GovernanceVerification(valid=True)


class RegistryGateway:
    """Governance-aware admission front door for C5."""

    def __init__(
        self,
        *,
        registry: InMemoryRegistry,
        trust_store: BundleTrustStore,
        governance_ledger: GovernanceLedger,
        signer_secret: bytes,
        registry_available: bool = True,
    ) -> None:
        self._registry = registry
        self._trust_store = trust_store
        self._governance_ledger = governance_ledger
        self._signer_secret = signer_secret
        self._registry_available = registry_available
        self._approved_submissions: set[str] = set()
        self._directory: dict[str, CapabilityDescriptor] = {}
        self.events: list[dict[str, Any]] = []

    def submit(self, bundle: SubmissionBundle) -> SubmissionDecision:
        if not verify_submission_bundle(bundle, self._trust_store):
            return SubmissionDecision(False, "REJECTED", "SIGNATURE_INVALID")
        identity_entry = self._trust_store.get(bundle.key_id)
        if identity_entry is None or identity_entry[1].standing != "active":
            return SubmissionDecision(False, "REJECTED", "REVOKED")
        self._governance_ledger.append(
            action="SUBMIT",
            entity_id=bundle.entity_id,
            actor_id=bundle.maintainer_id,
            payload={"submission_id": bundle.submission_id},
        )
        self.events.append({"kind": "submission.received", "submission_id": bundle.submission_id})
        return SubmissionDecision(True, "SUBMITTED")

    def approve(self, *, submission_id: str, entity_id: str, reviewer_id: str) -> None:
        self._approved_submissions.add(submission_id)
        self._governance_ledger.append(
            action="APPROVE",
            entity_id=entity_id,
            actor_id=reviewer_id,
            payload={"submission_id": submission_id},
        )

    def admit(
        self,
        *,
        bundle: SubmissionBundle,
        conformance_record: ConformanceRecord | None,
        suite: ConformanceSuiteVersion,
    ) -> AdmissionDecision:
        rejection = self._admission_rejection(bundle=bundle, record=conformance_record, suite=suite)
        if rejection is not None:
            return AdmissionDecision(False, rejection[0], rejection[1])
        if bundle.submission_id not in self._approved_submissions:
            return AdmissionDecision(False, "IN_REVIEW", "APPROVAL_REQUIRED")
        if not self._registry_available:
            return AdmissionDecision(False, "APPROVED", "REGISTRY_UNAVAILABLE")

        assert conformance_record is not None
        descriptor = federated_descriptor_from_submission(bundle, conformance_record=conformance_record)
        published = self._registry.publish(descriptor)
        self._directory[published.entity_id] = published
        self._governance_ledger.append(
            action="ADMIT",
            entity_id=published.entity_id,
            actor_id="registry-gateway",
            payload={"submission_id": bundle.submission_id, "level": conformance_record.level_awarded},
        )
        self.events.append(
            {
                "kind": "entity.admitted",
                "entity_id": published.entity_id,
                "level": conformance_record.level_awarded,
                "trust_class": published.trust_class,
            }
        )
        return AdmissionDecision(True, "ADMITTED", None, published)

    def directory_get(self, entity_id: str) -> CapabilityDescriptor:
        return self._directory[entity_id]

    def revoke(self, *, entity_id: str, actor_id: str, in_flight_job_ids: tuple[str, ...]) -> RevocationResult:
        self._registry.revoke(entity_id)
        self._directory.pop(entity_id, None)
        self._governance_ledger.append(
            action="REVOKE",
            entity_id=entity_id,
            actor_id=actor_id,
            payload={"halted_job_ids": in_flight_job_ids},
        )
        self.events.append({"kind": "entity.revoked", "entity_id": entity_id})
        return RevocationResult(
            entity_id=entity_id,
            registry_revoked=True,
            halted_job_ids=tuple(sorted(in_flight_job_ids)),
            escalated=False,
        )

    def _admission_rejection(
        self,
        *,
        bundle: SubmissionBundle,
        record: ConformanceRecord | None,
        suite: ConformanceSuiteVersion,
    ) -> tuple[str, str] | None:
        if not verify_submission_bundle(bundle, self._trust_store):
            return ("REJECTED", "SIGNATURE_INVALID")
        identity_entry = self._trust_store.get(bundle.key_id)
        if identity_entry is None or identity_entry[1].standing != "active":
            return ("REJECTED", "REVOKED")
        if not _digest_pinned(bundle.container_digest):
            return ("REJECTED", "DIGEST_UNPINNED")
        if not bundle.sbom_hash:
            return ("REJECTED", "SBOM_MISSING")
        if record is None:
            return ("REJECTED", "CONFORMANCE_MISSING")
        if suite.yanked or record.suite_version != suite.suite_version:
            return ("REJECTED", "CONFORMANCE_EXPIRED")
        if not verify_conformance_record(record, secret=self._signer_secret):
            return ("REJECTED", "CONFORMANCE_SIGNATURE")
        if not record.aggregate_passed:
            return ("REJECTED", "CONFORMANCE_FAILED")
        if record.entity_id != bundle.entity_id or record.submission_id != bundle.submission_id:
            return ("REJECTED", "CONFORMANCE_BINDING")
        if _level_rank(record.level_awarded) < _level_rank(bundle.claimed_level):
            return ("REJECTED", "CONFORMANCE_LEVEL_MISMATCH")
        return None


class Taxonomy:
    """Versioned taxonomy DAG validator."""

    def __init__(self, initial: dict[str, str | None]) -> None:
        self._current = TaxonomyVersion(version=1, parents=dict(initial))

    @property
    def current(self) -> TaxonomyVersion:
        return self._current

    def merge(self, proposal: dict[str, str | None]) -> TaxonomyVersion:
        merged = {**self._current.parents, **proposal}
        if _has_cycle(merged):
            raise S12Error("taxonomy proposal introduces a cycle")
        self._current = TaxonomyVersion(version=self._current.version + 1, parents=merged)
        return self._current


def classify_schema_change(old_schema: dict[str, Any], new_schema: dict[str, Any]) -> str:
    result = classify_json_schema_change(old_schema, new_schema)
    if result.classification == "unchanged":
        return "patch-compatible"
    return result.classification


def assert_declared_semver_bump(*, old_version: str, new_version: str, classification: str) -> None:
    normalized_classification = BREAKING_MAJOR if classification == "MAJOR" else classification
    if not schema_version_declares_change(
        old_version=old_version,
        new_version=new_version,
        classification=normalized_classification,
    ):
        raise SemverCompatibilityError(f"{new_version} under-declares {classification}")


def deterministic_codegen(schema: dict[str, Any], *, language: str) -> bytes:
    return canonical_json_bytes(
        {
            "generator": "argus-s12-codegen",
            "language": language,
            "schema": schema,
        }
    )


def sign_standard_release(release: StandardRelease, *, secret: bytes) -> StandardRelease:
    unsigned = replace(release, signature="")
    return replace(unsigned, signature=_hmac_signature(asdict(unsigned), secret))


def sign_submission_bundle(bundle: SubmissionBundle, *, secret: bytes) -> SubmissionBundle:
    unsigned = replace(bundle, signature="")
    return replace(unsigned, signature=_hmac_signature(_bundle_unsigned_payload(unsigned), secret))


def verify_submission_bundle(bundle: SubmissionBundle, trust_store: BundleTrustStore) -> bool:
    entry = trust_store.get(bundle.key_id)
    if entry is None:
        return False
    secret, identity = entry
    if identity.maintainer_id != bundle.maintainer_id:
        return False
    expected = _hmac_signature(_bundle_unsigned_payload(replace(bundle, signature="")), secret)
    return hmac.compare_digest(bundle.signature, expected)


def sign_conformance_record(record: ConformanceRecord, *, secret: bytes) -> ConformanceRecord:
    unsigned = replace(record, signature="")
    return replace(unsigned, signature=_hmac_signature(_record_unsigned_payload(unsigned), secret))


def verify_conformance_record(record: ConformanceRecord, *, secret: bytes) -> bool:
    expected = _hmac_signature(_record_unsigned_payload(replace(record, signature="")), secret)
    return hmac.compare_digest(record.signature, expected)


def federated_descriptor_from_submission(
    bundle: SubmissionBundle,
    *,
    conformance_record: ConformanceRecord,
) -> CapabilityDescriptor:
    return replace(
        bundle.descriptor_draft,
        revision=1,
        trust_class="federated",
        capability_scopes=FEDERATION_DEFAULT_SCOPES,
        conformance_level=conformance_record.level_awarded,
        provenance_ref=conformance_record.record_id,
        status="active",
    )


def challenge_conformance_record(
    *,
    original: ConformanceRecord,
    rerun: ConformanceRecord,
) -> ConformanceChallenge:
    matches = (
        original.determinism_hash == rerun.determinism_hash
        and original.level_awarded == rerun.level_awarded
        and tuple(asdict(check) for check in original.checks) == tuple(asdict(check) for check in rerun.checks)
    )
    return ConformanceChallenge(
        matches=matches,
        quarantined=not matches,
        reason=None if matches else "CONFORMANCE_RERUN_DIVERGED",
    )


def _conformance_checks(bundle: SubmissionBundle, level: str) -> list[ConformanceCheck]:
    checks = [
        _check("BRZ-LIFECYCLE-STATEMACHINE", bundle.lifecycle_valid, "C1 lifecycle transitions are valid"),
        _check("BRZ-PROVENANCE-COMPLETE", bundle.provenance_complete, "all emitted artifacts carry C4 provenance"),
        _check("BRZ-NO-SELF-NOVEL", bundle.attempted_claim_tier == "ran-toy", "subagent cannot self-assign promoted tiers"),
    ]
    if _level_rank(level) >= _level_rank("silver"):
        checks.extend(
            [
                _check("SLV-UNCERTAINTY-MANDATORY", bundle.uncertainty_tagged, "outputs include uncertainty tags"),
                _check("SLV-REFUSE-NO-VERIFIER", bundle.refuses_without_verifier, "accept refuses null verifier profile"),
                _check("SLV-ERROR-ENVELOPE", bundle.typed_error_envelope, "errors use typed envelope"),
            ]
        )
    if _level_rank(level) >= _level_rank("gold"):
        grad_ok = (not bundle.differentiable) or bundle.grad_implemented
        checks.extend(
            [
                _check(
                    "GLD-RECURSION-NO-REWARD-WRITE",
                    not bundle.reward_path_write_attempt,
                    "gold candidates cannot write reward or verifier paths",
                ),
                _check("GLD-C6-UNITS", bundle.c6_units_present, "C6 outputs include units"),
                _check("GLD-C6-GRAD", grad_ok, "grad exists iff differentiable"),
                _check("GLD-REPRO-MANIFEST", bundle.reproducibility_manifest_complete, "manifest has sufficient pins"),
                _check("GLD-SANDBOX-EGRESS", not bundle.egress_attempt, "conformance sandbox denies egress"),
                _check("GLD-NO-TRUST-PATH-WRITE", not bundle.trust_path_write_attempt, "sandbox cannot write trust paths"),
                _check("GLD-NO-SIGNING-KEY", not bundle.signing_key_visible_in_sandbox, "signing keys stay out of sandbox"),
            ]
        )
    return checks


def _check(check_id: str, passed: bool, oracle_spec: str) -> ConformanceCheck:
    return ConformanceCheck(
        check_id=check_id,
        status="PASS" if passed else "FAIL",
        oracle_spec=oracle_spec,
        reason=None if passed else "predicate failed",
    )


def _bundle_unsigned_payload(bundle: SubmissionBundle) -> dict[str, Any]:
    payload = asdict(bundle)
    payload["signature"] = ""
    return payload


def _record_unsigned_payload(record: ConformanceRecord) -> dict[str, Any]:
    payload = asdict(record)
    payload["signature"] = ""
    return payload


def _hmac_signature(payload: dict[str, Any], secret: bytes) -> str:
    digest = hmac.new(secret, canonical_json_bytes(payload), sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def _digest_pinned(container_digest: str) -> bool:
    return container_digest.startswith("sha256:") and len(container_digest) > len("sha256:")


def _level_rank(level: str) -> int:
    return CONFORMANCE_LEVEL_ORDER[level]


def _previous_level(level: str) -> str:
    rank = max(1, _level_rank(level) - 1)
    for name, candidate_rank in CONFORMANCE_LEVEL_ORDER.items():
        if candidate_rank == rank:
            return name
    return "bronze"


def _semver(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def _latest_semver(versions: tuple[str, ...]) -> str:
    return max(versions, key=_semver)


def _zero_hash() -> str:
    return hash_bytes(b"s12-governance-ledger-genesis")


def _has_cycle(parents: dict[str, str | None]) -> bool:
    for node in parents:
        seen: set[str] = set()
        current = node
        while current is not None:
            if current in seen:
                return True
            seen.add(current)
            current = parents.get(current)
    return False
