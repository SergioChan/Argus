from __future__ import annotations

import unittest

from argus_core import (
    AdapterDescriptor,
    CapabilityDescriptor,
    InMemoryRegistry,
    InMemoryVerifierProfileRegistry,
    S3CostCeiling,
    S3ProfileCompiler,
    S3ProfileCompilerError,
)


def _profile_spec(profile_id: str = "ewpt-resolver") -> dict[str, object]:
    return {
        "profile_id": profile_id,
        "subtopic": "electroweak.phase_transition",
        "checks": ["INJECTION", "CROSS_CODE", "CALIBRATION"],
        "check_specs": [
            {
                "check": "INJECTION",
                "plugin_ref": "argus.s3.plugins.injection",
                "plugin_version": "1.2.0",
                "thresholds": {"recovery_rate_min": 0.9},
                "determinism": "seeded",
                "seed": 17,
                "mandatory": True,
                "budget": {"max_wallclock_s": 1.0, "max_cost_usd": 0.004},
            },
            {
                "check": "CROSS_CODE",
                "plugin_ref": "argus.s3.plugins.cross_code",
                "plugin_version": "1.1.0",
                "thresholds": {"max_reduced_chi2": 2.0},
                "determinism": "deterministic",
                "requires_independence": True,
                "adapter_id": "gw_spectrum_surrogate",
                "adapter_major": 1,
                "mandatory": True,
                "budget": {"max_wallclock_s": 1.5, "max_cost_usd": 0.006},
            },
            {
                "check": "CALIBRATION",
                "plugin_ref": "argus.s3.plugins.calibration",
                "plugin_version": "1.0.0",
                "thresholds": {"nominal_coverage": 0.68, "tolerance": 0.05},
                "determinism": "stochastic",
                "tolerance": {"coverage_abs": 0.05},
                "mandatory": True,
                "budget": {"max_wallclock_s": 0.75, "max_cost_usd": 0.003},
            },
        ],
        "determinism_policy": {"class": "seeded", "seed": 17},
        "independence_policy": {"requires_cross_code": True, "min_independent_codes": 1},
        "cost_estimate": {"max_wallclock_s": 2.9, "max_cost_usd": 0.02},
        "review_signatures": [
            {
                "reviewer_id": "s3-profile-registrar",
                "signed_at": "2026-07-07T00:00:00Z",
                "signature": "hmac-sha256:" + "b" * 64,
            }
        ],
    }


class S3ProfileResolverCompilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = InMemoryVerifierProfileRegistry()
        self.c5 = InMemoryRegistry()
        self._publish_adapter_capability("gw_spectrum_surrogate")
        self.compiler = S3ProfileCompiler(
            profile_registry=self.registry,
            adapter_descriptors=(
                self._adapter("gw_spectrum_surrogate", version="1.0.0"),
                self._adapter("gw_spectrum_surrogate", version="1.2.0"),
                self._adapter("gw_spectrum_surrogate", version="2.0.0"),
            ),
            capability_registry=self.c5,
            cost_ceiling=S3CostCeiling(
                max_profile_wallclock_s=3.0,
                max_profile_cost_usd=0.05,
                max_check_wallclock_s=2.0,
                max_check_cost_usd=0.01,
                allowed_adapter_cost_classes=("standard",),
            ),
        )

    def test_compiles_pinned_revision_specs_and_surfaces_determinism(self) -> None:
        revision_one = self.registry.publish(_profile_spec())
        revision_two_spec = _profile_spec()
        revision_two_spec["check_specs"][0]["thresholds"] = {"recovery_rate_min": 0.95}  # type: ignore[index]
        self.registry.publish(revision_two_spec)

        compiled = self.compiler.compile(
            profile_ref=revision_one.profile_ref,
            subtopic="electroweak.phase_transition",
        )

        self.assertEqual(compiled.profile_ref, revision_one.profile_ref)
        self.assertEqual(compiled.revision, 1)
        self.assertEqual(compiled.spec_hash, revision_one.spec_hash)
        self.assertEqual([check.check for check in compiled.checks], ["INJECTION", "CROSS_CODE", "CALIBRATION"])
        self.assertEqual(compiled.checks[0].thresholds, {"recovery_rate_min": 0.9})
        self.assertEqual(compiled.checks[1].adapter.selected_version, "1.2.0")
        self.assertEqual(compiled.checks[1].adapter.c5_revision, 1)
        self.assertTrue(compiled.checks[1].requires_independence)
        self.assertEqual(compiled.determinism_profile["seeded_checks"], [{"check": "INJECTION", "seed": 17}])
        self.assertEqual(compiled.determinism_profile["deterministic_checks"], ["CROSS_CODE"])
        self.assertEqual(
            compiled.determinism_profile["stochastic_checks"],
            [{"check": "CALIBRATION", "tolerance": {"coverage_abs": 0.05}}],
        )
        self.assertEqual(compiled.public_profile, revision_one.to_c3_profile())

    def test_over_ceiling_c6_adapter_is_rejected_before_compile_succeeds(self) -> None:
        expensive_spec = _profile_spec("ewpt-expensive")
        expensive_spec["check_specs"][1]["adapter_id"] = "hpc_adapter"  # type: ignore[index]
        revision = self.registry.publish(expensive_spec)
        self._publish_adapter_capability("hpc_adapter")
        compiler = S3ProfileCompiler(
            profile_registry=self.registry,
            adapter_descriptors=(self._adapter("hpc_adapter", cost_class="flagship-hpc"),),
            capability_registry=self.c5,
            cost_ceiling=S3CostCeiling(allowed_adapter_cost_classes=("standard",)),
        )

        with self.assertRaises(S3ProfileCompilerError) as raised:
            compiler.compile(profile_ref=revision.profile_ref, subtopic=revision.subtopic)

        self.assertEqual(raised.exception.category, "POLICY")
        self.assertEqual(raised.exception.code, "C6_COST_CEILING_EXCEEDED")
        self.assertTrue(raised.exception.before_execution)

    def test_profile_unsupported_is_fail_closed_for_wrong_subtopic(self) -> None:
        revision = self.registry.publish(_profile_spec())

        with self.assertRaises(S3ProfileCompilerError) as raised:
            self.compiler.compile(profile_ref=revision.profile_ref, subtopic="higgs.observables")

        self.assertEqual(raised.exception.category, "VERIFIER_UNAVAILABLE")
        self.assertEqual(raised.exception.code, "PROFILE_UNSUPPORTED")
        self.assertTrue(raised.exception.before_execution)

    def _publish_adapter_capability(self, adapter_id: str) -> None:
        self.c5.publish(
            CapabilityDescriptor(
                entity_id=adapter_id,
                revision=1,
                kind="adapter",
                owner_subsystem="S7",
                contract_versions={"C5": "1.0.0", "C6": "1.0.0"},
                trust_class="local",
                capability_scopes=("evaluate", "grad"),
                provenance_ref=f"c4://descriptor/{adapter_id}/v1",
                subtopics=("electroweak.phase_transition",),
                independence_tags=(f"{adapter_id}-impl",),
            )
        )

    @staticmethod
    def _adapter(adapter_id: str, *, version: str = "1.0.0", cost_class: str = "standard") -> AdapterDescriptor:
        return AdapterDescriptor(
            adapter_id=adapter_id,
            version=version,
            input_units={"T_n": "GeV", "alpha": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"alpha": (0.0, 1.0)},
            determinism="deterministic",
            provenance_ref=f"c4://adapter/{adapter_id}/v{version}",
            differentiable=True,
            cost_class=cost_class,
            independence_tags=(f"{adapter_id}-impl",),
        )


if __name__ == "__main__":
    unittest.main()
