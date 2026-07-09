from __future__ import annotations

import json
import unittest

from argus_core import (
    AdapterBroker,
    AdapterConformanceError,
    AdapterDescriptor,
    Adapter,
    AdapterVersionError,
    EvalContext,
    EvalRequest,
    GradRequest,
    InMemoryArtifactStore,
    InMemoryRegistry,
    NotDifferentiableError,
    NormalizedQuantity,
    OutOfDomainError,
    ProvenanceUnavailableError,
    Quantity,
    S7JaxBackend,
    S7NativePythonBackend,
    S7ValidityDomainGuard,
    S7AdapterValidationResult,
    S7UnitRegistry,
    SimpleAdapter,
    UNCERTAINTY_ENGINE_HASH,
    UNCERTAINTY_ENGINE_VERSION,
    UNIT_REGISTRY_HASH,
    UNIT_REGISTRY_VERSION,
    VALIDITY_DOMAIN_GUARD_HASH,
    VALIDITY_DOMAIN_GUARD_VERSION,
    UnitsMismatchError,
    publish_adapter_capability,
    adapter_metadata,
    build_adapter_conformance_test_stub,
    declare_domain_box,
    derive_seed,
    differentiable,
    normalize_quantity,
    resolve_independent_adapter_capabilities,
    select_adapter_version,
    uncertainty,
    units_in,
    units_out,
    validate_adapter_locally,
    validity_domain,
)


class S7UnitsAndAdapterTests(unittest.TestCase):
    def test_native_python_backend_records_backend_provenance(self) -> None:
        store = InMemoryArtifactStore()
        descriptor = AdapterDescriptor(
            adapter_id="native_backend_adapter",
            version="1.0.0",
            input_units={"alpha": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"alpha": (0.0, 1.0)},
            determinism="deterministic",
            provenance_ref="c4://adapter/native-backend/v1",
        )
        backend = S7NativePythonBackend(
            evaluate=lambda inputs, ctx: {
                "omega": Quantity(
                    value=inputs["alpha"].value + float(ctx.seed or 0) / 1000.0,
                    units="dimensionless",
                    uncertainty={"kind": "interval", "radius": 0.01},
                )
            },
            underlying_code_version="native-test@1",
        )
        broker = AdapterBroker(artifact_store=store)
        broker.register(SimpleAdapter(descriptor, backend=backend))

        result = broker.evaluate(
            EvalRequest(
                adapter_id="native_backend_adapter",
                inputs={"alpha": Quantity(value=0.2, units="dimensionless")},
                seed=5,
            )
        )

        self.assertAlmostEqual(result.outputs["omega"].value, 0.205)
        self.assertEqual(result.backend_name, "native_python")
        self.assertEqual(result.underlying_code_version, "native-test@1")
        provenance = json.loads(store.get_artifact(result.provenance_ref))
        self.assertEqual(provenance["method"], "evaluate")
        self.assertEqual(provenance["backend_name"], "native_python")
        self.assertEqual(provenance["underlying_code_version"], "native-test@1")

    def test_jax_backend_evaluates_and_returns_jacobian_with_units(self) -> None:
        store = InMemoryArtifactStore()
        descriptor = AdapterDescriptor(
            adapter_id="jax_gw_surrogate",
            version="1.0.0",
            input_units={"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"},
            output_units={"omega": "Omega_h2"},
            validity_domain={"v_w": (0.4, 0.95)},
            determinism="deterministic",
            provenance_ref="c4://adapter/jax-gw/v1",
            differentiable=True,
        )
        backend = S7JaxBackend(
            function=lambda values: {
                "omega": values["alpha"] * values["T_n"] / 1000.0 + values["v_w"] ** 2,
            },
            output_uncertainties={"omega": {"kind": "interval", "radius": 0.01, "source": "jax-surrogate"}},
            underlying_code_version="jax-test@1",
        )
        broker = AdapterBroker(artifact_store=store)
        broker.register(SimpleAdapter(descriptor, backend=backend))
        inputs = {
            "T_n": Quantity(value=100.0, units="GeV"),
            "alpha": Quantity(value=0.2, units="dimensionless"),
            "v_w": Quantity(value=0.7, units="dimensionless"),
        }

        eval_result = broker.evaluate(EvalRequest(adapter_id="jax_gw_surrogate", inputs=inputs, seed=11))
        grad_result = broker.grad(GradRequest(adapter_id="jax_gw_surrogate", inputs=inputs, seed=11))

        self.assertAlmostEqual(eval_result.outputs["omega"].value, 0.51, places=7)
        self.assertEqual(eval_result.outputs["omega"].units, "Omega_h2")
        self.assertEqual(eval_result.backend_name, "jax")
        self.assertAlmostEqual(grad_result.jacobian["omega"]["T_n"].value, 0.0002, places=9)
        self.assertEqual(grad_result.jacobian["omega"]["T_n"].units, "1/GeV")
        self.assertAlmostEqual(grad_result.jacobian["omega"]["alpha"].value, 0.1, places=9)
        self.assertEqual(grad_result.jacobian["omega"]["alpha"].units, "1")
        self.assertAlmostEqual(grad_result.jacobian["omega"]["v_w"].value, 1.4, places=7)
        self.assertEqual(grad_result.backend_name, "jax")
        self.assertEqual(grad_result.underlying_code_version, "jax-test@1")

        provenance = json.loads(store.get_artifact(grad_result.provenance_ref))
        self.assertEqual(provenance["method"], "grad")
        self.assertEqual(provenance["backend_name"], "jax")
        self.assertEqual(provenance["jacobian"]["omega"]["T_n"]["units"], "1/GeV")
        self.assertEqual(provenance["input_hash"], json.loads(store.get_artifact(eval_result.provenance_ref))["input_hash"])

    def test_grad_on_non_differentiable_adapter_fails_closed(self) -> None:
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        descriptor = AdapterDescriptor(
            adapter_id="non_diff_adapter",
            version="1.0.0",
            input_units={"alpha": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"alpha": (0.0, 1.0)},
            determinism="deterministic",
            provenance_ref="c4://adapter/non-diff/v1",
            differentiable=False,
        )
        broker.register(
            SimpleAdapter(
                descriptor,
                lambda inputs, _seed: {
                    "omega": Quantity(
                        value=inputs["alpha"].value,
                        units="dimensionless",
                        uncertainty={"kind": "interval", "radius": 0.01},
                    )
                },
            )
        )

        with self.assertRaises(NotDifferentiableError) as raised:
            broker.grad(
                GradRequest(
                    adapter_id="non_diff_adapter",
                    inputs={"alpha": Quantity(value=0.2, units="dimensionless")},
                )
            )

        self.assertEqual(raised.exception.category, "NOT_DIFFERENTIABLE")

    def test_adapter_sdk_core_auto_generates_descriptor_and_passes_local_validate(self) -> None:
        @adapter_metadata(
            adapter_id="sdk_gw_example",
            version="1.2.3",
            determinism="deterministic",
            cost_class="standard",
            independence_tags=("sdk-example",),
        )
        @differentiable(backend="native_python")
        @uncertainty(kind="interval")
        @validity_domain(declare_domain_box({"v_w": (0.4, 0.95, "dimensionless")}), policy="flag")
        @units_out({"omega": "dimensionless"})
        @units_in({"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"})
        class SDKGWExample(Adapter):
            def __init__(self) -> None:
                self.seen_context_seed: int | None = None

            def evaluate(
                self,
                inputs: dict[str, NormalizedQuantity],
                ctx: EvalContext,
            ) -> dict[str, Quantity]:
                self.seen_context_seed = ctx.seed
                omega = inputs["alpha"].value * inputs["T_n"].value / 1000.0
                return {
                    "omega": Quantity(
                        value=omega,
                        units="dimensionless",
                        uncertainty={"kind": "interval", "radius": 0.02},
                    )
                }

        adapter = SDKGWExample()
        descriptor = adapter.describe()

        self.assertEqual(descriptor.adapter_id, "sdk_gw_example")
        self.assertEqual(descriptor.version, "1.2.3")
        self.assertEqual(descriptor.input_units["T_n"], "GeV")
        self.assertEqual(descriptor.output_units["omega"], "dimensionless")
        self.assertEqual(descriptor.validity_domain["kind"], "box")
        self.assertEqual(descriptor.domain_policy, "flag")
        self.assertTrue(descriptor.differentiable)
        self.assertEqual(descriptor.independence_tags, ("sdk-example",))
        self.assertEqual(descriptor.provenance_ref, "c4://adapter/sdk_gw_example/v1.2.3")

        validation = validate_adapter_locally(
            adapter,
            inputs={
                "T_n": Quantity(value=0.1, units="TeV"),
                "alpha": Quantity(value=0.2, units="dimensionless"),
                "v_w": Quantity(value=0.7, units="dimensionless"),
            },
            seed=42,
        )

        self.assertIsInstance(validation, S7AdapterValidationResult)
        self.assertTrue(validation.passed)
        self.assertEqual(validation.descriptor, descriptor)
        self.assertIsNotNone(validation.eval_result)
        assert validation.eval_result is not None
        self.assertEqual(validation.eval_result.adapter_id, "sdk_gw_example")
        self.assertAlmostEqual(validation.eval_result.outputs["omega"].value, 0.02)
        self.assertEqual(validation.eval_result.outputs["omega"].uncertainty["kind"], "interval")
        self.assertEqual(adapter.seen_context_seed, 42)

        stub = build_adapter_conformance_test_stub(
            adapter,
            adapter_import="project.adapters:SDKGWExample",
            sample_inputs={
                "T_n": Quantity(value=0.1, units="TeV"),
                "alpha": Quantity(value=0.2, units="dimensionless"),
                "v_w": Quantity(value=0.7, units="dimensionless"),
            },
        )
        self.assertIn("# Generated by argus-adapter-sdk for sdk_gw_example 1.2.3.", stub)
        self.assertIn("from project.adapters import SDKGWExample", stub)
        self.assertIn("validate_adapter_locally", stub)
        self.assertIn('"T_n": Quantity(value=0.1, units="TeV")', stub)
        self.assertIn('self.assertEqual(result.descriptor.adapter_id, "sdk_gw_example")', stub)
        self.assertEqual(
            adapter.conformance_test_stub(
                adapter_import="project.adapters:SDKGWExample",
                sample_inputs={
                    "T_n": Quantity(value=0.1, units="TeV"),
                    "alpha": Quantity(value=0.2, units="dimensionless"),
                    "v_w": Quantity(value=0.7, units="dimensionless"),
                },
            ),
            stub,
        )

    def test_adapter_sdk_missing_descriptor_metadata_fails_closed(self) -> None:
        @units_out({"omega": "dimensionless"})
        @units_in({"alpha": "dimensionless"})
        class MissingMetadataAdapter(Adapter):
            def evaluate(
                self,
                inputs: dict[str, NormalizedQuantity],
                ctx: EvalContext,
            ) -> dict[str, Quantity]:
                return {
                    "omega": Quantity(
                        value=inputs["alpha"].value,
                        units="dimensionless",
                        uncertainty={"kind": "interval", "radius": 0.01},
                    )
                }

        with self.assertRaises(AdapterConformanceError) as raised:
            MissingMetadataAdapter().describe()

        self.assertEqual(raised.exception.category, "ADAPTER_ERROR")
        self.assertIn("adapter_id", raised.exception.message)

    def test_adapter_sdk_local_validate_rejects_missing_output_uncertainty(self) -> None:
        @adapter_metadata(adapter_id="sdk_bad_uncertainty", version="1.0.0")
        @uncertainty(kind="interval")
        @validity_domain(declare_domain_box({"alpha": (0.0, 1.0, "dimensionless")}), policy="flag")
        @units_out({"omega": "dimensionless"})
        @units_in({"alpha": "dimensionless"})
        class MissingUncertaintyAdapter(Adapter):
            def evaluate(
                self,
                inputs: dict[str, NormalizedQuantity],
                ctx: EvalContext,
            ) -> dict[str, Quantity]:
                return {"omega": Quantity(value=inputs["alpha"].value, units="dimensionless")}

        with self.assertRaises(AdapterConformanceError) as raised:
            validate_adapter_locally(
                MissingUncertaintyAdapter(),
                inputs={"alpha": Quantity(value=0.2, units="dimensionless")},
            )

        self.assertEqual(raised.exception.category, "ADAPTER_ERROR")
        self.assertIn("uncertainty", raised.exception.message)

    def test_frozen_unit_registry_digest_is_pinned_into_normalized_quantities_and_results(self) -> None:
        registry = S7UnitRegistry.default()

        normalized = normalize_quantity(Quantity(value=0.1, units="TeV"), "GeV", registry=registry)
        result = self._evaluate_with_broker(
            self._adapter(domain_policy="flag"),
            {
                "T_n": Quantity(value=0.1, units="TeV"),
                "alpha": Quantity(value=0.2, units="dimensionless"),
                "v_w": Quantity(value=0.7, units="dimensionless"),
            },
        )

        self.assertEqual(registry.version, UNIT_REGISTRY_VERSION)
        self.assertEqual(registry.registry_hash, UNIT_REGISTRY_HASH)
        self.assertEqual(normalized.unit_registry_version, UNIT_REGISTRY_VERSION)
        self.assertEqual(normalized.unit_registry_hash, UNIT_REGISTRY_HASH)
        self.assertEqual(result.unit_registry_version, UNIT_REGISTRY_VERSION)
        self.assertEqual(result.unit_registry_hash, UNIT_REGISTRY_HASH)

    def test_units_normalized_not_silently_coerced(self) -> None:
        normalized = normalize_quantity(Quantity(value=0.1, units="TeV"), "GeV")

        self.assertEqual(normalized.units, "GeV")
        self.assertEqual(normalized.original_units, "TeV")
        self.assertAlmostEqual(normalized.value, 100.0)
        self.assertEqual(normalized.unit_registry_version, UNIT_REGISTRY_VERSION)

    def test_units_mismatch_is_hard_error(self) -> None:
        with self.assertRaises(UnitsMismatchError) as raised:
            normalize_quantity(Quantity(value=1.0, units="s"), "GeV")

        self.assertEqual(raised.exception.category, "UNITS_MISMATCH")

    def test_compound_units_normalize_and_reject_dimension_mismatch(self) -> None:
        normalized = normalize_quantity(Quantity(value=2.0, units="TeV/Hz"), "GeV/Hz")

        self.assertEqual(normalized.units, "GeV/Hz")
        self.assertEqual(normalized.original_units, "TeV/Hz")
        self.assertAlmostEqual(normalized.value, 2000.0)
        with self.assertRaises(UnitsMismatchError):
            normalize_quantity(Quantity(value=1.0, units="GeV/Hz"), "GeV")

    def test_log_space_inputs_are_delinearized_before_backend(self) -> None:
        captured: dict[str, float] = {}
        descriptor = AdapterDescriptor(
            adapter_id="log_adapter",
            version="1.0.0",
            input_units={
                "log10_beta_over_H": {"units": "dimensionless", "log_space": "log10"},
            },
            output_units={"omega": "dimensionless"},
            validity_domain={"log10_beta_over_H": (1.0, 3.0)},
            determinism="deterministic",
            provenance_ref="c4://adapter/log_adapter/v1",
        )

        def evaluate(inputs: dict[str, NormalizedQuantity], _seed: int | None) -> dict[str, Quantity]:
            captured["beta_over_H"] = inputs["log10_beta_over_H"].value
            return {
                "omega": Quantity(
                    value=inputs["log10_beta_over_H"].value,
                    units="dimensionless",
                    uncertainty={"kind": "interval", "radius": 0.01},
                )
            }

        result = self._evaluate_with_broker(
            SimpleAdapter(descriptor, evaluate),
            {"log10_beta_over_H": Quantity(value=2.0, units="dimensionless")},
        )

        self.assertAlmostEqual(captured["beta_over_H"], 100.0)
        self.assertEqual(result.outputs["omega"].value, 100.0)
        self.assertEqual(result.unit_registry_version, UNIT_REGISTRY_VERSION)

    def test_outputs_are_normalized_to_declared_units(self) -> None:
        descriptor = AdapterDescriptor(
            adapter_id="frequency_adapter",
            version="1.0.0",
            input_units={"alpha": "dimensionless"},
            output_units={"peak_frequency": "Hz"},
            validity_domain={},
            determinism="deterministic",
            provenance_ref="c4://adapter/frequency_adapter/v1",
        )
        result = self._evaluate_with_broker(
            SimpleAdapter(
                descriptor,
                lambda _inputs, _seed: {
                    "peak_frequency": Quantity(
                        value=2.0,
                        units="mHz",
                        uncertainty={"kind": "interval", "radius": 0.5},
                    )
                },
            ),
            {"alpha": Quantity(value=0.2, units="dimensionless")},
        )

        self.assertEqual(result.outputs["peak_frequency"].units, "Hz")
        self.assertAlmostEqual(result.outputs["peak_frequency"].value, 0.002)
        uncertainty = result.outputs["peak_frequency"].uncertainty
        self.assertEqual(uncertainty["kind"], "interval")
        self.assertEqual(uncertainty["source"], "adapter:peak_frequency")
        self.assertAlmostEqual(uncertainty["radius"], 0.0005)
        self.assertAlmostEqual(uncertainty["lower"], 0.0015)
        self.assertAlmostEqual(uncertainty["upper"], 0.0025)

    def test_evaluate_writes_provenance_and_flags_extrapolation(self) -> None:
        store = InMemoryArtifactStore()
        broker = AdapterBroker(artifact_store=store)
        broker.register(self._adapter(domain_policy="flag"))

        result = broker.evaluate(
            EvalRequest(
                adapter_id="gw_spectrum_surrogate",
                inputs={
                    "T_n": Quantity(value=0.1, units="TeV"),
                    "alpha": Quantity(value=0.2, units="dimensionless"),
                    "v_w": Quantity(value=1.2, units="dimensionless"),
                },
                seed=123,
            )
        )

        self.assertFalse(result.in_validity_domain)
        self.assertTrue(result.extrapolation_flag)
        self.assertEqual(result.violated_fields, ("v_w",))
        self.assertEqual(result.outputs["omega"].uncertainty["kind"], "interval")
        self.assertEqual(result.outputs["omega"].uncertainty["source"], "adapter:omega")
        self.assertAlmostEqual(result.outputs["omega"].uncertainty["radius"], 0.01)
        self.assertEqual(result.outputs["omega"].uncertainty["uncertainty_engine_version"], UNCERTAINTY_ENGINE_VERSION)
        self.assertEqual(result.validity_domain_guard_version, VALIDITY_DOMAIN_GUARD_VERSION)
        self.assertEqual(result.validity_domain_guard_hash, VALIDITY_DOMAIN_GUARD_HASH)
        self.assertEqual(result.domain_diagnostics["violated_fields"], ("v_w",))
        self.assertEqual(result.domain_diagnostics["policy"], "flag")
        self.assertAlmostEqual(result.domain_diagnostics["distance"], 0.25)
        self.assertEqual(store.get_record(result.provenance_ref).kind, "log")

    def test_refuse_policy_rejects_out_of_domain(self) -> None:
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(self._adapter(domain_policy="refuse"))

        with self.assertRaises(OutOfDomainError) as raised:
            broker.evaluate(
                EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=1.2, units="dimensionless"),
                    },
                )
            )

        self.assertEqual(raised.exception.category, "OUT_OF_DOMAIN")
        self.assertEqual(raised.exception.diagnostics["violated_fields"], ("v_w",))
        self.assertEqual(raised.exception.diagnostics["policy"], "refuse")

    def test_clamp_with_flag_policy_clamps_backend_input_and_records_diagnostics(self) -> None:
        captured: dict[str, float | None] = {}
        descriptor = self._descriptor(domain_policy="clamp_with_flag")
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(
            SimpleAdapter(
                descriptor,
                lambda inputs, _seed: self._evaluate_and_capture(inputs, captured),
            )
        )

        result = broker.evaluate(
            EvalRequest(
                adapter_id="gw_spectrum_surrogate",
                inputs={
                    "T_n": Quantity(value=100, units="GeV"),
                    "alpha": Quantity(value=0.2, units="dimensionless"),
                    "v_w": Quantity(value=1.2, units="dimensionless"),
                },
            )
        )

        self.assertTrue(result.extrapolation_flag)
        self.assertFalse(result.in_validity_domain)
        self.assertEqual(result.violated_fields, ("v_w",))
        self.assertAlmostEqual(captured["v_w_value"] or 0.0, 0.95)
        self.assertAlmostEqual(captured["v_w_domain_value"] or 0.0, 0.95)
        self.assertEqual(result.domain_diagnostics["clamped_fields"], ("v_w",))
        self.assertAlmostEqual(result.domain_diagnostics["fields"]["v_w"]["original_value"], 1.2)
        self.assertAlmostEqual(result.domain_diagnostics["fields"]["v_w"]["effective_value"], 0.95)

    def test_structured_box_domain_uses_log_coordinate_for_validity(self) -> None:
        captured: dict[str, float | None] = {}
        descriptor = AdapterDescriptor(
            adapter_id="log_domain_adapter",
            version="1.0.0",
            input_units={"log10_beta_over_H": {"units": "dimensionless", "log_space": "log10"}},
            output_units={"omega": "dimensionless"},
            validity_domain={
                "kind": "box",
                "box": {"log10_beta_over_H": {"min": 1.0, "max": 3.0, "unit": "dimensionless"}},
            },
            determinism="deterministic",
            provenance_ref="c4://adapter/log_domain_adapter/v1",
        )
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(
            SimpleAdapter(
                descriptor,
                lambda inputs, _seed: self._evaluate_log_domain(inputs, captured),
            )
        )

        result = broker.evaluate(
            EvalRequest(
                adapter_id="log_domain_adapter",
                inputs={"log10_beta_over_H": Quantity(value=4.0, units="dimensionless")},
            )
        )

        self.assertAlmostEqual(captured["backend_value"] or 0.0, 10000.0)
        self.assertTrue(result.extrapolation_flag)
        self.assertEqual(result.violated_fields, ("log10_beta_over_H",))
        self.assertEqual(result.domain_diagnostics["fields"]["log10_beta_over_H"]["value"], 4.0)
        self.assertAlmostEqual(result.domain_diagnostics["fields"]["log10_beta_over_H"]["distance"], 1.0)

    def test_malformed_validity_domain_fails_closed_before_backend_call(self) -> None:
        called = False
        descriptor = self._descriptor(domain_policy="flag")
        descriptor = AdapterDescriptor(
            adapter_id=descriptor.adapter_id,
            version=descriptor.version,
            input_units=descriptor.input_units,
            output_units=descriptor.output_units,
            validity_domain={"v_w": (0.95, 0.4)},
            determinism=descriptor.determinism,
            provenance_ref=descriptor.provenance_ref,
            domain_policy=descriptor.domain_policy,
            differentiable=descriptor.differentiable,
            independence_tags=descriptor.independence_tags,
        )
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())

        def evaluate(_inputs: dict[str, NormalizedQuantity], _seed: int | None) -> dict[str, Quantity]:
            nonlocal called
            called = True
            return self._evaluate(_inputs, _seed)

        broker.register(SimpleAdapter(descriptor, evaluate))

        with self.assertRaises(AdapterConformanceError) as raised:
            broker.evaluate(
                EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                    },
                )
            )

        self.assertFalse(called)
        self.assertEqual(raised.exception.category, "ADAPTER_ERROR")
        self.assertIn("validity domain", raised.exception.message)

    def test_validity_domain_guard_digest_is_stable(self) -> None:
        guard = S7ValidityDomainGuard.default()

        self.assertEqual(guard.version, VALIDITY_DOMAIN_GUARD_VERSION)
        self.assertEqual(guard.guard_hash, VALIDITY_DOMAIN_GUARD_HASH)

    def test_missing_uncertainty_is_conformance_error(self) -> None:
        descriptor = self._descriptor(domain_policy="flag")
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(
            SimpleAdapter(
                descriptor,
                lambda _inputs, _seed: {"omega": Quantity(value=1.0, units="dimensionless")},
            )
        )

        with self.assertRaises(AdapterConformanceError) as raised:
            broker.evaluate(
                EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                    },
                )
            )

        self.assertEqual(raised.exception.category, "ADAPTER_ERROR")

    def test_malformed_uncertainty_is_conformance_error(self) -> None:
        invalid_uncertainties = (
            {},
            {"kind": "none", "source": "adapter"},
            {"kind": "point_estimate", "source": "adapter"},
            {"kind": "interval", "radius": float("nan"), "source": "adapter"},
            {"kind": "interval", "lower": 2.0, "upper": 1.0, "source": "adapter"},
            {"kind": "samples", "samples": [0.1, float("inf")], "source": "adapter"},
        )
        for uncertainty in invalid_uncertainties:
            with self.subTest(uncertainty=uncertainty):
                descriptor = self._descriptor(domain_policy="flag")
                broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
                broker.register(
                    SimpleAdapter(
                        descriptor,
                        lambda _inputs, _seed, uncertainty=uncertainty: {
                            "omega": Quantity(
                                value=1.0,
                                units="dimensionless",
                                uncertainty=dict(uncertainty),
                            )
                        },
                    )
                )

                with self.assertRaises(AdapterConformanceError) as raised:
                    broker.evaluate(
                        EvalRequest(
                            adapter_id="gw_spectrum_surrogate",
                            inputs={
                                "T_n": Quantity(value=100, units="GeV"),
                                "alpha": Quantity(value=0.2, units="dimensionless"),
                                "v_w": Quantity(value=0.7, units="dimensionless"),
                            },
                        )
                    )

                self.assertEqual(raised.exception.category, "ADAPTER_ERROR")

    def test_uncertainty_engine_normalizes_outputs_and_provenance_summary(self) -> None:
        store = InMemoryArtifactStore()
        descriptor = AdapterDescriptor(
            adapter_id="frequency_adapter",
            version="1.0.0",
            input_units={"alpha": "dimensionless"},
            output_units={"peak_frequency": "Hz"},
            validity_domain={},
            determinism="deterministic",
            provenance_ref="c4://adapter/frequency_adapter/v1",
        )
        broker = AdapterBroker(artifact_store=store)
        broker.register(
            SimpleAdapter(
                descriptor,
                lambda _inputs, _seed: {
                    "peak_frequency": Quantity(
                        value=2.0,
                        units="mHz",
                        uncertainty={
                            "kind": "interval",
                            "radius": 0.5,
                            "confidence": 0.9,
                            "source": "native-solver",
                        },
                    )
                },
            )
        )

        result = broker.evaluate(
            EvalRequest(
                adapter_id="frequency_adapter",
                inputs={"alpha": Quantity(value=0.2, units="dimensionless")},
                seed=123,
            )
        )

        self.assertEqual(result.uncertainty_engine_version, UNCERTAINTY_ENGINE_VERSION)
        self.assertEqual(result.uncertainty_engine_hash, UNCERTAINTY_ENGINE_HASH)
        uncertainty = result.outputs["peak_frequency"].uncertainty
        self.assertIsNotNone(uncertainty)
        self.assertEqual(uncertainty["kind"], "interval")
        self.assertEqual(uncertainty["source"], "native-solver")
        self.assertEqual(uncertainty["uncertainty_engine_version"], UNCERTAINTY_ENGINE_VERSION)
        self.assertEqual(uncertainty["uncertainty_engine_hash"], UNCERTAINTY_ENGINE_HASH)
        self.assertAlmostEqual(uncertainty["radius"], 0.0005)
        self.assertAlmostEqual(uncertainty["lower"], 0.0015)
        self.assertAlmostEqual(uncertainty["upper"], 0.0025)
        self.assertAlmostEqual(uncertainty["confidence"], 0.9)
        provenance = json.loads(store.get_artifact(result.provenance_ref))
        self.assertEqual(provenance["uncertainty_engine_version"], UNCERTAINTY_ENGINE_VERSION)
        self.assertEqual(provenance["uncertainty_engine_hash"], UNCERTAINTY_ENGINE_HASH)
        self.assertEqual(provenance["validity_domain_guard_version"], VALIDITY_DOMAIN_GUARD_VERSION)
        self.assertEqual(provenance["validity_domain_guard_hash"], VALIDITY_DOMAIN_GUARD_HASH)
        self.assertEqual(provenance["domain_diagnostics"]["violated_fields"], [])
        self.assertEqual(
            provenance["uncertainty_summary"]["peak_frequency"],
            {
                "kind": "interval",
                "source": "native-solver",
                "confidence": 0.9,
            },
        )

    def test_provenance_unavailable_fails_closed(self) -> None:
        broker = AdapterBroker(artifact_store=None)
        broker.register(self._adapter(domain_policy="flag"))

        with self.assertRaises(ProvenanceUnavailableError) as raised:
            broker.evaluate(
                EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                    },
                )
            )

        self.assertEqual(raised.exception.category, "PROVENANCE_UNAVAILABLE")

    def test_seed_derivation_is_deterministic(self) -> None:
        first = derive_seed(job_seed=7, dag_node_id="node-a", call_index=1, adapter_id="adapter")
        second = derive_seed(job_seed=7, dag_node_id="node-a", call_index=1, adapter_id="adapter")
        other = derive_seed(job_seed=7, dag_node_id="node-a", call_index=2, adapter_id="adapter")

        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_seed_manager_derives_seed_and_records_replayable_provenance(self) -> None:
        store = InMemoryArtifactStore()
        captured: list[int | None] = []
        descriptor = AdapterDescriptor(
            adapter_id="seeded_adapter",
            version="1.0.0",
            input_units={"alpha": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"alpha": (0.0, 1.0)},
            determinism="deterministic",
            provenance_ref="c4://adapter/seeded_adapter/v1",
        )

        def evaluate(_inputs: dict[str, NormalizedQuantity], seed: int | None) -> dict[str, Quantity]:
            captured.append(seed)
            return {
                "omega": Quantity(
                    value=float((seed or 0) % 1000),
                    units="dimensionless",
                    uncertainty={"kind": "interval", "radius": 0.01},
                )
            }

        broker = AdapterBroker(artifact_store=store)
        broker.register(SimpleAdapter(descriptor, evaluate))
        request = EvalRequest(
            adapter_id="seeded_adapter",
            inputs={"alpha": Quantity(value=0.2, units="dimensionless")},
            job_seed=7,
            dag_node_id="node-a",
            call_index=1,
        )
        expected_seed = derive_seed(job_seed=7, dag_node_id="node-a", call_index=1, adapter_id="seeded_adapter")

        first = broker.evaluate(request)
        second = broker.evaluate(request)

        self.assertEqual(captured, [expected_seed, expected_seed])
        self.assertEqual(first.seed_used, expected_seed)
        self.assertEqual(first.seed_source, "derived")
        self.assertEqual(first.seed_derivation["job_seed"], 7)
        self.assertEqual(first.seed_derivation["dag_node_id"], "node-a")
        self.assertEqual(first.seed_derivation["call_index"], 1)
        self.assertEqual(first.seed_derivation["adapter_id"], "seeded_adapter")
        self.assertEqual(first.seed_derivation["algorithm"], "blake3-kdf-v1")
        self.assertEqual(first.outputs, second.outputs)

        first_provenance = json.loads(store.get_artifact(first.provenance_ref))
        second_provenance = json.loads(store.get_artifact(second.provenance_ref))
        self.assertEqual(first_provenance["seed"], expected_seed)
        self.assertEqual(first_provenance["seed_used"], expected_seed)
        self.assertEqual(first_provenance["seed_source"], "derived")
        self.assertEqual(first_provenance["seed_derivation"], first.seed_derivation)
        self.assertEqual(first_provenance["output_hash"], second_provenance["output_hash"])
        self.assertEqual(store.get_record(first.provenance_ref).lineage.seeds, (str(expected_seed),))

    def test_explicit_seed_overrides_derivation_but_keeps_context(self) -> None:
        store = InMemoryArtifactStore()
        captured: list[int | None] = []
        descriptor = AdapterDescriptor(
            adapter_id="explicit_seed_adapter",
            version="1.0.0",
            input_units={"alpha": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"alpha": (0.0, 1.0)},
            determinism="seeded",
            provenance_ref="c4://adapter/explicit_seed_adapter/v1",
        )
        broker = AdapterBroker(artifact_store=store)
        broker.register(
            SimpleAdapter(
                descriptor,
                lambda _inputs, seed: captured.append(seed)
                or {
                    "omega": Quantity(
                        value=float(seed or 0),
                        units="dimensionless",
                        uncertainty={"kind": "interval", "radius": 0.01},
                    )
                },
            )
        )

        result = broker.evaluate(
            EvalRequest(
                adapter_id="explicit_seed_adapter",
                inputs={"alpha": Quantity(value=0.2, units="dimensionless")},
                seed=555,
                job_seed=7,
                dag_node_id="node-a",
                call_index=1,
            )
        )

        self.assertEqual(captured, [555])
        self.assertEqual(result.seed_used, 555)
        self.assertEqual(result.seed_source, "explicit")
        self.assertEqual(result.seed_derivation["job_seed"], 7)
        self.assertEqual(result.seed_derivation["adapter_id"], "explicit_seed_adapter")
        provenance = json.loads(store.get_artifact(result.provenance_ref))
        self.assertEqual(provenance["seed"], 555)
        self.assertEqual(provenance["seed_source"], "explicit")

    def test_seed_manager_rejects_partial_or_invalid_derivation_context(self) -> None:
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(self._adapter(domain_policy="flag"))
        base_inputs = {
            "T_n": Quantity(value=100, units="GeV"),
            "alpha": Quantity(value=0.2, units="dimensionless"),
            "v_w": Quantity(value=0.7, units="dimensionless"),
        }
        invalid_requests = (
            EvalRequest(
                adapter_id="gw_spectrum_surrogate",
                inputs=base_inputs,
                job_seed=7,
                dag_node_id="node-a",
            ),
            EvalRequest(
                adapter_id="gw_spectrum_surrogate",
                inputs=base_inputs,
                job_seed=7,
                dag_node_id="node-a",
                call_index=-1,
            ),
        )

        for request in invalid_requests:
            with self.subTest(request=request):
                with self.assertRaises(AdapterConformanceError) as raised:
                    broker.evaluate(request)

                self.assertEqual(raised.exception.category, "ADAPTER_ERROR")

    def test_adapter_capability_publishes_to_c5_registry(self) -> None:
        registry = InMemoryRegistry()

        published = publish_adapter_capability(registry, self._descriptor(domain_policy="flag"), subtopics=("ewpt",))
        resolution = registry.resolve(kind="adapter", subtopic="ewpt", required_scope="grad")

        self.assertEqual(published.kind, "adapter")
        self.assertEqual(published.owner_subsystem, "S7")
        self.assertEqual(published.contract_versions["C6"], "2.1.0")
        self.assertIn("gw-surrogate-a", published.independence_tags)
        self.assertEqual([descriptor.entity_id for descriptor in resolution.descriptors], ["gw_spectrum_surrogate"])

    def test_independent_adapter_resolution_excludes_revoked_and_same_lineage(self) -> None:
        registry = InMemoryRegistry()
        first = self._descriptor(domain_policy="flag", adapter_id="gw_a", tags=("impl-a",))
        second = self._descriptor(domain_policy="flag", adapter_id="gw_b", tags=("impl-b",))
        revoked = self._descriptor(domain_policy="flag", adapter_id="gw_c", tags=("impl-c",))
        publish_adapter_capability(registry, first, subtopics=("ewpt",))
        publish_adapter_capability(registry, second, subtopics=("ewpt",))
        publish_adapter_capability(registry, revoked, subtopics=("ewpt",))
        registry.revoke("gw_c")

        attestation = resolve_independent_adapter_capabilities(
            registry,
            subtopic="ewpt",
            excluded_independence_tags=("impl-a",),
            min_independent=1,
        )

        self.assertTrue(attestation.lineage_disjoint)
        self.assertEqual(attestation.selected_entity_ids, ("gw_b",))
        self.assertNotIn("gw_c", attestation.candidate_ids)

    def test_select_adapter_version_uses_highest_compatible_major(self) -> None:
        descriptors = (
            self._descriptor(domain_policy="flag", adapter_id="gw", version="1.0.0"),
            self._descriptor(domain_policy="flag", adapter_id="gw", version="1.2.0"),
            self._descriptor(domain_policy="flag", adapter_id="gw", version="2.0.0"),
        )

        selected = select_adapter_version(descriptors, requested_major=1)

        self.assertEqual(selected.selected_version, "1.2.0")
        with self.assertRaises(AdapterVersionError):
            select_adapter_version(descriptors, requested_major=3)

    def _adapter(self, *, domain_policy: str) -> SimpleAdapter:
        return SimpleAdapter(self._descriptor(domain_policy=domain_policy), self._evaluate)

    @staticmethod
    def _descriptor(
        *,
        domain_policy: str,
        adapter_id: str = "gw_spectrum_surrogate",
        version: str = "1.0.0",
        tags: tuple[str, ...] = ("gw-surrogate-a",),
    ) -> AdapterDescriptor:
        return AdapterDescriptor(
            adapter_id=adapter_id,
            version=version,
            input_units={"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"v_w": (0.4, 0.95)},
            determinism="deterministic",
            provenance_ref=f"c4://adapter/{adapter_id}/v{version}",
            domain_policy=domain_policy,
            differentiable=True,
            independence_tags=tags,
        )

    @staticmethod
    def _evaluate(inputs: dict[str, NormalizedQuantity], _seed: int | None) -> dict[str, Quantity]:
        omega = inputs["alpha"].value * inputs["T_n"].value / 1000.0
        return {
            "omega": Quantity(
                value=omega,
                units="dimensionless",
                uncertainty={"kind": "interval", "radius": 0.01},
            )
        }

    @staticmethod
    def _evaluate_and_capture(
        inputs: dict[str, NormalizedQuantity],
        captured: dict[str, float | None],
    ) -> dict[str, Quantity]:
        captured["v_w_value"] = inputs["v_w"].value
        captured["v_w_domain_value"] = inputs["v_w"].domain_value
        return S7UnitsAndAdapterTests._evaluate(inputs, None)

    @staticmethod
    def _evaluate_log_domain(
        inputs: dict[str, NormalizedQuantity],
        captured: dict[str, float | None],
    ) -> dict[str, Quantity]:
        captured["backend_value"] = inputs["log10_beta_over_H"].value
        return {
            "omega": Quantity(
                value=inputs["log10_beta_over_H"].value,
                units="dimensionless",
                uncertainty={"kind": "interval", "radius": 0.01},
            )
        }

    @staticmethod
    def _evaluate_with_broker(adapter: SimpleAdapter, inputs: dict[str, Quantity]):
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(adapter)
        return broker.evaluate(EvalRequest(adapter_id=adapter.descriptor.adapter_id, inputs=inputs, seed=123))


if __name__ == "__main__":
    unittest.main()
