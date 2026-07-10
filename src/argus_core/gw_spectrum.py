"""Reference sound-wave gravitational-wave spectrum adapter for EWPT studies.

The model implements the commonly used radiation-era sound-wave template for
first-order phase transitions. It is intentionally a transparent reference
calculation rather than a surrogate: the peak frequency, peak amplitude, and
spectral shape are evaluated from the same published-fit parameters on every
call. See Caprini et al., arXiv:1910.13125, for the sound-wave framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite, sqrt
from typing import Mapping

from .s7 import (
    Adapter,
    AdapterConformanceError,
    EvalContext,
    NormalizedQuantity,
    Quantity,
    S7NativePythonBackend,
    S7RegistrationResult,
    S7RegistrationService,
    S7UnitRegistry,
    SimpleAdapter,
    adapter_metadata,
    declare_domain_box,
    uncertainty,
    units_in,
    units_out,
    validity_domain,
)


GW_SPECTRUM_ADAPTER_ID = "gw_spectrum"
GW_SPECTRUM_VERSION = "1.0.0"
GW_SPECTRUM_UNDERLYING_CODE_VERSION = "argus-core:gw-sound-wave-template-v1"
GW_SPECTRUM_SUBTOPIC = "ewpt"
GW_SPECTRUM_STANDARD_MODEL_G_STAR = 106.75
GW_SPECTRUM_RELATIVE_THEORY_UNCERTAINTY = 0.35
GW_SPECTRUM_PEAK_FREQUENCY_RELATIVE_UNCERTAINTY = 0.10
GW_SPECTRUM_ABSOLUTE_OMEGA_FLOOR = 1e-30
GW_SPECTRUM_ABSOLUTE_FREQUENCY_FLOOR_HZ = 1e-30

_SOUND_WAVE_PEAK_FREQUENCY_COEFFICIENT_HZ = 1.9e-5
_SOUND_WAVE_PEAK_AMPLITUDE_COEFFICIENT = 2.65e-6


@dataclass(frozen=True)
class GWSpectrumEvaluation:
    """Scalar spectrum result and the physical peak that generated it."""

    omega: float
    peak_omega: float
    peak_frequency_hz: float
    efficiency: float
    spectral_shape: float


def gw_spectrum_sample_inputs() -> dict[str, Quantity]:
    """Return a reproducible in-domain EWPT sample for conformance and demos."""

    return {
        "T_n": Quantity(value=100.0, units="GeV"),
        "alpha": Quantity(value=0.2, units="dimensionless"),
        "beta_over_H": Quantity(value=100.0, units="dimensionless"),
        "v_w": Quantity(value=0.7, units="dimensionless"),
        "frequency": Quantity(value=0.003, units="Hz"),
    }


def sound_wave_efficiency(alpha: float) -> float:
    """Return the non-runaway sound-wave efficiency fit for a positive alpha."""

    alpha = _positive_finite(alpha, "alpha")
    return alpha / (0.73 + 0.083 * sqrt(alpha) + alpha)


def sound_wave_peak_frequency_hz(
    *,
    temperature_gev: float,
    beta_over_h: float,
    wall_velocity: float,
    g_star: float = GW_SPECTRUM_STANDARD_MODEL_G_STAR,
) -> float:
    """Return the present-day sound-wave peak frequency in Hz."""

    temperature_gev = _positive_finite(temperature_gev, "T_n")
    beta_over_h = _positive_finite(beta_over_h, "beta_over_H")
    wall_velocity = _positive_finite(wall_velocity, "v_w")
    g_star = _positive_finite(g_star, "g_star")
    return (
        _SOUND_WAVE_PEAK_FREQUENCY_COEFFICIENT_HZ
        * beta_over_h
        * (temperature_gev / 100.0)
        * (g_star / 100.0) ** (1.0 / 6.0)
        / wall_velocity
    )


def sound_wave_peak_omega_h2(
    *,
    alpha: float,
    beta_over_h: float,
    wall_velocity: float,
    g_star: float = GW_SPECTRUM_STANDARD_MODEL_G_STAR,
) -> float:
    """Return the sound-wave peak Omega_GW h^2 from the same template."""

    alpha = _positive_finite(alpha, "alpha")
    beta_over_h = _positive_finite(beta_over_h, "beta_over_H")
    wall_velocity = _positive_finite(wall_velocity, "v_w")
    g_star = _positive_finite(g_star, "g_star")
    efficiency = sound_wave_efficiency(alpha)
    fluid_energy_fraction = efficiency * alpha / (1.0 + alpha)
    return (
        _SOUND_WAVE_PEAK_AMPLITUDE_COEFFICIENT
        * (1.0 / beta_over_h)
        * fluid_energy_fraction**2
        * (100.0 / g_star) ** (1.0 / 3.0)
        * wall_velocity
    )


def sound_wave_spectral_shape(*, frequency_hz: float, peak_frequency_hz: float) -> float:
    """Return the normalized positive sound-wave shape with unit value at peak."""

    frequency_hz = _positive_finite(frequency_hz, "frequency")
    peak_frequency_hz = _positive_finite(peak_frequency_hz, "peak_frequency")
    ratio = frequency_hz / peak_frequency_hz
    return ratio**3 * (7.0 / (4.0 + 3.0 * ratio**2)) ** 3.5


def evaluate_sound_wave_spectrum(
    *,
    temperature_gev: float,
    alpha: float,
    beta_over_h: float,
    wall_velocity: float,
    frequency_hz: float,
    g_star: float = GW_SPECTRUM_STANDARD_MODEL_G_STAR,
) -> GWSpectrumEvaluation:
    """Evaluate the reference spectrum at one frequency without broker concerns."""

    peak_frequency_hz = sound_wave_peak_frequency_hz(
        temperature_gev=temperature_gev,
        beta_over_h=beta_over_h,
        wall_velocity=wall_velocity,
        g_star=g_star,
    )
    peak_omega = sound_wave_peak_omega_h2(
        alpha=alpha,
        beta_over_h=beta_over_h,
        wall_velocity=wall_velocity,
        g_star=g_star,
    )
    spectral_shape = sound_wave_spectral_shape(
        frequency_hz=frequency_hz,
        peak_frequency_hz=peak_frequency_hz,
    )
    omega = peak_omega * spectral_shape
    _positive_finite(omega, "omega")
    return GWSpectrumEvaluation(
        omega=omega,
        peak_omega=peak_omega,
        peak_frequency_hz=peak_frequency_hz,
        efficiency=sound_wave_efficiency(alpha),
        spectral_shape=spectral_shape,
    )


@adapter_metadata(
    adapter_id=GW_SPECTRUM_ADAPTER_ID,
    version=GW_SPECTRUM_VERSION,
    determinism="deterministic",
    cost_class="standard",
    independence_tags=("gw-sound-wave-template-v1",),
)
@uncertainty(kind="interval", representation={"model": "sound-wave-template-systematic-v1"})
@validity_domain(
    declare_domain_box(
        {
            "T_n": (10.0, 1_000.0, "GeV"),
            "alpha": (0.01, 1.0, "dimensionless"),
            "beta_over_H": (10.0, 1_000.0, "dimensionless"),
            "v_w": (0.4, 0.95, "dimensionless"),
            "frequency": (1e-8, 1.0, "Hz"),
        }
    ),
    policy="flag",
)
@units_out({"omega": "dimensionless", "peak_omega": "dimensionless", "peak_frequency": "Hz"})
@units_in(
    {
        "T_n": "GeV",
        "alpha": "dimensionless",
        "beta_over_H": "dimensionless",
        "v_w": "dimensionless",
        "frequency": "Hz",
    }
)
class GWSpectrumAdapter(Adapter):
    """Deterministic, non-differentiable reference sound-wave spectrum adapter."""

    def evaluate(
        self,
        inputs: dict[str, NormalizedQuantity],
        _ctx: EvalContext,
    ) -> dict[str, Quantity]:
        evaluation = evaluate_sound_wave_spectrum(
            temperature_gev=inputs["T_n"].value,
            alpha=inputs["alpha"].value,
            beta_over_h=inputs["beta_over_H"].value,
            wall_velocity=inputs["v_w"].value,
            frequency_hz=inputs["frequency"].value,
        )
        return {
            "omega": Quantity(
                value=evaluation.omega,
                units="dimensionless",
                uncertainty=_omega_uncertainty(evaluation.omega),
            ),
            "peak_omega": Quantity(
                value=evaluation.peak_omega,
                units="dimensionless",
                uncertainty=_omega_uncertainty(evaluation.peak_omega),
            ),
            "peak_frequency": Quantity(
                value=evaluation.peak_frequency_hz,
                units="Hz",
                uncertainty={
                    "kind": "interval",
                    "radius": max(
                        GW_SPECTRUM_ABSOLUTE_FREQUENCY_FLOOR_HZ,
                        evaluation.peak_frequency_hz * GW_SPECTRUM_PEAK_FREQUENCY_RELATIVE_UNCERTAINTY,
                    ),
                    "confidence": 0.68,
                    "source": "sound-wave-template-peak-fit-v1",
                },
            ),
        }

    def as_simple_adapter(self, *, unit_registry: S7UnitRegistry | None = None) -> SimpleAdapter:
        del unit_registry
        return SimpleAdapter(
            self.describe(),
            backend=S7NativePythonBackend(
                evaluate=self.evaluate,
                underlying_code_version=GW_SPECTRUM_UNDERLYING_CODE_VERSION,
            ),
        )


def register_gw_spectrum_adapter(
    service: S7RegistrationService,
    *,
    subtopics: tuple[str, ...] = (GW_SPECTRUM_SUBTOPIC,),
    sample_inputs: Mapping[str, Quantity] | None = None,
    seed: int | None = 17,
) -> S7RegistrationResult:
    """Run conformance and publish the real GW reference adapter through C5."""

    return service.register(
        adapter=GWSpectrumAdapter(),
        subtopics=subtopics,
        sample_inputs=dict(sample_inputs or gw_spectrum_sample_inputs()),
        seed=seed,
    )


def _omega_uncertainty(omega: float) -> dict[str, float | str]:
    return {
        "kind": "interval",
        "radius": max(GW_SPECTRUM_ABSOLUTE_OMEGA_FLOOR, omega * GW_SPECTRUM_RELATIVE_THEORY_UNCERTAINTY),
        "confidence": 0.68,
        "source": "sound-wave-template-systematic-v1",
    }


def _positive_finite(value: float, field: str) -> float:
    numeric = float(value)
    if not isfinite(numeric) or numeric <= 0.0:
        raise AdapterConformanceError(f"{field} must be finite and strictly positive for the sound-wave template")
    return numeric
