# M1.5 Pilot Console

## Purpose

The Pilot Console is the browser-facing onboarding and review surface for the
bounded M1 reference slice. It is served by `s1-reference-demo` at `/` and
uses that service's deployed `M1ReferenceLifecycleRunner`; it does not use a
mock runner or a separate demo artifact.

The console is a supporting artifact for the M1.5 demand-validation gate. It
does not by itself record a human pilot, close M1.5, or authorize M2 work.

## Supported Study Boundary

Only the following reference profile can start a pilot run:

- Scope: `ewpt_gw_spectrum_reference`
- Subject: EWPT sound-wave gravitational-wave spectrum
- Adapter: `gw_spectrum`
- Runtime inputs: the fixed M1 reference input set displayed in the console

The research question and established result entered by the pilot are study
context, not executable physics input. The API rejects every other reference
scope before it starts a runtime operation. The console must never be presented
as an arbitrary-topic or uploaded-data interface.

## Operator Setup

The deployed service requires `ARGUS_S1_REFERENCE_DEMO_PILOT_ACCESS_TOKEN`.
Configure one unique short-lived value for the one-at-a-time pilot session and
deliver it through an approved channel; rotate it before the next invitation.
The `argus-m0` Compose target exposes the service only on the host loopback
interface by default; use an approved authenticated tunnel or reverse proxy
before inviting an external pilot.

Start the declared target with the normal M0 Compose environment, then open:

```text
http://127.0.0.1:${ARGUS_M0_S1_DEMO_PORT}
```

The access code is sent only in the browser's same-origin Authorization header
for protected run and artifact endpoints. It is retained in browser session
storage and is not embedded in the rendered page or exported evidence.

## Pilot Flow

1. The pilot opens the console and unlocks the browser session with the
   invitation access code.
2. They enter an in-scope research question, the established result they want
   to recapitulate, and a status-quo time estimate.
3. They acknowledge the fixed reference scope. They may choose whether the
   study context is shared with the run operator for the in-memory session.
4. They start the verified run and observe actual runtime events for identity,
   verifier profile, controlled dataset, C1 acceptance/plan/build/report, S3
   blind verification, and S11 Observatory rendering.
5. They inspect the embedded signed Observatory report and use **Re-verify
   artifact** to re-read the persisted C3 report and C4 lineage. The action
   independently checks report signature, report/result equality, and the
   Observatory verification gate.
6. They record a positive, neutral, or negative signal with notes and export
   the browser-local pilot session record.

The browser export contains the study note, baseline estimate, observed run
duration, artifact references, fresh verification result, and pilot feedback.
It is not automatically committed to the repository. A real pilot's consent
and the operator's evidence review are required before recording M1.5 demand
validation evidence.

## Technical Acceptance Battery

Run the deployed end-to-end battery against an isolated Compose target:

```bash
python3 scripts/run_m1_pilot_console_battery.py \
  --evidence-file /tmp/m1-pilot-console-evidence.json
```

The battery verifies all of the following against real Postgres, MinIO, S10,
S1, S2, S3, S7, and S11 services:

- the root route serves the browser UI with same-origin content security policy;
- pilot operations require the invitation access code;
- an unsupported profile fails closed;
- an authenticated in-scope intake launches the deployed M1 lifecycle;
- the returned timeline includes actual lifecycle boundaries;
- S11 returns a VERIFIED Observatory artifact;
- a fresh C3/C4 re-verification succeeds;
- an unshared study context is not returned by the service.

GitHub Actions uploads this battery as `m1-pilot-console-evidence` for each
push to the tracked branches.

## Roadmap Boundary

This console is intentionally narrower than M2 `S11-T37`:

- It observes exactly one fixed M1 reference profile and one active run.
- It has no general intake queue, no multi-job control plane, no platform-wide
  semantic event stream, and no arbitrary adapter selection.
- It does not change the M1.5 gate: a real pilot physicist, a real in-scope
  subtopic, net-time accounting, measured cost evidence, and an honest review
  of the pilot signal remain required.
