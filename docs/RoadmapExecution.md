# Roadmap Execution Discipline

This document defines the execution rules for Project Argus roadmap delivery.
It is intentionally stricter than the current prototype codebase.

## Current Baseline

The repository currently contains an in-memory core semantics slice for the
Argus subsystems and local unit tests. That work is useful foundation code, but
it does not complete the roadmap subtasks.

Strict roadmap completion count at this baseline:

- Completed roadmap subtasks: 0
- Completed roadmap stages: 0
- Real deployed stage gates: 0
- Real end-to-end stage validations: 0

## Completion States

Each backlog subtask has exactly one execution state:

- `not_started`: no implementation accepted for the subtask.
- `in_progress`: implementation work has started, but completion evidence is
  missing.
- `implemented`: code or documentation exists, but verification is incomplete.
- `unit_tested`: comprehensive unit tests pass for the subtask.
- `deployed`: the containing stage has been deployed to a real target.
- `e2e_passed`: real end-to-end validation passed against the deployed target.
- `complete`: all required evidence is present and reviewed.
- `blocked`: work cannot continue without an explicit external decision or
  resource.

## Subtask Completion Rule

A roadmap subtask may be marked `complete` only when all of these are true:

1. The subtask has a concrete acceptance note mapped to the backlog row.
2. The implementation is present in the repository.
3. Comprehensive unit tests cover the subtask's success, failure, and policy
   boundary paths.
4. The relevant local checks pass.
5. The work is committed as a focused commit that does not mix unrelated tasks.
6. The commit is pushed to the active branch.
7. Any required integration contract evidence is linked in the roadmap status
   file.

## Declared Deployment Targets (Rev B, 2026-07-01)

The "declared real target environment" referenced by the stage rules below is:

- **M0–M2:** a Linux host (Ubuntu 24.04 LTS VM or GitHub Actions `ubuntu-latest`)
  running the `argus-m0` docker-compose stack (Postgres 16 + MinIO + S8 writer +
  S10 supervisor). macOS development machines never satisfy a stage gate.
- **M3+:** to be declared before M3 starts, as part of the M1.5/M2 review.

## Stage E2E Binding (Rev B)

A stage's "real end-to-end test" is not self-selected: it MUST be the
demo/acceptance battery defined for that milestone in `docs/Roadmap.md`
(e.g. the M0 Spine Integration Slice battery items (a)–(g)), executed against
the declared target above, with the battery item IDs recorded in the evidence.

## M1.5 Demand-Validation Gate (Rev B)

M2 work may not start until the M1.5 gate defined in `docs/Roadmap.md` §0a.4 is
recorded in this repository: pilot-physicist demo evidence, net-time accounting,
and the measured build:verify cost ratio. A negative pilot signal triggers a
direction re-review before further infrastructure investment.

## Stage Completion Rule

A roadmap stage may be marked `complete` only when all of these are true:

1. Every included subtask is `complete`.
2. The stage is deployed to the declared real target environment.
3. A real end-to-end test runs against the deployed target.
4. Deployment evidence is recorded, including target, version, commit, command,
   and result.
5. E2E evidence is recorded, including command, scenario, target URL or service
   endpoint, and pass/fail result.
6. The stage evidence is committed and pushed.

## Non-Completion Rules

The following never count as roadmap completion by themselves:

- In-memory prototypes.
- Unit tests without deployment evidence for a stage gate.
- Mock-only integration tests for a deployed-stage claim.
- Documentation assertions without executable validation.
- Passing `make check` alone.
- A commit whose title uses a milestone name but does not satisfy the subtask
  evidence rule.

## Required Command Discipline

For each completed subtask:

1. Run the focused test file or suite.
2. Run the full local check suite.
3. Commit one focused change.
4. Push the commit.
5. Update the roadmap status file with exact evidence.

For each completed stage:

1. Deploy the stage to the declared target.
2. Run real end-to-end validation against the deployed target.
3. Record deployment and E2E evidence.
4. Run the full local check suite.
5. Commit and push the evidence update.

## Commons Coordination

Commons scope is currently unresolved for this workspace. Until it is enrolled
as `remote`, `local`, or `disabled`, no deployment, shared runtime mutation, or
lease-required shared-resource operation should be treated as coordinated.
