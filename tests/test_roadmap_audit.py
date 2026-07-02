from __future__ import annotations

import unittest

from scripts.roadmap_audit import (
    BacklogTask,
    StageStatus,
    TaskStatus,
    expand_ledger_cell,
    parse_backlog,
    parse_roadmap_stage_map,
    parse_summary_counts,
    render_status,
    stage_evidence_anchor_error,
    validate_status,
)


class RoadmapAuditTests(unittest.TestCase):
    def test_parse_backlog_extracts_authoritative_task_rows(self) -> None:
        text = (
            "| id | title | est | depends_on | interfaces_touched | acceptance_criteria |\n"
            "|----|-------|-----|------------|--------------------|---------------------|\n"
            "| S1-T01 | Author canonical C1 JSON Schema | M | C1 | C1 | schema validates |\n"
            "| S4-TDB1 | Debate-round orchestrator | L | C3 | C3,C4 | verdict emitted |\n"
        )

        tasks = parse_backlog(text)

        self.assertEqual([task.task_id for task in tasks], ["S1-T01", "S4-TDB1"])
        self.assertEqual(tasks[0].subsystem, "S1")
        self.assertEqual(tasks[1].estimate, "L")

    def test_expand_ledger_cell_handles_ranges_and_single_tokens(self) -> None:
        ids = expand_ledger_cell("S1", "T01,T03,T25,T30")
        ranged = expand_ledger_cell("S2", "T04–T06")

        self.assertEqual(ids, ["S1-T01", "S1-T03", "S1-T25", "S1-T30"])
        self.assertEqual(ranged, ["S2-T04", "S2-T05", "S2-T06"])

    def test_parse_roadmap_stage_map_extracts_coverage_table(self) -> None:
        text = """
## 9. Coverage ledger (every subtask appears exactly once)
| Subsystem | Total | M0 | M1 |
|---|---|---|---|
| **S1** | 2 | T01 | T02 |
## 10. Milestone summary
"""

        stage_map = parse_roadmap_stage_map(text)

        self.assertEqual(stage_map, {"S1-T01": "M0", "S1-T02": "M1"})

    def test_complete_task_requires_all_evidence_keys(self) -> None:
        tasks = (
            BacklogTask(
                task_id="S1-T01",
                title="Author canonical C1 JSON Schema",
                estimate="M",
                depends_on="C1",
                interfaces_touched="C1",
                acceptance_criteria="schema validates",
            ),
        )
        statuses = {
            "S1-T01": TaskStatus(task_id="S1-T01", stage="M0", status="complete", evidence="impl=schema")
        }

        errors = validate_status(
            tasks=tasks,
            stage_map={"S1-T01": "M0"},
            stages={"M0": StageStatus("M0", "not_started", "-", "-")},
            statuses=statuses,
        )

        self.assertTrue(errors)
        self.assertIn("acceptance", errors[0])
        self.assertIn("push", errors[0])

    def test_complete_task_requires_verifiable_evidence_anchor(self) -> None:
        tasks = (
            BacklogTask(
                task_id="S1-T01",
                title="Author canonical C1 JSON Schema",
                estimate="M",
                depends_on="C1",
                interfaces_touched="C1",
                acceptance_criteria="schema validates",
            ),
        )
        stages = {"M0": StageStatus("M0", "not_started", "-", "-")}
        stage_map = {"S1-T01": "M0"}
        evidence_prefix = "acceptance=x; impl=x; unit=x; local=x; commit=x; push=x"

        local_path_errors = validate_status(
            tasks=tasks,
            stage_map=stage_map,
            stages=stages,
            statuses={
                "S1-T01": TaskStatus(
                    task_id="S1-T01",
                    stage="M0",
                    status="complete",
                    evidence=f"{evidence_prefix}; ci=GitHub Actions CI run 28605979333; local=/tmp/evidence.json",
                )
            },
        )
        no_anchor_errors = validate_status(
            tasks=tasks,
            stage_map=stage_map,
            stages=stages,
            statuses={
                "S1-T01": TaskStatus(
                    task_id="S1-T01",
                    stage="M0",
                    status="complete",
                    evidence=evidence_prefix,
                )
            },
        )
        ci_anchor_errors = validate_status(
            tasks=tasks,
            stage_map=stage_map,
            stages=stages,
            statuses={
                "S1-T01": TaskStatus(
                    task_id="S1-T01",
                    stage="M0",
                    status="complete",
                    evidence=f"{evidence_prefix}; ci=GitHub Actions CI run 28605979333",
                )
            },
        )
        repo_anchor_errors = validate_status(
            tasks=tasks,
            stage_map=stage_map,
            stages=stages,
            statuses={
                "S1-T01": TaskStatus(
                    task_id="S1-T01",
                    stage="M0",
                    status="complete",
                    evidence=f"{evidence_prefix}; ci=docs/RoadmapStatus.md",
                )
            },
        )

        self.assertTrue(any("local-only path" in error for error in local_path_errors))
        self.assertTrue(any("lacks a verifiable" in error for error in no_anchor_errors))
        self.assertFalse(ci_anchor_errors)
        self.assertFalse(repo_anchor_errors)

    def test_deployed_and_e2e_task_states_require_verifiable_evidence_anchor(self) -> None:
        tasks = (
            BacklogTask(
                task_id="S1-T01",
                title="Author canonical C1 JSON Schema",
                estimate="M",
                depends_on="C1",
                interfaces_touched="C1",
                acceptance_criteria="schema validates",
            ),
        )
        stages = {"M0": StageStatus("M0", "not_started", "-", "-")}
        stage_map = {"S1-T01": "M0"}

        e2e_local_path_errors = validate_status(
            tasks=tasks,
            stage_map=stage_map,
            stages=stages,
            statuses={
                "S1-T01": TaskStatus(
                    task_id="S1-T01",
                    stage="M0",
                    status="e2e_passed",
                    evidence="acceptance_partial=x; local=/tmp/evidence.json",
                )
            },
        )
        deployed_no_anchor_errors = validate_status(
            tasks=tasks,
            stage_map=stage_map,
            stages=stages,
            statuses={
                "S1-T01": TaskStatus(
                    task_id="S1-T01",
                    stage="M0",
                    status="deployed",
                    evidence="acceptance_partial=x; local=compose passed",
                )
            },
        )
        e2e_ci_anchor_errors = validate_status(
            tasks=tasks,
            stage_map=stage_map,
            stages=stages,
            statuses={
                "S1-T01": TaskStatus(
                    task_id="S1-T01",
                    stage="M0",
                    status="e2e_passed",
                    evidence="acceptance_partial=x; ci=GitHub Actions CI run 28613222944",
                )
            },
        )
        deployed_repo_anchor_errors = validate_status(
            tasks=tasks,
            stage_map=stage_map,
            stages=stages,
            statuses={
                "S1-T01": TaskStatus(
                    task_id="S1-T01",
                    stage="M0",
                    status="deployed",
                    evidence="acceptance_partial=x; ci=docs/RoadmapStatus.md",
                )
            },
        )

        self.assertTrue(any("e2e_passed evidence uses local-only path" in error for error in e2e_local_path_errors))
        self.assertTrue(any("deployed evidence lacks a verifiable" in error for error in deployed_no_anchor_errors))
        self.assertFalse(e2e_ci_anchor_errors)
        self.assertFalse(deployed_repo_anchor_errors)

    def test_complete_stage_requires_all_stage_tasks_and_real_gates(self) -> None:
        tasks = (
            BacklogTask("S1-T01", "Author canonical C1 JSON Schema", "M", "C1", "C1", "schema validates"),
            BacklogTask("S1-T02", "Binding codegen", "M", "S1-T01", "C1", "bindings compile"),
        )
        statuses = {
            "S1-T01": TaskStatus(
                task_id="S1-T01",
                stage="M0",
                status="complete",
                evidence="acceptance=x; impl=x; unit=x; local=x; commit=x; push=x",
            ),
            "S1-T02": TaskStatus(task_id="S1-T02", stage="M0", status="unit_tested", evidence="unit=x"),
        }

        errors = validate_status(
            tasks=tasks,
            stage_map={"S1-T01": "M0", "S1-T02": "M0"},
            stages={"M0": StageStatus("M0", "complete", "-", "-")},
            statuses=statuses,
        )

        self.assertTrue(any("incomplete tasks" in error for error in errors))
        self.assertTrue(any("deployment and e2e evidence" in error for error in errors))

    def test_non_complete_stage_gate_states_require_matching_real_evidence(self) -> None:
        tasks = (
            BacklogTask("S1-T01", "Author canonical C1 JSON Schema", "M", "C1", "C1", "schema validates"),
        )
        statuses = {
            "S1-T01": TaskStatus(
                task_id="S1-T01",
                stage="M0",
                status="complete",
                evidence="acceptance=x; impl=x; unit=x; local=x; commit=x; push=x",
            ),
        }

        deployed_errors = validate_status(
            tasks=tasks,
            stage_map={"S1-T01": "M0"},
            stages={"M0": StageStatus("M0", "deployed", "-", "-")},
            statuses=statuses,
        )
        e2e_errors = validate_status(
            tasks=tasks,
            stage_map={"S1-T01": "M0"},
            stages={"M0": StageStatus("M0", "e2e_passed", "compose stack", "-")},
            statuses=statuses,
        )

        self.assertTrue(any("without deployment evidence" in error for error in deployed_errors))
        self.assertTrue(any("without e2e evidence" in error for error in e2e_errors))

    def test_stage_gate_evidence_requires_verifiable_anchor(self) -> None:
        self.assertIsNone(stage_evidence_anchor_error("passed on GitHub Actions CI run 28605979333 artifact m0-spine-evidence"))
        self.assertIsNone(stage_evidence_anchor_error("evidence file docs/RoadmapStatus.md records the gate"))
        self.assertIn(
            "local-only path",
            stage_evidence_anchor_error(
                "local evidence /tmp/argus-m0-stage-gate.json commit 5ce93f4e1429a0de5924bcb5a551390ef42c928a"
            )
            or "",
        )
        self.assertIn("lacks a verifiable", stage_evidence_anchor_error("compose stack passed on my machine") or "")

    def test_validate_status_derives_gate_counts_from_stage_table(self) -> None:
        tasks = (
            BacklogTask("S1-T01", "Author canonical C1 JSON Schema", "M", "C1", "C1", "schema validates"),
        )
        statuses = {
            "S1-T01": TaskStatus(
                task_id="S1-T01",
                stage="M0",
                status="complete",
                evidence="acceptance=x; impl=x; unit=x; local=x; commit=x; push=x",
            ),
        }

        errors = validate_status(
            tasks=tasks,
            stage_map={"S1-T01": "M0"},
            stages={
                "M0": StageStatus(
                    "M0",
                    "e2e_passed",
                    "GitHub Actions CI run 28605979333 deployment artifact m0-spine-evidence",
                    "GitHub Actions CI run 28605979333 E2E artifact m0-spine-evidence",
                )
            },
            statuses=statuses,
            summary_counts={
                "Real deployment slice gates passed": 999,
                "Real end-to-end slice gates passed": 1,
            },
        )

        self.assertTrue(any("Real deployment slice gates passed" in error for error in errors))

    def test_parse_summary_counts_reads_gate_headlines(self) -> None:
        counts = parse_summary_counts(
            """
- Real deployment slice gates passed: 1
- Real end-to-end slice gates passed: 2
"""
        )

        self.assertEqual(counts["Real deployment slice gates passed"], 1)
        self.assertEqual(counts["Real end-to-end slice gates passed"], 2)

    def test_render_status_defaults_every_task_to_not_started(self) -> None:
        tasks = (
            BacklogTask("S1-T01", "Author canonical C1 JSON Schema", "M", "C1", "C1", "schema validates"),
        )

        rendered = render_status(tasks, {"S1-T01": "M0"})

        self.assertIn("- Backlog subtasks: 1", rendered)
        self.assertIn("| M0 | not_started | - | - |", rendered)
        self.assertIn("| S1-T01 | M0 | Author canonical C1 JSON Schema | M | not_started | - |", rendered)


if __name__ == "__main__":
    unittest.main()
