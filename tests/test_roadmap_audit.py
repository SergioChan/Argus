from __future__ import annotations

import unittest

from scripts.roadmap_audit import (
    BacklogTask,
    StageStatus,
    TaskStatus,
    expand_ledger_cell,
    parse_backlog,
    parse_roadmap_stage_map,
    render_status,
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
