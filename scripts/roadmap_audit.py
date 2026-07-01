#!/usr/bin/env python3
"""Audit roadmap task status against the authoritative backlog."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
BACKLOG = DOCS / "Backlog-and-Interfaces.md"
ROADMAP = DOCS / "Roadmap.md"
STATUS = DOCS / "RoadmapStatus.md"

VALID_TASK_STATES = {
    "not_started",
    "in_progress",
    "implemented",
    "unit_tested",
    "deployed",
    "e2e_passed",
    "complete",
    "blocked",
}
VALID_STAGE_STATES = {"not_started", "in_progress", "deployed", "e2e_passed", "complete", "blocked"}
COMPLETE_EVIDENCE_KEYS = ("acceptance", "impl", "unit", "local", "commit", "push")

TASK_ROW = re.compile(
    r"^\|\s*(S\d+-(?:T\d+[a-z]?|TPR\d+|TDB\d+))\s*"
    r"\|\s*([^|]+?)\s*"
    r"\|\s*(S|M|L|XL)\s*"
    r"\|\s*([^|]*?)\s*"
    r"\|\s*([^|]*?)\s*"
    r"\|\s*([^|]+?)\s*\|",
    re.M,
)


@dataclass(frozen=True)
class BacklogTask:
    task_id: str
    title: str
    estimate: str
    depends_on: str
    interfaces_touched: str
    acceptance_criteria: str

    @property
    def subsystem(self) -> str:
        return self.task_id.split("-", 1)[0]


@dataclass(frozen=True)
class TaskStatus:
    task_id: str
    stage: str
    status: str
    evidence: str


@dataclass(frozen=True)
class StageStatus:
    stage: str
    status: str
    deployment_evidence: str
    e2e_evidence: str


def parse_backlog(text: str) -> tuple[BacklogTask, ...]:
    tasks = tuple(
        BacklogTask(
            task_id=task_id,
            title=_clean_cell(title),
            estimate=estimate,
            depends_on=_clean_cell(depends_on),
            interfaces_touched=_clean_cell(interfaces_touched),
            acceptance_criteria=_clean_cell(acceptance),
        )
        for task_id, title, estimate, depends_on, interfaces_touched, acceptance in TASK_ROW.findall(text)
    )
    duplicate_ids = sorted(task_id for task_id, count in Counter(task.task_id for task in tasks).items() if count > 1)
    if duplicate_ids:
        raise ValueError(f"duplicate backlog task ids: {duplicate_ids}")
    return tasks


def parse_roadmap_stage_map(text: str) -> dict[str, str]:
    try:
        ledger = text.split("## 9. Coverage ledger (every subtask appears exactly once)", 1)[1]
        ledger = ledger.split("## 10. Milestone summary", 1)[0]
    except IndexError as exc:
        raise ValueError("could not locate roadmap coverage ledger") from exc

    stage_headers: list[str] = []
    task_to_stage: dict[str, str] = {}
    for line in ledger.splitlines():
        if line.startswith("| Subsystem "):
            cells = split_row(line)
            stage_headers = cells[2:]
            continue
        if not line.startswith("| **S"):
            continue
        cells = split_row(line)
        subsystem_match = re.search(r"\*\*(S\d+)\*\*", cells[0])
        if subsystem_match is None:
            raise ValueError(f"could not parse subsystem in coverage row: {line}")
        subsystem = subsystem_match.group(1)
        for stage, cell in zip(stage_headers, cells[2:]):
            stage_id = stage.strip()
            for task_id in expand_ledger_cell(subsystem, cell):
                if task_id in task_to_stage:
                    raise ValueError(f"task appears in multiple roadmap stages: {task_id}")
                task_to_stage[task_id] = stage_id
    return task_to_stage


def parse_status(text: str) -> tuple[dict[str, StageStatus], dict[str, TaskStatus]]:
    stages: dict[str, StageStatus] = {}
    tasks: dict[str, TaskStatus] = {}
    section = None
    for line in text.splitlines():
        if line == "## Stage Gates":
            section = "stages"
            continue
        if line == "## Task Ledger":
            section = "tasks"
            continue
        if not line.startswith("|") or line.startswith("|---") or line.startswith("| Stage ") or line.startswith("| Task ID "):
            continue
        cells = split_row(line)
        if section == "stages" and len(cells) >= 4:
            stages[cells[0]] = StageStatus(
                stage=cells[0],
                status=cells[1],
                deployment_evidence=cells[2],
                e2e_evidence=cells[3],
            )
        elif section == "tasks" and len(cells) >= 6:
            tasks[cells[0]] = TaskStatus(
                task_id=cells[0],
                stage=cells[1],
                status=cells[4],
                evidence=cells[5],
            )
    return stages, tasks


def render_status(tasks: tuple[BacklogTask, ...], stage_map: dict[str, str]) -> str:
    by_subsystem = Counter(task.subsystem for task in tasks)
    by_estimate = Counter(task.estimate for task in tasks)
    stages = tuple(f"M{index}" for index in range(7))
    lines = [
        "# Roadmap Status",
        "",
        "This file is the authoritative execution ledger for roadmap delivery status.",
        "It is generated by `python3 scripts/roadmap_audit.py --write` and audited by `make check`.",
        "",
        "## Summary",
        "",
        f"- Backlog subtasks: {len(tasks)}",
        "- Strictly complete subtasks: 0",
        "- Strictly complete stages: 0",
        "- Real deployment gates passed: 0",
        "- Real end-to-end gates passed: 0",
        f"- Subsystems: {_counter_text(by_subsystem)}",
        f"- Estimates: {_counter_text(by_estimate)}",
        "",
        "## Stage Gates",
        "",
        "| Stage | Status | Deployment Evidence | E2E Evidence |",
        "|---|---|---|---|",
    ]
    for stage in stages:
        lines.append(f"| {stage} | not_started | - | - |")
    lines.extend(
        [
            "",
            "## Task Ledger",
            "",
            "| Task ID | Stage | Title | Estimate | Status | Evidence |",
            "|---|---|---|---|---|---|",
        ]
    )
    for task in tasks:
        stage = stage_map.get(task.task_id, "UNMAPPED")
        lines.append(f"| {task.task_id} | {stage} | {_escape(task.title)} | {task.estimate} | not_started | - |")
    lines.append("")
    return "\n".join(lines)


def validate_status(
    *,
    tasks: tuple[BacklogTask, ...],
    stage_map: dict[str, str],
    stages: dict[str, StageStatus],
    statuses: dict[str, TaskStatus],
) -> list[str]:
    errors: list[str] = []
    task_ids = {task.task_id for task in tasks}
    status_ids = set(statuses)
    if task_ids != status_ids:
        errors.append(f"task status mismatch: missing={sorted(task_ids - status_ids)} extra={sorted(status_ids - task_ids)}")
    if set(stage_map) != task_ids:
        errors.append(f"roadmap stage map mismatch: missing={sorted(task_ids - set(stage_map))} extra={sorted(set(stage_map) - task_ids)}")

    for status in statuses.values():
        if status.status not in VALID_TASK_STATES:
            errors.append(f"{status.task_id} has invalid status {status.status!r}")
            continue
        expected_stage = stage_map.get(status.task_id)
        if expected_stage is not None and status.stage != expected_stage:
            errors.append(f"{status.task_id} stage mismatch: status={status.stage} roadmap={expected_stage}")
        if status.status == "complete":
            missing_keys = [key for key in COMPLETE_EVIDENCE_KEYS if f"{key}=" not in status.evidence]
            if missing_keys:
                errors.append(f"{status.task_id} complete without required evidence keys: {missing_keys}")

    for stage, status in stages.items():
        if status.status not in VALID_STAGE_STATES:
            errors.append(f"{stage} has invalid stage status {status.status!r}")
        if status.status == "complete":
            stage_tasks = [task_status for task_status in statuses.values() if task_status.stage == stage]
            incomplete = [task_status.task_id for task_status in stage_tasks if task_status.status != "complete"]
            if incomplete:
                errors.append(f"{stage} complete with incomplete tasks: {incomplete}")
            if status.deployment_evidence == "-" or status.e2e_evidence == "-":
                errors.append(f"{stage} complete without deployment and e2e evidence")
    return errors


def split_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def expand_ledger_cell(prefix: str, cell: str) -> list[str]:
    if "—" in cell or not cell.strip():
        return []
    text = re.sub(r"\([^)]*\)", "", cell)
    text = text.replace("`", "").replace("**", "").replace("+", ",")
    ids: list[str] = []
    for raw_part in text.split(","):
        part = raw_part.strip()
        if not part:
            continue
        range_match = re.fullmatch(
            r"(T|TPR|TDB)(\d+)([a-z]?)\s*[–-]\s*(?:T|TPR|TDB)(\d+)([a-z]?)",
            part,
        )
        if range_match:
            kind, start, start_suffix, end, end_suffix = range_match.groups()
            if start_suffix or end_suffix:
                raise ValueError(f"unsupported suffixed range in coverage ledger: {prefix} {part}")
            width = len(start)
            ids.extend(f"{prefix}-{kind}{number:0{width}d}" for number in range(int(start), int(end) + 1))
            continue
        single_match = re.fullmatch(r"(T|TPR|TDB)(\d+)([a-z]?)", part)
        if single_match:
            kind, number, suffix = single_match.groups()
            ids.append(f"{prefix}-{kind}{int(number):0{len(number)}d}{suffix}")
            continue
        raise ValueError(f"could not parse coverage ledger token: {prefix} {part!r}")
    return ids


def load_inputs() -> tuple[tuple[BacklogTask, ...], dict[str, str]]:
    tasks = parse_backlog(BACKLOG.read_text(encoding="utf-8"))
    stage_map = parse_roadmap_stage_map(ROADMAP.read_text(encoding="utf-8"))
    return tasks, stage_map


def _clean_cell(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("`", "").replace("**", "")).strip()


def _counter_text(counter: Counter[str]) -> str:
    return ", ".join(f"{key}={counter[key]}" for key in sorted(counter))


def _escape(value: str) -> str:
    return value.replace("|", "\\|")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write docs/RoadmapStatus.md from current roadmap")
    parser.add_argument("--summary", action="store_true", help="print status summary")
    args = parser.parse_args()

    tasks, stage_map = load_inputs()
    if args.write:
        STATUS.write_text(render_status(tasks, stage_map), encoding="utf-8")

    if not STATUS.exists():
        print("ERROR: docs/RoadmapStatus.md is missing; run scripts/roadmap_audit.py --write", file=sys.stderr)
        return 1
    stages, statuses = parse_status(STATUS.read_text(encoding="utf-8"))
    errors = validate_status(tasks=tasks, stage_map=stage_map, stages=stages, statuses=statuses)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    complete_tasks = sum(1 for status in statuses.values() if status.status == "complete")
    complete_stages = sum(1 for status in stages.values() if status.status == "complete")
    if args.summary:
        print(f"roadmap tasks: {len(tasks)}")
        print(f"complete tasks: {complete_tasks}")
        print(f"complete stages: {complete_stages}")
    else:
        print(f"roadmap audit passed: {len(tasks)} tasks, {complete_tasks} complete, {complete_stages} stages complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
