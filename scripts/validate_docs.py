#!/usr/bin/env python3
"""Validate consistency across the Project Argus design documents."""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

EXPECTED_CONTRACT_CONSUMERS = {
    "C1": {"S2", "S3", "S4", "S5", "S11", "S12"},
    "C2": {"S1", "S2", "S3", "S4", "S7", "S9", "S10", "S11", "S12"},
    "C3": {"S1", "S2", "S4", "S5", "S7", "S8", "S9", "S11", "S12"},
    "C4": {"S1", "S2", "S3", "S4", "S5", "S6", "S7", "S9", "S10", "S11", "S12"},
    "C5": {"S1", "S2", "S3", "S4", "S5", "S7", "S9", "S10", "S11"},
    "C6": {"S1", "S2", "S3", "S5", "S6", "S10", "S11", "S12"},
}


TASK_ROW = re.compile(r"^\|\s*(S\d+-(?:T\d+[a-z]?|TPR\d+|TDB\d+))\s*\|.*?\|\s*(S|M|L|XL)\s*\|", re.M)


def read_doc(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


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
                fail(f"Unsupported suffixed range in coverage ledger: {prefix} {part}")
            width = len(start)
            ids.extend(f"{prefix}-{kind}{number:0{width}d}" for number in range(int(start), int(end) + 1))
            continue

        single_match = re.fullmatch(r"(T|TPR|TDB)(\d+)([a-z]?)", part)
        if single_match:
            kind, number, suffix = single_match.groups()
            ids.append(f"{prefix}-{kind}{int(number):0{len(number)}d}{suffix}")
            continue

        fail(f"Could not parse coverage ledger token: {prefix} {part!r}")

    return ids


def validate_backlog_and_roadmap() -> None:
    backlog = read_doc("Backlog-and-Interfaces.md")
    roadmap = read_doc("Roadmap.md")

    backlog_rows = TASK_ROW.findall(backlog)
    backlog_ids = [task_id for task_id, _estimate in backlog_rows]
    if len(backlog_ids) != len(set(backlog_ids)):
        duplicates = sorted(task_id for task_id, count in Counter(backlog_ids).items() if count > 1)
        fail(f"Duplicate backlog task ids: {duplicates}")

    declared_distribution = re.search(
        r"Estimate distribution across the \d+ subtasks:\*\*\s*S=(\d+), M=(\d+), L=(\d+), XL=(\d+)",
        backlog,
    )
    if not declared_distribution:
        fail("Could not find declared estimate distribution in Backlog-and-Interfaces.md")

    actual_distribution = Counter(estimate for _task_id, estimate in backlog_rows)
    expected_distribution = {
        "S": int(declared_distribution.group(1)),
        "M": int(declared_distribution.group(2)),
        "L": int(declared_distribution.group(3)),
        "XL": int(declared_distribution.group(4)),
    }
    if dict(actual_distribution) != expected_distribution:
        fail(f"Estimate distribution mismatch: actual={dict(actual_distribution)} expected={expected_distribution}")

    try:
        ledger = roadmap.split("## 9. Coverage ledger (every subtask appears exactly once)", 1)[1]
        ledger = ledger.split("## 10. Milestone summary", 1)[0]
    except IndexError as exc:
        raise SystemExit("ERROR: Could not locate roadmap coverage ledger") from exc

    ledger_ids: list[str] = []
    for line in ledger.splitlines():
        if not line.startswith("| **S"):
            continue
        cells = split_row(line)
        subsystem_match = re.search(r"\*\*(S\d+)\*\*", cells[0])
        if not subsystem_match:
            fail(f"Could not parse subsystem in coverage ledger row: {line}")
        subsystem = subsystem_match.group(1)
        for cell in cells[2:]:
            ledger_ids.extend(expand_ledger_cell(subsystem, cell))

    missing = sorted(set(backlog_ids) - set(ledger_ids))
    extra = sorted(set(ledger_ids) - set(backlog_ids))
    duplicates = sorted(task_id for task_id, count in Counter(ledger_ids).items() if count > 1)
    if missing or extra or duplicates:
        fail(f"Roadmap coverage mismatch: missing={missing} extra={extra} duplicates={duplicates}")


def extract_contract_maps(path: Path) -> dict[str, set[str]]:
    maps: dict[str, set[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = split_row(line)
        if len(cells) < 3:
            continue
        contract_match = re.search(r"\b(C[1-6])\b", cells[0])
        if not contract_match:
            continue
        contract = contract_match.group(1)
        consumer_cell = re.sub(r"\([^)]*\)", "", cells[-1])
        consumers = set(re.findall(r"\bS\d+\b", consumer_cell))
        if consumers:
            maps[contract] = consumers
    return maps


def validate_contract_maps() -> None:
    for doc_name in ("README.md", "Architecture.md", "TechDesign.md"):
        maps = extract_contract_maps(DOCS / doc_name)
        for contract, expected in EXPECTED_CONTRACT_CONSUMERS.items():
            actual = maps.get(contract)
            if actual != expected:
                fail(f"{doc_name} {contract} consumers mismatch: actual={sorted(actual or [])} expected={sorted(expected)}")


def validate_test_ids() -> None:
    text = read_doc("TestPlan.md")

    bare_defs = re.findall(r"^\|\s*(TC-\d+[a-z]?(?:-[A-Z]+)?)\s*\|", text, re.M)
    if bare_defs:
        fail(f"TestPlan has bare test case ids without subsystem prefixes: {bare_defs}")

    bare_debate_refs = sorted(set(re.findall(r"(?<!S4-)TC-\d{2}-DB\b", text)))
    if bare_debate_refs:
        fail(f"TestPlan has bare debate case references: {bare_debate_refs}")

    for section, prefix in (("## 5. S4", "S4"), ("## 7. S6", "S6")):
        try:
            section_text = text.split(section, 1)[1].split("\n---", 1)[0]
        except IndexError as exc:
            raise SystemExit(f"ERROR: Could not locate {section} section") from exc
        malformed = re.findall(r"^\|\s*((?!%s-TC)[^|\s]+)\s*\|" % prefix, section_text, re.M)
        malformed = [value for value in malformed if value not in {"ID", "----"}]
        if malformed:
            fail(f"{section} contains malformed test ids: {malformed}")


def main() -> None:
    validate_backlog_and_roadmap()
    validate_contract_maps()
    validate_test_ids()
    print("docs validation passed")


if __name__ == "__main__":
    main()
