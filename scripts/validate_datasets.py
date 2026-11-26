#!/usr/bin/env python3
"""Validate the selected LogHub-2k files without displaying log contents."""

from __future__ import annotations

import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DATASETS = ("OpenSSH", "Linux", "Apache")
EXPECTED_LOG_LINES = 2_000
REQUIRED_STRUCTURED_COLUMNS = {"EventId", "EventTemplate"}
REQUIRED_TEMPLATE_COLUMNS = {"EventId", "EventTemplate"}


def is_html(path: Path) -> bool:
    with path.open("rb") as stream:
        prefix = stream.read(512).lstrip().lower()
    return prefix.startswith((b"<!doctype html", b"<html", b"<head"))


def check_file(path: Path, errors: list[str]) -> int | None:
    if not path.is_file():
        errors.append(f"Missing: {path.relative_to(ROOT)}")
        return None
    size = path.stat().st_size
    if size == 0:
        errors.append(f"Empty: {path.relative_to(ROOT)}")
        return None
    if is_html(path):
        errors.append(f"Invalid HTML response: {path.relative_to(ROOT)}")
        return None
    return size


def read_csv(
    path: Path,
    required_columns: set[str],
    errors: list[str],
) -> tuple[list[dict[str, str]], set[str]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            headers = reader.fieldnames or []
            if len(headers) != len(set(headers)):
                errors.append(f"Duplicate CSV headers: {path.relative_to(ROOT)}")
            missing = required_columns.difference(headers)
            if missing:
                errors.append(
                    f"Missing CSV columns in {path.relative_to(ROOT)}: "
                    f"{', '.join(sorted(missing))}"
                )
                return [], set()

            rows: list[dict[str, str]] = []
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    errors.append(
                        f"Extra CSV fields at row {row_number}: {path.relative_to(ROOT)}"
                    )
                rows.append(row)
            event_ids = {row["EventId"].strip() for row in rows if row.get("EventId")}
            if any(not row.get("EventId", "").strip() for row in rows):
                errors.append(f"Blank EventId found: {path.relative_to(ROOT)}")
            return rows, event_ids
    except (OSError, UnicodeError, csv.Error) as error:
        errors.append(f"Could not parse {path.relative_to(ROOT)}: {error}")
        return [], set()


def main() -> int:
    errors: list[str] = []
    sizes: dict[str, int] = {}
    summary: dict[str, dict[str, int]] = {}
    required_paths = [ROOT / "data" / "LICENSE"]

    for dataset in DATASETS:
        raw_path = ROOT / "data" / "raw" / dataset / f"{dataset}_2k.log"
        structured_path = (
            ROOT / "data" / "reference" / dataset / f"{dataset}_2k.log_structured.csv"
        )
        templates_path = (
            ROOT / "data" / "reference" / dataset / f"{dataset}_2k.log_templates.csv"
        )
        required_paths.extend((raw_path, structured_path, templates_path))
        sizes_for_dataset: dict[str, int] = {}
        for path in (raw_path, structured_path, templates_path):
            size = check_file(path, errors)
            if size is not None:
                sizes[path.relative_to(ROOT).as_posix()] = size
                sizes_for_dataset[path.name] = size

        log_lines = 0
        if raw_path.is_file() and raw_path.stat().st_size > 0 and not is_html(raw_path):
            try:
                with raw_path.open("r", encoding="utf-8", errors="strict") as stream:
                    log_lines = sum(1 for _ in stream)
                if log_lines != EXPECTED_LOG_LINES:
                    errors.append(
                        f"{dataset} raw log has {log_lines:,} lines; "
                        f"expected {EXPECTED_LOG_LINES:,}"
                    )
            except (OSError, UnicodeError) as error:
                errors.append(f"Could not read {raw_path.relative_to(ROOT)}: {error}")

        structured_rows: list[dict[str, str]] = []
        template_ids: set[str] = set()
        template_rows: list[dict[str, str]] = []
        if structured_path.is_file() and structured_path.stat().st_size > 0:
            structured_rows, _ = read_csv(
                structured_path, REQUIRED_STRUCTURED_COLUMNS, errors
            )
        if templates_path.is_file() and templates_path.stat().st_size > 0:
            template_rows, template_ids = read_csv(
                templates_path, REQUIRED_TEMPLATE_COLUMNS, errors
            )
            if len(template_ids) != len(template_rows):
                errors.append(f"Duplicate or blank template EventId: {dataset}")

        referenced_ids = {
            row["EventId"].strip()
            for row in structured_rows
            if row.get("EventId") and row["EventId"].strip()
        }
        unresolved = referenced_ids.difference(template_ids)
        if unresolved:
            errors.append(
                f"{dataset} structured data references {len(unresolved)} "
                "EventId value(s) without a template"
            )

        summary[dataset] = {
            "raw_lines": log_lines,
            "structured_records": len(structured_rows),
            "templates": len(template_rows),
        }

    license_path = ROOT / "data" / "LICENSE"
    license_size = check_file(license_path, errors)
    if license_size is not None:
        sizes[license_path.relative_to(ROOT).as_posix()] = license_size

    print("LogGuard AI dataset validation")
    print("=" * 34)
    for dataset, counts in summary.items():
        print(
            f"{dataset}: raw lines={counts['raw_lines']:,}, "
            f"structured records={counts['structured_records']:,}, "
            f"templates={counts['templates']:,}"
        )
    print(f"Files verified: {len(sizes)}/{len(required_paths)}")
    print(f"Total size: {sum(sizes.values()):,} bytes")

    if errors:
        print(f"\nFAILED: {len(errors)} issue(s)")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("\nPASSED: all files exist, are non-empty, and passed structural checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
