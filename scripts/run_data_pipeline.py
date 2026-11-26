#!/usr/bin/env python3
"""Parse selected LogHub-2k logs, compare references, and write an EDA report."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data_engineering.apache_parser import parse_line as parse_apache  # noqa: E402
from data_engineering.common import (  # noqa: E402
    calculate_relative_times,
    clean_message,
    validate_event,
)
from data_engineering.linux_parser import parse_line as parse_linux  # noqa: E402
from data_engineering.openssh_parser import parse_line as parse_openssh  # noqa: E402


PARSERS = {
    "OpenSSH": parse_openssh,
    "Linux": parse_linux,
    "Apache": parse_apache,
}
MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}
HOUR_PATTERN = re.compile(r"\b(\d{2}):\d{2}:\d{2}\b")


def load_reference(dataset: str) -> list[dict[str, str]]:
    path = ROOT / "data" / "reference" / dataset / f"{dataset}_2k.log_structured.csv"
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def reference_timestamp(dataset: str, row: dict[str, str]) -> str | None:
    if dataset == "Apache":
        return (row.get("Time") or "").strip() or None
    month = (row.get("Month") or row.get("Date") or "").strip()
    day = (row.get("Date") if dataset == "Linux" else row.get("Day") or "").strip()
    time = (row.get("Time") or "").strip()
    if month in MONTHS and day and time:
        return f"{month} {int(day)} {time}"
    return None


def compare_to_reference(
    dataset: str,
    events: list[dict],
    rows: list[dict[str, str]],
) -> dict[str, int]:
    comparisons: Counter[str] = Counter()
    comparisons["reference_rows"] = len(rows)
    comparisons["raw_rows"] = len(events)
    comparisons["row_count_discrepancies"] = abs(len(rows) - len(events))
    for event, row in zip(events, rows):
        metadata = event["metadata"]
        if metadata["raw_parse_matched"]:
            comparisons["prefix_parsed"] += 1

        reference_content = clean_message(row.get("Content") or "")
        if reference_content:
            comparisons["content_compared"] += 1
            parsed_content = clean_message(event["message"])
            content_matches = parsed_content == reference_content
            component_boundary_match = False
            if dataset == "Linux" and not content_matches:
                prefix, separator, remainder = parsed_content.partition(": ")
                expected_component = (row.get("Component") or "").strip()
                parsed_process = str(metadata.get("process") or "")
                component_boundary_match = (
                    bool(separator)
                    and remainder == reference_content
                    and expected_component == f"{parsed_process} {prefix}"
                )
                if component_boundary_match:
                    comparisons["component_boundary_content_matches"] += 1
                    metadata["reference_component_boundary_match"] = True
            if not content_matches and not component_boundary_match:
                comparisons["content_discrepancies"] += 1

        expected_timestamp = reference_timestamp(dataset, row)
        if expected_timestamp is not None:
            comparisons["timestamp_compared"] += 1
            if metadata.get("timestamp_raw") != expected_timestamp:
                comparisons["timestamp_discrepancies"] += 1

        pid_column = "Pid" if "Pid" in row else "PID"
        expected_pid = (row.get(pid_column) or "").strip()
        if expected_pid:
            comparisons["pid_compared"] += 1
            if str(metadata.get("pid") or "") != expected_pid:
                comparisons["pid_discrepancies"] += 1

        expected_component = (row.get("Component") or "").strip()
        if expected_component:
            comparisons["component_compared"] += 1
            normalized_component = re.sub(r"^--\s+", "", expected_component)
            candidates = {
                str(metadata.get("hostname") or "").strip(),
                str(metadata.get("process") or "").strip(),
            }
            if metadata.get("reference_component_boundary_match"):
                candidates.add(expected_component)
            if normalized_component not in candidates:
                comparisons["component_discrepancies"] += 1

        expected_level = (row.get("Level") or "").strip()
        if expected_level and dataset == "Apache":
            comparisons["severity_compared"] += 1
            if str(metadata.get("severity") or "").strip() != expected_level:
                comparisons["severity_discrepancies"] += 1
        elif expected_level and dataset == "Linux":
            comparisons["hostname_compared"] += 1
            if str(metadata.get("hostname") or "").strip() != expected_level:
                comparisons["hostname_discrepancies"] += 1

        event["metadata"]["log_template_id"] = (row.get("EventId") or "").strip() or None
        event["metadata"]["reference_alignment"] = "row-order"

    return dict(comparisons)


def missing_counts(events: list[dict]) -> Counter[str]:
    fields = ("timestamp", "username", "source_ip", "status")
    return Counter(
        {
            field: sum(event[field] is None or event[field] == "" for event in events)
            for field in fields
        }
    )


def timestamp_buckets(
    dataset: str, rows: list[dict[str, str]]
) -> tuple[Counter[str], str]:
    buckets: Counter[str] = Counter()
    parsed_dates: list[datetime] = []
    for row in rows:
        raw = reference_timestamp(dataset, row)
        if not raw:
            continue
        hour = HOUR_PATTERN.search(raw)
        if hour:
            buckets[hour.group(1)] += 1
        if dataset == "Apache":
            try:
                parsed_dates.append(datetime.strptime(raw, "%a %b %d %H:%M:%S %Y"))
            except ValueError:
                continue
    if dataset == "Apache" and parsed_dates:
        range_text = (
            f"{min(parsed_dates).date().isoformat()} to "
            f"{max(parsed_dates).date().isoformat()} (source has no timezone)"
        )
    else:
        range_text = "year/timezone unavailable; partial month/day/time only"
    return buckets, range_text


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def render_report(
    events_by_source: dict[str, list[dict]],
    references: dict[str, list[dict[str, str]]],
    comparisons: dict[str, dict[str, int]],
) -> str:
    all_events = [event for events in events_by_source.values() for event in events]
    source_rows = [
        [source, f"{len(events):,}"]
        for source, events in events_by_source.items()
    ]
    type_rows: list[list[str]] = []
    for source, events in events_by_source.items():
        counts = Counter(event["event_type"] for event in events)
        type_rows.extend(
            [source, event_type, f"{count:,}"]
            for event_type, count in sorted(counts.items())
        )

    missing_rows = []
    for source, events in events_by_source.items():
        missing_rows.extend(
            [source, field, f"{count:,}", f"{count / len(events):.1%}"]
            for field, count in missing_counts(events).items()
        )

    temporal_sections = []
    template_sections = []
    for source, rows in references.items():
        buckets, period = timestamp_buckets(source, rows)
        temporal_sections.append(
            f"### {source}\n\n"
            f"Observed period: {period}.\n\n"
            + (
                markdown_table(
                    ["Hour", "Entries"],
                    [[hour, f"{count:,}"] for hour, count in sorted(buckets.items())],
                )
                if buckets
                else "No reliable time-of-day values were available."
            )
        )
        template_counts = Counter(
            (row.get("EventTemplate") or "").strip() for row in rows
        )
        template_rows = [
            [
                template.replace("|", r"\|").replace("\n", " "),
                f"{count:,}",
            ]
            for template, count in template_counts.most_common(10)
        ]
        template_sections.append(
            f"### {source}\n\n"
            + markdown_table(["Reference event template", "Occurrences"], template_rows)
        )

    reference_missing_rows: list[list[str]] = []
    for source, rows in references.items():
        columns = list(rows[0]) if rows else []
        for column in columns:
            count = sum(not (row.get(column) or "").strip() for row in rows)
            if count:
                reference_missing_rows.append([source, column, f"{count:,}"])
    if not reference_missing_rows:
        reference_missing_rows.append(["All sources", "None", "0"])

    comparison_rows = []
    linux_boundary_matches = comparisons.get("Linux", {}).get(
        "component_boundary_content_matches", 0
    )
    relative_rows = []
    for source, events in events_by_source.items():
        relative_statuses = Counter(
            event["metadata"]["relative_time"]["status"] for event in events
        )
        ambiguous_count = sum(
            count
            for status, count in relative_statuses.items()
            if "ambiguous" in status
        )
        non_chronological_count = sum(
            count
            for status, count in relative_statuses.items()
            if "non_chronological" in status
        )
        relative_rows.append(
            [
                source,
                f"{sum(event['metadata']['relative_time']['delta_from_previous_seconds'] is not None for event in events):,}",
                f"{ambiguous_count:,}",
                f"{non_chronological_count:,}",
                f"{max((event['metadata']['relative_time']['segment'] for event in events), default=0):,}",
            ]
        )
    comparison_fields = (
        ("prefix_parsed", "raw_rows", "raw prefix parse coverage"),
        ("content_discrepancies", "content_compared", "message content"),
        ("timestamp_discrepancies", "timestamp_compared", "timestamp fields"),
        ("pid_discrepancies", "pid_compared", "PID fields"),
        ("component_discrepancies", "component_compared", "component/host fields"),
        ("hostname_discrepancies", "hostname_compared", "hostname fields"),
        ("severity_discrepancies", "severity_compared", "severity fields"),
    )
    for source, counts in comparisons.items():
        for discrepancy_key, compared_key, label in comparison_fields:
            if discrepancy_key == "prefix_parsed":
                covered = counts.get(discrepancy_key, 0)
                total = counts.get("raw_rows", 0)
                comparison_rows.append(
                    [source, label, f"{covered:,}/{total:,}", f"{total - covered:,}"]
                )
            elif counts.get(compared_key, 0):
                comparison_rows.append(
                    [
                        source,
                        label,
                        f"{counts.get(compared_key, 0):,}",
                        f"{counts.get(discrepancy_key, 0):,}",
                    ]
                )

    return "\n".join(
        [
            "# Exploratory Data Analysis — LogHub-2k",
            "",
            "Generated by `scripts/run_data_pipeline.py` from the local raw logs "
            "and reference CSVs. No log records or identifying values are included "
            "in this report.",
            "",
            "## Scope",
            "",
            f"- Entries analyzed: **{len(all_events):,}** across three sources.",
            "- LogPAI `EventId` is a template identifier only; it is not an attack "
            "label and was not used as a security outcome.",
            "- Source distributions count input records; event types below are "
            "coarse parser classifications, not labeled threat classes.",
            "",
            "## Source distribution",
            "",
            markdown_table(["Source", "Entries"], source_rows),
            "",
            "## Event-type distribution",
            "",
            markdown_table(["Source", "Normalized event type", "Entries"], type_rows),
            "",
            "## Missing normalized fields",
            "",
            markdown_table(["Source", "Field", "Missing", "Share"], missing_rows),
            "",
            "## Missing values in reference CSVs",
            "",
            markdown_table(
                ["Source", "Reference column", "Blank rows"], reference_missing_rows
            ),
            "",
            "## Temporal patterns",
            "",
            "OpenSSH and Linux timestamps omit the year and timezone. Their "
            "normalized `timestamp` is therefore null; only partial source time "
            "components are reported. Apache includes year and seconds but no "
            "timezone, so its normalized timestamps are timezone-naive.",
            "",
            "\n\n".join(temporal_sections),
            "",
            "## Relative source-sequence timing",
            "",
            "Relative deltas are calculated only in original row order and within "
            "each dataset. They are wall-clock differences, not absolute UTC "
            "durations. Unknown-year syslog entries never receive an assigned "
            "year; ambiguous leap-day crossings and non-chronological date changes "
            "are marked rather than guessed. Apache deltas remain timezone-naive.",
            "",
            markdown_table(
                [
                    "Source",
                    "Adjacent deltas calculated",
                    "Ambiguous deltas",
                    "Non-chronological records",
                    "Sequence segments",
                ],
                relative_rows,
            ),
            "",
            "## Most frequent reference event templates",
            "",
            "Templates are reported as descriptive message patterns, not attack labels.",
            "",
            "\n\n".join(template_sections),
            "",
            "## Parser/reference comparison",
            "",
            "Content, timestamps, PIDs, component/host values, and severity are "
            "compared only where a corresponding reference column exists. The "
            "comparison is aligned by source row order; it does not claim that "
            "the reference labels are security labels.",
            "",
            f"For Linux, {linux_boundary_matches} row(s) split a colon-terminated prefix between the "
            "raw message and the reference `Component` field. These rows count "
            "as boundary-equivalent only when the remaining content and combined "
            "component match the same row.",
            "",
            markdown_table(
                ["Source", "Comparable field", "Compared/parsed", "Discrepancies"],
                comparison_rows,
            ),
            "",
        ]
    )


def write_jsonl(path: Path, events: list[dict], force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise FileExistsError(
            f"{path.relative_to(ROOT)} already exists; use --force to replace it"
        )
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            for event in events:
                validate_event(event)
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace existing generated JSONL outputs",
    )
    arguments = parser.parse_args(argv)
    events_by_source: dict[str, list[dict]] = {}
    references: dict[str, list[dict[str, str]]] = {}
    comparisons: dict[str, dict[str, int]] = {}
    try:
        expected_outputs = [
            ROOT / "data" / "processed" / f"{source.lower()}_events.jsonl"
            for source in PARSERS
        ]
        expected_outputs.append(ROOT / "docs" / "EDA_REPORT.md")
        if not arguments.force:
            existing_outputs = [
                path.relative_to(ROOT).as_posix()
                for path in expected_outputs
                if path.exists()
            ]
            if existing_outputs:
                raise FileExistsError(
                    "Generated outputs already exist; use --force to replace: "
                    + ", ".join(existing_outputs)
                )

        for source, parse_line in PARSERS.items():
            raw_path = ROOT / "data" / "raw" / source / f"{source}_2k.log"
            if not raw_path.is_file():
                raise FileNotFoundError(f"Required input is missing: {raw_path}")
            with raw_path.open("r", encoding="utf-8", newline="") as stream:
                raw_lines = list(stream)
            reference_rows = load_reference(source)
            events = [
                parse_line(line, line_number)
                for line_number, line in enumerate(raw_lines, start=1)
            ]
            calculate_relative_times(events)
            comparison = compare_to_reference(source, events, reference_rows)
            output_path = ROOT / "data" / "processed" / f"{source.lower()}_events.jsonl"
            write_jsonl(output_path, events, arguments.force)
            events_by_source[source] = events
            references[source] = reference_rows
            comparisons[source] = comparison
            print(
                f"{source}: {len(events):,} events; "
                f"prefix parsed {comparison.get('prefix_parsed', 0):,}/"
                f"{len(events):,}; output {output_path.relative_to(ROOT)}"
            )

        report_path = ROOT / "docs" / "EDA_REPORT.md"
        report_path.write_text(
            render_report(events_by_source, references, comparisons),
            encoding="utf-8",
            newline="\n",
        )
        print(f"EDA report: {report_path.relative_to(ROOT)}")
        print(
            "Reference discrepancies: "
            + "; ".join(
                f"{source} "
                + ", ".join(
                    f"{field}={counts.get(field, 0)}"
                    for field in (
                        "content_discrepancies",
                        "timestamp_discrepancies",
                        "pid_discrepancies",
                        "component_discrepancies",
                        "hostname_discrepancies",
                        "severity_discrepancies",
                    )
                )
                for source, counts in comparisons.items()
            )
        )
    except (OSError, UnicodeError, csv.Error, ValueError, FileExistsError) as error:
        print(f"Pipeline failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
