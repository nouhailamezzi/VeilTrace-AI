# Phase 2 data pipeline

## Overview

This phase parses the local 2,000-entry OpenSSH, Linux, and Apache LogHub-2k
samples. It does not download data or implement threat detection, attack
labeling, or a privacy engine.

Run from the repository root:

```text
python scripts/run_data_pipeline.py
python -m unittest discover -s tests -v
```

For an intentional repeat run after the generated outputs exist:

```text
python scripts/run_data_pipeline.py --force
```

The pipeline writes:

- `data/processed/openssh_events.jsonl`
- `data/processed/linux_events.jsonl`
- `data/processed/apache_events.jsonl`
- `docs/EDA_REPORT.md`

Generated JSONL files are ignored by Git because event records may contain
identifying operational values. An existing output is preserved and the
pipeline stops rather than replacing it; use `--force` only when intentionally
regenerating outputs.

## Parsers and shared event schema

Source-specific parsers live in `data_engineering/openssh_parser.py`,
`data_engineering/linux_parser.py`, and `data_engineering/apache_parser.py`.
Shared cleaning, extraction, normalization, and validation are in
`data_engineering/common.py`.

Every JSONL record has exactly these top-level keys:

```text
event_id, source, timestamp, event_type, username, source_ip,
status, message, metadata
```

`event_id` is a deterministic source-and-line identifier. In `metadata`,
`hostname`, `process`, `pid`, and `severity` are populated only when present in
the parsed source line. `log_template_id` is copied from the row-aligned
reference CSV for comparison only; LogPAI's `EventId` is not a threat label.
Authentication `status` is `success`, `failure`, or null based on explicit
message text. No login failures are deduplicated.

Control characters and repeated whitespace are cleaned in `message`; the
original log files remain untouched. Malformed lines remain represented as
events with `raw_parse_matched=false` and a parse error in metadata; available
text is retained rather than silently discarded.

## Timestamp decisions

OpenSSH and Linux timestamps contain month, day, and time, but no year or
timezone. The pipeline preserves that value as `metadata.timestamp_raw`,
extracts numeric `month`, `day`, `hour`, `minute`, and `second` into separate
metadata fields, describes the limitation in `metadata.limitations`, and
leaves the normalized `timestamp` null. `year` and `timezone` remain null. It
does not infer either value.

Apache timestamps contain a year and second precision but no timezone. They
are normalized to a timezone-naive ISO-like value in `timestamp`, while the
original text is retained in `metadata.timestamp_raw` and the missing timezone
is explicitly represented by `metadata.timezone=null`. Its numeric month, day,
hour, minute, second, and year are separately available. Temporal EDA reports
time-of-day for all sources and a calendar date range for Apache only.

## Relative time

Each event receives `metadata.relative_time`, calculated independently per
source in original row order. It contains the sequence index, segment number,
delta from the preceding event in seconds (when defensible), elapsed wall-clock
seconds from the current segment's anchor, the basis, and a status. No events
from different sources are compared.

Syslog deltas use their known month/day/time. Explicit Dec-to-Jan transitions
are treated as relative year-boundary rollovers without assigning a year.
Same-date late-to-early clock reversals may be marked as inferred midnight
rollovers; unrelated date reversals are not reordered. A date interval crossing
Feb 29 is marked ambiguous when the year is unknown, unless Feb 29 itself is
observed and resolves the leap-day length. Invalid/missing components and
non-chronological timestamps start a new relative segment instead of producing
a guessed duration. Apache differences are calculated as timezone-naive wall
clock values, not absolute elapsed time.

## Cleaning, validation, and reference comparison

Empty optional values become JSON null. Identifying values are extracted only
when the line contains recognizable username/IP syntax. IP candidates are
validated with Python's `ipaddress` module. Every event is validated against
the shared schema before JSONL output.

The pipeline compares parsed messages and source-specific fields against the
corresponding LogPAI structured CSV by row order. It reports comparison
coverage and discrepancy counts for message, timestamp, PID, component/host,
and severity where available. OpenSSH's `Component` is compared to parsed
hostname; Linux's `Level` is compared to hostname and its `Component` is
compared to the parsed process or hostname (`Level` is not treated as severity
in this Linux sample).
Comparisons describe parser fidelity, not security ground truth.

The EDA report includes source and normalized event-type distributions,
normalized and reference missing-value counts, temporal summaries, frequent
reference event templates, and parser/reference discrepancy counts. It omits
raw log lines and extracted usernames, IP addresses, and hostnames.

## Completed run

The local run produced 2,000 normalized events per source (6,000 total), with
100% raw-prefix parse coverage and zero discrepancies in the comparable
reference fields. The JSONL outputs each contain 2,000 distinct event IDs and
pass shared-schema validation. The 16 standard-library tests pass.

## Tests

`tests/test_log_parsers.py` uses the standard-library `unittest` runner to
cover source parsing, timestamp limitations, authentication extraction,
schema validation, malformed input, and preservation of repeated failures.
