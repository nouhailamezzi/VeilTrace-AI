# Deterministic detection engine

## Scope and architecture

The detector in `cybersecurity/detection_engine.py` evaluates normalized
events from `data/processed/` and produces local JSONL alerts. It uses
deterministic Python rules only; it does not call an LLM, transmit logs, or
consume synthetic ground-truth annotations. Events must pass the shared
`data_engineering.common.validate_event` schema check. Malformed events are
counted and excluded.

Run from the repository root:

```text
python scripts/run_detection.py --synthetic
python scripts/run_detection.py --real-logs
```

Outputs are written to `data/processed/`. Existing outputs are preserved by
default; pass `--force` to intentionally replace them. The synthetic command
also refreshes `docs/DETECTION_EVALUATION.md`. Detection thresholds can be
overridden with a JSON object passed to `--config-json`; unknown or invalid
values fail explicitly.

## Rules and default thresholds

| Rule | Behavior | Default threshold and scope |
| --- | --- | --- |
| R01 | Repeated failed authentication | At least 5 attempts in 600 seconds from one IP, source, and hostname |
| R02 | Success after repeated failures | At least 3 prior failures followed by success within 900 seconds for the same account, IP, source, and hostname |
| R03 | Repeated invalid usernames | At least 4 invalid-username failures in 600 seconds for one username, source, and hostname |
| R04 | Failures across accounts | At least 5 failures across at least 5 accounts in 600 seconds from one IP, source, and hostname |
| R05 | Suspicious privilege indicators | In a 900-second same-host/account context: privilege activity, a sensitive target, and denial/failure or explicit elevated execution context; trusted privilege usernames are excluded |
| R06 | Authentication volume above baseline | More than a per-source/hostname threshold in 600 seconds; threshold is `max(12, ceil(median + 3 * MAD))` from development observations |
| R07 | Repeated application errors | At least 6 errors in 300 seconds on one source and hostname; reported as `operational_anomaly`, not a security alert |

These are initial heuristic values, not universal policy. R01, R02, R03,
R04, and R07 require timestamps that can be compared within a valid sequence.
Authentication correlation also requires a parsed hostname. R05 requires
contextual evidence and never alerts merely because a user is `root`, a `sudo`
command appears, or an administrative action is successful. For an event
without a usable timestamp, R05 can only use evidence contained in that same
event; it does not create a time-window correlation.

R06 uses only a supplied development baseline. The synthetic evaluation builds
this baseline from development events; the unlabeled LogHub run does not
provide a baseline, so R06 is skipped there. Thresholds based on a small
synthetic baseline may not represent production behavior.

## Temporal correlation and deduplication

The engine reuses Phase 2 timestamp and `relative_time` metadata. It preserves
input order and divides timestamp rollbacks or source-relative sequence
boundaries into separate segments. Rules group by source and hostname and, as
applicable, source IP/account; events from different sources or hosts are not
combined. It does not infer a missing year or timezone. Apache's parsed time
is timezone-naive. Alert timestamps are null when an absolute timestamp is
unavailable, with `timestamp_quality` identifying relative or unknown time.

Authentication messages with the same source, hostname, IP, account, outcome,
and segment within 3 seconds are treated as one attempt. Repeated-message
counters are used as occurrence weights, capped at 100,000, rather than
discarded or counted as a collection of separate log records. This is a
conservative heuristic: source logs do not always provide a canonical
authentication-attempt identifier.

## Alert contract

Each alert is a JSON object with `alert_id`, `rule_id`, `rule_name`,
`category`, `severity`, `source`, `timestamp`, `timestamp_quality`,
`source_ip`, `username`, `event_count`, `evidence_event_ids`, `description`,
`recommended_action`, and `detection_method`. The stable alert ID is derived
from the rule, scope, and evidence IDs. Alerts with the same ID are emitted
once. Each alert lists the event IDs used as evidence; R07 is explicitly an
operational anomaly. Alerts remain local in ignored `data/processed/*.jsonl`
files.

## Current unlabeled LogHub run

The latest local run processed 2,000 records from each source with no malformed
events:

| Dataset | Rule matches |
| --- | --- |
| OpenSSH | 34: R01 14, R03 15, R04 5 |
| Linux | 2: R01 2 |
| Apache | 0 |

These counts are patterns matched by heuristics in unlabeled data, not
confirmed attacks or accuracy measurements. No R06 baseline was supplied.
Apache records in this pipeline lack parsed hostnames, so host-scoped R07
aggregation is unavailable for those records.
