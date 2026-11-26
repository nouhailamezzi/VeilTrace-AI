"""Deterministic rule-based detection over normalized local log events."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

from data_engineering.common import validate_event


_REPEAT_COUNTER = re.compile(
    r"\b(?:last message repeated|message repeated)\s+(\d+)\s+times\b",
    re.IGNORECASE,
)
_INVALID_USER = re.compile(r"\binvalid user\b", re.IGNORECASE)
_PRIVILEGE = re.compile(r"\b(?:sudo|su)\b|COMMAND=|setuid", re.IGNORECASE)
_SENSITIVE_TARGET = re.compile(
    r"/etc/(?:shadow|sudoers)|/root/|not in sudoers|"
    r"\b(?:authorized_keys|private key)\b",
    re.IGNORECASE,
)
_PRIVILEGE_DENIAL = re.compile(
    r"\b(?:not in sudoers|authentication failure|permission denied|"
    r"denied|failed)\b",
    re.IGNORECASE,
)
_ROOT_EXECUTION = re.compile(
    r"\b(?:uid=0|runas=root|user=root)\b", re.IGNORECASE
)
_APPLICATION_ERROR_LEVELS = {"error", "crit", "alert", "emerg"}


@dataclass(frozen=True)
class DetectionConfig:
    r01_min_failed_attempts: int = 5
    r01_window_seconds: int = 600
    r02_min_prior_failures: int = 3
    r02_window_seconds: int = 900
    r03_min_invalid_attempts: int = 4
    r03_window_seconds: int = 600
    r04_min_failed_attempts: int = 5
    r04_min_distinct_accounts: int = 5
    r04_window_seconds: int = 600
    r05_window_seconds: int = 900
    r06_min_auth_events: int = 12
    r06_mad_multiplier: float = 3.0
    r06_window_seconds: int = 600
    r07_min_errors: int = 6
    r07_window_seconds: int = 300
    duplicate_attempt_window_seconds: int = 3
    trusted_privilege_users: tuple[str, ...] = (
        "ops-admin",
        "backup-admin",
        "root",
    )

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> "DetectionConfig":
        allowed = set(cls.__dataclass_fields__)
        unknown = set(values).difference(allowed)
        if unknown:
            raise ValueError(f"unknown detection config keys: {', '.join(sorted(unknown))}")
        normalized = dict(values)
        if "trusted_privilege_users" in normalized:
            users = normalized["trusted_privilege_users"]
            if not isinstance(users, list) or not all(
                isinstance(user, str) for user in users
            ):
                raise ValueError("trusted_privilege_users must be a list of strings")
            normalized["trusted_privilege_users"] = tuple(users)
        config = cls(**normalized)
        for name, value in asdict(config).items():
            if name == "trusted_privilege_users":
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be numeric")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        return config

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if name == "trusted_privilege_users":
                if not isinstance(value, tuple) or not all(
                    isinstance(user, str) and user for user in value
                ):
                    raise ValueError("trusted privilege users must be non-empty strings")
            elif name == "r06_mad_multiplier":
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"{name} must be numeric")
                if value <= 0:
                    raise ValueError(f"{name} must be positive")
            elif isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be numeric")
            elif value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass
class DetectionResult:
    alerts: list[dict[str, Any]]
    malformed_event_count: int = 0


@dataclass
class Baseline:
    thresholds: dict[tuple[str, str], int] = field(default_factory=dict)
    window_seconds: int = 600


@dataclass
class TimedEvent:
    event: dict[str, Any]
    sequence_index: int
    clock: float | None
    segment: tuple[Any, int]
    timestamp_quality: str


@dataclass
class AuthAttempt:
    records: list[TimedEvent]
    source: str
    hostname: str
    source_ip: str | None
    username: str | None
    status: str
    clock: float
    segment: tuple[Any, int]
    sequence_index: int
    weight: int
    invalid_username: bool


@dataclass
class Finding:
    rule_id: str
    units: list[Any]
    source: str
    hostname: str
    group_key: tuple[Any, ...]
    event_count: int
    username: str | None = None
    source_ip: str | None = None
    detail: str = ""


RULES = {
    "R01": ("Repeated failed logins from one source", "security", "medium"),
    "R02": ("Successful login following repeated failures", "security", "high"),
    "R03": ("Repeated invalid username attempts", "security", "medium"),
    "R04": ("Authentication failures across multiple accounts", "security", "high"),
    "R05": ("Suspicious privilege escalation indicators", "security", "high"),
    "R06": ("Authentication activity above baseline", "security", "medium"),
    "R07": ("Repeated application errors", "operational_anomaly", "low"),
}


def _repeat_count(event: dict[str, Any]) -> int:
    value = event.get("metadata", {}).get("repeat_count")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return min(value, 100_000)
    match = _REPEAT_COUNTER.search(event.get("message", ""))
    if match:
        return min(int(match.group(1)), 100_000)
    return 1


def _time_from_event(event: dict[str, Any]) -> tuple[float | None, Any, str]:
    metadata = event["metadata"]
    relative = metadata.get("relative_time")
    base_segment = (
        relative.get("segment", 0) if isinstance(relative, dict) else 0
    )
    timestamp = event.get("timestamp")
    if isinstance(timestamp, str) and timestamp:
        try:
            parsed = datetime.fromisoformat(timestamp)
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.utcoffset() is not None:
                return parsed.timestamp(), base_segment, "complete"
            return (
                parsed.toordinal() * 86400
                + parsed.hour * 3600
                + parsed.minute * 60
                + parsed.second,
                base_segment,
                "timezone_unknown",
            )
    if isinstance(relative, dict) and isinstance(relative.get("elapsed_seconds"), (int, float)):
        return (
            float(relative["elapsed_seconds"]),
            base_segment,
            "source_relative_wall_clock",
        )
    return None, base_segment, "unknown"


def _prepare_events(
    events: Iterable[Any],
) -> tuple[list[TimedEvent], int]:
    prepared: list[TimedEvent] = []
    malformed = 0
    source_state: dict[str, dict[str, Any]] = {}
    for sequence_index, event in enumerate(events, start=1):
        try:
            if not isinstance(event, dict):
                raise ValueError("event must be an object")
            validate_event(event)
            source = event["source"]
            clock, base_segment, quality = _time_from_event(event)
        except (ValueError, TypeError, KeyError):
            malformed += 1
            continue

        state = source_state.setdefault(
            source, {"base_segment": None, "local_segment": 0, "last_clock": None}
        )
        if state["base_segment"] != base_segment:
            if state["base_segment"] is not None:
                state["local_segment"] += 1
            state["base_segment"] = base_segment
            state["last_clock"] = None
        if clock is None:
            segment = (base_segment, state["local_segment"])
            state["local_segment"] += 1
            state["last_clock"] = None
        else:
            if (
                state["last_clock"] is not None
                and clock < state["last_clock"]
            ):
                state["local_segment"] += 1
            segment = (base_segment, state["local_segment"])
            state["last_clock"] = clock
        prepared.append(
            TimedEvent(event, sequence_index, clock, segment, quality)
        )
    return prepared, malformed


def _make_auth_attempts(
    records: list[TimedEvent], config: DetectionConfig
) -> list[AuthAttempt]:
    attempts: list[AuthAttempt] = []
    last_by_key: dict[tuple[Any, ...], AuthAttempt] = {}
    for record in records:
        event = record.event
        status = event.get("status")
        metadata = event["metadata"]
        hostname = metadata.get("hostname")
        if (
            status not in {"success", "failure"}
            or record.clock is None
            or not hostname
        ):
            continue
        username = event.get("username")
        source_ip = event.get("source_ip")
        key = (
            event["source"],
            hostname,
            source_ip,
            username,
            status,
            record.segment,
        )
        previous = last_by_key.get(key)
        weight = _repeat_count(event)
        if (
            previous is not None
            and 0 <= record.clock - previous.clock
            <= config.duplicate_attempt_window_seconds
        ):
            previous.records.append(record)
            previous.weight = max(previous.weight, weight)
            previous.invalid_username = previous.invalid_username or bool(
                _INVALID_USER.search(event.get("message", ""))
            )
            continue
        attempt = AuthAttempt(
            records=[record],
            source=event["source"],
            hostname=hostname,
            source_ip=source_ip,
            username=username,
            status=status,
            clock=record.clock,
            segment=record.segment,
            sequence_index=record.sequence_index,
            weight=weight,
            invalid_username=bool(_INVALID_USER.search(event.get("message", ""))),
        )
        attempts.append(attempt)
        last_by_key[key] = attempt
    return attempts


def _unit_events(unit: Any) -> list[dict[str, Any]]:
    if isinstance(unit, AuthAttempt):
        return [record.event for record in unit.records]
    return [unit.event]


def _unit_sequence(unit: Any) -> int:
    if isinstance(unit, AuthAttempt):
        return unit.sequence_index
    return unit.sequence_index


def _unit_weight(unit: Any) -> int:
    if isinstance(unit, AuthAttempt):
        return unit.weight
    return _repeat_count(unit.event)


def _merge_overlapping(
    candidates: list[list[Any]],
) -> list[list[Any]]:
    merged: list[list[Any]] = []
    for candidate in candidates:
        candidate_ids = {id(item) for item in candidate}
        matching = [
            index
            for index, previous in enumerate(merged)
            if candidate_ids.intersection(id(item) for item in previous)
        ]
        if not matching:
            merged.append(list(candidate))
            continue
        first = matching[0]
        combined = {id(item): item for item in merged[first]}
        combined.update({id(item): item for item in candidate})
        for index in reversed(matching[1:]):
            combined.update({id(item): item for item in merged.pop(index)})
        merged[first] = sorted(combined.values(), key=_unit_sequence)
    return merged


def _qualifying_windows(
    items: list[Any],
    window_seconds: int,
    predicate: Callable[[list[Any]], bool],
) -> list[list[Any]]:
    candidates: list[list[Any]] = []
    left = 0
    for right, item in enumerate(items):
        while (
            left <= right
            and item.clock - items[left].clock > window_seconds
        ):
            left += 1
        window = items[left : right + 1]
        if predicate(window):
            candidates.append(window)
    return _merge_overlapping(candidates)


def _group_items(
    items: list[Any], key_fn: Callable[[Any], tuple[Any, ...]]
) -> dict[tuple[Any, ...], list[Any]]:
    grouped: dict[tuple[Any, ...], list[Any]] = defaultdict(list)
    for item in items:
        grouped[key_fn(item)].append(item)
    return grouped


def build_baseline(
    events: Iterable[Any], config: DetectionConfig | None = None
) -> Baseline:
    """Derive per-source/host authentication volume thresholds from dev events."""
    config = config or DetectionConfig()
    records, _ = _prepare_events(events)
    attempts = _make_auth_attempts(records, config)
    buckets: dict[tuple[str, str, tuple[Any, int], int], int] = defaultdict(int)
    for attempt in attempts:
        bucket = math.floor(attempt.clock / config.r06_window_seconds)
        buckets[
            (
                attempt.source,
                attempt.hostname,
                attempt.segment,
                bucket,
            )
        ] += attempt.weight

    observations_by_host: dict[tuple[str, str], list[int]] = defaultdict(list)
    for (source, hostname, _, _), count in buckets.items():
        observations_by_host[(source, hostname)].append(count)
    thresholds: dict[tuple[str, str], int] = {}
    for key, observations in observations_by_host.items():
        median = statistics.median(observations)
        deviations = [abs(value - median) for value in observations]
        mad = statistics.median(deviations)
        thresholds[key] = max(
            config.r06_min_auth_events,
            math.ceil(median + config.r06_mad_multiplier * mad),
        )
    return Baseline(thresholds, config.r06_window_seconds)


def _finding(
    rule_id: str,
    units: list[Any],
    group_key: tuple[Any, ...],
    count: int | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    detail: str = "",
) -> Finding:
    first_event = _unit_events(units[0])[0]
    return Finding(
        rule_id=rule_id,
        units=sorted(units, key=_unit_sequence),
        source=first_event["source"],
        hostname=first_event["metadata"].get("hostname") or "",
        group_key=group_key,
        event_count=count if count is not None else sum(_unit_weight(unit) for unit in units),
        username=username,
        source_ip=source_ip,
        detail=detail,
    )


def _auth_findings(
    attempts: list[AuthAttempt],
    config: DetectionConfig,
    baseline: Baseline | None,
) -> list[Finding]:
    findings: list[Finding] = []
    failures = [attempt for attempt in attempts if attempt.status == "failure"]

    for key, group in _group_items(
        failures,
        lambda item: (
            item.source,
            item.hostname,
            item.source_ip,
            item.segment,
        ),
    ).items():
        source, hostname, source_ip, _ = key
        if source_ip is None:
            continue
        windows = _qualifying_windows(
            group,
            config.r01_window_seconds,
            lambda items: sum(item.weight for item in items)
            >= config.r01_min_failed_attempts,
        )
        for window in windows:
            findings.append(
                _finding("R01", window, key, source_ip=source_ip)
            )

    r02_groups = _group_items(
        attempts,
        lambda item: (
            item.source,
            item.hostname,
            item.source_ip,
            item.username,
            item.segment,
        ),
    )
    for key, group in r02_groups.items():
        source, hostname, source_ip, username, _ = key
        if source_ip is None or username is None:
            continue
        candidates: list[list[AuthAttempt]] = []
        for success in group:
            if success.status != "success":
                continue
            prior_failures = [
                attempt
                for attempt in group
                if attempt.status == "failure"
                and attempt.sequence_index < success.sequence_index
                and 0 <= success.clock - attempt.clock <= config.r02_window_seconds
            ]
            if sum(item.weight for item in prior_failures) >= config.r02_min_prior_failures:
                candidates.append(prior_failures + [success])
        for candidate in _merge_overlapping(candidates):
            findings.append(
                _finding(
                    "R02",
                    candidate,
                    key,
                    username=username,
                    source_ip=source_ip,
                )
            )

    invalid = [
        attempt
        for attempt in failures
        if attempt.invalid_username and attempt.username is not None
    ]
    for key, group in _group_items(
        invalid,
        lambda item: (
            item.source,
            item.hostname,
            item.username,
            item.segment,
        ),
    ).items():
        source, hostname, username, _ = key
        windows = _qualifying_windows(
            group,
            config.r03_window_seconds,
            lambda items: sum(item.weight for item in items)
            >= config.r03_min_invalid_attempts,
        )
        for window in windows:
            ips = {item.source_ip for item in window if item.source_ip}
            findings.append(
                _finding(
                    "R03",
                    window,
                    key,
                    username=username,
                    source_ip=next(iter(ips)) if len(ips) == 1 else None,
                )
            )

    for key, group in _group_items(
        failures,
        lambda item: (
            item.source,
            item.hostname,
            item.source_ip,
            item.segment,
        ),
    ).items():
        source, hostname, source_ip, _ = key
        if source_ip is None:
            continue
        windows = _qualifying_windows(
            group,
            config.r04_window_seconds,
            lambda items: (
                sum(item.weight for item in items)
                >= config.r04_min_failed_attempts
                and len({item.username for item in items if item.username})
                >= config.r04_min_distinct_accounts
            ),
        )
        for window in windows:
            findings.append(
                _finding("R04", window, key, source_ip=source_ip)
            )

    if baseline:
        auth_groups = _group_items(
            attempts,
            lambda item: (
                item.source,
                item.hostname,
                item.segment,
            ),
        )
        for key, group in auth_groups.items():
            source, hostname, _ = key
            threshold = baseline.thresholds.get((source, hostname))
            if threshold is None:
                continue
            windows = _qualifying_windows(
                group,
                config.r06_window_seconds,
                lambda items: sum(item.weight for item in items) > threshold,
            )
            for window in windows:
                findings.append(
                    _finding(
                        "R06",
                        window,
                        key,
                        detail=f"baseline threshold={threshold}",
                    )
                )
    return findings


def _privilege_findings(
    records: list[TimedEvent], config: DetectionConfig
) -> list[Finding]:
    trusted = {name.casefold() for name in config.trusted_privilege_users}
    eligible = [
        record
        for record in records
        if record.event["metadata"].get("hostname")
        and record.event.get("username")
        and record.event["username"].casefold() not in trusted
    ]
    groups = _group_items(
        eligible,
        lambda record: (
            record.event["source"],
            record.event["metadata"]["hostname"],
            record.event["username"],
            record.segment,
        ),
    )
    findings: list[Finding] = []
    for key, group in groups.items():
        source, hostname, username, _ = key
        candidates: list[list[TimedEvent]] = []
        for current in group:
            if not _PRIVILEGE.search(current.event.get("message", "")):
                continue
            if current.clock is None:
                context = [current]
            else:
                context = [
                    record
                    for record in group
                    if record.sequence_index <= current.sequence_index
                    and record.clock is not None
                    and 0 <= current.clock - record.clock <= config.r05_window_seconds
                ]
            messages = [record.event.get("message", "") for record in context]
            has_privilege = any(_PRIVILEGE.search(message) for message in messages)
            has_sensitive = any(
                _SENSITIVE_TARGET.search(message) for message in messages
            )
            has_denial_or_root_context = any(
                record.event.get("status") == "failure"
                or _PRIVILEGE_DENIAL.search(record.event.get("message", ""))
                or (
                    _ROOT_EXECUTION.search(record.event.get("message", ""))
                    and _PRIVILEGE.search(record.event.get("message", ""))
                )
                for record in context
            )
            if has_privilege and has_sensitive and has_denial_or_root_context:
                unique_context = list(
                    {record.sequence_index: record for record in context}.values()
                )
                candidates.append(unique_context)
        for candidate in _merge_overlapping(candidates):
            source_ips = {
                record.event.get("source_ip")
                for record in candidate
                if record.event.get("source_ip")
            }
            findings.append(
                _finding(
                    "R05",
                    candidate,
                    key,
                    username=username,
                    source_ip=next(iter(source_ips)) if len(source_ips) == 1 else None,
                )
            )
    return findings


def _application_error_findings(
    records: list[TimedEvent], config: DetectionConfig
) -> list[Finding]:
    errors = [
        record
        for record in records
        if record.clock is not None
        and record.event["metadata"].get("hostname")
        and (
            str(record.event["metadata"].get("severity") or "").lower()
            in _APPLICATION_ERROR_LEVELS
            or "error" in record.event.get("event_type", "").lower()
        )
    ]
    groups = _group_items(
        errors,
        lambda record: (
            record.event["source"],
            record.event["metadata"]["hostname"],
            record.segment,
        ),
    )
    findings: list[Finding] = []
    for key, group in groups.items():
        windows = _qualifying_windows(
            group,
            config.r07_window_seconds,
            lambda items: sum(_repeat_count(item.event) for item in items)
            >= config.r07_min_errors,
        )
        for window in windows:
            findings.append(
                _finding(
                    "R07",
                    window,
                    key,
                    detail="operational anomaly; not classified as an attack",
                )
            )
    return findings


def _timestamp_for_alert(events: list[dict[str, Any]]) -> tuple[str | None, str]:
    event = events[-1]
    timestamp = event.get("timestamp")
    if isinstance(timestamp, str) and timestamp:
        try:
            parsed = datetime.fromisoformat(timestamp)
        except ValueError:
            return None, "unknown"
        return (
            timestamp,
            "complete_with_timezone"
            if parsed.utcoffset() is not None
            else "timezone_unknown",
        )
    relative = event["metadata"].get("relative_time")
    if isinstance(relative, dict) and relative.get("elapsed_seconds") is not None:
        return None, "source_relative_wall_clock"
    return None, "unknown"


def _render_alert(finding: Finding) -> dict[str, Any]:
    rule_name, category, severity = RULES[finding.rule_id]
    events_by_id: dict[str, tuple[int, dict[str, Any]]] = {}
    for unit in finding.units:
        records = unit.records if isinstance(unit, AuthAttempt) else [unit]
        for record in records:
            events_by_id[record.event["event_id"]] = (
                record.sequence_index,
                record.event,
            )
    ordered_records = sorted(events_by_id.values(), key=lambda item: item[0])
    evidence_events = [event for _, event in ordered_records]
    timestamp, timestamp_quality = _timestamp_for_alert(evidence_events)
    evidence_ids = [event["event_id"] for event in evidence_events]
    alert_key = json.dumps(
        [finding.rule_id, finding.source, finding.group_key, evidence_ids],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    alert_id = f"alert-{finding.rule_id.lower()}-{hashlib.sha256(alert_key.encode()).hexdigest()[:16]}"
    descriptions = {
        "R01": f"Observed {finding.event_count} distinct failed authentication attempt(s) from one source in the configured time window.",
        "R02": "A successful authentication followed repeated recent failure attempts for the same account and source.",
        "R03": f"Observed {finding.event_count} invalid-username authentication attempt(s) in the configured time window.",
        "R04": f"Observed {finding.event_count} authentication failure(s) across multiple accounts from one source.",
        "R05": "Correlated privilege escalation, sensitive-target, and denial or elevated-context evidence requires analyst review.",
        "R06": f"Observed {finding.event_count} authentication event(s) above the available development baseline ({finding.detail}).",
        "R07": f"Observed {finding.event_count} repeated application error occurrence(s); this is an operational anomaly, not an attack determination.",
    }
    actions = {
        "R01": "Review the source and authentication evidence; apply access controls only after confirming the activity.",
        "R02": "Review the account and preceding failures promptly; verify the successful login with the account owner.",
        "R03": "Review invalid-account targeting and check whether the activity is expected.",
        "R04": "Review for password-spraying behavior and apply proportionate authentication protections if confirmed.",
        "R05": "Review privilege audit records and the requested target; verify authorization before taking action.",
        "R06": "Compare the burst with operational context and the development baseline before treating it as suspicious.",
        "R07": "Investigate application health and error causes; do not classify this anomaly as malicious without separate evidence.",
    }
    return {
        "alert_id": alert_id,
        "rule_id": finding.rule_id,
        "rule_name": rule_name,
        "category": category,
        "severity": severity,
        "source": finding.source,
        "timestamp": timestamp,
        "timestamp_quality": timestamp_quality,
        "source_ip": finding.source_ip,
        "username": finding.username,
        "event_count": finding.event_count,
        "evidence_event_ids": evidence_ids,
        "description": descriptions[finding.rule_id],
        "recommended_action": actions[finding.rule_id],
        "detection_method": "deterministic_rule",
    }


def detect(
    events: Iterable[Any],
    config: DetectionConfig | None = None,
    baseline: Baseline | None = None,
) -> DetectionResult:
    """Run deterministic rules; malformed records are counted and excluded."""
    config = config or DetectionConfig()
    records, malformed_count = _prepare_events(events)
    attempts = _make_auth_attempts(records, config)
    findings = (
        _auth_findings(attempts, config, baseline)
        + _privilege_findings(records, config)
        + _application_error_findings(records, config)
    )
    alerts = [_render_alert(finding) for finding in findings]
    unique_alerts = {alert["alert_id"]: alert for alert in alerts}
    ordered = sorted(
        unique_alerts.values(),
        key=lambda alert: (
            alert["source"],
            alert["rule_id"],
            alert["evidence_event_ids"][0] if alert["evidence_event_ids"] else "",
        ),
    )
    return DetectionResult(ordered, malformed_count)
