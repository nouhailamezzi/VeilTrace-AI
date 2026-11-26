"""Shared normalization, extraction, and schema validation for source parsers."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any


EVENT_KEYS = {
    "event_id",
    "source",
    "timestamp",
    "event_type",
    "username",
    "source_ip",
    "status",
    "message",
    "metadata",
}

_IP_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_.:])(?:\d{1,3}(?:\.\d{1,3}){3}|"
    r"[0-9A-Fa-f:]{3,})(?![A-Za-z0-9_.:])"
)
_USERNAME_PATTERNS = (
    re.compile(r"\binvalid user\s+([^\s,;]+)", re.IGNORECASE),
    re.compile(
        r"\b(?:for\s+(?:(?:invalid\s+)?user\s+)?|user\s+)"
        r"([^\s,;]+)",
        re.IGNORECASE,
    ),
    re.compile(r"\buser[=:]\s*([^\s,;]+)", re.IGNORECASE),
)
_SUCCESS = re.compile(
    r"\b(?:accepted (?:password|publickey|keyboard-interactive)|"
    r"successful authentication|authentication succeeded|login succeeded|"
    r"session opened for user)\b",
    re.IGNORECASE,
)
_FAILURE = re.compile(
    r"\b(?:failed (?:password|publickey|keyboard-interactive)|invalid user|"
    r"authentication failure|failed authentication|authentication failed|"
    r"login incorrect|permission denied (?:for|to)|access denied for user)\b",
    re.IGNORECASE,
)
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")
_MONTH_NUMBERS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}
_COMMON_MONTH_LENGTHS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def clean_message(value: str) -> str:
    """Remove terminal/control noise and normalize whitespace without deduping."""
    return _WHITESPACE.sub(" ", _CONTROL.sub("", _ANSI.sub("", value))).strip()


def extract_username(message: str) -> str | None:
    for pattern in _USERNAME_PATTERNS:
        match = pattern.search(message)
        if match:
            return match.group(1).strip("[](){}<>:'\"")
    return None


def extract_ip(message: str) -> str | None:
    for match in _IP_CANDIDATE.finditer(message):
        candidate = match.group(0).strip("[](){}<>,'\"")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def authentication_status(message: str) -> str | None:
    failure = _FAILURE.search(message)
    success = _SUCCESS.search(message)
    if failure and (not success or failure.start() <= success.start()):
        return "failure"
    if success:
        return "success"
    return None


def classify_event(
    source: str, message: str, severity: str | None, process: str | None
) -> str:
    searchable = f"{process or ''} {message}"
    if authentication_status(message) is not None or re.search(
        r"\b(?:authentication|login|password|publickey|pam_unix|session opened|"
        r"session closed)\b",
        searchable,
        re.IGNORECASE,
    ):
        return "authentication"
    if source == "Apache":
        if severity and severity.lower() in {"error", "crit", "alert", "emerg"}:
            return "web_server_error"
        if severity:
            return f"web_server_{severity.lower()}"
        return "web_server_event"
    if re.search(r"\b(?:kernel|systemd|service|daemon)\b", searchable, re.IGNORECASE):
        return "system_event"
    return "log_event"


def build_event(
    *,
    source: str,
    line_number: int,
    raw_line: str,
    parsed: dict[str, Any],
    template_id: str | None = None,
) -> dict[str, Any]:
    message = clean_message(parsed.get("message") or "")
    metadata: dict[str, Any] = {
        "hostname": parsed.get("hostname") or None,
        "process": parsed.get("process") or None,
        "pid": parsed.get("pid") or None,
        "severity": parsed.get("severity") or None,
        "timestamp_raw": parsed.get("timestamp_raw") or None,
        "timestamp_precision": parsed.get("timestamp_precision"),
        "month": parsed.get("month"),
        "day": parsed.get("day"),
        "hour": parsed.get("hour"),
        "minute": parsed.get("minute"),
        "second": parsed.get("second"),
        "year": parsed.get("year"),
        "timezone": parsed.get("timezone"),
        "limitations": list(parsed.get("limitations") or []),
        "raw_parse_matched": bool(parsed.get("matched")),
    }
    if template_id:
        metadata["log_template_id"] = template_id
    if parsed.get("parse_error"):
        metadata["parse_error"] = parsed["parse_error"]

    timestamp = parsed.get("timestamp")
    event = {
        "event_id": f"{source.lower()}-{line_number:06d}",
        "source": source,
        "timestamp": timestamp,
        "event_type": classify_event(
            source, message, metadata["severity"], metadata["process"]
        ),
        "username": extract_username(message),
        "source_ip": parsed.get("source_ip") or extract_ip(message),
        "status": authentication_status(message),
        "message": message or clean_message(raw_line),
        "metadata": metadata,
    }
    if parsed.get("source_ip_context"):
        metadata["source_ip_context"] = parsed["source_ip_context"]
    validate_event(event)
    return event


def validate_event(event: dict[str, Any]) -> None:
    """Raise ValueError for missing keys or invalid shared-schema values."""
    if set(event) != EVENT_KEYS:
        missing = sorted(EVENT_KEYS.difference(event))
        extra = sorted(set(event).difference(EVENT_KEYS))
        raise ValueError(f"event schema keys differ (missing={missing}, extra={extra})")
    for key in ("event_id", "source", "event_type", "message"):
        if not isinstance(event[key], str) or not event[key]:
            raise ValueError(f"{key} must be a non-empty string")
    for key in ("timestamp", "username", "source_ip", "status"):
        if event[key] is not None and not isinstance(event[key], str):
            raise ValueError(f"{key} must be a string or null")
    if event["status"] not in (None, "success", "failure"):
        raise ValueError("status must be success, failure, or null")
    if not isinstance(event["metadata"], dict):
        raise ValueError("metadata must be an object")


def parse_apache_timestamp(
    value: str,
) -> tuple[str | None, list[str], dict[str, int | None]]:
    try:
        parsed = datetime.strptime(value, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None, ["timestamp could not be parsed; source text preserved"], {}
    return (
        parsed.isoformat(timespec="seconds"),
        ["timestamp has no timezone in source; normalized value is timezone-naive"],
        {
            "month": parsed.month,
            "day": parsed.day,
            "hour": parsed.hour,
            "minute": parsed.minute,
            "second": parsed.second,
            "year": parsed.year,
            "timezone": None,
        },
    )


def parse_syslog_timestamp_parts(
    month_name: str, day_text: str, time_text: str
) -> dict[str, int | None]:
    """Extract known syslog components without supplying a year or timezone."""
    month = _MONTH_NUMBERS.get(month_name)
    day: int | None = None
    hour: int | None = None
    minute: int | None = None
    second: int | None = None

    try:
        candidate_day = int(day_text)
        if month is not None:
            maximum_day = _COMMON_MONTH_LENGTHS[month - 1]
            if month == 2:
                maximum_day = 29
            if 1 <= candidate_day <= maximum_day:
                day = candidate_day
    except ValueError:
        pass

    try:
        hour_text, minute_text, second_text = time_text.split(":")
        candidate_hour = int(hour_text)
        candidate_minute = int(minute_text)
        candidate_second = int(second_text)
        if 0 <= candidate_hour <= 23:
            hour = candidate_hour
        if 0 <= candidate_minute <= 59:
            minute = candidate_minute
        if 0 <= candidate_second <= 59:
            second = candidate_second
    except ValueError:
        pass

    return {
        "month": month,
        "day": day,
        "hour": hour,
        "minute": minute,
        "second": second,
        "year": None,
        "timezone": None,
    }


def _clock_seconds(parts: dict[str, Any]) -> int:
    return (
        int(parts["hour"]) * 3600
        + int(parts["minute"]) * 60
        + int(parts["second"])
    )


def _day_ordinal(month: int, day: int, leap_year: bool = False) -> int:
    month_lengths = list(_COMMON_MONTH_LENGTHS)
    if leap_year:
        month_lengths[1] = 29
    return sum(month_lengths[: month - 1]) + day


def _syslog_relative_delta(
    previous: dict[str, Any], current: dict[str, Any]
) -> tuple[int | None, str]:
    previous_date = (int(previous["month"]), int(previous["day"]))
    current_date = (int(current["month"]), int(current["day"]))
    previous_clock = _clock_seconds(previous)
    current_clock = _clock_seconds(current)

    if current_date == previous_date:
        if current_clock >= previous_clock:
            return current_clock - previous_clock, "same_calendar_day"
        if previous_clock >= 12 * 3600 and current_clock < 12 * 3600:
            return (
                24 * 3600 - previous_clock + current_clock,
                "inferred_midnight_rollover_same_date",
            )
        return None, "non_chronological_clock_order"

    if previous_date < current_date:
        crosses_unknown_leap_day = (
            previous_date <= (2, 28) and current_date >= (3, 1)
        )
        if crosses_unknown_leap_day:
            return None, "ambiguous_leap_day_year_unknown"
        leap_day_observed = previous_date == (2, 29) or current_date == (2, 29)
        days = _day_ordinal(
            current_date[0], current_date[1], leap_year=leap_day_observed
        ) - _day_ordinal(
            previous_date[0], previous_date[1], leap_year=leap_day_observed
        )
        return days * 86400 + current_clock - previous_clock, "calendar_day_advance"

    if previous_date[0] == 12 and current_date[0] == 1:
        days = (
            _COMMON_MONTH_LENGTHS[11]
            - previous_date[1]
            + current_date[1]
        )
        return days * 86400 + current_clock - previous_clock, "year_boundary_rollover"

    return None, "non_chronological_date_order"


def calculate_relative_times(events: list[dict[str, Any]]) -> None:
    """Annotate one source's ordered events with relative, non-absolute times."""
    sources = {event.get("source") for event in events}
    if len(sources) > 1:
        raise ValueError("relative times must be calculated within one source")
    source = next(iter(sources), None)
    apache_source = source == "Apache"
    previous: dict[str, Any] | None = None
    elapsed: int | None = None
    anchor_sequence_index: int | None = None
    segment = 0

    for sequence_index, event in enumerate(events, start=1):
        metadata = event["metadata"]
        parts = {
            key: metadata.get(key)
            for key in ("year", "month", "day", "hour", "minute", "second")
        }
        valid = all(
            parts[key] is not None
            for key in ("month", "day", "hour", "minute", "second")
        )
        if apache_source:
            valid = valid and parts["year"] is not None and event.get("timestamp") is not None

        basis = (
            "timezone_naive_wall_clock"
            if apache_source
            else "month_day_time_without_year_or_timezone"
        )
        delta: int | None = None
        if not valid:
            status = "timestamp_components_unavailable"
            previous = None
            elapsed = None
            anchor_sequence_index = None
            segment += 1
        elif previous is None:
            status = "segment_start"
            elapsed = 0
            anchor_sequence_index = sequence_index
            segment += 1
        elif apache_source:
            previous_datetime = datetime.fromisoformat(previous["timestamp"])
            current_datetime = datetime.fromisoformat(event["timestamp"])
            difference = int((current_datetime - previous_datetime).total_seconds())
            if difference >= 0:
                delta = difference
                status = "timezone_naive_wall_clock_advance"
                if elapsed is not None:
                    elapsed += delta
            else:
                status = "non_chronological_timestamp_order"
                elapsed = 0
                anchor_sequence_index = sequence_index
                segment += 1
        else:
            delta, status = _syslog_relative_delta(previous["parts"], parts)
            if delta is None:
                elapsed = 0
                anchor_sequence_index = sequence_index
                segment += 1
            elif elapsed is not None:
                elapsed += delta

        metadata["relative_time"] = {
            "sequence_index": sequence_index,
            "segment": segment,
            "anchor_sequence_index": anchor_sequence_index,
            "delta_from_previous_seconds": delta,
            "elapsed_seconds": elapsed if valid else None,
            "basis": basis,
            "status": status,
        }
        previous = (
            {"parts": parts, "timestamp": event.get("timestamp")} if valid else None
        )
