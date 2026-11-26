"""Fail-closed construction and validation of minimized cloud-analysis payloads."""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Mapping
from typing import Any

from .anonymizer import Pseudonymizer
from .privacy_filter import ALERT_KEYS, has_sensitive_content, validate_alert


PAYLOAD_KEYS = {
    "schema_version",
    "rule_id",
    "severity",
    "category",
    "source",
    "entities",
    "event_count",
    "relative_time",
    "evidence_summary",
}
_SOURCES = {"OpenSSH", "Linux", "Apache"}
_CATEGORIES = {"security", "operational_anomaly"}
_SEVERITIES = {"low", "medium", "high", "critical"}
_RULE_ID = re.compile(r"R0[1-7]")
_ALIAS = re.compile(r"^(?P<prefix>IP|USER)_(?P<context>[A-F0-9]{8})_\d{3,}$")
_TIME_KEYS = {
    "elapsed_seconds",
    "delta_from_previous_seconds",
    "basis",
}
_TIME_BASES = {
    "month_day_time_without_year_or_timezone",
    "timezone_naive_wall_clock",
    "source_relative_wall_clock",
}


class CloudPayloadRejected(ValueError):
    """Raised when a payload cannot be proven to meet the local contract."""


def _validate_relative_time(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value).difference(_TIME_KEYS):
        raise CloudPayloadRejected("relative_time contains unexpected fields")
    if (
        not value
        or "basis" not in value
        or not isinstance(value["basis"], str)
        or value["basis"] not in _TIME_BASES
    ):
        raise CloudPayloadRejected("relative_time must include a recognized basis")
    output: dict[str, Any] = {"basis": value["basis"]}
    for key in ("elapsed_seconds", "delta_from_previous_seconds"):
        if key not in value:
            continue
        number = value[key]
        if number is None:
            continue
        if isinstance(number, bool) or not isinstance(number, (int, float)):
            raise CloudPayloadRejected(f"relative_time {key} must be non-negative")
        if number < 0 or (
            isinstance(number, float) and not math.isfinite(number)
        ):
            raise CloudPayloadRejected(f"relative_time {key} must be non-negative")
        output[key] = number
    if not any(
        output.get(key) is not None
        for key in ("elapsed_seconds", "delta_from_previous_seconds")
    ):
        raise CloudPayloadRejected("relative_time has no usable relative value")
    return output


def build_cloud_payload(
    alert: Mapping[str, Any],
    *,
    authorized: bool = False,
    context: Pseudonymizer | None = None,
    relative_time: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build only allowlisted, sanitized alert fields; never call a cloud API."""
    if authorized is not True:
        raise CloudPayloadRejected("explicit cloud authorization is required")
    if not isinstance(context, Pseudonymizer):
        raise CloudPayloadRejected("an investigation-scoped pseudonymizer is required")
    try:
        if not isinstance(alert, Mapping) or set(alert) != ALERT_KEYS:
            raise ValueError("alert has missing or unexpected fields")
        validate_alert(alert)
    except (TypeError, ValueError) as error:
        raise CloudPayloadRejected(f"invalid alert input: {error}") from error

    if alert["rule_id"] not in {f"R0{index}" for index in range(1, 8)}:
        raise CloudPayloadRejected("unsupported rule identifier")
    if alert["severity"] not in _SEVERITIES:
        raise CloudPayloadRejected("unsupported alert severity")
    if alert["category"] not in _CATEGORIES:
        raise CloudPayloadRejected("unsupported event category")
    if alert["source"] not in _SOURCES:
        raise CloudPayloadRejected("unsupported event source")
    if not _RULE_ID.fullmatch(alert["rule_id"]):
        raise CloudPayloadRejected("malformed rule identifier")
    if alert["detection_method"] != "deterministic_rule":
        raise CloudPayloadRejected("unsupported detection method")
    if alert["event_count"] < 1:
        raise CloudPayloadRejected("event_count must be positive")

    entities: dict[str, str] = {}
    source_ip = alert["source_ip"]
    if source_ip is not None:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError as error:
            raise CloudPayloadRejected("source_ip is not a valid IP address") from error
        entities["source_ip"] = context.pseudonymize(source_ip, "ip_address")
    username = alert["username"]
    if username is not None:
        if not username or len(username) > 256:
            raise CloudPayloadRejected("username is empty or too long")
        entities["username"] = context.pseudonymize(username, "username")

    try:
        summary = context.sanitize_text(
            f"{alert['rule_name']}: {alert['description']}".strip()
        )
        payload = {
            "schema_version": "1",
            "rule_id": alert["rule_id"],
            "severity": alert["severity"],
            "category": alert["category"],
            "source": alert["source"],
            "entities": entities,
            "event_count": alert["event_count"],
            "relative_time": _validate_relative_time(relative_time),
            "evidence_summary": summary,
        }
        validate_cloud_payload(payload)
        return payload
    except CloudPayloadRejected:
        raise
    except (TypeError, ValueError) as error:
        raise CloudPayloadRejected(
            "payload sanitization or validation failed"
        ) from error


def validate_cloud_payload(payload: Mapping[str, Any]) -> None:
    """Reject extra fields, malformed values, and any detected residual PII."""
    if not isinstance(payload, Mapping) or set(payload) != PAYLOAD_KEYS:
        raise CloudPayloadRejected("payload has missing or unexpected fields")
    if not isinstance(payload["schema_version"], str) or payload["schema_version"] != "1":
        raise CloudPayloadRejected("unsupported payload schema version")
    if (
        not isinstance(payload["rule_id"], str)
        or payload["rule_id"] not in {f"R0{index}" for index in range(1, 8)}
    ):
        raise CloudPayloadRejected("unsupported rule identifier")
    if not isinstance(payload["severity"], str) or payload["severity"] not in _SEVERITIES:
        raise CloudPayloadRejected("unsupported severity")
    if not isinstance(payload["category"], str) or payload["category"] not in _CATEGORIES:
        raise CloudPayloadRejected("unsupported category")
    if not isinstance(payload["source"], str) or payload["source"] not in _SOURCES:
        raise CloudPayloadRejected("unsupported source")
    if (
        isinstance(payload["event_count"], bool)
        or not isinstance(payload["event_count"], int)
        or payload["event_count"] < 1
    ):
        raise CloudPayloadRejected("event_count must be a positive integer")
    if not isinstance(payload["evidence_summary"], str):
        raise CloudPayloadRejected("evidence_summary must be a string")
    entities = payload["entities"]
    if not isinstance(entities, Mapping) or set(entities).difference(
        {"source_ip", "username"}
    ):
        raise CloudPayloadRejected("entities contains unexpected fields")
    expected_prefix = {"source_ip": "IP_", "username": "USER_"}
    for key, alias in entities.items():
        alias_match = _ALIAS.fullmatch(alias) if isinstance(alias, str) else None
        if (
            not isinstance(alias, str)
            or not alias.startswith(expected_prefix[key])
            or alias_match is None
            or alias_match.group("prefix") != expected_prefix[key][:-1]
        ):
            raise CloudPayloadRejected(f"entities.{key} is not pseudonymized")
    _validate_relative_time(payload["relative_time"])
    if has_sensitive_content(payload):
        raise CloudPayloadRejected("sensitive content remains in cloud payload")
