"""Non-mutating sanitization of events, alerts, and nested JSON structures."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from data_engineering.common import validate_event

from .anonymizer import Pseudonymizer
from .pii_detector import scan_sensitive, secret_kind_for_field


ALERT_KEYS = {
    "alert_id",
    "rule_id",
    "rule_name",
    "category",
    "severity",
    "source",
    "timestamp",
    "timestamp_quality",
    "source_ip",
    "username",
    "event_count",
    "evidence_event_ids",
    "description",
    "recommended_action",
    "detection_method",
}


def sanitize_structure(value: Any, context: Pseudonymizer) -> Any:
    """Return a sanitized JSON-compatible copy; never mutate the input value."""
    return _sanitize(value, context, None)


def _sanitize(
    value: Any, context: Pseudonymizer, field_name: str | None
) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            secret_kind = secret_kind_for_field(key)
            if secret_kind and child is not None:
                result[key] = context.sanitize_value(
                    child if isinstance(child, str) else _redaction_marker(secret_kind),
                    field_name=key,
                )
            else:
                result[key] = _sanitize(child, context, key)
        return result
    if isinstance(value, list):
        return [_sanitize(child, context, field_name) for child in value]
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite numbers are not valid JSON values")
        return context.sanitize_value(value, field_name=field_name)
    if isinstance(value, str):
        return context.sanitize_value(value, field_name=field_name)
    raise TypeError(
        f"unsupported value for JSON sanitization: {type(value).__name__}"
    )


def _redaction_marker(kind: str) -> str:
    return {
        "password": "[REDACTED_PASSWORD]",
        "api_key": "[REDACTED_SECRET]",
        "access_token": "[REDACTED_SECRET]",
        "authorization": "[REDACTED_AUTHORIZATION]",
        "session_id": "[REDACTED_SESSION]",
        "private_key": "[REDACTED_PRIVATE_KEY]",
        "secret": "[REDACTED_SECRET]",
    }.get(kind, "[REDACTED_SECRET]")


def sanitize_event(event: Mapping[str, Any], context: Pseudonymizer) -> dict[str, Any]:
    """Validate and sanitize a normalized event without changing the source."""
    if not isinstance(event, Mapping):
        raise TypeError("event must be a mapping")
    copied = dict(event)
    validate_event(copied)
    sanitized = sanitize_structure(copied, context)
    validate_event(sanitized)
    return sanitized


def validate_alert(alert: Mapping[str, Any]) -> None:
    if not isinstance(alert, Mapping) or set(alert) != ALERT_KEYS:
        raise ValueError("alert does not match the cybersecurity alert schema")
    for key in ("alert_id", "rule_id", "rule_name", "category", "severity", "source"):
        if not isinstance(alert[key], str) or not alert[key]:
            raise ValueError(f"alert {key} must be a non-empty string")
    if alert["timestamp"] is not None and not isinstance(alert["timestamp"], str):
        raise ValueError("alert timestamp must be a string or null")
    if alert["source_ip"] is not None and not isinstance(alert["source_ip"], str):
        raise ValueError("alert source_ip must be a string or null")
    if alert["username"] is not None and not isinstance(alert["username"], str):
        raise ValueError("alert username must be a string or null")
    if isinstance(alert["event_count"], bool) or not isinstance(alert["event_count"], int):
        raise ValueError("alert event_count must be an integer")
    if alert["event_count"] < 1:
        raise ValueError("alert event_count must be positive")
    if not isinstance(alert["evidence_event_ids"], list) or not all(
        isinstance(item, str) and item for item in alert["evidence_event_ids"]
    ):
        raise ValueError("alert evidence_event_ids must be a list of strings")
    for key in (
        "description",
        "recommended_action",
        "detection_method",
        "timestamp_quality",
    ):
        if not isinstance(alert[key], str):
            raise ValueError(f"alert {key} must be a string")


def sanitize_alert(
    alert: Mapping[str, Any], context: Pseudonymizer
) -> dict[str, Any]:
    """Validate and sanitize a detector alert, preserving its schema."""
    validate_alert(alert)
    sanitized = sanitize_structure(dict(alert), context)
    validate_alert(sanitized)
    return sanitized


def has_sensitive_content(value: Any) -> bool:
    """Return whether any string in a nested object still matches the detector."""
    return bool(scan_sensitive(value, allow_pseudonyms=True))
