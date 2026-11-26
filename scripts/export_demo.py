#!/usr/bin/env python3
"""Export deterministic, fictional integration data from the local Python engines."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import math
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cybersecurity.detection_engine import DetectionConfig, detect  # noqa: E402
from data_engineering.apache_parser import parse_line as parse_apache  # noqa: E402
from data_engineering.common import validate_event  # noqa: E402
from data_engineering.linux_parser import parse_line as parse_linux  # noqa: E402
from data_engineering.openssh_parser import parse_line as parse_openssh  # noqa: E402
from privacy.anonymizer import Pseudonymizer  # noqa: E402
from privacy.cloud_payload_builder import (  # noqa: E402
    CloudPayloadRejected,
    build_cloud_payload,
    validate_cloud_payload,
)
from privacy.privacy_filter import (  # noqa: E402
    has_sensitive_content,
    sanitize_alert,
    sanitize_event,
    validate_alert,
)


FIXTURE_VERSION = "1"
DEMO_CONTEXT_TAG = "A5D3C0DE"
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
ANNOTATION_KEYS = {"event_id", "scenario_id", "scenario_type", "ground_truth"}
SENSITIVE_LABEL_KEYS = {"scenario_id", "scenario_type", "ground_truth"}
SCHEMA_FILES = {
    "event": "event-v1.json",
    "alert": "alert-v1.json",
    "cloud_payload": "cloud-payload-v1.json",
    "detection_defaults": "detection-defaults-v1.schema.json",
}


def _check_type(value: Any, schema_type: str) -> bool:
    if schema_type == "object":
        return isinstance(value, dict)
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        )
    if schema_type == "null":
        return value is None
    raise ValueError(f"unsupported JSON Schema type: {schema_type}")


def validate_json_schema(schema: dict[str, Any], value: Any, path: str = "$") -> None:
    """Validate the JSON Schema subset used by the checked-in contracts."""
    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = (
            expected_type if isinstance(expected_type, list) else [expected_type]
        )
        if not any(_check_type(value, type_name) for type_name in allowed_types):
            raise ValueError(f"{path} has an invalid JSON type")

    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path} does not match its contract constant")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} is outside its contract enum")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValueError(f"{path} is shorter than its contract minimum")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise ValueError(f"{path} does not match its contract pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path} is below its contract minimum")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            raise ValueError(f"{path} is below its exclusive contract minimum")

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ValueError(f"{path} has fewer items than its contract minimum")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_json_schema(schema["items"], item, f"{path}[{index}]")

    if isinstance(value, dict):
        missing = set(schema.get("required", ())).difference(value)
        if missing:
            raise ValueError(f"{path} is missing required contract fields")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, child in value.items():
            if key in properties:
                validate_json_schema(properties[key], child, f"{path}.{key}")
            elif additional is False:
                raise ValueError(f"{path} contains an unexpected contract field")
            elif isinstance(additional, dict):
                validate_json_schema(additional, child, f"{path}.{key}")

    for branch in schema.get("allOf", []):
        validate_json_schema(branch, value, path)

    for keyword, required_matches in (("anyOf", 1), ("oneOf", 1)):
        if keyword not in schema:
            continue
        matches = 0
        for branch in schema[keyword]:
            try:
                validate_json_schema(branch, value, path)
                matches += 1
            except ValueError:
                continue
        if (keyword == "anyOf" and matches < required_matches) or (
            keyword == "oneOf" and matches != 1
        ):
            raise ValueError(f"{path} does not satisfy its {keyword} contract")


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _load_contracts(contracts_dir: Path) -> dict[str, dict[str, Any]]:
    contracts: dict[str, dict[str, Any]] = {}
    for name, filename in SCHEMA_FILES.items():
        schema = _load_json(contracts_dir / filename)
        if not isinstance(schema, dict) or schema.get("$schema") != (
            "https://json-schema.org/draft/2020-12/schema"
        ):
            raise ValueError(f"{filename} is not a Draft 2020-12 JSON Schema")
        contracts[name] = schema
    defaults = _load_json(contracts_dir / "detection-defaults-v1.json")
    if not isinstance(defaults, dict):
        raise ValueError("detection-defaults-v1.json must contain an object")
    validate_json_schema(contracts["detection_defaults"], defaults)
    config = DetectionConfig.from_mapping(defaults)
    if config != DetectionConfig():
        raise ValueError("detection defaults do not match the Python engine defaults")
    contracts["detection_defaults_data"] = defaults
    return contracts


def _new_event(
    *,
    event_id: str,
    source: str,
    timestamp: datetime,
    hostname: str,
    username: str | None,
    source_ip: str | None,
    status: str | None,
    message: str,
    process: str,
) -> dict[str, Any]:
    timestamp = timestamp.astimezone(timezone.utc)
    event = {
        "event_id": event_id,
        "source": source,
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "event_type": (
            "authentication" if status is not None else "system_event"
        ),
        "username": username,
        "source_ip": source_ip,
        "status": status,
        "message": message,
        "metadata": {
            "hostname": hostname,
            "process": process,
            "pid": None,
            "severity": None,
            "timestamp_raw": timestamp.isoformat(timespec="seconds"),
            "timestamp_precision": "second",
            "month": timestamp.month,
            "day": timestamp.day,
            "hour": timestamp.hour,
            "minute": timestamp.minute,
            "second": timestamp.second,
            "year": timestamp.year,
            "timezone": "UTC",
            "limitations": [],
            "raw_parse_matched": True,
        },
    }
    validate_event(event)
    return event


def build_demo_scenarios() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Build deterministic fictional inputs and a separate annotation sidecar."""
    origin = datetime(2025, 2, 1, tzinfo=timezone.utc)
    events: list[dict[str, Any]] = []
    annotations: list[dict[str, str]] = []

    def add(
        scenario_id: str,
        scenario_type: str,
        ground_truth: str,
        source: str,
        hostname: str,
        seconds: int,
        username: str | None,
        source_ip: str | None,
        status: str | None,
        message: str,
        process: str = "sshd",
    ) -> None:
        event_id = f"demo-event-{len(events) + 1:04d}"
        event = _new_event(
            event_id=event_id,
            source=source,
            timestamp=origin + timedelta(seconds=seconds),
            hostname=hostname,
            username=username,
            source_ip=source_ip,
            status=status,
            message=message,
            process=process,
        )
        events.append(event)
        annotations.append(
            {
                "event_id": event_id,
                "scenario_id": scenario_id,
                "scenario_type": scenario_type,
                "ground_truth": ground_truth,
            }
        )

    for index in range(2):
        user = f"staff-demo-{index + 1}"
        address = f"192.0.2.{10 + index}"
        add(
            "normal-auth",
            "normal_authentication",
            "benign",
            "OpenSSH",
            "ssh-normal.example.test",
            index * 30,
            user,
            address,
            "success",
            f"Accepted publickey for {user} from {address} port 22 ssh2",
        )

    for index in range(5):
        user = "operator-demo"
        address = "192.0.2.21"
        add(
            "repeated-failures",
            "repeated_failed_logins",
            "suspicious",
            "OpenSSH",
            "ssh-repeat.example.test",
            600 + index * 40,
            user,
            address,
            "failure",
            f"Failed password for {user} from {address} port 22 ssh2",
        )

    for index, status in enumerate(("failure", "failure", "failure", "success")):
        user = "returning-demo"
        address = "198.51.100.30"
        verb = "Accepted publickey" if status == "success" else "Failed password"
        add(
            "failure-then-success",
            "success_after_repeated_failures",
            "suspicious",
            "OpenSSH",
            "ssh-recovery.example.test",
            1_200 + index * 30,
            user,
            address,
            status,
            f"{verb} for {user} from {address} port 22 ssh2",
        )

    for index in range(5):
        user = f"spray-demo-{index + 1}"
        address = "203.0.113.42"
        add(
            "password-spray",
            "password_spraying_indicator",
            "suspicious",
            "OpenSSH",
            "ssh-spray.example.test",
            1_800 + index * 30,
            user,
            address,
            "failure",
            f"Failed password for {user} from {address} port 22 ssh2",
        )

    for index, message in enumerate(
        (
            "sudo: pam_unix(sudo:auth): authentication failure; "
            "user=build-bot; COMMAND=/usr/bin/cat /etc/shadow",
            "sudo: user build-bot is not in sudoers; "
            "COMMAND=/usr/bin/cat /etc/shadow",
        )
    ):
        add(
            "privilege-context",
            "suspicious_privilege_escalation_context",
            "suspicious",
            "Linux",
            "linux-privilege.example.test",
            2_400 + index * 20,
            "build-bot",
            "192.0.2.51",
            "failure",
            message,
            process="sudo",
        )

    add(
        "privacy-demo",
        "sensitive_value_pseudonymization",
        "benign",
        "OpenSSH",
        "privacy-gateway.example.test",
        3_000,
        "privacy-demo-user",
        "198.51.100.77",
        "failure",
        "Failed password for privacy-demo-user from 198.51.100.77 "
        "access_token=FICTIONAL-DEMO-TOKEN-NOT-VALID",
    )

    events.sort(key=lambda event: (event["timestamp"], event["source"], event["event_id"]))
    for source in sorted({event["source"] for event in events}):
        source_events = [event for event in events if event["source"] == source]
        first_timestamp = datetime.fromisoformat(source_events[0]["timestamp"])
        previous_timestamp: datetime | None = None
        for sequence_index, event in enumerate(source_events, start=1):
            current_timestamp = datetime.fromisoformat(event["timestamp"])
            event["metadata"]["relative_time"] = {
                "sequence_index": sequence_index,
                "segment": 0,
                "anchor_sequence_index": 1,
                "delta_from_previous_seconds": (
                    None
                    if previous_timestamp is None
                    else int((current_timestamp - previous_timestamp).total_seconds())
                ),
                "elapsed_seconds": int(
                    (current_timestamp - first_timestamp).total_seconds()
                ),
                "basis": "source_relative_wall_clock",
                "status": (
                    "segment_start"
                    if previous_timestamp is None
                    else "timezone_aware_wall_clock_advance"
                ),
            }
            previous_timestamp = current_timestamp

    for event in events:
        validate_event(event)
        if SENSITIVE_LABEL_KEYS.intersection(event):
            raise ValueError("ground-truth fields must not enter detector inputs")
    return events, annotations


def _assert_fictional_events(events: list[dict[str, Any]]) -> None:
    for event in events:
        source_ip = event["source_ip"]
        if source_ip is not None:
            address = ipaddress.ip_address(source_ip)
            if not any(address in network for network in DOCUMENTATION_NETWORKS):
                raise ValueError("demo event contains a non-documentation IP")
        hostname = event["metadata"].get("hostname")
        if hostname and not hostname.endswith(".example.test"):
            raise ValueError("demo event contains a non-fictional hostname")
        if "access_token=" in event["message"] and (
            "FICTIONAL-DEMO-TOKEN-NOT-VALID" not in event["message"]
        ):
            raise ValueError("demo credential marker is missing")


def _contains_annotation_key(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(SENSITIVE_LABEL_KEYS.intersection(value)) or any(
            _contains_annotation_key(child) for child in value.values()
        )
    if isinstance(value, list):
        return any(_contains_annotation_key(child) for child in value)
    return False


def _parser_cases() -> list[dict[str, Any]]:
    cases = (
        (
            "OpenSSH",
            "Feb  1 00:00:00 ssh-demo.example.test sshd[100]: "
            "Failed password for parser-demo from 192.0.2.8 port 22 ssh2\n",
            parse_openssh,
        ),
        (
            "Linux",
            "Feb  1 00:00:01 linux-demo.example.test sshd[101]: "
            "Accepted publickey for parser-demo from 198.51.100.8 port 22 ssh2\n",
            parse_linux,
        ),
        (
            "Apache",
            "[Sun Feb 02 00:00:02 2025] [error] fictional worker failed\n",
            parse_apache,
        ),
    )
    return [
        {
            "source": source,
            "raw_line": raw_line,
            "expected_event": parser(raw_line, index),
        }
        for index, (source, raw_line, parser) in enumerate(cases, start=1)
    ]


def _relative_time_for_alert(
    alert: dict[str, Any], events_by_id: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    evidence = [
        events_by_id[event_id]
        for event_id in alert["evidence_event_ids"]
        if event_id in events_by_id
    ]
    if not evidence:
        return None
    relative = evidence[-1]["metadata"].get("relative_time")
    if not isinstance(relative, dict):
        return None
    result = {
        key: relative.get(key)
        for key in (
            "elapsed_seconds",
            "delta_from_previous_seconds",
            "basis",
        )
        if key in relative
    }
    if result.get("elapsed_seconds") is None and result.get(
        "delta_from_previous_seconds"
    ) is None:
        return None
    return result


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _assert_no_mapping_export(value: Any) -> None:
    if isinstance(value, dict):
        forbidden_mapping_keys = {"mapping", "mappings", "pseudonym_map", "_mapping"}
        if any(str(key).lower() in forbidden_mapping_keys for key in value):
            raise ValueError("private pseudonym mapping data cannot be exported")
        for child in value.values():
            _assert_no_mapping_export(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_mapping_export(child)


def export_demo(
    demo_dir: Path,
    fixtures_dir: Path,
    contracts_dir: Path | None = None,
) -> dict[str, Any]:
    contracts_dir = contracts_dir or ROOT / "contracts"
    contracts = _load_contracts(contracts_dir)
    config = DetectionConfig.from_mapping(contracts["detection_defaults_data"])
    events, annotations = build_demo_scenarios()
    _assert_fictional_events(events)

    for event in events:
        validate_event(event)
        validate_json_schema(contracts["event"], event)
    if any(_contains_annotation_key(event) for event in events):
        raise ValueError("ground-truth annotations leaked into detector input")

    detection = detect(events, config)
    if detection.malformed_event_count:
        raise ValueError("fictional demo events failed detector input validation")
    alerts = detection.alerts
    for alert in alerts:
        validate_alert(alert)
        validate_json_schema(contracts["alert"], alert)

    events_by_id = {event["event_id"]: event for event in events}
    evidence_ids = {
        event_id
        for alert in alerts
        for event_id in alert["evidence_event_ids"]
    }
    if not evidence_ids.issubset(events_by_id):
        raise ValueError("alert evidence references a missing demo event")

    context = Pseudonymizer(context_tag=DEMO_CONTEXT_TAG)
    sanitized_events = [
        sanitize_event(copy.deepcopy(event), context) for event in events
    ]
    sanitized_alerts = [sanitize_alert(alert, context) for alert in alerts]
    for event in sanitized_events:
        validate_event(event)
        validate_json_schema(contracts["event"], event)
    for alert in sanitized_alerts:
        validate_alert(alert)
        validate_json_schema(contracts["alert"], alert)
    if any(has_sensitive_content(event) for event in sanitized_events):
        raise ValueError("sensitive content remains in sanitized demo events")
    if any(has_sensitive_content(alert) for alert in sanitized_alerts):
        raise ValueError("sensitive content remains in sanitized demo alerts")

    cloud_context = Pseudonymizer(context_tag=DEMO_CONTEXT_TAG)
    cloud_payloads: list[dict[str, Any]] = []
    for alert in alerts:
        if alert["category"] != "security":
            continue
        relative_time = _relative_time_for_alert(alert, events_by_id)
        payload = build_cloud_payload(
            alert,
            authorized=True,
            context=cloud_context,
            relative_time=relative_time,
        )
        validate_cloud_payload(payload)
        validate_json_schema(contracts["cloud_payload"], payload)
        cloud_payloads.append(payload)

    if not cloud_payloads:
        raise ValueError("expected at least one valid cloud payload example")

    rejection_examples: list[dict[str, Any]] = []
    sample_alert = next(alert for alert in alerts if alert["category"] == "security")
    try:
        build_cloud_payload(
            sample_alert,
            context=Pseudonymizer(context_tag=DEMO_CONTEXT_TAG),
        )
    except CloudPayloadRejected as error:
        rejection_examples.append(
            {
                "case": "missing_authorization",
                "rejected": True,
                "reason": str(error),
            }
        )
    else:
        raise ValueError("cloud payload without authorization was accepted")

    residual_payload = copy.deepcopy(cloud_payloads[0])
    residual_payload["evidence_summary"] += " Contact demo@example.test"
    try:
        validate_cloud_payload(residual_payload)
    except CloudPayloadRejected as error:
        rejection_examples.append(
            {
                "case": "residual_sensitive_information",
                "rejected": True,
                "reason": str(error),
            }
        )
    else:
        raise ValueError("cloud payload with residual sensitive information was accepted")

    parser_cases = _parser_cases()
    for case in parser_cases:
        validate_event(case["expected_event"])
        validate_json_schema(contracts["event"], case["expected_event"])
    privacy_event = next(
        event
        for event in events
        if event["event_id"]
        == next(
            annotation["event_id"]
            for annotation in annotations
            if annotation["scenario_id"] == "privacy-demo"
        )
    )
    sanitized_privacy_event = sanitize_event(
        copy.deepcopy(privacy_event),
        Pseudonymizer(context_tag=DEMO_CONTEXT_TAG),
    )

    scenario_counts: dict[str, int] = {}
    for annotation in annotations:
        scenario_counts[annotation["scenario_type"]] = (
            scenario_counts.get(annotation["scenario_type"], 0) + 1
        )
    dashboard_summary = {
        "schema_version": "1",
        "event_count": len(events),
        "alert_count": len(alerts),
        "security_alert_count": sum(
            alert["category"] == "security" for alert in alerts
        ),
        "operational_anomaly_count": sum(
            alert["category"] == "operational_anomaly" for alert in alerts
        ),
        "alert_counts_by_rule": {
            rule_id: sum(alert["rule_id"] == rule_id for alert in alerts)
            for rule_id in sorted({alert["rule_id"] for alert in alerts})
        },
        "scenario_event_counts": scenario_counts,
        "data_is_fictional": True,
        "cloud_requests_made": 0,
    }
    cloud_examples = {
        "schema_version": "1",
        "notice": "Examples only; these objects do not grant authorization or trigger network requests.",
        "accepted_payloads": cloud_payloads,
        "rejections": rejection_examples,
    }
    fixture_bundle = {
        "fixture_version": FIXTURE_VERSION,
        "parser_cases": parser_cases,
        "detection": {
            "input_events": events,
            "expected_alerts": alerts,
            "malformed_event_count": detection.malformed_event_count,
        },
        "privacy": {
            "input_event": privacy_event,
            "expected_sanitized_event": sanitized_privacy_event,
        },
        "cloud_payload": {
            "accepted_payloads": cloud_payloads,
            "rejections": rejection_examples,
        },
    }

    output_files = {
        "events.json": events,
        "alerts.json": alerts,
        "sanitized-events.json": sanitized_events,
        "sanitized-alerts.json": sanitized_alerts,
        "cloud-payload-examples.json": cloud_examples,
        "dashboard-summary.json": dashboard_summary,
        "annotations.json": annotations,
        "validation-report.json": {
            "fixture_version": FIXTURE_VERSION,
            "valid": True,
            "events_checked": len(events),
            "alerts_checked": len(alerts),
            "parser_cases_checked": len(parser_cases),
            "accepted_cloud_payloads_checked": len(cloud_payloads),
            "expected_cloud_rejections_checked": len(rejection_examples),
            "ground_truth_separate": True,
            "pseudonym_mappings_exported": False,
            "real_loghub_data_exported": False,
            "cloud_requests_made": 0,
        },
    }
    _assert_no_mapping_export(output_files)
    _assert_no_mapping_export(fixture_bundle)

    for filename, value in output_files.items():
        _atomic_json(demo_dir / filename, value)
    _atomic_json(fixtures_dir / "integration-v1.json", fixture_bundle)
    return output_files["validation-report.json"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo-dir", type=Path, default=ROOT / "demo")
    parser.add_argument("--fixtures-dir", type=Path, default=ROOT / "tests" / "fixtures")
    parser.add_argument("--contracts-dir", type=Path, default=ROOT / "contracts")
    arguments = parser.parse_args(argv)
    try:
        report = export_demo(
            arguments.demo_dir,
            arguments.fixtures_dir,
            arguments.contracts_dir,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        print(f"Demo export failed: {error}", file=sys.stderr)
        return 1
    print(
        "Demo export validated: "
        f"{report['events_checked']} events, "
        f"{report['alerts_checked']} alerts, "
        f"{report['parser_cases_checked']} parser cases, "
        f"{report['accepted_cloud_payloads_checked']} accepted cloud examples, "
        f"{report['expected_cloud_rejections_checked']} expected rejections; "
        "fictional-only, no mappings exported, no cloud requests."
    )
    print(f"Demo files: {arguments.demo_dir}")
    print(f"Golden fixture: {arguments.fixtures_dir / 'integration-v1.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
