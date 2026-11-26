#!/usr/bin/env python3
"""Generate deterministic fictional security log events and isolated labels."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data_engineering.common import calculate_relative_times, validate_event  # noqa: E402


SEED = 20261126
TARGET_PER_SPLIT = 250
SOURCE_HOSTS = {
    "OpenSSH": "ssh-gw-01.example.test",
    "Linux": "linux-auth-01.example.test",
    "Apache": "web-01.example.test",
}


def build_event(
    event_id: str,
    source: str,
    timestamp: datetime,
    hostname: str,
    message: str,
    *,
    username: str | None = None,
    source_ip: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    repeat_count: int | None = None,
) -> dict[str, Any]:
    timestamp = timestamp.astimezone(timezone.utc)
    if source == "Apache":
        event_type = (
            "web_server_error"
            if severity in {"error", "crit", "alert", "emerg"}
            else "web_server_notice"
        )
    elif status is not None or any(
        word in message.lower()
        for word in ("authentication", "password", "login", "pam_unix")
    ):
        event_type = "authentication"
    else:
        event_type = "system_event"

    metadata: dict[str, Any] = {
        "hostname": hostname,
        "process": {"OpenSSH": "sshd", "Linux": "sshd", "Apache": None}[source],
        "pid": None,
        "severity": severity,
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
    }
    if repeat_count is not None:
        metadata["repeat_count"] = repeat_count
    event = {
        "event_id": event_id,
        "source": source,
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "status": status,
        "message": message,
        "metadata": metadata,
    }
    validate_event(event)
    return event


class DatasetBuilder:
    def __init__(self, split: str, rng: random.Random) -> None:
        self.split = split
        self.rng = rng
        self.events: list[dict[str, Any]] = []
        self.annotations: list[dict[str, str]] = []
        self.counter = 0

    def add(
        self,
        scenario_id: str,
        scenario_type: str,
        ground_truth: str,
        source: str,
        timestamp: datetime,
        message: str,
        *,
        hostname: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        repeat_count: int | None = None,
    ) -> dict[str, Any]:
        self.counter += 1
        event_id = f"{self.split}-{self.counter:06d}"
        event = build_event(
            event_id,
            source,
            timestamp,
            hostname or SOURCE_HOSTS[source],
            message,
            username=username,
            source_ip=source_ip,
            status=status,
            severity=severity,
            repeat_count=repeat_count,
        )
        self.events.append(event)
        self.annotations.append(
            {
                "event_id": event_id,
                "scenario_id": scenario_id,
                "scenario_type": scenario_type,
                "ground_truth": ground_truth,
                "split": self.split,
            }
        )
        return event


def documentation_ip(number: int, network: str = "192.0.2") -> str:
    octet = (number - 1) % 253 + 1
    return f"{network}.{octet}"


def add_success_burst(
    builder: DatasetBuilder,
    scenario_id: str,
    label: str,
    source: str,
    start: datetime,
    count: int,
    step_seconds: int = 45,
) -> None:
    for index in range(count):
        username = f"staff-{builder.rng.randint(1, 50):02d}"
        builder.add(
            scenario_id,
            "normal_successful_authentication",
            label,
            source,
            start + timedelta(seconds=index * step_seconds),
            f"Accepted publickey for {username} from "
            f"{documentation_ip(index + 1)} port 2200 ssh2",
            username=username,
            source_ip=documentation_ip(index + 1),
            status="success",
        )


def generate_development() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    builder = DatasetBuilder("dev", random.Random(SEED))
    origin = datetime(2025, 1, 1, tzinfo=timezone.utc)

    for window in range(20):
        add_success_burst(
            builder,
            f"dev-ssh-baseline-{window + 1:02d}",
            "benign",
            "OpenSSH",
            origin + timedelta(hours=window),
            10,
        )
    for window in range(3):
        add_success_burst(
            builder,
            f"dev-linux-baseline-{window + 1:02d}",
            "benign",
            "Linux",
            origin + timedelta(days=2, hours=window * 4),
            10,
        )
    for window in range(2):
        start = origin + timedelta(days=4, hours=window * 4)
        for index in range(10):
            builder.add(
                f"dev-apache-baseline-{window + 1:02d}",
                "normal_application_activity",
                "benign",
                "Apache",
                start + timedelta(seconds=index * 50),
                "workerEnv.init() completed",
                severity="notice",
            )

    return _ordered_split(builder)


def generate_evaluation() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    builder = DatasetBuilder("eval", random.Random(SEED + 1))
    origin = datetime(2025, 2, 1, tzinfo=timezone.utc)
    scenario_index = 0

    def start_next() -> datetime:
        nonlocal scenario_index
        scenario_index += 1
        return origin + timedelta(hours=2 * scenario_index)

    # Benign cases, including activity that is close to but below rule thresholds.
    start = start_next()
    add_success_burst(builder, "eval-normal-success", "benign", "OpenSSH", start, 10)

    start = start_next()
    for index in range(4):
        builder.add(
            "eval-occasional-failures",
            "occasional_legitimate_failures",
            "benign",
            "OpenSSH",
            start + timedelta(seconds=index * 50),
            "Failed password for staff-07 from 198.51.100.20 port 2200 ssh2",
            username="staff-07",
            source_ip="198.51.100.20",
            status="failure",
        )

    start = start_next()
    for index in range(6):
        builder.add(
            "eval-normal-admin",
            "normal_administrative_activity",
            "benign",
            "Linux",
            start + timedelta(seconds=index * 35),
            "sudo: ops-admin TTY=pts/0 USER=root "
            "COMMAND=/usr/bin/systemctl restart sshd",
            username="ops-admin",
            source_ip="203.0.113.10",
        )

    start = start_next()
    for index in range(7):
        builder.add(
            "eval-repeated-app-errors",
            "repeated_application_errors",
            "benign",
            "Apache",
            start + timedelta(seconds=index * 20),
            "upstream worker returned a temporary error",
            severity="error",
        )

    start = start_next()
    for index in range(4):
        username = f"staff-{index + 20:02d}"
        builder.add(
            "eval-below-spray-threshold",
            "password-spray-like_but_below_threshold",
            "benign",
            "OpenSSH",
            start + timedelta(seconds=index * 40),
            f"Failed password for {username} from 198.51.100.30 port 2200 ssh2",
            username=username,
            source_ip="198.51.100.30",
            status="failure",
        )

    start = start_next()
    for index in range(2):
        builder.add(
            "eval-below-invalid-threshold",
            "repeated_invalid_username_below_threshold",
            "benign",
            "OpenSSH",
            start + timedelta(seconds=index * 40),
            "Invalid user made-up-account from 198.51.100.31",
            username="made-up-account",
            source_ip="198.51.100.31",
            status="failure",
        )

    start = start_next()
    builder.add(
        "eval-root-login",
        "successful_root_login_without_other_evidence",
        "benign",
        "OpenSSH",
        start,
        "Accepted publickey for root from 203.0.113.11 port 2200 ssh2",
        username="root",
        source_ip="203.0.113.11",
        status="success",
    )

    start = start_next()
    for index, status in enumerate(("failure", "failure", "success")):
        phrase = "Failed password" if status == "failure" else "Accepted password"
        builder.add(
            "eval-success-after-two-failures",
            "successful_login_after_too_few_failures",
            "benign",
            "OpenSSH",
            start + timedelta(seconds=index * 45),
            f"{phrase} for staff-15 from 198.51.100.32 port 2200 ssh2",
            username="staff-15",
            source_ip="198.51.100.32",
            status=status,
        )

    start = start_next()
    for index in range(12):
        status = "failure" if index in {2, 8} else "success"
        username = f"staff-{index + 1:02d}"
        source_ip = documentation_ip(index + 60, "203.0.113")
        phrase = "Failed password" if status == "failure" else "Accepted publickey"
        builder.add(
            "eval-mixed-benign",
            "mixed_normal_activity",
            "benign",
            "OpenSSH",
            start + timedelta(seconds=index * 30),
            f"{phrase} for {username} from {source_ip} port 2200 ssh2",
            username=username,
            source_ip=source_ip,
            status=status,
        )

    # Suspicious scenarios, each with a separate host/time context.
    start = start_next()
    for index in range(6):
        builder.add(
            "eval-r01-repeated-failures",
            "repeated_failed_logins",
            "suspicious",
            "OpenSSH",
            start + timedelta(seconds=index * 35),
            "Failed password for staff-40 from 192.0.2.40 port 2200 ssh2",
            username="staff-40",
            source_ip="192.0.2.40",
            status="failure",
        )

    start = start_next()
    for index, status in enumerate(("failure", "failure", "failure", "success")):
        phrase = "Failed password" if status == "failure" else "Accepted password"
        builder.add(
            "eval-r02-fail-then-success",
            "successful_authentication_after_repeated_failures",
            "suspicious",
            "OpenSSH",
            start + timedelta(seconds=index * 40),
            f"{phrase} for staff-41 from 192.0.2.41 port 2200 ssh2",
            username="staff-41",
            source_ip="192.0.2.41",
            status=status,
        )

    start = start_next()
    for index in range(4):
        source_ip = documentation_ip(index + 80, "198.51.100")
        builder.add(
            "eval-r03-invalid-usernames",
            "repeated_invalid_username_across_sources",
            "suspicious",
            "OpenSSH",
            start + timedelta(seconds=index * 40),
            f"Invalid user abandoned-account from {source_ip}",
            username="abandoned-account",
            source_ip=source_ip,
            status="failure",
        )

    start = start_next()
    for index in range(7):
        username = f"spray-{index + 1:02d}"
        builder.add(
            "eval-r04-password-spray",
            "multiple_accounts_from_one_source",
            "suspicious",
            "OpenSSH",
            start + timedelta(seconds=index * 30),
            f"Failed password for {username} from 192.0.2.44 port 2200 ssh2",
            username=username,
            source_ip="192.0.2.44",
            status="failure",
        )

    start = start_next()
    for index, message in enumerate(
        (
            "sudo: pam_unix(sudo:auth): authentication failure; "
            "user=build-bot; COMMAND=/usr/bin/cat /etc/shadow",
            "sudo: user build-bot is not in sudoers; "
            "COMMAND=/usr/bin/cat /etc/shadow",
        )
    ):
        builder.add(
            "eval-r05-privilege-escalation",
            "unauthorized_sensitive_privilege_attempt",
            "suspicious",
            "Linux",
            start + timedelta(seconds=index * 20),
            message,
            username="build-bot",
            source_ip="203.0.113.45",
            status="failure",
        )

    start = start_next()
    for index in range(15):
        username = f"burst-user-{index + 1:02d}"
        source_ip = documentation_ip(index + 100, "203.0.113")
        builder.add(
            "eval-r06-auth-volume",
            "authentication_volume_above_baseline",
            "suspicious",
            "OpenSSH",
            start + timedelta(seconds=index * 12),
            f"Failed password for {username} from {source_ip} port 2200 ssh2",
            username=username,
            source_ip=source_ip,
            status="failure",
        )

    start = start_next()
    for index in range(12):
        status = "failure" if index < 5 else "success"
        username = f"staff-{index + 1:02d}"
        phrase = "Failed password" if status == "failure" else "Accepted publickey"
        builder.add(
            "eval-mixed-suspicious",
            "mixed_normal_and_suspicious_activity",
            "suspicious",
            "OpenSSH",
            start + timedelta(seconds=index * 25),
            f"{phrase} for {username} from 192.0.2.46 port 2200 ssh2",
            username=username,
            source_ip="192.0.2.46",
            status=status,
        )

    start = start_next()
    for index in range(5):
        builder.add(
            "eval-r01-with-operational-errors",
            "security_activity_with_application_errors",
            "suspicious",
            "OpenSSH",
            start + timedelta(seconds=index * 35),
            "Failed password for staff-55 from 192.0.2.55 port 2200 ssh2",
            username="staff-55",
            source_ip="192.0.2.55",
            status="failure",
        )
    for index in range(6):
        builder.add(
            "eval-r01-with-operational-errors",
            "security_activity_with_application_errors",
            "suspicious",
            "Apache",
            start + timedelta(seconds=index * 25),
            "upstream worker returned a temporary error",
            severity="error",
        )

    # Benign busy periods resemble volume anomalies but stay at the baseline threshold.
    for window in range(11):
        start = start_next()
        add_success_burst(
            builder,
            f"eval-routine-window-{window + 1:02d}",
            "benign",
            "OpenSSH",
            start,
            12,
            step_seconds=35,
        )
    start = start_next()
    add_success_burst(
        builder,
        "eval-routine-window-12",
        "benign",
        "OpenSSH",
        start,
        8,
        step_seconds=35,
    )

    return _ordered_split(builder)


def _ordered_split(
    builder: DatasetBuilder,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in builder.events:
        by_source[event["source"]].append(event)
    for source_events in by_source.values():
        source_events.sort(key=lambda event: event["timestamp"])
        calculate_relative_times(source_events)

    ordered = sorted(
        builder.events,
        key=lambda event: (event["timestamp"], event["source"], event["event_id"]),
    )
    return ordered, builder.annotations


def _write_jsonl(path: Path, records: list[dict[str, Any]], force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path.relative_to(ROOT)} exists; use --force to replace")
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
            for record in records:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="replace generated files")
    arguments = parser.parse_args(argv)

    development = generate_development()
    evaluation = generate_evaluation()
    outputs = {
        "development_events.jsonl": development[0],
        "development_annotations.jsonl": development[1],
        "evaluation_events.jsonl": evaluation[0],
        "evaluation_annotations.jsonl": evaluation[1],
    }
    destination = ROOT / "data" / "synthetic"
    existing = [name for name in outputs if (destination / name).exists()]
    if existing and not arguments.force:
        print(
            "Synthetic outputs already exist; use --force to replace: "
            + ", ".join(existing),
            file=sys.stderr,
        )
        return 1

    try:
        for filename, rows in outputs.items():
            _write_jsonl(destination / filename, rows, force=arguments.force)
            print(f"{filename}: {len(rows):,} records")
    except (OSError, ValueError) as error:
        print(f"Generation failed: {error}", file=sys.stderr)
        return 1

    for split_name, annotations in (
        ("development", development[1]),
        ("evaluation", evaluation[1]),
    ):
        scenario_labels: dict[str, str] = {}
        for annotation in annotations:
            scenario_labels[annotation["scenario_id"]] = annotation["ground_truth"]
        counts = Counter(annotation["scenario_type"] for annotation in annotations)
        print(
            f"{split_name}: {len(scenario_labels)} scenarios; "
            f"{sum(value == 'suspicious' for value in scenario_labels.values())} "
            f"suspicious and "
            f"{sum(value == 'benign' for value in scenario_labels.values())} benign; "
            f"scenario types={dict(sorted(counts.items()))}"
        )

    if len(development[0]) + len(evaluation[0]) != TARGET_PER_SPLIT * 2:
        print("Generation count did not match the planned 500 entries.", file=sys.stderr)
        return 1
    print(f"Total generated event records: {TARGET_PER_SPLIT * 2:,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
