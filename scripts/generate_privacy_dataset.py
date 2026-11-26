#!/usr/bin/env python3
"""Generate a reproducible fictional privacy test set and isolated annotations."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SEED = 20261127
RECORD_COUNT = 100


class PrivacyDatasetBuilder:
    def __init__(self, seed: int = SEED) -> None:
        self.rng = random.Random(seed)
        self.records: list[dict[str, Any]] = []
        self.annotations: list[dict[str, Any]] = []

    def add(
        self,
        scenario_type: str,
        payload: Any,
        entities: list[tuple[str, str]] | None = None,
    ) -> None:
        record_id = f"privacy-{len(self.records) + 1:03d}"
        self.records.append({"record_id": record_id, "input": payload})
        self.annotations.append(
            {
                "record_id": record_id,
                "scenario_type": scenario_type,
                "sensitive_entities": [
                    {"kind": kind, "value": value}
                    for kind, value in (entities or [])
                ],
            }
        )


def build_dataset(seed: int = SEED) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    builder = PrivacyDatasetBuilder(seed)

    for index in range(10):
        builder.add(
            "benign_numeric_and_version_values",
            {
                "event_type": "worker_status",
                "message": (
                    f"Completed batch job-{index + 100} in "
                    f"{builder.rng.randint(400, 2000)} ms"
                ),
                "metadata": {
                    "retry_count": index % 4,
                    "build": "release-2026.11.26",
                    "ratio": 0.875,
                },
            },
        )

    for index in range(10):
        address = f"192.0.2.{index + 1}"
        builder.add(
            "structured_ipv4",
            {"event_type": "peer_connect", "source_ip": address, "message": "Peer connected"},
            [("ip_address", address)],
        )

    for index in range(10):
        address = f"2001:db8::{index + 1:x}"
        builder.add(
            "structured_ipv6",
            {"event_type": "peer_connect", "source_ip": address, "message": "Peer connected"},
            [("ip_address", address)],
        )

    for index in range(10):
        address = f"analyst-{index + 1:02d}@example.test"
        builder.add(
            "nested_email",
            {
                "event_type": "contact_update",
                "message": "Account metadata refreshed",
                "metadata": {"contact": {"email_address": address}},
            },
            [("email", address)],
        )

    for index in range(10):
        username = f"analyst-{index + 1:02d}"
        hostname = f"gateway-{index + 1:02d}.example.test"
        builder.add(
            "username_and_hostname",
            {
                "event_type": "authentication",
                "username": username,
                "message": f"Successful login for {username} from {hostname}",
                "metadata": {"hostname": hostname},
            },
            [("username", username), ("hostname", hostname)],
        )

    for index in range(10):
        phone = f"+1-202-555-{1000 + index:04d}"
        mac = f"02:00:00:00:00:{index + 1:02x}"
        builder.add(
            "phone_and_mac",
            {
                "event_type": "device_contact",
                "message": f"Contact {phone}; device address {mac}",
            },
            [("phone_number", phone), ("mac_address", mac)],
        )

    credential_cases = (
        ("password", "password", "Fictional-Password-001"),
        ("api_key", "api_key", "FAKE_API_KEY_001"),
        ("access_token", "access_token", "fictional-access-token-001"),
        ("authorization", "authorization", "Bearer fictional-bearer-001"),
        ("session_id", "session_id", "fictional-session-001"),
        (
            "private_key",
            "private_key",
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "FICTIONAL-ONLY-KEY-MATERIAL-001\n"
            "-----END RSA PRIVATE KEY-----",
        ),
        ("secret", "secret", "fictional-client-secret-001"),
        (
            "authorization_header_in_message",
            "message",
            "Request Authorization: Bearer fictional-header-token-001",
        ),
        (
            "query_token_in_message",
            "message",
            "GET /status?access_token=fictional-query-token-001",
        ),
        ("password", "password", "Fictional-Password-010"),
    )
    for index, (scenario, field, value) in enumerate(credential_cases):
        if field == "message":
            payload = {"event_type": "request", "message": value}
        else:
            payload = {
                "event_type": "credential_test",
                "metadata": {field: value},
            }
        kind = scenario if scenario in {"authorization"} else field
        if scenario == "authorization_header_in_message":
            kind = "authorization"
            value = "Authorization: Bearer fictional-header-token-001"
        elif scenario == "query_token_in_message":
            kind = "access_token"
            value = "fictional-query-token-001"
        builder.add(scenario, payload, [(kind, value)])

    for index in range(10):
        token = f"fictional-query-token-{index + 1:03d}"
        hostname = f"api-{index + 1:02d}.example.test"
        path = f"/home/demo-{index + 1:02d}/private/report.txt"
        builder.add(
            "url_query_and_nested_path",
            {
                "event_type": "http_request",
                "message": f"GET https://{hostname}/export?access_token={token}",
                "metadata": {"file_path": path},
            },
            [
                ("access_token", token),
                ("hostname", hostname),
                ("file_path", path),
            ],
        )

    repeated_ip = "192.0.2.77"
    repeated_user = "repeat-user"
    repeated_host = "ssh-gw.example.test"
    for _ in range(10):
        builder.add(
            "repeated_entities_for_consistency",
            {
                "event_type": "authentication",
                "username": repeated_user,
                "source_ip": repeated_ip,
                "message": (
                    f"Failed login for {repeated_user} from {repeated_ip}; "
                    f"retry via {repeated_host}"
                ),
                "metadata": {"hostname": repeated_host},
            },
            [
                ("username", repeated_user),
                ("ip_address", repeated_ip),
                ("hostname", repeated_host),
            ],
        )

    for index in range(10):
        if index % 2:
            payload: Any = {
                "message": (
                    "Malformed candidate 999.999.999.999; "
                    "build=2026.11.26; elapsed=00:12:34"
                ),
                "metadata": {"request_count": 4242, "fraction": 3.14159},
            }
        else:
            payload = {
                "message": None if index == 0 else "ordinary event",
                "metadata": [None, True, 17, {"custom_code": "ABCDEF123456"}],
            }
        builder.add("malformed_or_ambiguous_decoy", payload)

    if len(builder.records) != RECORD_COUNT:
        raise ValueError(f"expected {RECORD_COUNT} records, generated {len(builder.records)}")
    return builder.records, builder.annotations


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
    parser.add_argument("--force", action="store_true", help="replace generated records")
    arguments = parser.parse_args(argv)
    records, annotations = build_dataset()
    destination = ROOT / "data" / "synthetic"
    outputs = {
        "privacy_test_records.jsonl": records,
        "privacy_test_annotations.jsonl": annotations,
    }
    if not arguments.force:
        existing = [name for name in outputs if (destination / name).exists()]
        if existing:
            print(
                "Privacy test outputs already exist; use --force to replace: "
                + ", ".join(existing),
                file=sys.stderr,
            )
            return 1
    try:
        for filename, rows in outputs.items():
            _write_jsonl(destination / filename, rows, arguments.force)
            print(f"{filename}: {len(rows)} records")
    except (OSError, ValueError) as error:
        print(f"Privacy dataset generation failed: {error}", file=sys.stderr)
        return 1
    print(f"Seed: {SEED}; total privacy test inputs: {len(records)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
