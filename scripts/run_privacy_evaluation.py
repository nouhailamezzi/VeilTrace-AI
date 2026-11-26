#!/usr/bin/env python3
"""Evaluate local privacy detection and sanitization on fictional records."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from privacy.anonymizer import Pseudonymizer  # noqa: E402
from privacy.cloud_payload_builder import (  # noqa: E402
    CloudPayloadRejected,
    build_cloud_payload,
    validate_cloud_payload,
)
from privacy.pii_detector import canonical_entity, scan_sensitive  # noqa: E402
from privacy.privacy_filter import has_sensitive_content, sanitize_structure  # noqa: E402


PSEUDONYM_KINDS = {
    "ipv4",
    "ipv6",
    "ip_address",
    "username",
    "hostname",
    "email",
    "phone_number",
    "mac_address",
    "file_path",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"malformed JSONL at line {line_number}") from error
            if not isinstance(record, dict):
                raise ValueError(f"JSONL record at line {line_number} is not an object")
            records.append(record)
    return records


def _entity_key(kind: str, value: str) -> tuple[str, str]:
    comparison_kind = (
        "ip_address" if kind in {"ipv4", "ipv6"} else kind
    )
    return comparison_kind, canonical_entity(kind, value)[1]


def _score_entities(
    records: list[dict[str, Any]], annotations: list[dict[str, Any]]
) -> tuple[dict[str, Any], dict[str, set[tuple[str, str]]]]:
    record_ids = [record.get("record_id") for record in records]
    if any(not isinstance(record_id, str) or not record_id for record_id in record_ids):
        raise ValueError("every privacy record requires a record_id")
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("privacy record IDs must be unique")
    by_id = {record["record_id"]: record for record in records}

    truth: dict[str, set[tuple[str, str]]] = {}
    for annotation in annotations:
        if set(annotation) != {"record_id", "scenario_type", "sensitive_entities"}:
            raise ValueError("privacy annotation has unexpected or missing fields")
        record_id = annotation["record_id"]
        if record_id not in by_id or record_id in truth:
            raise ValueError("privacy annotation has an unknown or duplicate record ID")
        entities = annotation["sensitive_entities"]
        if not isinstance(entities, list):
            raise ValueError("sensitive_entities must be a list")
        truth[record_id] = set()
        for entity in entities:
            if (
                not isinstance(entity, dict)
                or set(entity) != {"kind", "value"}
                or not isinstance(entity["kind"], str)
                or not isinstance(entity["value"], str)
            ):
                raise ValueError("invalid sensitive entity annotation")
            truth[record_id].add(_entity_key(entity["kind"], entity["value"]))
    if set(truth) != set(by_id):
        raise ValueError("every privacy input must have exactly one annotation")

    predicted: dict[str, set[tuple[str, str]]] = {}
    for record_id, record in by_id.items():
        if set(record) != {"record_id", "input"}:
            raise ValueError("privacy input includes unexpected fields or labels")
        predicted[record_id] = {
            _entity_key(match.kind, match.value)
            for match in scan_sensitive(record["input"])
        }

    tp = sum(len(truth[key] & predicted[key]) for key in truth)
    fp = sum(len(predicted[key] - truth[key]) for key in truth)
    fn = sum(len(truth[key] - predicted[key]) for key in truth)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return (
        {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        truth,
    )


def _measure_pseudonyms(
    records: list[dict[str, Any]], context: Pseudonymizer
) -> tuple[float, float, int]:
    appearances: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    sanitized_by_id: dict[str, str] = {}
    for record in records:
        record_id = record["record_id"]
        sanitized = sanitize_structure(record["input"], context)
        sanitized_json = json.dumps(sanitized, sort_keys=True, ensure_ascii=False)
        sanitized_by_id[record_id] = sanitized_json
        unique_entities = {
            _entity_key(match.kind, match.value): (match.kind, match.value)
            for match in scan_sensitive(record["input"])
            if match.kind in PSEUDONYM_KINDS
        }
        for entity_key, (kind, value) in unique_entities.items():
            alias = context.pseudonymize(value, kind)
            appearances[entity_key].append((record_id, alias))
            if alias not in sanitized_json:
                raise ValueError("pseudonym missing from sanitized record")

    repeated = {
        key: values for key, values in appearances.items() if len(values) > 1
    }
    consistent = sum(len({alias for _, alias in values}) == 1 for values in repeated.values())
    consistency_rate = consistent / len(repeated) if repeated else 1.0

    possible_pairs = 0
    preserved_pairs = 0
    for values in repeated.values():
        for left_index, (left_id, left_alias) in enumerate(values):
            for right_id, right_alias in values[left_index + 1 :]:
                possible_pairs += 1
                if (
                    left_alias == right_alias
                    and left_alias in sanitized_by_id[left_id]
                    and right_alias in sanitized_by_id[right_id]
                ):
                    preserved_pairs += 1
    relationship_rate = (
        preserved_pairs / possible_pairs if possible_pairs else 1.0
    )
    return consistency_rate, relationship_rate, len(repeated)


def _payload_checks() -> tuple[int, int]:
    alert = {
        "alert_id": "synthetic-alert-001",
        "rule_id": "R01",
        "rule_name": "Repeated failed logins",
        "category": "security",
        "severity": "medium",
        "source": "OpenSSH",
        "timestamp": "2025-02-01T00:00:00+00:00",
        "timestamp_quality": "complete_with_timezone",
        "source_ip": "192.0.2.200",
        "username": "demo-operator",
        "event_count": 5,
        "evidence_event_ids": ["synthetic-event-001"],
        "description": (
            "Repeated failures for demo-operator from 192.0.2.200."
        ),
        "recommended_action": "Review the local authentication evidence.",
        "detection_method": "deterministic_rule",
    }
    relative_time = {
        "elapsed_seconds": 30,
        "delta_from_previous_seconds": 5,
        "basis": "source_relative_wall_clock",
    }
    payload = build_cloud_payload(
        alert,
        authorized=True,
        context=Pseudonymizer(context_tag="A1B2C3D4"),
        relative_time=relative_time,
    )
    validate_cloud_payload(payload)

    rejection_checks = 0
    rejected = 0
    for action in (
        lambda: build_cloud_payload(
            alert,
            authorized=False,
            context=Pseudonymizer(context_tag="A1B2C3D4"),
            relative_time=relative_time,
        ),
        lambda: build_cloud_payload(
            {**alert, "raw_log": "fictional extra field"},
            authorized=True,
            context=Pseudonymizer(context_tag="A1B2C3D4"),
            relative_time=relative_time,
        ),
        lambda: validate_cloud_payload(
            {**payload, "evidence_summary": "Contact alice@example.test"}
        ),
    ):
        rejection_checks += 1
        try:
            action()
        except CloudPayloadRejected:
            rejected += 1
    return rejected, rejection_checks


def evaluate(
    records: list[dict[str, Any]], annotations: list[dict[str, Any]]
) -> dict[str, Any]:
    started = time.perf_counter()
    entity_metrics, _ = _score_entities(records, annotations)
    context = Pseudonymizer(context_tag="A1B2C3D4")
    consistency, relationship_preservation, repeated_entity_count = (
        _measure_pseudonyms(records, context)
    )
    leaked_records = sum(
        has_sensitive_content(sanitize_structure(record["input"], context))
        for record in records
    )
    rejected, rejection_checks = _payload_checks()
    execution_seconds = time.perf_counter() - started
    return {
        "record_count": len(records),
        **entity_metrics,
        "residual_sensitive_records": leaked_records,
        "residual_leakage_rate": leaked_records / len(records) if records else 0.0,
        "pseudonym_consistency": consistency,
        "relationship_preservation": relationship_preservation,
        "repeated_entity_count": repeated_entity_count,
        "payload_rejection_checks": rejection_checks,
        "payload_rejections": rejected,
        "valid_payload_accepted": True,
        "execution_seconds": execution_seconds,
    }


def _render_report(metrics: dict[str, Any]) -> str:
    demo_context = Pseudonymizer(context_tag="A1B2C3D4")
    demo_input = {
        "username": "analyst-01",
        "source_ip": "192.0.2.25",
        "message": "Failed login for analyst-01 from 192.0.2.25",
    }
    demo_output = sanitize_structure(demo_input, demo_context)
    rows = [
        ["TP", str(metrics["tp"])],
        ["FP", str(metrics["fp"])],
        ["FN", str(metrics["fn"])],
    ]
    return "\n".join(
        [
            "# Privacy Engine Evaluation",
            "",
            "Generated locally by `scripts/run_privacy_evaluation.py`. Inputs and "
            "annotations contain fictional values only; annotations are loaded "
            "only by the evaluator and are not passed to sanitization or payload construction.",
            "",
            "## Evaluation unit and metrics",
            "",
            "- Detection unit: one unique `(record, entity type, canonical entity)` "
            "pair. Repeated mentions of the same entity within one record count once.",
            "- Precision = TP / (TP + FP); recall = TP / (TP + FN); F1 is the "
            "harmonic mean of precision and recall.",
            "- Residual leakage rate = sanitized records with at least one "
            "sensitive finding / all records.",
            "- Pseudonym consistency measures repeated entity identities mapped "
            "to one alias within the same investigation context.",
            "- Relationship preservation measures same-identity record pairs "
            "that retain a shared pseudonym after sanitization.",
            "",
            "## Results",
            "",
            f"- Privacy input records: {metrics['record_count']}",
            f"- Detection precision: {metrics['precision']:.4f}",
            f"- Detection recall: {metrics['recall']:.4f}",
            f"- Detection F1: {metrics['f1']:.4f}",
            f"- Residual sensitive records: {metrics['residual_sensitive_records']}",
            f"- Residual sensitive leakage rate: {metrics['residual_leakage_rate']:.4f}",
            f"- Pseudonym consistency: {metrics['pseudonym_consistency']:.4f}",
            f"- Relationship preservation: {metrics['relationship_preservation']:.4f}",
            f"- Repeated entity identities evaluated: {metrics['repeated_entity_count']}",
            f"- Payload rejection checks: {metrics['payload_rejections']}/"
            f"{metrics['payload_rejection_checks']} rejected as expected",
            "- Valid authorized payload: accepted",
            f"- Processing time: {metrics['execution_seconds']:.6f} seconds",
            "",
            "### Entity detection counts",
            "",
            "| Count | Value |",
            "| --- | ---: |",
            *[f"| {name} | {value} |" for name, value in rows],
            "",
            "## Synthetic example",
            "",
            "The following values are fictional and use a documentation-only IP:",
            "",
            "```json",
            json.dumps(demo_input, indent=2, ensure_ascii=False),
            "```",
            "",
            "After sanitization in the example investigation context:",
            "",
            "```json",
            json.dumps(demo_output, indent=2, ensure_ascii=False),
            "```",
            "",
            "These results characterize only this small, constructed dataset. "
            "Pattern matching can miss obfuscated or novel secrets and can "
            "overmatch unusual text; this is not a guarantee of anonymity or "
            "real-world privacy effectiveness.",
            "",
        ]
    )


def _write_report(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path.relative_to(ROOT)} exists; use --force to replace")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="replace evaluation report")
    arguments = parser.parse_args(argv)
    synthetic = ROOT / "data" / "synthetic"
    try:
        records = load_jsonl(synthetic / "privacy_test_records.jsonl")
        annotations = load_jsonl(synthetic / "privacy_test_annotations.jsonl")
        if len(records) != 100:
            raise ValueError(f"expected 100 privacy records, found {len(records)}")
        metrics = evaluate(records, annotations)
        _write_report(
            ROOT / "docs" / "PRIVACY_EVALUATION.md",
            _render_report(metrics),
            arguments.force,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        print(f"Privacy evaluation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"Privacy evaluation: {metrics['record_count']} records; "
        f"TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']}; "
        f"precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
        f"F1={metrics['f1']:.4f}; "
        f"leakage={metrics['residual_leakage_rate']:.4f}; "
        f"payload rejections={metrics['payload_rejections']}/"
        f"{metrics['payload_rejection_checks']}; "
        f"elapsed={metrics['execution_seconds']:.6f}s"
    )
    print("No record values or pseudonym mappings were written to terminal output.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
