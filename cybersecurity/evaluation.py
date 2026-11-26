"""Scenario-level evaluation using labels isolated from detector inputs."""

from __future__ import annotations

from collections import Counter
from typing import Any


def evaluate_scenarios(
    annotations: list[dict[str, str]],
    alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    scenario_labels: dict[str, str] = {}
    event_scenarios: dict[str, str] = {}
    for annotation in annotations:
        event_id = annotation.get("event_id")
        scenario_id = annotation.get("scenario_id")
        label = annotation.get("ground_truth")
        if not event_id or not scenario_id or label not in {"benign", "suspicious"}:
            raise ValueError("invalid or incomplete evaluation annotation")
        if event_id in event_scenarios:
            raise ValueError(f"duplicate event annotation: {event_id}")
        existing_label = scenario_labels.setdefault(scenario_id, label)
        if existing_label != label:
            raise ValueError(f"conflicting ground truth within scenario: {scenario_id}")
        event_scenarios[event_id] = scenario_id

    if not scenario_labels:
        raise ValueError("no annotated evaluation scenarios were provided")

    predicted_scenarios: set[str] = set()
    for alert in alerts:
        if alert.get("category") != "security":
            continue
        for event_id in alert.get("evidence_event_ids", []):
            scenario_id = event_scenarios.get(event_id)
            if scenario_id:
                predicted_scenarios.add(scenario_id)

    counts = Counter(
        (
            scenario_labels[scenario_id] == "suspicious",
            scenario_id in predicted_scenarios,
        )
        for scenario_id in scenario_labels
    )
    tp = counts[(True, True)]
    fn = counts[(True, False)]
    fp = counts[(False, True)]
    tn = counts[(False, False)]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {
        "unit": "scenario",
        "scenario_count": len(scenario_labels),
        "suspicious_scenarios": sum(
            label == "suspicious" for label in scenario_labels.values()
        ),
        "benign_scenarios": sum(label == "benign" for label in scenario_labels.values()),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "operational_anomaly_alerts_excluded": sum(
            alert.get("category") == "operational_anomaly" for alert in alerts
        ),
        "predicted_scenario_ids": sorted(predicted_scenarios),
        "scenario_type_counts": dict(
            Counter(annotation["scenario_type"] for annotation in annotations)
        ),
    }
