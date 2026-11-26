import unittest
from datetime import datetime, timedelta, timezone

from cybersecurity.detection_engine import (
    DetectionConfig,
    build_baseline,
    detect,
)
from cybersecurity.evaluation import evaluate_scenarios


BASE = datetime(2025, 2, 1, tzinfo=timezone.utc)


def event(
    index,
    *,
    source="OpenSSH",
    hostname="ssh-gw-01.example.test",
    timestamp=BASE,
    username="staff-01",
    source_ip="192.0.2.10",
    status="failure",
    message="Failed password for staff-01 from 192.0.2.10 port 2200 ssh2",
    severity=None,
    segment=0,
):
    if timestamp is not None:
        timestamp_value = timestamp.isoformat(timespec="seconds")
        parts = {
            "year": timestamp.year,
            "month": timestamp.month,
            "day": timestamp.day,
            "hour": timestamp.hour,
            "minute": timestamp.minute,
            "second": timestamp.second,
            "timezone": "UTC",
        }
    else:
        timestamp_value = None
        parts = {
            "year": None,
            "month": 2,
            "day": 1,
            "hour": 0,
            "minute": 0,
            "second": 0,
            "timezone": None,
        }
    metadata = {
        "hostname": hostname,
        "process": "sshd" if source != "Apache" else None,
        "pid": None,
        "severity": severity,
        "timestamp_raw": timestamp_value,
        "timestamp_precision": "second",
        **parts,
        "limitations": [],
        "raw_parse_matched": True,
        "relative_time": {
            "sequence_index": index,
            "segment": segment,
            "anchor_sequence_index": 1,
            "delta_from_previous_seconds": None if index == 1 else 1,
            "elapsed_seconds": None if timestamp is None else index,
            "basis": "test",
            "status": "test",
        },
    }
    event_type = (
        "web_server_error"
        if source == "Apache" and severity == "error"
        else "authentication"
        if status is not None
        else "log_event"
    )
    return {
        "event_id": f"test-{index:04d}",
        "source": source,
        "timestamp": timestamp_value,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "status": status,
        "message": message,
        "metadata": metadata,
    }


class DetectionEngineTests(unittest.TestCase):
    def test_normal_authentication_does_not_alert(self):
        events = [
            event(1, status="success", message="Accepted publickey for staff-01"),
            event(
                2,
                status="failure",
                timestamp=BASE + timedelta(seconds=30),
            ),
        ]

        self.assertEqual(detect(events).alerts, [])

    def test_repeated_failures_generate_one_evidence_backed_r01_alert(self):
        events = [
            event(index, timestamp=BASE + timedelta(seconds=index * 30))
            for index in range(1, 6)
        ]

        result = detect(events)
        r01_alerts = [alert for alert in result.alerts if alert["rule_id"] == "R01"]

        self.assertEqual(len(r01_alerts), 1)
        self.assertEqual(r01_alerts[0]["event_count"], 5)
        self.assertEqual(len(r01_alerts[0]["evidence_event_ids"]), 5)
        self.assertEqual(r01_alerts[0]["detection_method"], "deterministic_rule")

    def test_success_after_three_failures_generates_r02(self):
        events = [
            event(index, timestamp=BASE + timedelta(seconds=index * 30))
            for index in range(1, 4)
        ]
        events.append(
            event(
                4,
                timestamp=BASE + timedelta(seconds=120),
                status="success",
                message="Accepted password for staff-01 from 192.0.2.10",
            )
        )

        alerts = detect(events).alerts

        self.assertIn("R02", {alert["rule_id"] for alert in alerts})

    def test_password_spray_generates_r04(self):
        events = [
            event(
                index,
                timestamp=BASE + timedelta(seconds=index * 30),
                username=f"staff-{index:02d}",
                message=f"Failed password for staff-{index:02d} from 192.0.2.10",
            )
            for index in range(1, 6)
        ]

        alerts = detect(events).alerts

        self.assertIn("R04", {alert["rule_id"] for alert in alerts})

    def test_repeated_invalid_usernames_across_sources_generate_r03(self):
        events = [
            event(
                index,
                timestamp=BASE + timedelta(seconds=index * 40),
                username="retired-account",
                source_ip=f"198.51.100.{index}",
                message=f"Invalid user retired-account from 198.51.100.{index}",
            )
            for index in range(1, 5)
        ]

        alerts = detect(events).alerts

        self.assertIn("R03", {alert["rule_id"] for alert in alerts})

    def test_window_boundary_is_inclusive_and_outside_window_is_not_alerted(self):
        at_boundary = [
            event(
                index,
                timestamp=BASE + timedelta(seconds=(index - 1) * 150),
            )
            for index in range(1, 6)
        ]
        outside = [
            event(
                index,
                timestamp=BASE + timedelta(seconds=offset),
            )
            for index, offset in enumerate((0, 150, 300, 450, 601), start=1)
        ]

        self.assertIn("R01", {alert["rule_id"] for alert in detect(at_boundary).alerts})
        self.assertNotIn("R01", {alert["rule_id"] for alert in detect(outside).alerts})

    def test_missing_timestamps_do_not_create_time_window_alerts(self):
        events = [
            event(index, timestamp=None)
            for index in range(1, 6)
        ]

        self.assertEqual(detect(events).alerts, [])

    def test_non_chronological_sequence_is_not_correlated_across_boundary(self):
        timestamps = (
            BASE,
            BASE + timedelta(seconds=30),
            BASE + timedelta(seconds=60),
            BASE - timedelta(hours=1),
            BASE - timedelta(hours=1) + timedelta(seconds=30),
        )
        events = [
            event(index, timestamp=timestamp)
            for index, timestamp in enumerate(timestamps, start=1)
        ]

        self.assertNotIn("R01", {alert["rule_id"] for alert in detect(events).alerts})

    def test_duplicate_auth_messages_and_repeat_counters_are_not_double_counted(self):
        duplicate_events = [
            event(index, timestamp=BASE)
            for index in range(1, 6)
        ]
        duplicate_events_result = detect(duplicate_events)
        self.assertNotIn(
            "R01",
            {alert["rule_id"] for alert in duplicate_events_result.alerts},
        )

        repeated = event(
            1,
            timestamp=BASE,
            message=(
                "Failed password for staff-01 from 192.0.2.10; "
                "last message repeated 5 times"
            ),
        )
        repeated_result = detect([repeated])
        r01 = next(alert for alert in repeated_result.alerts if alert["rule_id"] == "R01")
        self.assertEqual(r01["event_count"], 5)
        self.assertEqual(r01["evidence_event_ids"], ["test-0001"])

    def test_legitimate_admin_and_root_login_are_not_r05(self):
        events = [
            event(
                1,
                source="Linux",
                username="ops-admin",
                message=(
                    "sudo: ops-admin USER=root "
                    "COMMAND=/usr/bin/systemctl restart sshd"
                ),
                status=None,
            ),
            event(
                2,
                username="root",
                message="Accepted publickey for root from 203.0.113.1",
                status="success",
            ),
        ]

        self.assertNotIn("R05", {alert["rule_id"] for alert in detect(events).alerts})

    def test_privilege_rule_requires_suspicious_context_and_deduplicates(self):
        events = [
            event(
                1,
                source="Linux",
                username="build-bot",
                status="failure",
                message=(
                    "sudo: pam_unix(sudo:auth): authentication failure; "
                    "user=build-bot; COMMAND=/usr/bin/cat /etc/shadow"
                ),
            ),
            event(
                2,
                source="Linux",
                username="build-bot",
                timestamp=BASE + timedelta(seconds=20),
                status="failure",
                message=(
                    "sudo: user build-bot is not in sudoers; "
                    "COMMAND=/usr/bin/cat /etc/shadow"
                ),
            ),
        ]

        alerts = [alert for alert in detect(events).alerts if alert["rule_id"] == "R05"]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0]["evidence_event_ids"]), 2)

    def test_r06_requires_an_available_baseline(self):
        config = DetectionConfig(r06_min_auth_events=3)
        development = [
            event(index, status="success", timestamp=BASE + timedelta(seconds=index))
            for index in range(1, 3)
        ]
        development.extend(
            event(
                index + 2,
                status="success",
                timestamp=BASE + timedelta(minutes=10, seconds=index),
            )
            for index in range(1, 3)
        )
        baseline = build_baseline(development, config)
        evaluation = [
            event(
                index,
                status="success",
                username=f"staff-{index:02d}",
                source_ip=f"198.51.100.{index}",
                timestamp=BASE + timedelta(minutes=30, seconds=index * 20),
            )
            for index in range(1, 5)
        ]

        alerts = detect(evaluation, config, baseline).alerts

        self.assertIn("R06", {alert["rule_id"] for alert in alerts})
        self.assertNotIn(
            "R06",
            {alert["rule_id"] for alert in detect(evaluation, config).alerts},
        )

    def test_repeated_application_errors_are_operational_not_security_alerts(self):
        events = [
            event(
                index,
                source="Apache",
                hostname="web-01.example.test",
                username=None,
                source_ip=None,
                status=None,
                severity="error",
                message="upstream worker failed",
                timestamp=BASE + timedelta(seconds=index * 20),
            )
            for index in range(1, 7)
        ]

        alerts = detect(events).alerts

        self.assertEqual([alert["rule_id"] for alert in alerts], ["R07"])
        self.assertEqual(alerts[0]["category"], "operational_anomaly")

    def test_empty_and_malformed_inputs_are_safe_and_explicit(self):
        self.assertEqual(detect([]).alerts, [])
        malformed = {"event_id": "bad", "source": "OpenSSH"}
        result = detect([malformed, None])
        self.assertEqual(result.alerts, [])
        self.assertEqual(result.malformed_event_count, 2)

    def test_annotation_fields_are_rejected_as_detector_input(self):
        labeled = event(1, status="success")
        labeled["ground_truth"] = "suspicious"
        result = detect([labeled])

        self.assertEqual(result.alerts, [])
        self.assertEqual(result.malformed_event_count, 1)

    def test_evaluation_is_scenario_level_and_excludes_operational_alerts(self):
        annotations = [
            {
                "event_id": "event-1",
                "scenario_id": "benign",
                "scenario_type": "normal",
                "ground_truth": "benign",
                "split": "evaluation",
            },
            {
                "event_id": "event-2",
                "scenario_id": "suspicious",
                "scenario_type": "attack-like",
                "ground_truth": "suspicious",
                "split": "evaluation",
            },
        ]
        alerts = [
            {
                "category": "operational_anomaly",
                "evidence_event_ids": ["event-2"],
            }
        ]

        result = evaluate_scenarios(annotations, alerts)

        self.assertEqual(result["unit"], "scenario")
        self.assertEqual((result["tp"], result["tn"], result["fp"], result["fn"]), (0, 1, 0, 1))


if __name__ == "__main__":
    unittest.main()
