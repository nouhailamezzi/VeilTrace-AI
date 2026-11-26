import copy
import unittest
from datetime import datetime, timedelta, timezone

from cybersecurity.detection_engine import detect
from privacy.anonymizer import Pseudonymizer
from privacy.cloud_payload_builder import (
    CloudPayloadRejected,
    build_cloud_payload,
    validate_cloud_payload,
)
from privacy.pii_detector import detect_text, scan_sensitive
from privacy.privacy_filter import (
    has_sensitive_content,
    sanitize_alert,
    sanitize_event,
    sanitize_structure,
)


BASE = datetime(2025, 2, 1, tzinfo=timezone.utc)


def event(index, *, username="analyst-01", source_ip="192.0.2.10"):
    timestamp = BASE + timedelta(seconds=index * 10)
    return {
        "event_id": f"privacy-event-{index:03d}",
        "source": "OpenSSH",
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "event_type": "authentication",
        "username": username,
        "source_ip": source_ip,
        "status": "failure",
        "message": f"Failed password for {username} from {source_ip}",
        "metadata": {
            "hostname": "ssh-gw.example.test",
            "relative_time": {
                "sequence_index": index,
                "segment": 0,
                "elapsed_seconds": index * 10,
                "basis": "source_relative_wall_clock",
            },
        },
    }


class SensitiveDetectionTests(unittest.TestCase):
    def test_detects_ipv4_and_ipv6(self):
        matches = detect_text(
            "client 192.0.2.15 reached peer 2001:db8::5"
        )

        self.assertEqual(
            {(match.kind, match.value) for match in matches},
            {("ipv4", "192.0.2.15"), ("ipv6", "2001:db8::5")},
        )

    def test_detects_email_username_hostname_phone_mac_and_sensitive_path(self):
        text = (
            "contact=alice@example.test user=operator-7 "
            "host=ssh-gw.example.test phone=+1-202-555-0101 "
            "device=02:00:00:00:00:01 file=/home/alice/private/notes.txt"
        )
        matches = detect_text(text)

        self.assertEqual(
            {match.kind for match in matches},
            {"email", "username", "hostname", "phone_number", "mac_address", "file_path"},
        )

    def test_detects_url_secrets_and_credential_patterns(self):
        text = (
            "GET https://api.example.test/export?access_token=fake-token-123 "
            "Authorization: Bearer fictional-header-456"
        )
        matches = detect_text(text)

        self.assertIn("access_token", {match.kind for match in matches})
        self.assertIn("authorization", {match.kind for match in matches})
        self.assertIn("hostname", {match.kind for match in matches})

    def test_field_aware_detection_avoids_pseudonymizing_arbitrary_numbers(self):
        matches = scan_sensitive(
            {
                "message": "build 2026.11.26 duration 00:12:34 count 4242",
                "metadata": {"retry_count": 5, "user_id": 1001},
            }
        )

        self.assertEqual(
            [(match.kind, match.value) for match in matches],
            [("username", "1001")],
        )

    def test_rejects_invalid_ip_candidates_and_preserves_non_sensitive_text(self):
        self.assertEqual(
            detect_text("candidate=999.999.999.999 pid=3124 build=release-1.2"),
            [],
        )


class SanitizationTests(unittest.TestCase):
    def test_secret_values_are_fully_redacted(self):
        original = {
            "password": "Fictional-Password-001",
            "api_key": "FAKE_API_KEY_001",
            "private_key": (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "FICTIONAL-ONLY-KEY-MATERIAL\n"
                "-----END RSA PRIVATE KEY-----"
            ),
            "message": "access_token=fictional-token-001",
        }
        sanitized = sanitize_structure(original, Pseudonymizer(context_tag="A1B2C3D4"))
        serialized = str(sanitized)

        self.assertEqual(sanitized["password"], "[REDACTED_PASSWORD]")
        self.assertEqual(sanitized["api_key"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["private_key"], "[REDACTED_PRIVATE_KEY]")
        self.assertIn("[REDACTED_SECRET]", sanitized["message"])
        for secret in ("Fictional-Password-001", "FAKE_API_KEY_001", "fictional-token-001"):
            self.assertNotIn(secret, serialized)

    def test_nested_lists_and_metadata_are_sanitized_without_mutation(self):
        original = {
            "metadata": {
                "username": "operator-9",
                "user_id": 1205,
                "credentials": {"password": "fictional-password"},
                "peers": [{"source_ip": "198.51.100.12"}],
            }
        }
        before = copy.deepcopy(original)
        sanitized = sanitize_structure(original, Pseudonymizer(context_tag="A1B2C3D4"))

        self.assertEqual(original, before)
        self.assertTrue(sanitized["metadata"]["username"].startswith("USER_"))
        self.assertTrue(sanitized["metadata"]["user_id"].startswith("USER_"))
        self.assertEqual(
            sanitized["metadata"]["credentials"], "[REDACTED_SECRET]"
        )
        self.assertTrue(
            sanitized["metadata"]["peers"][0]["source_ip"].startswith("IP_")
        )
        self.assertFalse(has_sensitive_content(sanitized))

    def test_field_and_message_entities_share_one_investigation_alias(self):
        original = event(1)
        sanitized = sanitize_event(original, Pseudonymizer(context_tag="A1B2C3D4"))

        self.assertIn(sanitized["username"], sanitized["message"])
        self.assertIn(sanitized["source_ip"], sanitized["message"])
        self.assertTrue(sanitized["metadata"]["hostname"].startswith("HOST_"))
        self.assertNotIn(original["username"], sanitized["message"])
        self.assertNotIn(original["source_ip"], sanitized["message"])

    def test_investigation_contexts_do_not_share_aliases(self):
        first = Pseudonymizer(context_tag="A1B2C3D4")
        second = Pseudonymizer(context_tag="B1B2C3D4")

        first_alias = first.pseudonymize("same-user", "username")
        second_alias = second.pseudonymize("same-user", "username")

        self.assertNotEqual(first_alias, second_alias)
        self.assertEqual(first_alias, first.pseudonymize("same-user", "username"))

    def test_numeric_identifiers_are_pseudonymized_only_in_named_fields(self):
        sanitized = sanitize_structure(
            {
                "uid": 1000,
                "retry_count": 1000,
                "accessToken": "fictional-access-token",
                "phoneNumber": "+1-202-555-0101",
            },
            Pseudonymizer(context_tag="A1B2C3D4"),
        )

        self.assertTrue(sanitized["uid"].startswith("USER_"))
        self.assertEqual(sanitized["retry_count"], 1000)
        self.assertEqual(sanitized["accessToken"], "[REDACTED_SECRET]")
        self.assertTrue(sanitized["phoneNumber"].startswith("PHONE_"))

    def test_malformed_nested_json_is_explicit_and_safe(self):
        with self.assertRaises(TypeError):
            sanitize_structure({"not_json": object()}, Pseudonymizer())
        with self.assertRaises(ValueError):
            sanitize_structure({"number": float("inf")}, Pseudonymizer())
        with self.assertRaises(ValueError):
            sanitize_event({"event_id": "incomplete"}, Pseudonymizer())


class CloudPayloadTests(unittest.TestCase):
    def test_cloud_authorization_is_required(self):
        with self.assertRaises(CloudPayloadRejected):
            build_cloud_payload(
                self._alert(),
                context=Pseudonymizer(context_tag="A1B2C3D4"),
            )

    def test_payload_is_allowlisted_and_has_no_raw_entities_or_event_ids(self):
        alert = self._alert()
        payload = build_cloud_payload(
            alert,
            authorized=True,
            context=Pseudonymizer(context_tag="A1B2C3D4"),
            relative_time={
                "elapsed_seconds": 32,
                "delta_from_previous_seconds": 4,
                "basis": "source_relative_wall_clock",
            },
        )
        json_value = str(payload)

        self.assertEqual(
            set(payload),
            {
                "schema_version",
                "rule_id",
                "severity",
                "category",
                "source",
                "entities",
                "event_count",
                "relative_time",
                "evidence_summary",
            },
        )
        self.assertNotIn(alert["source_ip"], json_value)
        self.assertNotIn(alert["username"], json_value)
        self.assertNotIn(alert["alert_id"], json_value)
        self.assertNotIn(alert["evidence_event_ids"][0], json_value)
        self.assertNotIn("timestamp", payload)
        validate_cloud_payload(payload)

    def test_unexpected_alert_or_relative_time_fields_are_rejected(self):
        with self.assertRaises(CloudPayloadRejected):
            build_cloud_payload(
                {**self._alert(), "raw_log": "not allowed"},
                authorized=True,
                context=Pseudonymizer(context_tag="A1B2C3D4"),
            )
        with self.assertRaises(CloudPayloadRejected):
            build_cloud_payload(
                self._alert(),
                authorized=True,
                context=Pseudonymizer(context_tag="A1B2C3D4"),
                relative_time={"elapsed_seconds": 1, "hostname": "host.example.test"},
            )

    def test_residual_sensitive_information_is_rejected(self):
        payload = build_cloud_payload(
            self._alert(),
            authorized=True,
            context=Pseudonymizer(context_tag="A1B2C3D4"),
        )
        payload["evidence_summary"] = "Contact alice@example.test"

        with self.assertRaises(CloudPayloadRejected):
            validate_cloud_payload(payload)

    def test_unscoped_alias_shape_is_not_accepted_as_sanitized_content(self):
        payload = build_cloud_payload(
            self._alert(),
            authorized=True,
            context=Pseudonymizer(context_tag="A1B2C3D4"),
        )
        payload["evidence_summary"] = "Login for USER_001 from an unknown source"

        with self.assertRaises(CloudPayloadRejected):
            validate_cloud_payload(payload)

    def test_payload_integrates_with_existing_detector_alert_schema(self):
        alerts = detect([event(index) for index in range(1, 6)]).alerts
        self.assertTrue(alerts)
        alert = next(item for item in alerts if item["rule_id"] == "R01")
        sanitized = sanitize_alert(alert, Pseudonymizer(context_tag="A1B2C3D4"))
        payload = build_cloud_payload(
            alert,
            authorized=True,
            context=Pseudonymizer(context_tag="B1B2C3D4"),
        )

        self.assertEqual(set(sanitized), set(alert))
        self.assertNotIn(alert["source_ip"], str(sanitized))
        if alert["username"] is not None:
            self.assertNotIn(alert["username"], str(sanitized))
        self.assertEqual(payload["rule_id"], alert["rule_id"])
        validate_cloud_payload(payload)

    def test_invalid_alert_input_is_rejected(self):
        with self.assertRaises(CloudPayloadRejected):
            build_cloud_payload(
                {"rule_id": "R01"},
                authorized=True,
                context=Pseudonymizer(context_tag="A1B2C3D4"),
            )

    @staticmethod
    def _alert():
        return {
            "alert_id": "alert-r01-example",
            "rule_id": "R01",
            "rule_name": "Repeated failed logins",
            "category": "security",
            "severity": "medium",
            "source": "OpenSSH",
            "timestamp": "2025-02-01T00:00:00+00:00",
            "timestamp_quality": "complete_with_timezone",
            "source_ip": "192.0.2.80",
            "username": "fictional-user",
            "event_count": 5,
            "evidence_event_ids": ["openssh-000001"],
            "description": "Repeated failures from one source.",
            "recommended_action": "Review the local evidence.",
            "detection_method": "deterministic_rule",
        }


if __name__ == "__main__":
    unittest.main()
