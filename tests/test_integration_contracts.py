import copy
import json
import tempfile
import unittest
from pathlib import Path

from cybersecurity.detection_engine import DetectionConfig, detect
from data_engineering.apache_parser import parse_line as parse_apache
from data_engineering.common import EVENT_KEYS, validate_event
from data_engineering.linux_parser import parse_line as parse_linux
from data_engineering.openssh_parser import parse_line as parse_openssh
from privacy.anonymizer import Pseudonymizer
from privacy.cloud_payload_builder import PAYLOAD_KEYS, validate_cloud_payload
from privacy.privacy_filter import ALERT_KEYS, has_sensitive_content, sanitize_event
from scripts.export_demo import (
    ROOT,
    _load_contracts,
    build_demo_scenarios,
    export_demo,
    validate_json_schema,
)


CONTRACTS = ROOT / "contracts"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "integration-v1.json"


def load_json(path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def walk_values(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_values(child)
    elif isinstance(value, str):
        yield value


class IntegrationContractTests(unittest.TestCase):
    def test_contract_files_are_valid_json_schemas_and_match_python_keys(self):
        contracts = _load_contracts(CONTRACTS)
        event_schema = contracts["event"]
        alert_schema = load_json(CONTRACTS / "alert-v1.json")
        payload_schema = contracts["cloud_payload"]

        self.assertEqual(event_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(alert_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(payload_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(set(event_schema["required"]), EVENT_KEYS)
        self.assertEqual(set(alert_schema["required"]), ALERT_KEYS)
        self.assertEqual(set(payload_schema["required"]), PAYLOAD_KEYS)
        self.assertEqual(DetectionConfig.from_mapping(contracts["detection_defaults_data"]), DetectionConfig())
        invalid_defaults = dict(contracts["detection_defaults_data"])
        invalid_defaults["trusted_privilege_users"] = []
        with self.assertRaises(ValueError):
            validate_json_schema(contracts["detection_defaults"], invalid_defaults)

    def test_contracts_enforce_existing_schema_nullability_and_closed_keys(self):
        contracts = _load_contracts(CONTRACTS)
        events, _ = build_demo_scenarios()
        for event in events:
            validate_event(event)
            validate_json_schema(contracts["event"], event)

        invalid_event = dict(events[0])
        invalid_event["unexpected"] = True
        with self.assertRaises(ValueError):
            validate_json_schema(contracts["event"], invalid_event)

        invalid_status = dict(events[0])
        invalid_status["status"] = "unknown"
        with self.assertRaises(ValueError):
            validate_json_schema(contracts["event"], invalid_status)

    def test_export_contains_fictional_demo_and_versioned_golden_fixtures(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            demo_dir = base / "demo"
            fixtures_dir = base / "fixtures"
            report = export_demo(demo_dir, fixtures_dir, CONTRACTS)

            self.assertTrue(report["valid"])
            self.assertEqual(report["events_checked"], 19)
            self.assertEqual(report["parser_cases_checked"], 3)
            self.assertFalse(report["pseudonym_mappings_exported"])
            self.assertFalse(report["real_loghub_data_exported"])
            self.assertEqual(report["cloud_requests_made"], 0)

            events = load_json(demo_dir / "events.json")
            alerts = load_json(demo_dir / "alerts.json")
            annotations = load_json(demo_dir / "annotations.json")
            fixture = load_json(fixtures_dir / "integration-v1.json")
            self.assertEqual(fixture["fixture_version"], "1")
            self.assertEqual(len(fixture["parser_cases"]), 3)
            self.assertTrue(fixture["privacy"]["expected_sanitized_event"])

            annotation_ids = {item["event_id"] for item in annotations}
            event_ids = {event["event_id"] for event in events}
            self.assertEqual(annotation_ids, event_ids)
            for event in events:
                self.assertFalse(
                    {
                        "ground_truth",
                        "scenario_id",
                        "scenario_type",
                    }.intersection(walk_values(event))
                )
            for alert in alerts:
                self.assertTrue(set(alert["evidence_event_ids"]).issubset(event_ids))

            documented_networks = (
                "192.0.2.",
                "198.51.100.",
                "203.0.113.",
            )
            for event in events:
                self.assertTrue(event["metadata"]["hostname"].endswith(".example.test"))
                if event["source_ip"]:
                    self.assertTrue(event["source_ip"].startswith(documented_networks))
            self.assertIn(
                "FICTIONAL-DEMO-TOKEN-NOT-VALID",
                next(event["message"] for event in events if "access_token=" in event["message"]),
            )

    def test_golden_results_match_python_parser_detection_privacy_and_cloud(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture_dir = Path(temporary) / "fixtures"
            export_demo(Path(temporary) / "demo", fixture_dir, CONTRACTS)
            fixture = load_json(fixture_dir / "integration-v1.json")
            contracts = _load_contracts(CONTRACTS)

            parser_by_source = {
                "OpenSSH": parse_openssh,
                "Linux": parse_linux,
                "Apache": parse_apache,
            }
            for index, case in enumerate(fixture["parser_cases"], start=1):
                self.assertEqual(
                    parser_by_source[case["source"]](
                        case["raw_line"],
                        index,
                    ),
                    case["expected_event"],
                )
                validate_json_schema(contracts["event"], case["expected_event"])

            detection = fixture["detection"]
            result = detect(
                detection["input_events"],
                DetectionConfig.from_mapping(contracts["detection_defaults_data"]),
            )
            self.assertEqual(result.alerts, detection["expected_alerts"])
            self.assertEqual(result.malformed_event_count, 0)
            self.assertEqual(
                {alert["rule_id"] for alert in result.alerts},
                {"R01", "R02", "R04", "R05"},
            )

            privacy = fixture["privacy"]
            sanitized = sanitize_event(
                privacy["input_event"], Pseudonymizer(context_tag="A5D3C0DE")
            )
            self.assertEqual(sanitized, privacy["expected_sanitized_event"])
            self.assertFalse(has_sensitive_content(sanitized))
            self.assertIn("USER_A5D3C0DE_", sanitized["username"])
            self.assertIn("[REDACTED_SECRET]", sanitized["message"])

            for payload in fixture["cloud_payload"]["accepted_payloads"]:
                validate_cloud_payload(payload)
                validate_json_schema(contracts["cloud_payload"], payload)
            nullable_time_payload = copy.deepcopy(
                fixture["cloud_payload"]["accepted_payloads"][0]
            )
            nullable_time_payload["relative_time"] = None
            validate_cloud_payload(nullable_time_payload)
            validate_json_schema(contracts["cloud_payload"], nullable_time_payload)
            rejections = {
                item["case"]: item["rejected"]
                for item in fixture["cloud_payload"]["rejections"]
            }
            self.assertEqual(
                rejections,
                {
                    "missing_authorization": True,
                    "residual_sensitive_information": True,
                },
            )

    def test_export_is_reproducible_and_never_serializes_mapping_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_demo = root / "first-demo"
            second_demo = root / "second-demo"
            first_fixtures = root / "first-fixtures"
            second_fixtures = root / "second-fixtures"
            export_demo(first_demo, first_fixtures, CONTRACTS)
            export_demo(second_demo, second_fixtures, CONTRACTS)

            first_files = {
                path.name: path.read_bytes() for path in first_demo.iterdir()
            }
            second_files = {
                path.name: path.read_bytes() for path in second_demo.iterdir()
            }
            self.assertEqual(first_files, second_files)
            self.assertEqual(
                (first_fixtures / "integration-v1.json").read_bytes(),
                (second_fixtures / "integration-v1.json").read_bytes(),
            )
            exported = load_json(first_demo / "sanitized-events.json")
            keys_and_values = list(walk_values(exported))
            self.assertNotIn("_mapping", keys_and_values)
            self.assertNotIn("pseudonym_map", keys_and_values)
            self.assertNotIn("FICTIONAL-DEMO-TOKEN-NOT-VALID", keys_and_values)


if __name__ == "__main__":
    unittest.main()
