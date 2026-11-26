import unittest

from scripts.generate_privacy_dataset import RECORD_COUNT, build_dataset
from scripts.run_privacy_evaluation import evaluate


class PrivacyDatasetTests(unittest.TestCase):
    def test_dataset_has_100_reproducible_inputs_and_separate_annotations(self):
        first_records, first_annotations = build_dataset()
        second_records, second_annotations = build_dataset()

        self.assertEqual(len(first_records), RECORD_COUNT)
        self.assertEqual(first_records, second_records)
        self.assertEqual(first_annotations, second_annotations)
        self.assertEqual(len(first_annotations), RECORD_COUNT)
        for record, annotation in zip(first_records, first_annotations):
            self.assertEqual(set(record), {"record_id", "input"})
            self.assertNotIn("sensitive_entities", record["input"])
            self.assertEqual(record["record_id"], annotation["record_id"])

    def test_dataset_covers_benign_and_sensitive_scenarios(self):
        records, annotations = build_dataset()
        scenario_types = {item["scenario_type"] for item in annotations}

        self.assertIn("benign_numeric_and_version_values", scenario_types)
        self.assertIn("structured_ipv4", scenario_types)
        self.assertIn("structured_ipv6", scenario_types)
        self.assertIn("url_query_and_nested_path", scenario_types)
        self.assertIn("malformed_or_ambiguous_decoy", scenario_types)
        self.assertTrue(any(item["sensitive_entities"] for item in annotations))
        self.assertEqual(len(records), 100)

    def test_evaluation_uses_isolated_annotations_and_runs_end_to_end(self):
        records, annotations = build_dataset()
        metrics = evaluate(records, annotations)

        self.assertEqual(metrics["record_count"], 100)
        self.assertGreater(metrics["tp"], 0)
        self.assertEqual(metrics["payload_rejections"], metrics["payload_rejection_checks"])
        self.assertTrue(metrics["valid_payload_accepted"])
        self.assertEqual(metrics["residual_leakage_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
