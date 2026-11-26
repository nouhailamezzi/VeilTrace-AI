import ipaddress
import unittest

from scripts.generate_synthetic_dataset import (
    generate_development,
    generate_evaluation,
)


class SyntheticGeneratorTests(unittest.TestCase):
    def test_splits_are_fixed_size_reproducible_and_keep_labels_separate(self):
        development = generate_development()
        evaluation = generate_evaluation()
        development_repeat = generate_development()
        evaluation_repeat = generate_evaluation()

        self.assertEqual(len(development[0]), 250)
        self.assertEqual(len(evaluation[0]), 250)
        self.assertEqual(development, development_repeat)
        self.assertEqual(evaluation, evaluation_repeat)
        for events, annotations in (development, evaluation):
            self.assertEqual(
                {event["event_id"] for event in events},
                {annotation["event_id"] for annotation in annotations},
            )
            self.assertTrue(
                all("ground_truth" not in event and "scenario_id" not in event for event in events)
            )

    def test_synthetic_addresses_are_from_documentation_ranges(self):
        events, _ = generate_evaluation()
        allowed = tuple(
            ipaddress.ip_network(network)
            for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        )
        addresses = {
            event["source_ip"] for event in events if event["source_ip"] is not None
        }
        self.assertTrue(addresses)
        self.assertTrue(
            all(any(ipaddress.ip_address(address) in network for network in allowed) for address in addresses)
        )

    def test_evaluation_annotations_include_benign_and_suspicious_scenarios(self):
        _, annotations = generate_evaluation()
        scenario_labels = {}
        for annotation in annotations:
            scenario_labels[annotation["scenario_id"]] = annotation["ground_truth"]

        self.assertIn("benign", scenario_labels.values())
        self.assertIn("suspicious", scenario_labels.values())
        self.assertTrue(
            any("normal" in annotation["scenario_type"] for annotation in annotations)
        )


if __name__ == "__main__":
    unittest.main()
