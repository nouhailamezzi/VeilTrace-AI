import unittest

from data_engineering.apache_parser import parse_line as parse_apache
from data_engineering.common import (
    calculate_relative_times,
    clean_message,
    validate_event,
)
from data_engineering.linux_parser import parse_line as parse_linux
from data_engineering.openssh_parser import parse_line as parse_openssh


class ParserTests(unittest.TestCase):
    def test_openssh_extracts_identity_authentication_and_partial_timestamp(self):
        event = parse_openssh(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for "
            "alice from 192.0.2.14 port 22 ssh2\n",
            1,
        )

        self.assertEqual(event["source"], "OpenSSH")
        self.assertIsNone(event["timestamp"])
        self.assertEqual(event["username"], "alice")
        self.assertEqual(event["source_ip"], "192.0.2.14")
        self.assertEqual(event["status"], "failure")
        self.assertEqual(event["metadata"]["hostname"], "LabSZ")
        self.assertEqual(event["metadata"]["process"], "sshd")
        self.assertEqual(event["metadata"]["pid"], "24200")
        self.assertEqual(event["metadata"]["timestamp_raw"], "Dec 10 06:55:46")
        self.assertEqual(event["metadata"]["month"], 12)
        self.assertEqual(event["metadata"]["day"], 10)
        self.assertEqual(event["metadata"]["hour"], 6)
        self.assertEqual(event["metadata"]["minute"], 55)
        self.assertEqual(event["metadata"]["second"], 46)
        self.assertIsNone(event["metadata"]["year"])
        self.assertIsNone(event["metadata"]["timezone"])
        self.assertIn("year", event["metadata"]["limitations"][0])

    def test_linux_missing_pid_and_unknown_timestamp_are_not_invented(self):
        event = parse_linux(
            "Jun 14 15:16:01 combo kernel: device initialized\n",
            7,
        )

        self.assertIsNone(event["timestamp"])
        self.assertIsNone(event["metadata"]["pid"])
        self.assertEqual(event["metadata"]["hostname"], "combo")
        self.assertEqual(event["metadata"]["process"], "kernel")
        self.assertEqual(event["event_type"], "system_event")
        self.assertEqual(event["metadata"]["timestamp_raw"], "Jun 14 15:16:01")
        self.assertEqual(event["metadata"]["month"], 6)
        self.assertEqual(event["metadata"]["day"], 14)
        self.assertEqual(event["metadata"]["hour"], 15)
        self.assertEqual(event["metadata"]["minute"], 16)
        self.assertEqual(event["metadata"]["second"], 1)
        self.assertIsNone(event["metadata"]["year"])
        self.assertIsNone(event["metadata"]["timezone"])

    def test_linux_session_line_extracts_username_after_user_marker(self):
        event = parse_linux(
            "Jun 14 15:16:01 combo sshd[19939]: "
            "session closed for user alice\n",
            10,
        )

        self.assertEqual(event["username"], "alice")
        self.assertIsNone(event["status"])

    def test_linux_prefix_address_is_extracted_without_claiming_its_direction(self):
        event = parse_linux(
            "Jun 14 15:16:01 combo kerneld 192.0.2.8: device ready\n",
            8,
        )

        self.assertEqual(event["source_ip"], "192.0.2.8")
        self.assertEqual(event["message"], "device ready")
        self.assertIn("direction is unknown", event["metadata"]["source_ip_context"])

    def test_linux_optional_dash_component_prefix_is_supported(self):
        event = parse_linux(
            "Jun 14 15:16:01 combo -- sshd[19939]: "
            "Failed password for alice from 192.0.2.3 port 22 ssh2\n",
            9,
        )

        self.assertTrue(event["metadata"]["raw_parse_matched"])
        self.assertEqual(event["metadata"]["process"], "sshd")
        self.assertEqual(event["metadata"]["pid"], "19939")
        self.assertEqual(event["status"], "failure")

    def test_apache_timestamp_is_timezone_naive_and_original_is_retained(self):
        event = parse_apache(
            "[Sun Dec 04 04:47:44 2005] [error] worker failed\n",
            2,
        )

        self.assertEqual(event["timestamp"], "2005-12-04T04:47:44")
        self.assertEqual(event["metadata"]["timestamp_raw"], "Sun Dec 04 04:47:44 2005")
        self.assertEqual(
            {
                key: event["metadata"][key]
                for key in ("month", "day", "hour", "minute", "second", "year")
            },
            {"month": 12, "day": 4, "hour": 4, "minute": 47, "second": 44, "year": 2005},
        )
        self.assertIsNone(event["metadata"]["timezone"])
        self.assertIn("no timezone", event["metadata"]["limitations"][0])
        self.assertEqual(event["metadata"]["severity"], "error")
        self.assertEqual(event["event_type"], "web_server_error")

    def test_relative_time_handles_midnight_and_year_boundary_without_year(self):
        events = [
            parse_openssh(
                "Dec 31 23:59:30 host sshd[1]: event\n", 1
            ),
            parse_openssh(
                "Jan  1 00:00:15 host sshd[1]: event\n", 2
            ),
        ]

        calculate_relative_times(events)

        self.assertEqual(
            events[1]["metadata"]["relative_time"]["delta_from_previous_seconds"],
            45,
        )
        self.assertEqual(
            events[1]["metadata"]["relative_time"]["status"],
            "year_boundary_rollover",
        )
        self.assertIsNone(events[1]["metadata"]["year"])

    def test_relative_time_handles_clock_rollover_when_day_field_does_not_change(self):
        events = [
            parse_linux("Jun 14 23:59:30 host kernel: event\n", 1),
            parse_linux("Jun 14 00:00:15 host kernel: event\n", 2),
        ]

        calculate_relative_times(events)

        self.assertEqual(
            events[1]["metadata"]["relative_time"]["delta_from_previous_seconds"],
            45,
        )
        self.assertEqual(
            events[1]["metadata"]["relative_time"]["status"],
            "inferred_midnight_rollover_same_date",
        )

    def test_relative_time_marks_unknown_leap_day_span_ambiguous(self):
        events = [
            parse_linux("Feb 28 23:59:00 host kernel: event\n", 1),
            parse_linux("Mar  1 00:01:00 host kernel: event\n", 2),
        ]

        calculate_relative_times(events)

        relative = events[1]["metadata"]["relative_time"]
        self.assertIsNone(relative["delta_from_previous_seconds"])
        self.assertEqual(relative["status"], "ambiguous_leap_day_year_unknown")
        self.assertIsNone(events[1]["metadata"]["year"])

    def test_observed_february_29_makes_adjacent_leap_day_delta_exact(self):
        events = [
            parse_linux("Feb 29 23:59:00 host kernel: event\n", 1),
            parse_linux("Mar  1 00:01:00 host kernel: event\n", 2),
        ]

        calculate_relative_times(events)

        self.assertEqual(
            events[1]["metadata"]["relative_time"]["delta_from_previous_seconds"],
            120,
        )
        self.assertIsNone(events[1]["metadata"]["year"])

    def test_relative_time_does_not_reorder_non_chronological_events(self):
        events = [
            parse_apache("[Sun Dec 04 23:00:00 2005] [notice] event\n", 1),
            parse_apache("[Sun Dec 04 22:00:00 2005] [notice] event\n", 2),
        ]

        calculate_relative_times(events)

        relative = events[1]["metadata"]["relative_time"]
        self.assertIsNone(relative["delta_from_previous_seconds"])
        self.assertEqual(relative["status"], "non_chronological_timestamp_order")
        self.assertEqual(relative["elapsed_seconds"], 0)

    def test_apache_relative_time_is_naive_wall_clock_and_timezone_unknown(self):
        events = [
            parse_apache("[Sun Dec 04 23:59:00 2005] [notice] event\n", 1),
            parse_apache("[Mon Dec 05 00:01:00 2005] [notice] event\n", 2),
        ]

        calculate_relative_times(events)

        relative = events[1]["metadata"]["relative_time"]
        self.assertEqual(relative["delta_from_previous_seconds"], 120)
        self.assertEqual(relative["basis"], "timezone_naive_wall_clock")
        self.assertIsNone(events[1]["metadata"]["timezone"])

    def test_relative_time_rejects_mixed_sources(self):
        events = [
            parse_openssh("Dec 10 06:55:46 host sshd[1]: event\n", 1),
            parse_linux("Jun 14 15:16:01 host kernel: event\n", 1),
        ]

        with self.assertRaises(ValueError):
            calculate_relative_times(events)

    def test_repeated_auth_failures_are_kept_as_distinct_events(self):
        raw = (
            "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for "
            "alice from 192.0.2.14 port 22 ssh2"
        )
        events = [parse_openssh(raw, number) for number in (1, 2, 3)]

        self.assertEqual(len(events), 3)
        self.assertEqual(len({event["event_id"] for event in events}), 3)
        self.assertEqual([event["status"] for event in events], ["failure"] * 3)

    def test_malformed_prefix_keeps_message_without_fabricated_fields(self):
        event = parse_apache("unstructured log text\n", 9)

        self.assertFalse(event["metadata"]["raw_parse_matched"])
        self.assertIsNone(event["timestamp"])
        self.assertIsNone(event["metadata"]["hostname"])
        self.assertEqual(event["message"], "unstructured log text")

    def test_cleaning_and_schema_validation(self):
        self.assertEqual(clean_message("line\t with  spaces\x00"), "line with spaces")
        event = parse_apache("[Sun Dec 04 04:47:44 2005] [notice] ready", 1)
        validate_event(event)
        event["unexpected"] = True
        with self.assertRaises(ValueError):
            validate_event(event)


if __name__ == "__main__":
    unittest.main()
