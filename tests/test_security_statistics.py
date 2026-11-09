"""Vérifications des statistiques de sécurité produites par le parseur."""
from __future__ import annotations

from collections import Counter
import logging
import unittest

from logging.handlers import RotatingFileHandler

from logging_config import RedactingFormatter, get_logger, redact_sensitive_text
from process.extract_transforme import analyze_rows, summarize


class SecurityStatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = analyze_rows(
            [
                "Nov 08 10:00:00 host sshd[1]: Accepted password for alice from 192.0.2.10 port 22 ssh2",
                "Nov 08 10:01:00 host sshd[2]: Failed password for bob from 192.0.2.11 port 22 ssh2",
                "Nov 08 10:02:00 host sshd[3]: Invalid user ghost from 192.0.2.12 port 22 ssh2",
                "Nov 08 10:03:00 host sshd[4]: message repeated 2 times: [ Failed password for bob from 192.0.2.11 port 22 ssh2 ]",
                "Nov 08 10:04:00 host sshd[5]: Connection closed by 192.0.2.13 port 22 [preauth]",
            ],
            year=2026,
        )

    def test_summary_counts_successes_failures_and_unknown_ssh_events(self) -> None:
        statistics = summarize(self.events)

        self.assertEqual(statistics["total_events"], 6)
        self.assertEqual(statistics["ssh_events"], 6)
        self.assertEqual(statistics["successful_logins"], 1)
        self.assertEqual(statistics["failed_logins"], 4)
        self.assertEqual(statistics["other_ssh_events"], 1)
        self.assertEqual(statistics["unique_ips"], 4)

    def test_failed_attempts_are_grouped_by_ip_without_double_counting(self) -> None:
        failed_by_ip = Counter(
            ip
            for event in self.events
            if event["category"] == "ssh" and event["outcome"] == "failure"
            for ip in event["ips"]
        )

        self.assertEqual(failed_by_ip, Counter({"192.0.2.11": 3, "192.0.2.12": 1}))

    def test_successes_are_grouped_by_username(self) -> None:
        successful_by_user = Counter(
            event["user"]
            for event in self.events
            if event["category"] == "ssh"
            and event["outcome"] == "success"
            and event["user"] is not None
        )

        self.assertEqual(successful_by_user, Counter({"alice": 1}))

    def test_invalid_user_contains_only_observed_data(self) -> None:
        invalid_events = [event for event in self.events if event["invalid_user"]]

        self.assertEqual(len(invalid_events), 1)
        self.assertEqual(invalid_events[0]["user"], "ghost")
        self.assertEqual(invalid_events[0]["ips"], ["192.0.2.12"])

    def test_repeated_events_are_included_in_statistics(self) -> None:
        repeated_events = [
            event for event in self.events if event["ips"] == ["192.0.2.11"]
        ]

        self.assertEqual(len(repeated_events), 3)
        self.assertEqual(
            sum(event["outcome"] == "failure" for event in repeated_events),
            3,
        )

    def test_threshold_marks_only_ips_reaching_threshold(self) -> None:
        statistics = summarize(self.events, suspicious_threshold=3)

        self.assertEqual(
            statistics["suspicious_ips"],
            [{"ip": "192.0.2.11", "failed_attempts": 3}],
        )

    def test_non_positive_suspicion_threshold_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            summarize(self.events, suspicious_threshold=0)

    def test_log_formatter_redacts_passwords_and_url_credentials(self) -> None:
        record = logging.LogRecord(
            "test",
            logging.ERROR,
            __file__,
            1,
            "request failed: password hunter2 https://alice:pass123@example.test",
            (),
            None,
        )

        formatted = RedactingFormatter("%(message)s").format(record)

        self.assertNotIn("hunter2", formatted)
        self.assertNotIn("pass123", formatted)
        self.assertIn("[REDACTED]", formatted)

    def test_sensitive_text_helper_redacts_secret_values(self) -> None:
        redacted = redact_sensitive_text(
            "token=abc123 password hunter2 https://alice:pass123@example.test"
        )

        self.assertNotIn("abc123", redacted)
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("pass123", redacted)

    def test_logger_uses_rotating_redacting_handler_without_duplicates(self) -> None:
        first = get_logger("test_logging")
        second = get_logger("test_logging")

        self.assertIs(first, second)
        self.assertEqual(len(first.handlers), 1)
        self.assertIsInstance(first.handlers[0], RotatingFileHandler)
        self.assertEqual(first.handlers[0].maxBytes, 2_000_000)
        self.assertEqual(first.handlers[0].backupCount, 3)
        self.assertIsInstance(first.handlers[0].formatter, RedactingFormatter)


if __name__ == "__main__":
    unittest.main()
