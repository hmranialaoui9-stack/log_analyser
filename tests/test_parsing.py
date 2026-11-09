from __future__ import annotations

import unittest

from process.extract_transforme import analyze_rows, summarize


class SshParsingTests(unittest.TestCase):
    def test_invalid_user_extracts_username_and_ip(self) -> None:
        event = analyze_rows(
            ["Nov 08 10:00:00 host sshd[1]: Invalid user ghost from 192.0.2.10 port 22"],
            year=2026,
        )[0]

        self.assertEqual(event["category"], "ssh")
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["user"], "ghost")
        self.assertTrue(event["invalid_user"])
        self.assertEqual(event["ips"], ["192.0.2.10"])

    def test_empty_invalid_user_is_not_invented_from_from_keyword(self) -> None:
        event = analyze_rows(
            ["Nov 08 10:00:00 host sshd[1]: Invalid user  from 192.0.2.10 port 22"],
            year=2026,
        )[0]

        self.assertIsNone(event["user"])
        self.assertTrue(event["invalid_user"])
        self.assertEqual(event["ips"], ["192.0.2.10"])

    def test_ssh_outcomes_are_classified(self) -> None:
        events = analyze_rows(
            [
                "Nov 08 10:00:00 host sshd[1]: Accepted password for alice from 192.0.2.10 port 22 ssh2",
                "Nov 08 10:01:00 host sshd[2]: Failed password for bob from 192.0.2.11 port 22 ssh2",
                "Nov 08 10:02:00 host sshd[3]: Connection reset by authenticating user root 192.0.2.12 port 22 [preauth]",
                "Nov 08 10:03:00 host sshd[4]: Connection closed by 192.0.2.13 port 22 [preauth]",
            ],
            year=2026,
        )

        self.assertEqual(
            [event["outcome"] for event in events],
            ["success", "failure", "other", "other"],
        )
        self.assertEqual(events[2]["user"], "root")
        self.assertEqual(events[3]["ips"], ["192.0.2.13"])

    def test_authentication_failure_formats_are_failures(self) -> None:
        events = analyze_rows(
            [
                "Nov 08 10:00:00 host sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=192.0.2.10",
                "Nov 08 10:01:00 host sshd[2]: PAM 4 more authentication failures; user=root rhost=192.0.2.11",
            ],
            year=2026,
        )

        self.assertEqual([event["outcome"] for event in events], ["failure", "failure"])
        self.assertEqual(events[0]["ips"], ["192.0.2.10"])
        self.assertEqual(events[1]["user"], "root")

    def test_repeated_message_becomes_multiple_events(self) -> None:
        events = analyze_rows(
            [
                "Nov 08 10:00:00 host sshd[1]: message repeated 3 times: "
                "[ Failed password for root from 192.0.2.15 port 22 ssh2 ]",
            ],
            year=2026,
        )

        self.assertEqual(len(events), 3)
        self.assertTrue(all(event["outcome"] == "failure" for event in events))
        self.assertTrue(all(event["ips"] == ["192.0.2.15"] for event in events))

    def test_non_positive_suspicion_threshold_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            summarize([], suspicious_threshold=0)

    def test_unknown_ssh_event_remains_an_other_outcome(self) -> None:
        event = analyze_rows(
            ["Nov 08 10:00:00 host sshd[1]: an unrecognised SSH message"],
            year=2026,
        )[0]

        self.assertEqual(event["category"], "ssh")
        self.assertEqual(event["outcome"], "other")


if __name__ == "__main__":
    unittest.main()
