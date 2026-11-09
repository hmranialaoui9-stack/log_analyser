from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from storage import get_database


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "log_analyser.sqlite3"
        self.events = [
            {
                "timestamp": "2026-11-08 10:00:00",
                "category": "ssh",
                "outcome": "success",
                "ips": ["8.8.8.8"],
                "user": "alice",
                "invalid_user": False,
                "message": "Accepted password for alice from 8.8.8.8",
            },
            {
                "timestamp": "2026-11-08 10:01:00",
                "category": "ssh",
                "outcome": "failure",
                "ips": ["1.1.1.1"],
                "user": "ghost",
                "invalid_user": True,
                "message": "Invalid user ghost from 1.1.1.1",
            },
        ]
        self.database = get_database(self.database_path)

    def tearDown(self) -> None:
        self.database.close()
        self.temporary_directory.cleanup()

    def test_database_initializes_schema_and_empty_queries(self) -> None:
        self.database.connect()

        self.assertEqual(self.database.list_runs(), [])
        self.assertEqual(self.database.get_timeline(1), {})
        self.assertEqual(self.database.get_outcome_counts(1), {})
        self.assertEqual(self.database.query_events(1), ([], 0))

    def test_run_events_and_enrichments_are_persisted(self) -> None:
        run_id = self.database.create_run(
            source="unit-test",
            rows_analyzed=2,
            threshold=5,
            summary={"total_events": 2, "ssh_events": 2},
            events=self.events,
            enrichments={"1.1.1.1": {"country": "FR"}},
        )

        self.assertEqual(self.database.get_outcome_counts(run_id), {"failure": 1, "success": 1})
        self.assertEqual(self.database.get_top_ips(run_id), [("1.1.1.1", 1), ("8.8.8.8", 1)])
        self.assertEqual(
            self.database.get_failed_attempts_by_country(run_id),
            {"FR": 1},
        )
        self.assertEqual(
            self.database.get_successful_logins_by_user(run_id),
            [{"username": "alice", "count": 1}],
        )
        attempts, total = self.database.get_invalid_user_attempts(run_id)
        self.assertEqual(total, 1)
        self.assertEqual(attempts[0]["country"], "FR")

    def test_repeating_the_same_analysis_does_not_duplicate_data(self) -> None:
        arguments = {
            "source": "unit-test",
            "rows_analyzed": 2,
            "threshold": 5,
            "summary": {"total_events": 2},
            "events": self.events,
        }

        first_id = self.database.create_run(**arguments)
        second_id = self.database.create_run(**arguments)

        self.assertEqual(first_id, second_id)
        self.assertEqual(len(self.database.list_runs()), 1)
        self.assertEqual(self.database.query_events(first_id)[1], 2)

    def test_event_search_and_pagination_are_parameterized(self) -> None:
        run_id = self.database.create_run(
            source="unit-test",
            rows_analyzed=2,
            threshold=5,
            summary={},
            events=self.events,
        )

        rows, total = self.database.query_events(
            run_id, search="1.1.1.1", category="ssh", outcome="failure"
        )

        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["username"], "ghost")
        self.assertEqual(rows[0]["ips"], ["1.1.1.1"])


if __name__ == "__main__":
    unittest.main()
