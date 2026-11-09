"""Accès transactionnel aux analyses et événements SQLite."""
from __future__ import annotations

from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable

from logging_config import get_logger, redact_sensitive_text

logger = get_logger("repository")


class Database:
    """Repository SQLite centralisant les écritures et lectures du dashboard."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.connection: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        if self.connection is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(self.path)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA journal_mode = WAL")
            self._initialize_schema()
        return self.connection

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def __enter__(self) -> Database:
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _initialize_schema(self) -> None:
        connection = self.connection
        if connection is None:
            raise RuntimeError("La base SQLite n'est pas connectée")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                rows_analyzed INTEGER NOT NULL,
                threshold INTEGER NOT NULL,
                summary_json TEXT NOT NULL,
                ipinfo_status_json TEXT NOT NULL DEFAULT '{}',
                input_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
                timestamp TEXT,
                category TEXT NOT NULL,
                outcome TEXT NOT NULL,
                username TEXT,
                invalid_user INTEGER NOT NULL DEFAULT 0,
                message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS event_ips (
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                PRIMARY KEY(event_id, ip)
            );
            CREATE TABLE IF NOT EXISTS ip_enrichments (
                run_id INTEGER NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                details_json TEXT NOT NULL,
                PRIMARY KEY(run_id, ip)
            );
            CREATE INDEX IF NOT EXISTS idx_events_run_timestamp
                ON events(run_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_event_ips_ip ON event_ips(ip);
            """
        )
        self._add_column_if_missing("analysis_runs", "input_hash", "TEXT")
        self._add_column_if_missing("events", "invalid_user", "INTEGER NOT NULL DEFAULT 0")
        connection.commit()

    def _add_column_if_missing(self, table: str, column: str, definition: str) -> None:
        connection = self.connection
        if connection is None:
            raise RuntimeError("La base SQLite n'est pas connectée")
        columns = connection.execute(f"PRAGMA table_info({table})").fetchall()
        if column not in {row["name"] for row in columns}:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @staticmethod
    def _input_hash(source: str, events: Iterable[dict[str, Any]]) -> str:
        payload = json.dumps(
            {"source": source, "events": list(events)},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def create_run(
        self,
        source: str,
        rows_analyzed: int,
        threshold: int,
        summary: dict[str, Any],
        events: list[dict[str, Any]],
        enrichments: dict[str, dict[str, Any]] | None = None,
        ipinfo_status: dict[str, Any] | None = None,
    ) -> int:
        connection = self.connect()
        input_hash = self._input_hash(source, events)
        existing = connection.execute(
            "SELECT id FROM analysis_runs WHERE input_hash = ?",
            (input_hash,),
        ).fetchone()
        if existing is not None:
            return int(existing["id"])
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO analysis_runs
                        (source, created_at, rows_analyzed, threshold,
                         summary_json, ipinfo_status_json, input_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        redact_sensitive_text(source),
                        created_at,
                        rows_analyzed,
                        threshold,
                        json.dumps(summary, ensure_ascii=False),
                        json.dumps(ipinfo_status or {}, ensure_ascii=False),
                        input_hash,
                    ),
                )
                run_id = int(cursor.lastrowid)
                for event in events:
                    event_cursor = connection.execute(
                        """
                        INSERT INTO events
                            (run_id, timestamp, category, outcome, username,
                             invalid_user, message)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            event.get("timestamp"),
                            event["category"],
                            event["outcome"],
                            event.get("user"),
                            int(bool(event.get("invalid_user", False))),
                            redact_sensitive_text(event["message"]),
                        ),
                    )
                    event_id = int(event_cursor.lastrowid)
                    connection.executemany(
                        "INSERT INTO event_ips (event_id, ip) VALUES (?, ?)",
                        ((event_id, ip) for ip in event.get("ips", [])),
                    )
                for ip, details in (enrichments or {}).items():
                    connection.execute(
                        """
                        INSERT INTO ip_enrichments (run_id, ip, details_json)
                        VALUES (?, ?, ?)
                        """,
                        (run_id, ip, json.dumps(details, ensure_ascii=False)),
                    )
        except sqlite3.Error:
            logger.exception("Échec de la persistance de l'analyse %s", source)
            raise
        logger.info("Analyse persistée: run_id=%d, événements=%d", run_id, len(events))
        return run_id

    def list_runs(self) -> list[dict[str, Any]]:
        rows = self.connect().execute(
            """
            SELECT id, source, created_at, rows_analyzed, threshold,
                   summary_json, ipinfo_status_json
            FROM analysis_runs ORDER BY created_at DESC, id DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def _fetchall(self, query: str, parameters: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return self.connect().execute(query, parameters).fetchall()

    def get_timeline(self, run_id: int) -> dict[str, int]:
        rows = self._fetchall(
            """
            SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS count
            FROM events
            WHERE run_id = ? AND timestamp IS NOT NULL
            GROUP BY hour ORDER BY hour
            """,
            (run_id,),
        )
        return {row["hour"]: row["count"] for row in rows}

    def get_outcome_counts(self, run_id: int) -> dict[str, int]:
        rows = self._fetchall(
            """
            SELECT outcome, COUNT(*) AS count FROM events
            WHERE run_id = ? AND category = 'ssh'
            GROUP BY outcome
            """,
            (run_id,),
        )
        return {row["outcome"]: row["count"] for row in rows}

    def get_top_ips(self, run_id: int, limit: int = 10) -> list[tuple[str, int]]:
        rows = self._fetchall(
            """
            SELECT event_ips.ip, COUNT(*) AS count
            FROM event_ips JOIN events ON events.id = event_ips.event_id
            WHERE events.run_id = ?
            GROUP BY event_ips.ip ORDER BY count DESC, event_ips.ip LIMIT ?
            """,
            (run_id, limit),
        )
        return [(row["ip"], row["count"]) for row in rows]

    def query_events(
        self,
        run_id: int,
        search: str = "",
        category: str = "",
        outcome: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        conditions = ["events.run_id = ?"]
        parameters: list[Any] = [run_id]
        if search:
            conditions.append(
                "(events.message LIKE ? OR events.username LIKE ? OR EXISTS "
                "(SELECT 1 FROM event_ips WHERE event_ips.event_id = events.id AND event_ips.ip LIKE ?))"
            )
            pattern = f"%{search}%"
            parameters.extend([pattern, pattern, pattern])
        if category:
            conditions.append("events.category = ?")
            parameters.append(category)
        if outcome:
            conditions.append("events.outcome = ?")
            parameters.append(outcome)
        where = " AND ".join(conditions)
        total = self.connect().execute(
            f"SELECT COUNT(*) FROM events WHERE {where}", tuple(parameters)
        ).fetchone()[0]
        rows = self._fetchall(
            f"""
            SELECT id, timestamp, category, outcome, username,
                   invalid_user, message
            FROM events WHERE {where}
            ORDER BY id DESC LIMIT ? OFFSET ?
            """,
            tuple(parameters + [max(1, min(limit, 5000)), max(0, offset)]),
        )
        result = []
        for row in rows:
            item = dict(row)
            item["invalid_user"] = bool(item["invalid_user"])
            item["ips"] = [
                ip["ip"]
                for ip in self._fetchall(
                    "SELECT ip FROM event_ips WHERE event_id = ? ORDER BY ip",
                    (item["id"],),
                )
            ]
            result.append(item)
        return result, int(total)

    def _enrichments(self, run_id: int) -> dict[str, dict[str, Any]]:
        return {
            row["ip"]: json.loads(row["details_json"])
            for row in self._fetchall(
                "SELECT ip, details_json FROM ip_enrichments WHERE run_id = ?",
                (run_id,),
            )
        }

    def get_failed_attempts_by_country(self, run_id: int) -> dict[str, int]:
        enrichments = self._enrichments(run_id)
        counts: Counter[str] = Counter()
        rows = self._fetchall(
            """
            SELECT event_ips.ip FROM event_ips
            JOIN events ON events.id = event_ips.event_id
            WHERE events.run_id = ? AND events.category = 'ssh'
              AND events.outcome = 'failure'
            """,
            (run_id,),
        )
        for row in rows:
            counts[enrichments.get(row["ip"], {}).get("country", "Unknown")] += 1
        return dict(counts)

    def get_successful_logins_by_user(self, run_id: int) -> list[dict[str, Any]]:
        rows = self._fetchall(
            """
            SELECT username, COUNT(*) AS count FROM events
            WHERE run_id = ? AND category = 'ssh' AND outcome = 'success'
              AND username IS NOT NULL
            GROUP BY username ORDER BY count DESC, username
            """,
            (run_id,),
        )
        return [{"username": row["username"], "count": row["count"]} for row in rows]

    def get_invalid_user_attempts(self, run_id: int, limit: int = 100) -> tuple[list[dict[str, Any]], int]:
        total = self.connect().execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ? AND invalid_user = 1",
            (run_id,),
        ).fetchone()[0]
        rows = self._fetchall(
            """
            SELECT events.id, events.timestamp, events.username,
                   event_ips.ip
            FROM events JOIN event_ips ON event_ips.event_id = events.id
            WHERE events.run_id = ? AND events.invalid_user = 1
            ORDER BY events.id DESC LIMIT ?
            """,
            (run_id, limit),
        )
        enrichments = self._enrichments(run_id)
        attempts = [
            {
                "timestamp": row["timestamp"],
                "username": row["username"],
                "ip": row["ip"],
                "country": enrichments.get(row["ip"], {}).get("country", "Unknown"),
            }
            for row in rows
        ]
        return attempts, int(total)

    def get_ip_stats(self, run_id: int) -> list[dict[str, Any]]:
        enrichments = self._enrichments(run_id)
        rows = self._fetchall(
            """
            SELECT event_ips.ip, COUNT(*) AS occurrences,
                   SUM(events.outcome = 'failure') AS failures
            FROM event_ips JOIN events ON events.id = event_ips.event_id
            WHERE events.run_id = ?
            GROUP BY event_ips.ip ORDER BY occurrences DESC, event_ips.ip
            """,
            (run_id,),
        )
        return [
            {
                "ip": row["ip"],
                "occurrences": row["occurrences"],
                "failures": row["failures"] or 0,
                "enrichment": enrichments.get(row["ip"], {}),
            }
            for row in rows
        ]
