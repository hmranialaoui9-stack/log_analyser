"""Persistence SQLite du projet Log Analyzer."""
from __future__ import annotations

from pathlib import Path

from .repository import Database

DEFAULT_DATABASE_PATH = Path(__file__).resolve().parent / "log_analyser.sqlite3"


def get_database(path: str | Path | None = None) -> Database:
    """Retourne une base SQLite initialisée automatiquement."""
    return Database(path or DEFAULT_DATABASE_PATH)


__all__ = ["Database", "get_database"]
