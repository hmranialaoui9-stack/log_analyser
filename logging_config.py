"""Configuration commune des journaux applicatifs, sans dépendance externe."""
from __future__ import annotations

import logging
import os
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIRECTORY = Path(__file__).resolve().parent / "logs"
_LOGGERS: dict[str, logging.Logger] = {}
_SECRET_PATTERN = re.compile(
    r"(?i)(\b(?:password|passwd|token|api[_-]?key|secret)\b\s*[:=]\s*)([^\s&,;]+)"
)
_PASSWORD_PHRASE_PATTERN = re.compile(r"(?i)(\bpassword\s+)(?!for\b)([^\s,;]+)")
_URL_CREDENTIAL_PATTERN = re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)")
_LOG_LEVELS = {
    name: getattr(logging, name)
    for name in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
}


def _redact(text: str) -> str:
    text = _SECRET_PATTERN.sub(r"\1[REDACTED]", text)
    text = _PASSWORD_PHRASE_PATTERN.sub(r"\1[REDACTED]", text)
    return _URL_CREDENTIAL_PATTERN.sub(r"\1[REDACTED]\3", text)


def redact_sensitive_text(text: str) -> str:
    """Retire les valeurs de secrets connues des messages conservés/exportés."""
    return _redact(text)


def csv_safe_value(value: object) -> object:
    """Neutralise les valeurs textuelles interprétées comme tableur formulas."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


class RedactingFormatter(logging.Formatter):
    """Masque les secrets aussi dans les traces d'exception et les URLs."""

    def format(self, record: logging.LogRecord) -> str:
        return _redact(super().format(record))


def get_logger(module_name: str) -> logging.Logger:
    """Retourne un logger isolé qui écrit dans logs/<module>.log."""
    if module_name in _LOGGERS:
        return _LOGGERS[module_name]
    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    resolved_name = Path(sys.argv[0]).stem if module_name == "__main__" else module_name
    filename = resolved_name.rsplit(".", 1)[-1]
    logger = logging.getLogger(f"log_analyser.{resolved_name}")
    configured_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logger.setLevel(_LOG_LEVELS.get(configured_level, logging.INFO))
    logger.propagate = False
    if not logger.handlers:
        handler = RotatingFileHandler(
            LOG_DIRECTORY / f"{filename}.log", maxBytes=2_000_000,
            backupCount=3, encoding="utf-8",
        )
        handler.setFormatter(RedactingFormatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        ))
        logger.addHandler(handler)
    _LOGGERS[module_name] = logger
    return logger
