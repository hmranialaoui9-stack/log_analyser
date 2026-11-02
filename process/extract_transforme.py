"""Extraction et classification des événements d'authentification Linux."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import datetime
from typing import Any

MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
)}
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
STAMP_RE = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")


def _event(row: str, year: int | None = None) -> dict[str, Any]:
    """Transforme une ligne syslog en événement exploitable."""
    row = row.rstrip("\r\n")
    stamp = STAMP_RE.match(row)
    timestamp = None
    if stamp and stamp.group(1) in MONTHS:
        try:
            hour, minute, second = (int(part) for part in stamp.group(3).split(":"))
            timestamp = datetime(year or datetime.now().year, MONTHS[stamp.group(1)],
                                 int(stamp.group(2)), hour, minute, second).isoformat(sep=" ")
        except ValueError:
            pass
    ips: list[str] = []
    for match in IP_RE.findall(row):
        try:
            address = ipaddress.ip_address(match)
            if str(address) not in ips:
                ips.append(str(address))
        except ValueError:
            continue
    lowered = row.lower()
    if "sshd" in lowered:
        category = "ssh"
        if any(s in lowered for s in ("accepted password", "accepted publickey", "accepted keyboard-interactive")):
            outcome = "success"
        elif any(s in lowered for s in ("failed password", "invalid user", "authentication failure", "maximum authentication attempts")):
            outcome = "failure"
        else:
            outcome = "other"
    else:
        category, outcome = "other", "other"
    user_match = re.search(r"(?:for (?:invalid user )?|user=)([^\s]+)", row, re.IGNORECASE)
    return {
        "timestamp": timestamp, "category": category, "outcome": outcome,
        "ips": ips, "user": user_match.group(1) if user_match else None, "message": row,
    }


def extract_from_row(row: str) -> dict[str, Any] | None:
    """Compatibilité avec l'ancienne fonction ; renvoie désormais l'événement."""
    if not isinstance(row, str) or not row.strip():
        return None
    return _event(row)


def analyze_rows(rows: list[str], year: int | None = None) -> list[dict[str, Any]]:
    """Analyse toutes les lignes et renvoie uniquement les lignes non vides."""
    # Évite de recalculer l'année courante pour chaque ligne d'une archive volumineuse.
    analysis_year = year if year is not None else datetime.now().year
    return [_event(row, analysis_year) for row in rows if isinstance(row, str) and row.strip()]


def summarize(events: list[dict[str, Any]], suspicious_threshold: int = 5) -> dict[str, Any]:
    """Calcule des indicateurs et signale les sources d'échecs répétés.

    Une IP est suspecte à partir de `suspicious_threshold` événements SSH en
    échec ; ce seuil est volontairement simple et visible dans le rapport.
    """
    ssh = [event for event in events if event["category"] == "ssh"]
    counts = Counter(ip for event in events for ip in event["ips"])
    failed = Counter(ip for event in ssh if event["outcome"] == "failure" for ip in event["ips"])
    return {
        "total_events": len(events), "ssh_events": len(ssh),
        "successful_logins": sum(e["outcome"] == "success" for e in ssh),
        "failed_logins": sum(e["outcome"] == "failure" for e in ssh),
        "other_ssh_events": sum(e["outcome"] == "other" for e in ssh),
        "unique_ips": len(counts), "top_ips": counts.most_common(10),
        "suspicious_ips": [{"ip": ip, "failed_attempts": n} for ip, n in failed.most_common() if n >= suspicious_threshold],
        "suspicious_threshold": suspicious_threshold,
        "events_with_timestamp": sum(bool(e["timestamp"]) for e in events),
    }
