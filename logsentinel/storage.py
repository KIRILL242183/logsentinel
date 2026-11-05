"""Хранение алертов в SQLite. Все запросы параметризованы."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from logsentinel.models import Alert, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id   TEXT    NOT NULL,
    title     TEXT    NOT NULL,
    severity  INTEGER NOT NULL,
    ip        TEXT    NOT NULL,
    first_ts  TEXT    NOT NULL,
    last_ts   TEXT    NOT NULL,
    count     INTEGER NOT NULL,
    repeats   INTEGER NOT NULL,
    mitre     TEXT    NOT NULL,
    details   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts (ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
"""


class AlertStore:
    def __init__(self, path: str | Path):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)

    def __enter__(self) -> "AlertStore":
        return self

    def __exit__(self, *exc) -> None:
        self.conn.close()

    def add_many(self, alerts: list[Alert]) -> None:
        rows = [(a.rule_id, a.title, int(a.severity), a.ip, a.first_ts.isoformat(), a.last_ts.isoformat(),
                 a.count, a.repeats, a.mitre, json.dumps(a.details, ensure_ascii=False)) for a in alerts]
        with self.conn:
            self.conn.executemany(
                "INSERT INTO alerts (rule_id, title, severity, ip, first_ts, last_ts, count, repeats, mitre, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)

    def fetch(self, min_severity: Severity = Severity.LOW, ip: str | None = None) -> list[Alert]:
        query = ("SELECT rule_id, title, severity, ip, first_ts, last_ts, count, repeats, mitre, details "
                 "FROM alerts WHERE severity >= ?")
        params: list = [int(min_severity)]
        if ip:
            query += " AND ip = ?"
            params.append(ip)
        query += " ORDER BY first_ts, id"
        out = []
        for rule_id, title, sev, a_ip, first, last, count, repeats, mitre, details in self.conn.execute(query, params):
            out.append(Alert(rule_id=rule_id, title=title, severity=Severity(sev), ip=a_ip,
                             first_ts=datetime.fromisoformat(first), last_ts=datetime.fromisoformat(last),
                             count=count, repeats=repeats, mitre=mitre, details=json.loads(details)))
        return out
