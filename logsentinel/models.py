"""Базовые структуры данных: событие из лога и алерт."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(f"Неизвестный уровень важности: {name!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Event:
    """Одна строка лога, приведённая к общему виду."""

    ts: datetime              # всегда с часовым поясом, в UTC
    source: str               # "nginx" или "sshd"
    kind: str                 # "http", "ssh_fail", "ssh_invalid_user", "ssh_success"
    ip: str
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    raw: str = ""


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: Severity
    ip: str
    first_ts: datetime
    last_ts: datetime
    count: int                # сколько событий попало в окно, когда сработало правило
    mitre: str
    details: dict = field(default_factory=dict)
    repeats: int = 1          # сколько раз правило срабатывало на этот IP (с учётом подавленных)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "ip": self.ip,
            "first_ts": self.first_ts.isoformat(),
            "last_ts": self.last_ts.isoformat(),
            "count": self.count,
            "repeats": self.repeats,
            "mitre": self.mitre,
            "details": self.details,
        }
