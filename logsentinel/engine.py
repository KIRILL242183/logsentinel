"""Движок: прогоняет события через правила, подавляет повторы и не трогает доверенные адреса."""
from __future__ import annotations

import ipaddress
from typing import Iterable

from logsentinel.models import Alert, Event
from logsentinel.rules import Rule


class Engine:
    def __init__(self, rules: list[Rule], cooldown_seconds: float = 300, allowlist: Iterable[str] = ()):
        self.rules = rules
        self.cooldown = cooldown_seconds
        self.networks = [ipaddress.ip_network(a, strict=False) for a in allowlist]
        self._last_alert: dict[tuple[str, str], Alert] = {}
        self._emitted_at: dict[tuple[str, str], object] = {}
        self.events_seen = 0
        self.events_allowlisted = 0
        self.suppressed = 0

    def _is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def process(self, event: Event) -> list[Alert]:
        """Возвращает только НОВЫЕ алерты. Повторное срабатывание того же правила на тот же IP
        внутри cooldown (считая от момента первого алерта) не создаёт новый, а обновляет last_ts
        и repeats у прежнего. Долгая атака поэтому даёт новый алерт раз в cooldown, а не тысячи."""
        self.events_seen += 1
        if self._is_trusted(event.ip):
            self.events_allowlisted += 1
            return []
        new_alerts: list[Alert] = []
        for rule in self.rules:
            for alert in rule.feed(event):
                key = (alert.rule_id, alert.ip)
                prev = self._last_alert.get(key)
                emitted = self._emitted_at.get(key)
                if prev is not None and (alert.last_ts - emitted).total_seconds() < self.cooldown:
                    prev.repeats += 1
                    prev.last_ts = alert.last_ts
                    self.suppressed += 1
                    continue
                self._last_alert[key] = alert
                self._emitted_at[key] = alert.last_ts
                new_alerts.append(alert)
        return new_alerts

    def run(self, events: Iterable[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in sorted(events, key=lambda e: e.ts):
            alerts.extend(self.process(event))
        return alerts
