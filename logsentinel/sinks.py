"""Куда отправлять алерты: консоль, файл JSON Lines, Telegram."""
from __future__ import annotations

import json
import logging
import sys
import urllib.request
from pathlib import Path
from typing import Callable, TextIO

from logsentinel.models import Alert, Severity

log = logging.getLogger("logsentinel.sinks")

COLORS = {Severity.LOW: "\033[36m", Severity.MEDIUM: "\033[33m",
          Severity.HIGH: "\033[31m", Severity.CRITICAL: "\033[1;35m"}
RESET = "\033[0m"


def format_alert(alert: Alert) -> str:
    when = alert.first_ts.strftime("%Y-%m-%d %H:%M:%S")
    extra = f" x{alert.repeats}" if alert.repeats > 1 else ""
    return (f"[{alert.severity.name:<8}] {when}Z {alert.ip:<15} {alert.rule_id}{extra} "
            f"({alert.mitre}) {alert.title}")


class ConsoleSink:
    def __init__(self, stream: TextIO | None = None, color: bool = False):
        self.stream = stream or sys.stdout
        self.color = color

    def send(self, alert: Alert) -> None:
        line = format_alert(alert)
        if self.color:
            line = f"{COLORS[alert.severity]}{line}{RESET}"
        print(line, file=self.stream)


class JsonlSink:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def send(self, alert: Alert) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")


class TelegramSink:
    """Отправка в Telegram. Токен лежит в адресе запроса, поэтому адрес и токен нигде не логируем."""

    def __init__(self, token: str, chat_id: str, min_severity: Severity = Severity.HIGH,
                 opener: Callable = urllib.request.urlopen, timeout: float = 5):
        self._url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.min_severity = min_severity
        self._opener = opener
        self.timeout = timeout

    def send(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return
        body = json.dumps({"chat_id": self.chat_id, "text": format_alert(alert)}).encode()
        request = urllib.request.Request(self._url, data=body, headers={"Content-Type": "application/json"})
        try:
            self._opener(request, timeout=self.timeout).read()
        except Exception as exc:  # сеть не должна ронять разбор логов
            log.warning("Не удалось отправить алерт в Telegram: %s", type(exc).__name__)
