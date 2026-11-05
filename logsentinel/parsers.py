"""Разбор строк логов nginx (combined) и sshd (syslog) в объекты Event."""
from __future__ import annotations

import gzip
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from logsentinel.models import Event

# Названия месяцев задаём вручную: strptime("%b") зависит от локали системы.
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
NGINX_TIME_RE = re.compile(
    r"^(?P<d>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<y>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2}) "
    r"(?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2})$"
)

# Две формы заголовка syslog: классическая («Nov  4 10:15:02») и ISO 8601.
SYSLOG_RE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2}))"
    r"\s+\S+\s+sshd(?:\[\d+\])?: (?P<msg>.*)$"
)
SSH_FAILED_RE = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>.+?) "
    r"from (?P<ip>\S+) port \d+"
)
SSH_INVALID_RE = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)")
SSH_ACCEPTED_RE = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")


def parse_nginx_line(line: str) -> Event | None:
    """Формат nginx по умолчанию (combined). Возвращает None, если строка не подошла."""
    m = NGINX_RE.match(line.rstrip("\n"))
    if not m:
        return None
    t = NGINX_TIME_RE.match(m["time"])
    if not t or t["mon"] not in MONTHS:
        return None
    offset = timedelta(hours=int(t["oh"]), minutes=int(t["om"]))
    if t["sign"] == "-":
        offset = -offset
    try:
        ts = datetime(int(t["y"]), MONTHS[t["mon"]], int(t["d"]), int(t["h"]), int(t["mi"]),
                      int(t["s"]), tzinfo=timezone(offset)).astimezone(timezone.utc)
    except ValueError:
        return None

    parts = m["request"].split(" ")
    if len(parts) == 3 and parts[0].isalpha() and parts[0].isupper():
        method, path = parts[0], parts[1]
    else:
        # Мусор вместо запроса: TLS-рукопожатие на http-порт, бинарные данные и т. д.
        method, path = "-", m["request"]
    ua = m["ua"] if m["ua"] != "-" else None
    return Event(ts=ts, source="nginx", kind="http", ip=m["ip"], method=method, path=path,
                 status=int(m["status"]), user_agent=ua, raw=line.rstrip("\n"))


def make_ssh_parser(year: int, utc_offset_hours: float = 0.0) -> Callable[[str], Event | None]:
    """В классическом syslog нет года и часового пояса, поэтому их нужно передать."""
    tz = timezone(timedelta(hours=utc_offset_hours))

    def parse(line: str) -> Event | None:
        m = SYSLOG_RE.match(line.rstrip("\n"))
        if not m:
            return None
        try:
            if m["iso"]:
                ts = datetime.fromisoformat(m["iso"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=tz)
            else:
                if m["mon"] not in MONTHS:
                    return None
                h, mi, s = (int(x) for x in m["hms"].split(":"))
                ts = datetime(year, MONTHS[m["mon"]], int(m["day"]), h, mi, s, tzinfo=tz)
        except ValueError:
            return None
        ts = ts.astimezone(timezone.utc)
        msg = m["msg"]
        raw = line.rstrip("\n")

        if (f := SSH_FAILED_RE.match(msg)):
            return Event(ts=ts, source="sshd", kind="ssh_fail", ip=f["ip"], user=f["user"], raw=raw)
        if (i := SSH_INVALID_RE.match(msg)):
            return Event(ts=ts, source="sshd", kind="ssh_invalid_user", ip=i["ip"], user=i["user"], raw=raw)
        if (a := SSH_ACCEPTED_RE.match(msg)):
            return Event(ts=ts, source="sshd", kind="ssh_success", ip=a["ip"], user=a["user"], raw=raw)
        return None

    return parse


@dataclass
class ParseStats:
    total: int = 0     # прочитано строк
    parsed: int = 0    # превратилось в события
    ignored: int = 0   # строки, не подошедшие под формат (для sshd это нормально: там много лишнего)

    def merge(self, other: "ParseStats") -> None:
        self.total += other.total
        self.parsed += other.parsed
        self.ignored += other.ignored


def _open_log(path: str | Path):
    """Старые логи после logrotate обычно сжаты (access.log.2.gz), их читаем без распаковки на диск."""
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def parse_file(path: str | Path, parser: Callable[[str], Event | None]) -> tuple[list[Event], ParseStats]:
    events: list[Event] = []
    stats = ParseStats()
    with _open_log(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            stats.total += 1
            event = parser(line)
            if event is None:
                stats.ignored += 1
            else:
                stats.parsed += 1
                events.append(event)
    return events, stats
