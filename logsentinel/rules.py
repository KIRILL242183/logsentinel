"""Правила обнаружения. Каждое правило получает события по одному (в порядке времени)
и возвращает список алертов. Время берётся из самих событий, а не из часов системы,
поэтому один и тот же лог всегда даёт один и тот же результат."""
from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import unquote_plus, urlsplit

from logsentinel.models import Alert, Event, Severity


class SlidingWindow:
    """Скользящее окно: для каждого ключа (обычно IP) хранит события за последние N секунд."""

    PRUNE_EVERY = 5000

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._data: dict[str, deque] = defaultdict(deque)
        self._adds = 0

    def _trim(self, items: deque, now: datetime) -> None:
        while items and (now - items[0][0]).total_seconds() > self.seconds:
            items.popleft()

    def add(self, key: str, ts: datetime, value=None) -> deque:
        items = self._data[key]
        items.append((ts, value))
        self._trim(items, ts)
        self._adds += 1
        if self._adds % self.PRUNE_EVERY == 0:
            self._prune(ts)
        return items

    def peek(self, key: str, now: datetime) -> deque:
        """Посмотреть окно, ничего не добавляя."""
        items = self._data.get(key)
        if items is None:
            return deque()
        self._trim(items, now)
        return items

    def _prune(self, now: datetime) -> None:
        """Убираем ключи, по которым давно ничего не было, чтобы память не росла бесконечно."""
        for key in list(self._data):
            self._trim(self._data[key], now)
            if not self._data[key]:
                del self._data[key]


class Rule:
    id = "BASE"
    title = ""
    severity = Severity.MEDIUM
    mitre = ""

    def feed(self, event: Event) -> list[Alert]:
        raise NotImplementedError

    def _alert(self, event: Event, first_ts: datetime, count: int, **details) -> Alert:
        return Alert(rule_id=self.id, title=self.title, severity=self.severity, ip=event.ip,
                     first_ts=first_ts, last_ts=event.ts, count=count, mitre=self.mitre, details=details)


# ---------------------------------------------------------------- SSH

class SshBruteForce(Rule):
    id = "SSH-BRUTE-FORCE"
    title = "Подбор пароля SSH"
    severity = Severity.HIGH
    mitre = "T1110.001"

    def __init__(self, threshold: int = 5, window_seconds: float = 60):
        self.threshold = threshold
        self.window = SlidingWindow(window_seconds)

    def feed(self, event: Event) -> list[Alert]:
        if event.kind != "ssh_fail":
            return []
        hits = self.window.add(event.ip, event.ts, event.user)
        if len(hits) < self.threshold:
            return []
        users = sorted({u for _, u in hits if u})
        return [self._alert(event, hits[0][0], len(hits), users=users[:10])]


class SshUserEnumeration(Rule):
    id = "SSH-USER-ENUM"
    title = "Перебор имён пользователей SSH"
    severity = Severity.MEDIUM
    mitre = "T1110.003"

    def __init__(self, distinct_users: int = 6, window_seconds: float = 300):
        self.distinct_users = distinct_users
        self.window = SlidingWindow(window_seconds)

    def feed(self, event: Event) -> list[Alert]:
        if event.kind not in ("ssh_fail", "ssh_invalid_user") or not event.user:
            return []
        hits = self.window.add(event.ip, event.ts, event.user)
        users = {u for _, u in hits}
        if len(users) < self.distinct_users:
            return []
        return [self._alert(event, hits[0][0], len(users), users=sorted(users)[:15])]


class SshSuccessAfterFailures(Rule):
    """Самое важное из SSH-правил: успешный вход сразу после серии неудачных попыток."""

    id = "SSH-SUCCESS-AFTER-FAILS"
    title = "Успешный вход SSH после серии неудач"
    severity = Severity.CRITICAL
    mitre = "T1110, T1078"

    def __init__(self, min_failures: int = 5, window_seconds: float = 600):
        self.min_failures = min_failures
        self.window = SlidingWindow(window_seconds)

    def feed(self, event: Event) -> list[Alert]:
        if event.kind == "ssh_fail":
            self.window.add(event.ip, event.ts, event.user)
            return []
        if event.kind != "ssh_success":
            return []
        fails = self.window.peek(event.ip, event.ts)
        if len(fails) < self.min_failures:
            return []
        return [self._alert(event, fails[0][0], len(fails), user=event.user,
                            failed_users=sorted({u for _, u in fails if u})[:10])]


# ---------------------------------------------------------------- HTTP

def _path_only(path: str | None) -> str:
    return urlsplit(path or "").path


class WebLoginBruteForce(Rule):
    """Много неудачных POST на страницу входа.

    InvoiceShield при неверном пароле отвечает 200 (страница с ошибкой), при успехе — 303,
    поэтому 200 по умолчанию входит в «неудачные» статусы. Для другого приложения список меняется в конфиге.
    """

    id = "WEB-LOGIN-BRUTE-FORCE"
    title = "Подбор пароля на странице входа"
    severity = Severity.HIGH
    mitre = "T1110.001"

    def __init__(self, login_path: str = "/login", failure_statuses=(200, 401, 403, 429),
                 threshold: int = 8, window_seconds: float = 300):
        self.login_path = login_path
        self.failure_statuses = set(failure_statuses)
        self.threshold = threshold
        self.window = SlidingWindow(window_seconds)

    def feed(self, event: Event) -> list[Alert]:
        if (event.kind != "http" or event.method != "POST"
                or _path_only(event.path) != self.login_path
                or event.status not in self.failure_statuses):
            return []
        hits = self.window.add(event.ip, event.ts, event.status)
        if len(hits) < self.threshold:
            return []
        throttled = sum(1 for _, s in hits if s == 429)
        return [self._alert(event, hits[0][0], len(hits), throttled_by_app=throttled)]


class WebScanner(Rule):
    """Один IP за короткое время запрашивает много разных несуществующих адресов."""

    id = "WEB-SCANNER"
    title = "Сканирование адресов (много 404/403)"
    severity = Severity.MEDIUM
    mitre = "T1595.003"

    def __init__(self, distinct_paths: int = 15, window_seconds: float = 60,
                 statuses=(400, 403, 404, 405)):
        self.distinct_paths = distinct_paths
        self.statuses = set(statuses)
        self.window = SlidingWindow(window_seconds)

    def feed(self, event: Event) -> list[Alert]:
        if event.kind != "http" or event.status not in self.statuses:
            return []
        hits = self.window.add(event.ip, event.ts, _path_only(event.path))
        paths = {p for _, p in hits}
        if len(paths) < self.distinct_paths:
            return []
        sample = sorted(paths)[:5]
        return [self._alert(event, hits[0][0], len(paths), sample_paths=sample)]


# Сигнатуры считаются по декодированному адресу в нижнем регистре.
# Это грубые регулярки: они ловят типичные учебные и автоматические payload'ы
# и дают ложные срабатывания (см. docs/RULES.md).
ATTACK_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("sqli-union", re.compile(r"union\s+(all\s+)?select")),
    ("sqli-boolean", re.compile(r"['\"]\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|\b(or|and)\s+\d+\s*=\s*\d+")),
    ("sqli-time", re.compile(r"\b(sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay")),
    ("sqli-schema", re.compile(r"information_schema|sqlite_master|pg_catalog|xp_cmdshell")),
    ("sqli-comment", re.compile(r"['\"]\s*(--|#|/\*)")),
    ("xss", re.compile(r"<\s*script|javascript:|\bon(error|load|mouseover|focus|click)\s*=")),
    ("path-traversal", re.compile(r"\.\./|\.\.\\")),
    ("sensitive-file", re.compile(r"/etc/(passwd|shadow|hosts)|/proc/self/|\bwin\.ini\b|\bboot\.ini\b")),
    ("cmd-injection", re.compile(r"(;|\||`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b")),
    ("log4shell", re.compile(r"\$\{jndi:")),
    ("php-wrapper", re.compile(r"php://|data://|expect://")),
]


def normalize_url(value: str) -> str:
    """Декодируем адрес дважды (против двойного кодирования), убираем нулевые байты, приводим к нижнему регистру."""
    for _ in range(2):
        value = unquote_plus(value)
    return value.replace("\x00", "").lower()


class WebAttackPatterns(Rule):
    id = "WEB-ATTACK-PATTERN"
    title = "Признаки веб-атаки в запросе"
    severity = Severity.HIGH
    mitre = "T1190"

    def feed(self, event: Event) -> list[Alert]:
        if event.kind != "http":
            return []
        target = normalize_url(f"{event.path or ''} {event.user_agent or ''}")
        found = [name for name, rx in ATTACK_SIGNATURES if rx.search(target)]
        if not found:
            return []
        return [self._alert(event, event.ts, 1, signatures=found,
                            path=(event.path or "")[:200], response_status=event.status)]


SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|dirb\b|wpscan|nuclei|acunetix|zgrab|hydra|feroxbuster|ffuf",
    re.IGNORECASE,
)


class ScannerUserAgent(Rule):
    id = "WEB-SCANNER-UA"
    title = "User-Agent известного сканера"
    severity = Severity.MEDIUM
    mitre = "T1595.002"

    def feed(self, event: Event) -> list[Alert]:
        if event.kind != "http" or not event.user_agent:
            return []
        m = SCANNER_UA.search(event.user_agent)
        if not m:
            return []
        return [self._alert(event, event.ts, 1, tool=m.group(0).lower(), user_agent=event.user_agent[:120])]


SENSITIVE_PATHS = re.compile(
    r"^/\.(env|git|svn|aws|ssh|ds_store)"
    r"|/wp-(admin|login\.php|content|includes)|/xmlrpc\.php"
    r"|/phpmyadmin|/pma/|/server-(status|info)|/actuator|/cgi-bin/|/boaform|/vendor/phpunit"
    r"|/(config|database|db|backup|dump)\.(php|sql|bak|zip|tar\.gz)$"
    r"|\.(bak|old|swp|orig)$"
)


class SensitivePathProbe(Rule):
    id = "WEB-SENSITIVE-PATH"
    title = "Попытка открыть служебные файлы и админки"
    severity = Severity.MEDIUM
    mitre = "T1595.003"

    def feed(self, event: Event) -> list[Alert]:
        if event.kind != "http":
            return []
        path = normalize_url(_path_only(event.path))
        if not SENSITIVE_PATHS.search(path):
            return []
        return [self._alert(event, event.ts, 1, path=path[:200], response_status=event.status)]
