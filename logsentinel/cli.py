"""Командная строка: analyze, follow, simulate, blocklist."""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from logsentinel import __version__
from logsentinel.config import build_rules, load_config
from logsentinel.engine import Engine
from logsentinel.follow import Tailer
from logsentinel.models import Alert, Severity
from logsentinel.parsers import ParseStats, make_ssh_parser, parse_file, parse_nginx_line
from logsentinel.report import build_report
from logsentinel.simulate import generate
from logsentinel.sinks import ConsoleSink, JsonlSink, TelegramSink
from logsentinel.storage import AlertStore


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logsentinel", description="Обнаружение атак по логам nginx и sshd")
    p.add_argument("--version", action="version", version=f"logsentinel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_sources(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--nginx", nargs="*", default=[], metavar="FILE", help="access-логи nginx (формат combined)")
        sp.add_argument("--ssh", nargs="*", default=[], metavar="FILE", help="логи sshd (auth.log / secure)")
        sp.add_argument("--year", type=int, default=datetime.now().year, help="год для логов sshd без года")
        sp.add_argument("--ssh-tz-offset", type=float, default=0.0,
                        help="часовой пояс логов sshd относительно UTC в часах (по умолчанию 0)")
        sp.add_argument("--config", help="файл настроек TOML")

    a = sub.add_parser("analyze", help="разобрать готовые логи целиком")
    add_sources(a)
    a.add_argument("--min-severity", type=_severity, default=Severity.LOW)
    a.add_argument("--db", help="сохранить алерты в SQLite")
    a.add_argument("--jsonl", help="дописать алерты в файл JSON Lines")
    a.add_argument("--report", help="записать отчёт Markdown")
    a.add_argument("--fail-on", type=_severity, help="вернуть код 2, если есть алерт не ниже этого уровня")
    a.add_argument("--color", action="store_true")

    f = sub.add_parser("follow", help="следить за логами в реальном времени")
    add_sources(f)
    f.add_argument("--from-start", action="store_true", help="сначала прочитать файлы с начала")
    f.add_argument("--poll", type=float, default=1.0, help="пауза между проверками, секунды")
    f.add_argument("--telegram", action="store_true", help="слать high/critical в Telegram (TELEGRAM_TOKEN и TELEGRAM_CHAT_ID)")
    f.add_argument("--jsonl")
    f.add_argument("--color", action="store_true")

    s = sub.add_parser("simulate", help="создать учебные логи с «атаками»")
    s.add_argument("--out", required=True)
    s.add_argument("--seed", type=int, default=1)

    b = sub.add_parser("blocklist", help="список IP из сохранённых алертов для nginx или fail2ban")
    b.add_argument("--db", required=True)
    b.add_argument("--min-severity", type=_severity, default=Severity.HIGH)
    b.add_argument("--format", choices=["plain", "nginx"], default="plain")
    return p


def _load_all(args) -> tuple[list, ParseStats]:
    stats = ParseStats()
    events = []
    ssh_parser = make_ssh_parser(args.year, args.ssh_tz_offset)
    for path in args.nginx:
        found, st = parse_file(path, parse_nginx_line)
        events += found
        stats.merge(st)
    for path in args.ssh:
        found, st = parse_file(path, ssh_parser)
        events += found
        stats.merge(st)
    return events, stats


def cmd_analyze(args) -> int:
    if not (args.nginx or args.ssh):
        print("Укажите хотя бы один файл: --nginx или --ssh", file=sys.stderr)
        return 1
    cfg = load_config(args.config)
    engine = Engine(build_rules(cfg), cfg["engine"]["cooldown_seconds"], cfg["engine"]["allowlist"])
    events, stats = _load_all(args)
    alerts = [a for a in engine.run(events) if a.severity >= args.min_severity]

    sinks = [ConsoleSink(color=args.color)]
    if args.jsonl:
        sinks.append(JsonlSink(args.jsonl))
    for alert in alerts:
        for sink in sinks:
            sink.send(alert)
    if args.db:
        with AlertStore(args.db) as store:
            store.add_many(alerts)
    summary = {"lines_total": stats.total, "lines_parsed": stats.parsed, "lines_ignored": stats.ignored,
               "events_allowlisted": engine.events_allowlisted, "suppressed": engine.suppressed}
    if args.report:
        Path(args.report).write_text(build_report(alerts, summary), encoding="utf-8")
    print(f"\nСтрок: {stats.total}, событий: {stats.parsed}, алертов: {len(alerts)} "
          f"(повторов объединено: {engine.suppressed})")
    if args.fail_on and any(a.severity >= args.fail_on for a in alerts):
        return 2
    return 0


def cmd_follow(args) -> int:
    if not (args.nginx or args.ssh):
        print("Укажите хотя бы один файл: --nginx или --ssh", file=sys.stderr)
        return 1
    cfg = load_config(args.config)
    engine = Engine(build_rules(cfg), cfg["engine"]["cooldown_seconds"], cfg["engine"]["allowlist"])
    ssh_parser = make_ssh_parser(args.year, args.ssh_tz_offset)
    sources = [(Tailer(p, args.from_start), parse_nginx_line) for p in args.nginx]
    sources += [(Tailer(p, args.from_start), ssh_parser) for p in args.ssh]
    sinks = [ConsoleSink(color=args.color)]
    if args.jsonl:
        sinks.append(JsonlSink(args.jsonl))
    if args.telegram:
        token, chat = os.getenv("TELEGRAM_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")
        if not token or not chat:
            print("Для --telegram нужны переменные TELEGRAM_TOKEN и TELEGRAM_CHAT_ID", file=sys.stderr)
            return 1
        sinks.append(TelegramSink(token, chat))
    print("Слежу за логами. Остановить: Ctrl+C", file=sys.stderr)
    try:
        while True:
            for tailer, parser in sources:
                for line in tailer.read_new():
                    event = parser(line)
                    if event is None:
                        continue
                    for alert in engine.process(event):
                        for sink in sinks:
                            sink.send(alert)
            sys.stdout.flush()
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print("\nОстановлено", file=sys.stderr)
    finally:
        for tailer, _ in sources:
            tailer.close()
    return 0


def cmd_simulate(args) -> int:
    access, auth = generate(args.out, seed=args.seed)
    print(f"Созданы файлы:\n  {access}\n  {auth}")
    print("Дальше: logsentinel analyze --nginx", access, "--ssh", auth, "--year 2026")
    return 0


def cmd_blocklist(args) -> int:
    with AlertStore(args.db) as store:
        alerts: list[Alert] = store.fetch(min_severity=args.min_severity)
    ips = sorted({a.ip for a in alerts})
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if args.format == "nginx":
        print(f"# Создано LogSentinel {stamp}. Перед использованием проверьте адреса вручную.")
        for ip in ips:
            print(f"deny {ip};")
    else:
        for ip in ips:
            print(ip)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"analyze": cmd_analyze, "follow": cmd_follow, "simulate": cmd_simulate, "blocklist": cmd_blocklist}
    try:
        return handlers[args.command](args)
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
