import gzip
from datetime import datetime, timezone

from logsentinel.parsers import make_ssh_parser, parse_file, parse_nginx_line

NGINX_OK = ('203.0.113.5 - - [04/Nov/2026:12:00:01 +0300] "GET /api/invoices?id=1 HTTP/1.1" 200 512 '
            '"-" "Mozilla/5.0"')


def test_nginx_line_is_parsed_and_converted_to_utc():
    ev = parse_nginx_line(NGINX_OK)
    assert ev.ip == "203.0.113.5"
    assert ev.method == "GET"
    assert ev.path == "/api/invoices?id=1"
    assert ev.status == 200
    assert ev.ts == datetime(2026, 11, 4, 9, 0, 1, tzinfo=timezone.utc)


def test_nginx_negative_offset():
    line = '198.51.100.1 - - [04/Nov/2026:03:00:00 -0500] "GET / HTTP/1.1" 200 1 "-" "-"'
    assert parse_nginx_line(line).ts == datetime(2026, 11, 4, 8, 0, 0, tzinfo=timezone.utc)


def test_nginx_garbage_request_does_not_crash():
    line = '198.51.100.1 - - [04/Nov/2026:03:00:00 +0000] "\\x16\\x03\\x01" 400 150 "-" "-"'
    ev = parse_nginx_line(line)
    assert ev.method == "-"
    assert ev.status == 400


def test_nginx_returns_none_for_junk():
    assert parse_nginx_line("это не лог") is None
    assert parse_nginx_line("") is None
    assert parse_nginx_line('1.2.3.4 - - [99/Foo/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"') is None


def test_nginx_dash_user_agent_becomes_none():
    line = '198.51.100.1 - - [04/Nov/2026:03:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"'
    assert parse_nginx_line(line).user_agent is None


def test_ssh_failed_password_for_invalid_user():
    parse = make_ssh_parser(2026)
    ev = parse("Nov  4 10:15:02 srv01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2")
    assert (ev.kind, ev.user, ev.ip) == ("ssh_fail", "admin", "203.0.113.5")
    assert ev.ts == datetime(2026, 11, 4, 10, 15, 2, tzinfo=timezone.utc)


def test_ssh_failed_password_for_valid_user():
    parse = make_ssh_parser(2026)
    ev = parse("Nov 14 10:15:02 srv01 sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2")
    assert (ev.kind, ev.user) == ("ssh_fail", "root")


def test_ssh_invalid_user_and_accepted():
    parse = make_ssh_parser(2026)
    inv = parse("Nov  4 10:15:02 srv01 sshd[1]: Invalid user svc1 from 198.51.100.23 port 42000")
    ok = parse("Nov  4 10:15:09 srv01 sshd[1]: Accepted publickey for deploy from 198.51.100.7 port 5 ssh2: ED25519 SHA256:abc")
    assert (inv.kind, inv.user, inv.ip) == ("ssh_invalid_user", "svc1", "198.51.100.23")
    assert (ok.kind, ok.user) == ("ssh_success", "deploy")


def test_ssh_iso_timestamp_with_timezone():
    parse = make_ssh_parser(2026)
    ev = parse("2026-11-04T12:15:02.123456+03:00 srv01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
    assert ev.ts == datetime(2026, 11, 4, 9, 15, 2, 123456, tzinfo=timezone.utc)


def test_ssh_timezone_offset_option():
    parse = make_ssh_parser(2026, utc_offset_hours=3)
    ev = parse("Nov  4 12:00:00 srv01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
    assert ev.ts.hour == 9


def test_ssh_ignores_other_messages_and_other_daemons():
    parse = make_ssh_parser(2026)
    assert parse("Nov  4 10:15:02 srv01 sshd[1]: Connection closed by 203.0.113.5 port 1 [preauth]") is None
    assert parse("Nov  4 10:15:02 srv01 cron[1]: (root) CMD (run-parts)") is None


def test_parse_file_counts_ignored_lines(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(NGINX_OK + "\nмусор\n\n" + NGINX_OK + "\n", encoding="utf-8")
    events, stats = parse_file(path, parse_nginx_line)
    assert len(events) == 2
    assert (stats.total, stats.parsed, stats.ignored) == (3, 2, 1)


def test_parse_gzipped_rotated_log(tmp_path):
    path = tmp_path / "access.log.2.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write(NGINX_OK + "\n" + NGINX_OK + "\n")
    events, stats = parse_file(path, parse_nginx_line)
    assert len(events) == 2 and stats.ignored == 0


def test_ssh_journalctl_format_with_zero_padded_day():
    # так выглядит вывод `journalctl -u ssh`: день с ведущим нулём
    parse = make_ssh_parser(2026)
    ev = parse("Nov 04 10:15:02 srv01 sshd[812]: Failed password for root from 203.0.113.5 port 4242 ssh2")
    assert ev.ts == datetime(2026, 11, 4, 10, 15, 2, tzinfo=timezone.utc)
