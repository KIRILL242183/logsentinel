import json
import sqlite3

import pytest

from logsentinel.cli import main
from logsentinel.config import load_config
from logsentinel.models import Alert, Severity
from logsentinel.report import build_report
from logsentinel.simulate import EXPECTED, NORMAL_IPS, generate
from logsentinel.sinks import TelegramSink, format_alert
from logsentinel.storage import AlertStore


@pytest.fixture
def sim(tmp_path):
    access, auth = generate(tmp_path / "logs", seed=1)
    return tmp_path, access, auth


def run_analyze(sim, *extra):
    tmp_path, access, auth = sim
    return main(["analyze", "--nginx", str(access), "--ssh", str(auth), "--year", "2026",
                 "--db", str(tmp_path / "a.db"), "--jsonl", str(tmp_path / "a.jsonl"), *extra])


def test_simulated_attacks_are_found_exactly(sim, capsys):
    assert run_analyze(sim) == 0
    tmp_path = sim[0]
    with AlertStore(tmp_path / "a.db") as store:
        alerts = store.fetch()
    found: dict[str, set[str]] = {}
    for a in alerts:
        found.setdefault(a.ip, set()).add(a.rule_id)
    assert found == EXPECTED          # ни лишних IP, ни лишних правил


def test_normal_users_get_no_alerts(sim):
    run_analyze(sim)
    with AlertStore(sim[0] / "a.db") as store:
        assert not {a.ip for a in store.fetch()} & set(NORMAL_IPS)


def test_result_is_deterministic(sim):
    run_analyze(sim)
    first = (sim[0] / "a.jsonl").read_text()
    (sim[0] / "a.jsonl").unlink()
    run_analyze(sim)
    assert (sim[0] / "a.jsonl").read_text() == first


def test_jsonl_lines_are_valid_json(sim):
    run_analyze(sim)
    rows = [json.loads(line) for line in (sim[0] / "a.jsonl").read_text().splitlines()]
    assert rows and all({"rule_id", "severity", "ip", "mitre"} <= row.keys() for row in rows)


def test_fail_on_returns_exit_code_2(sim):
    assert run_analyze(sim, "--fail-on", "critical") == 2


def test_fail_on_not_triggered_for_clean_log(tmp_path):
    access, _ = generate(tmp_path / "logs")
    clean = tmp_path / "clean.log"
    clean.write_text("\n".join(line for line in access.read_text().splitlines()
                               if line.split()[0] in NORMAL_IPS) + "\n")
    assert main(["analyze", "--nginx", str(clean), "--fail-on", "low"]) == 0


def test_min_severity_filters(sim):
    run_analyze(sim, "--min-severity", "critical")
    with AlertStore(sim[0] / "a.db") as store:
        assert {a.severity for a in store.fetch()} == {Severity.CRITICAL}


def test_report_contains_sections(sim):
    out = sim[0] / "report.md"
    run_analyze(sim, "--report", str(out))
    text = out.read_text(encoding="utf-8")
    for part in ["## Сводка", "## Алерты по правилам", "## Источники атак", "SSH-SUCCESS-AFTER-FAILS", "203.0.113.77"]:
        assert part in text


def test_report_without_alerts():
    assert "Алертов нет" in build_report([], {})


def test_blocklist_nginx_format(sim, capsys):
    run_analyze(sim)
    capsys.readouterr()
    assert main(["blocklist", "--db", str(sim[0] / "a.db"), "--format", "nginx"]) == 0
    out = capsys.readouterr().out
    assert "deny 203.0.113.50;" in out
    assert "192.0.2.10" not in out


def test_missing_file_gives_error_not_traceback(tmp_path, capsys):
    assert main(["analyze", "--nginx", str(tmp_path / "нет.log")]) == 1
    assert "Ошибка" in capsys.readouterr().err


def test_analyze_requires_a_file(capsys):
    assert main(["analyze"]) == 1


def test_config_override_and_unknown_keys(tmp_path):
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text("[ssh_bruteforce]\nthreshold = 50\n")
    assert load_config(cfg_file)["ssh_bruteforce"]["threshold"] == 50
    cfg_file.write_text("[ssh_bruteforce]\nthreshhold = 50\n")      # опечатка должна быть замечена
    with pytest.raises(ValueError):
        load_config(cfg_file)


def test_storage_roundtrip_and_filters(sim):
    run_analyze(sim)
    with AlertStore(sim[0] / "a.db") as store:
        one_ip = store.fetch(ip="203.0.113.77")
        assert {a.rule_id for a in one_ip} == EXPECTED["203.0.113.77"]
        assert all(isinstance(a, Alert) for a in one_ip)


def test_storage_is_safe_against_sql_in_ip_filter(sim):
    run_analyze(sim)
    with AlertStore(sim[0] / "a.db") as store:
        assert store.fetch(ip="' OR '1'='1") == []
    conn = sqlite3.connect(sim[0] / "a.db")
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] > 0


class FakeResponse:
    def read(self):
        return b"{}"


def test_telegram_sink_filters_by_severity_and_survives_errors(sim):
    run_analyze(sim)
    with AlertStore(sim[0] / "a.db") as store:
        alerts = store.fetch()
    sent = []

    def fake_open(request, timeout):
        sent.append(json.loads(request.data))
        return FakeResponse()

    sink = TelegramSink("TOKEN", "42", min_severity=Severity.CRITICAL, opener=fake_open)
    for a in alerts:
        sink.send(a)
    assert len(sent) == 1 and sent[0]["chat_id"] == "42"
    assert "SSH-SUCCESS-AFTER-FAILS" in sent[0]["text"]

    def broken_open(request, timeout):
        raise OSError("нет сети")

    TelegramSink("TOKEN", "42", opener=broken_open).send(alerts[0])     # не должно бросить исключение


def test_telegram_token_not_leaked_in_log_on_error(sim, caplog):
    run_analyze(sim)
    with AlertStore(sim[0] / "a.db") as store:
        alert = store.fetch(min_severity=Severity.HIGH)[0]

    def broken_open(request, timeout):
        raise OSError(f"cannot reach {request.full_url}")

    with caplog.at_level("WARNING"):
        TelegramSink("SECRET-TOKEN-123", "42", opener=broken_open).send(alert)
    assert "SECRET-TOKEN-123" not in caplog.text


def test_format_alert_contains_key_fields(sim):
    run_analyze(sim)
    with AlertStore(sim[0] / "a.db") as store:
        line = format_alert(store.fetch()[0])
    assert "SSH-" in line and "T1110" in line
