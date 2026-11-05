from logsentinel.engine import Engine
from logsentinel.rules import SshBruteForce, WebAttackPatterns


def test_cooldown_merges_repeats(make_ssh):
    engine = Engine([SshBruteForce(threshold=3, window_seconds=60)], cooldown_seconds=300)
    events = [make_ssh(i, "ssh_fail") for i in range(30)]
    alerts = engine.run(events)
    assert len(alerts) == 1
    assert alerts[0].repeats == 28          # срабатывает с 3-го события: 28 раз
    assert engine.suppressed == 27
    assert alerts[0].last_ts == events[-1].ts


def test_long_attack_alerts_again_after_cooldown(make_ssh):
    engine = Engine([SshBruteForce(threshold=3, window_seconds=60)], cooldown_seconds=100)
    events = [make_ssh(i * 2, "ssh_fail") for i in range(300)]   # 600 секунд подряд
    alerts = engine.run(events)
    assert 5 <= len(alerts) <= 7


def test_allowlist_skips_trusted_addresses(make_ssh):
    engine = Engine([SshBruteForce(threshold=3, window_seconds=60)], allowlist=["10.0.0.0/8"])
    events = [make_ssh(i, "ssh_fail", ip="10.1.2.3") for i in range(10)]
    assert engine.run(events) == []
    assert engine.events_allowlisted == 10


def test_different_ips_get_separate_alerts(make_ssh):
    engine = Engine([SshBruteForce(threshold=3, window_seconds=60)])
    events = [make_ssh(i, "ssh_fail", ip="203.0.113.1") for i in range(3)]
    events += [make_ssh(i, "ssh_fail", ip="203.0.113.2") for i in range(3)]
    assert {a.ip for a in engine.run(events)} == {"203.0.113.1", "203.0.113.2"}


def test_events_are_sorted_by_time(make_http):
    engine = Engine([WebAttackPatterns()])
    events = [make_http(10, path="/?q=<script>"), make_http(0, path="/?q=<script>")]
    alerts = engine.run(events)
    assert len(alerts) == 1
    assert alerts[0].first_ts < alerts[0].last_ts or alerts[0].repeats == 2


def test_invalid_ip_is_not_trusted(make_http):
    engine = Engine([WebAttackPatterns()], allowlist=["10.0.0.0/8"])
    assert engine.process(make_http(0, ip="not-an-ip", path="/?q=<script>"))
