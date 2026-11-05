"""Настройки: значения по умолчанию + необязательный файл TOML."""
from __future__ import annotations

import tomllib
from pathlib import Path

from logsentinel import rules as r

DEFAULTS: dict[str, dict] = {
    "engine": {"cooldown_seconds": 300, "allowlist": ["127.0.0.1", "::1"]},
    "ssh_bruteforce": {"threshold": 5, "window_seconds": 60},
    "ssh_user_enum": {"distinct_users": 6, "window_seconds": 300},
    "ssh_success_after_fails": {"min_failures": 5, "window_seconds": 600},
    "web_login_bruteforce": {"login_path": "/login", "failure_statuses": [200, 401, 403, 429],
                             "threshold": 8, "window_seconds": 300},
    "web_scanner": {"distinct_paths": 15, "window_seconds": 60, "statuses": [400, 403, 404, 405]},
}


def load_config(path: str | Path | None = None) -> dict[str, dict]:
    cfg = {section: dict(values) for section, values in DEFAULTS.items()}
    if path is None:
        return cfg
    with open(path, "rb") as fh:
        user = tomllib.load(fh)
    for section, values in user.items():
        if section not in cfg:
            raise ValueError(f"Неизвестная секция в конфиге: [{section}]")
        for key, value in values.items():
            if key not in cfg[section]:
                raise ValueError(f"Неизвестный параметр [{section}] {key}")
            cfg[section][key] = value
    return cfg


def build_rules(cfg: dict[str, dict]) -> list[r.Rule]:
    return [
        r.SshBruteForce(**cfg["ssh_bruteforce"]),
        r.SshUserEnumeration(**cfg["ssh_user_enum"]),
        r.SshSuccessAfterFailures(**cfg["ssh_success_after_fails"]),
        r.WebLoginBruteForce(**cfg["web_login_bruteforce"]),
        r.WebScanner(**cfg["web_scanner"]),
        r.WebAttackPatterns(),
        r.ScannerUserAgent(),
        r.SensitivePathProbe(),
    ]
