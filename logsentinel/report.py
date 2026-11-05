"""Отчёт в Markdown по найденным алертам."""
from __future__ import annotations

from collections import Counter, defaultdict

from logsentinel.models import Alert, Severity

ADVICE = {
    "SSH-BRUTE-FORCE": "Отключить вход по паролю (PasswordAuthentication no), оставить ключи; fail2ban или блокировка IP.",
    "SSH-USER-ENUM": "Ограничить AllowUsers/AllowGroups; запретить вход root.",
    "SSH-SUCCESS-AFTER-FAILS": "Считать учётную запись скомпрометированной: проверить сессии и историю команд, сменить пароль/ключи.",
    "WEB-LOGIN-BRUTE-FORCE": "Проверить, что лимит попыток в приложении сработал; добавить ограничение частоты в nginx; рассмотреть MFA.",
    "WEB-SCANNER": "Ограничить частоту запросов на уровне nginx; проверить, нет ли среди найденных путей реально существующих.",
    "WEB-ATTACK-PATTERN": "Проверить по логам приложения, не дал ли запрос ответ 200 с данными; проверить валидацию ввода в этом эндпоинте.",
    "WEB-SCANNER-UA": "Заблокировать по User-Agent на nginx (легко обходится, но отсекает самые простые инструменты).",
    "WEB-SENSITIVE-PATH": "Убедиться, что служебные файлы (.env, .git, бэкапы) недоступны извне.",
}


def build_report(alerts: list[Alert], stats: dict, title: str = "Отчёт LogSentinel") -> str:
    lines = [f"# {title}", ""]
    lines += ["## Сводка", ""]
    lines.append(f"- Строк прочитано: {stats.get('lines_total', 0)}, разобрано в события: "
                 f"{stats.get('lines_parsed', 0)}, не подошло под формат: {stats.get('lines_ignored', 0)}")
    lines.append(f"- События от доверенных адресов (пропущены): {stats.get('events_allowlisted', 0)}")
    lines.append(f"- Алертов: {len(alerts)}; повторных срабатываний, объединённых с первым: {stats.get('suppressed', 0)}")
    by_sev = Counter(a.severity for a in alerts)
    for sev in sorted(Severity, reverse=True):
        lines.append(f"  - {sev.label}: {by_sev.get(sev, 0)}")
    if alerts:
        lines.append(f"- Период: {min(a.first_ts for a in alerts):%Y-%m-%d %H:%M:%S} — "
                     f"{max(a.last_ts for a in alerts):%Y-%m-%d %H:%M:%S} UTC")
    lines.append("")

    if not alerts:
        lines += ["Алертов нет.", ""]
        return "\n".join(lines)

    lines += ["## Алерты по правилам", "", "| Правило | MITRE ATT&CK | Важность | Алертов |", "|---|---|---|---|"]
    by_rule: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_rule[a.rule_id].append(a)
    for rule_id, items in sorted(by_rule.items(), key=lambda kv: (-max(a.severity for a in kv[1]), kv[0])):
        lines.append(f"| {rule_id} | {items[0].mitre} | {max(a.severity for a in items).label} | {len(items)} |")
    lines.append("")

    lines += ["## Источники атак", "", "| IP | Алертов | Макс. важность | Правила |", "|---|---|---|---|"]
    by_ip: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_ip[a.ip].append(a)
    for ip, items in sorted(by_ip.items(), key=lambda kv: (-max(a.severity for a in kv[1]), -len(kv[1]), kv[0])):
        rules = ", ".join(sorted({a.rule_id for a in items}))
        lines.append(f"| {ip} | {len(items)} | {max(a.severity for a in items).label} | {rules} |")
    lines.append("")

    serious = [a for a in alerts if a.severity >= Severity.HIGH]
    if serious:
        lines += ["## Хронология серьёзных алертов (high и выше)", ""]
        for a in sorted(serious, key=lambda x: x.first_ts)[:30]:
            lines.append(f"- {a.first_ts:%H:%M:%S} {a.ip} — {a.rule_id}, событий в окне: {a.count}, повторов: {a.repeats}")
        lines.append("")

    lines += ["## Что проверить", ""]
    for rule_id in sorted(by_rule):
        lines.append(f"- **{rule_id}**: {ADVICE.get(rule_id, 'Разобрать вручную.')}")
    lines += ["", "## Ограничения", "",
              "Правила работают по сигнатурам и порогам. Они пропустят медленные распределённые атаки "
              "и могут сработать на безобидный трафик (например, на пользователя, который забыл пароль). "
              "Перед блокировкой адреса алерт нужно проверить вручную.", ""]
    return "\n".join(lines)
