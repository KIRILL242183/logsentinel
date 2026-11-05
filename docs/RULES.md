# Правила обнаружения

Все пороги можно поменять в конфиге. Значения по умолчанию подобраны для небольшого сервера и проверены
только на учебных данных, для реального сервера их стоит подстраивать под обычную нагрузку.

| Правило | Условие по умолчанию | Важность | ATT&CK |
|---|---|---|---|
| SSH-BRUTE-FORCE | 5 неудачных паролей с одного IP за 60 с | high | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing |
| SSH-USER-ENUM | 6 разных имён с одного IP за 5 мин | medium | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying |
| SSH-SUCCESS-AFTER-FAILS | вход после 5 и более неудач с того же IP за 10 мин | critical | [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |
| WEB-LOGIN-BRUTE-FORCE | 8 неудачных `POST /login` с одного IP за 5 мин | high | T1110.001 |
| WEB-SCANNER | 15 разных путей с ответом 400/403/404/405 за 60 с | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) Wordlist Scanning |
| WEB-ATTACK-PATTERN | в адресе или User-Agent найдена сигнатура | high | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application |
| WEB-SCANNER-UA | User-Agent содержит имя известного сканера | medium | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) Vulnerability Scanning |
| WEB-SENSITIVE-PATH | запрос к служебному файлу или админке | medium | T1595.003 |

## Почему такие правила

**SSH-SUCCESS-AFTER-FAILS** важнее остальных SSH-правил. Подбор пароля сам по себе — шум, который идёт на любой
открытый сервер постоянно. Опасен момент, когда подбор удался. Поэтому правило critical.

**SSH-USER-ENUM** считает уникальные имена, а не попытки: боты перебирают списки типовых логинов (`admin`, `ubuntu`, `pi`),
а человек, забывший пароль, пробует одно имя.

**WEB-LOGIN-BRUTE-FORCE** считает только неудачные POST. Успешные входы (303 у InvoiceShield) и GET страницы входа не считаются,
это проверено тестами.

**WEB-ATTACK-PATTERN** перед проверкой декодирует адрес дважды: `%252e%252e%252f` превращается в `../`.

## Сигнатуры WEB-ATTACK-PATTERN

| Имя | Пример |
|---|---|
| sqli-union | `id=1 UNION SELECT null,password FROM users` |
| sqli-boolean | `id=1' OR '1'='1` |
| sqli-time | `id=1 AND SLEEP(5)` |
| sqli-schema | `information_schema`, `sqlite_master` |
| sqli-comment | `name=x'--` |
| xss | `<script>`, `javascript:`, `onerror=` |
| path-traversal | `../../` |
| sensitive-file | `/etc/passwd`, `win.ini` |
| cmd-injection | `;cat /etc/hosts`, `| id` |
| log4shell | `${jndi:ldap://...}` |
| php-wrapper | `php://filter` |

## Известные ложные срабатывания

- Пользователь, который неверно набирает пароль много раз, или несколько человек за одним NAT-адресом
  (SSH-BRUTE-FORCE, WEB-LOGIN-BRUTE-FORCE).
- Скрипты мониторинга и краулеры, которые проходят по несуществующим страницам (WEB-SCANNER).
- Обычный поисковый запрос со словом `select` и апострофом, например `q=O'Reilly -- book` (sqli-comment).
  Такие адреса можно добавить в список доверенных или поправить сигнатуру.
- Внутренний сканер уязвимостей компании (WEB-SCANNER-UA): его адрес нужно внести в `allowlist`.

## Что правила не видят

- Медленные атаки: одна попытка в 10 минут никогда не наберёт порог.
- Распределённый перебор с сотен адресов, где у каждого по одной попытке.
- Атаки в теле POST-запроса и в заголовках (кроме User-Agent): в стандартном логе nginx их нет.
- Успешность атаки. Ответ сервера записывается в `details`, но решает человек.

## Как добавить своё правило

Нужно создать класс-наследник `Rule` в `logsentinel/rules.py` с методом `feed(event)`, который возвращает список
алертов, и добавить его в `build_rules()` в `config.py`. Затем написать два теста: на срабатывание и на отсутствие ложного срабатывания.
