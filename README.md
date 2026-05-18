# micropki

Минимальная, но полнофункциональная реализация инфраструктуры открытых ключей (PKI) на Python — для обучения, демонстрации и лабораторных работ.

## Возможности

- Корневой УЦ (Root CA) — самоподписанный RSA-4096 или ECC P-384
- Промежуточный УЦ (Intermediate CA) — подписан корневым, с ограничением pathLen
- Сертификаты конечных сущностей — шаблоны: server, client, code_signing, ocsp, vpn, ipsec
- Генерация CSR — клиент создаёт запрос на сертификат (PKCS#10)
- Сервер репозитория — HTTP REST API для распространения сертификатов и CRL (FastAPI)
- Отзыв сертификатов и CRL — с сохранением причины отзыва по RFC 5280
- OCSP-ответчик — HTTP сервер, отвечает по RFC 6960 (GET и POST)
- Валидация цепочки — полная проверка по RFC 5280
- Проверка отзыва — OCSP -> CRL fallback
- Политики безопасности — минимальные размеры ключей, сроки, запрет wildcards
- Аудит-логирование — NDJSON с криптографической цепочкой хешей SHA-256
- Certificate Transparency (симуляция) — лог выпущенных сертификатов
- Компрометация ключей — блокировка, экстренный CRL
- Rate limiting — ограничение запросов по IP (token bucket)
- TLS-интеграция — сертификаты пригодны для реальных TLS-соединений
- Подпись кода — выпуск code signing сертификатов, подпись и проверка файлов


## Архитектура

```
CLI (cli.py)
  - ca init / issue-intermediate / issue-cert / revoke / gen-crl / compromise
  - client gen-csr / request-cert / validate / check-status
  - audit query / verify
         |
         v
CA Core (ca.py, certificates.py, csr.py, serial.py, templates.py, crypto_utils.py)
         |
         v
Безопасность (policy.py, audit.py, transparency.py, compromise.py, ratelimit.py)
         |
         v
Серверы
  - repo.py (FastAPI :8443)
  - ocsp_responder.py (FastAPI :8888)
         |
         v
Хранилище
  - SQLite: micropki.db
  - Файловая система: certs/, private/, crl/
  - audit.log + chain.dat
         |
         v
Валидация (chain.py, validation.py, revocation_check.py)
```

Все компоненты связаны через хранилище и серверы.


## Требования

- Python 3.10 или выше
- cryptography >= 42.0.0
- fastapi и uvicorn (для серверов)
- pydantic >= 2.0
- requests (для клиентских команд)
- OpenSSL (для демонстрации TLS и подписи кода)

Полный список — в requirements.txt.


## Установка

```bash
# Клонировать репозиторий
git clone https://github.com/megastormdoto/megacrypto.git
cd megacrypto

# Создать виртуальное окружение
# Linux/macOS:
python3 -m venv venv && source venv/bin/activate
# Windows:
py -m venv venv
.\venv\Scripts\activate

# Установить зависимости
pip install -r requirements.txt

# Установить пакет в dev-режиме
pip install -e .
```


## Конфигурация

Отдельного файла конфигурации нет: пути к БД, каталогам, парольным файлам и параметры выпуска задаются флагами CLI (см. --help у каждой команды). Правила политики реализованы в коде (micropki/policy.py).


## CLI Reference

### micropki ca — Операции удостоверяющего центра

| Команда | Описание |
|---------|----------|
| ca init | Создание самоподписанного корневого УЦ |
| ca issue-intermediate | Создание промежуточного УЦ |
| ca issue-cert | Выпуск сертификата конечной сущности |
| ca issue-ocsp-cert | Выпуск сертификата для OCSP-ответчика |
| ca verify | Проверка самоподписанного сертификата |
| ca verify-chain | Проверка цепочки сертификатов |
| ca list-certs | Список сертификатов в БД |
| ca show-cert | Показать PEM сертификата по серийному номеру |
| ca revoke | Отзыв сертификата |
| ca gen-crl | Генерация CRL |
| ca check-revoked | Проверка статуса отзыва в БД |
| ca compromise | Симуляция компрометации ключа |

### micropki client — Клиентские инструменты

| Команда | Описание |
|---------|----------|
| client gen-csr | Генерация ключа и CSR |
| client request-cert | Отправка CSR через API и получение сертификата |
| client validate | Валидация цепочки (chain / full с OCSP/CRL) |
| client check-status | Проверка статуса отзыва (OCSP -> CRL fallback) |

### micropki repo — Сервер репозитория

| Команда | Описание |
|---------|----------|
| repo serve | Запуск HTTP-сервера (порт 8443 по умолчанию) |

### micropki ocsp — OCSP-ответчик

| Команда | Описание |
|---------|----------|
| ocsp serve | Запуск OCSP-ответчика (порт 8888 по умолчанию) |

### micropki db — Управление базой данных

| Команда | Описание |
|---------|----------|
| db init | Инициализация SQLite базы данных |

### micropki audit — Аудит

| Команда | Описание |
|---------|----------|
| audit query | Запрос аудит-лога (фильтры: --operation, --level, --from, --to) |
| audit verify | Проверка целостности аудит-лога |

### micropki demo

| Команда | Описание |
|---------|----------|
| demo run | Полный автоматический сценарий |

Для подробной справки по любой команде используйте --help.


## Быстрый старт

```bash
# 1. Создать пароли
mkdir secrets
echo -n "root-passphrase" > secrets/ca.pass
echo -n "intermediate-passphrase" > secrets/inter.pass

# 2. Корневой УЦ
micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 --passphrase-file secrets/ca.pass --out-dir ./pki

# 3. Промежуточный УЦ
micropki ca issue-intermediate --root-cert pki/certs/ca.cert.pem --root-key pki/private/ca.key.pem --root-pass-file secrets/ca.pass --subject "/CN=Demo Intermediate CA" --key-type rsa --key-size 4096 --passphrase-file secrets/inter.pass --out-dir ./pki --validity-days 1825 --pathlen 0

# 4. Серверный сертификат
micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --template server --subject "/CN=example.com" --san dns:example.com --out-dir pki/certs

# 5. Проверка цепочки
micropki ca verify-chain --leaf pki/certs/example.com.cert.pem --intermediate pki/certs/intermediate.cert.pem --root pki/certs/ca.cert.pem
```


## Демонстрация (Demo)

Запуск автоматического сценария:

```bash
# Linux/macOS
python3 demo/demo.py

# Windows
py demo/demo.py

# Или через CLI
micropki demo run
```

Скрипт выполняет:
1. Настройку окружения
2. Инициализацию Root CA
3. Инициализацию Intermediate CA
4. Выпуск сертификатов (server, client, OCSP)
5. Запуск серверов (репозиторий :8443, OCSP :8888)
6. Валидацию цепочки с OCSP
7. Проверку политик
8. Отзыв сертификата
9. Проверку отзыва
10. Проверку целостности аудит-лога


## API Reference (Repository Server)

Сервер запускается командой `micropki repo serve`.

| Метод | Путь | Описание |
|-------|------|----------|
| GET | / | Статус сервера |
| GET | /certificate/{serial_hex} | Получить сертификат по серийному номеру (PEM) |
| GET | /ca/root | Получить сертификат Root CA |
| GET | /ca/intermediate | Получить сертификат Intermediate CA |
| GET | /crl?ca=intermediate | Получить CRL |
| POST | /request-cert | Выпустить сертификат по CSR (JSON: {csr_pem, template}) |

Примеры:

```bash
# Статус
curl http://localhost:8443/

# Получить Root CA
curl http://localhost:8443/ca/root -o root.pem

# Получить CRL
curl http://localhost:8443/crl?ca=intermediate -o intermediate.crl.pem

# Выпустить сертификат через CSR
curl -X POST http://localhost:8443/request-cert \
  -H "Content-Type: application/json" \
  -d '{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----", "template": "server"}'
```


## Аудит и безопасность

### Аудит-лог

Все операции записываются в ./pki/audit/audit.log (NDJSON) с SHA-256 хеш-цепочкой:

```bash
micropki audit query --operation issue_certificate --format json
micropki audit verify
```

### Политики безопасности

| Политика | Правило |
|----------|---------|
| RSA Root | >= 4096 бит |
| RSA Intermediate | >= 3072 бит |
| RSA End-entity | >= 3072 бит |
| ECC Root/Intermediate | P-384 |
| ECC End-entity | P-384 |
| Срок Root | <= 3650 дней |
| Срок Intermediate | <= 1825 дней |
| Срок End-entity | <= 90 дней |
| Wildcard SAN | Запрещён |
| SHA-1 | Запрещён |
| MD5 | Запрещён |

### Rate Limiting

```bash
micropki repo serve --rate-limit 5 --rate-burst 10
micropki ocsp serve --rate-limit 10 --rate-burst 20
```


## Замечания по безопасности

> ВНИМАНИЕ: Данная система предназначена для образовательных целей и НЕ рекомендуется для использования в production без дополнительного усиления.

1. Закрытые ключи конечных сущностей хранятся без шифрования
2. Пароли Root/Intermediate CA читаются из файлов
3. OCSP-ответчик не использует HTTPS
4. Rate limiting базовый (token bucket per IP)
5. Нет аутентификации на API /request-cert


## Тестирование

### Запуск тестов

```bash
# Все тесты
pytest tests/ -v

# Windows
py -m pytest tests/ -v

# С покрытием кода
pytest tests/ -v --cov=micropki --cov-report=term-missing --cov-fail-under=80

# Performance-тесты (1000 сертификатов)
pytest tests/test_performance.py -v --run-perf -s
```

### Требования к покрытию

Целевое покрытие: >= 80% line coverage.


## Структура проекта

```
megacrypto/
├── micropki/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py               # CLI парсер
│   ├── ca.py                # Root CA, Intermediate CA
│   ├── certificates.py      # X.509 builder
│   ├── chain.py             # Валидация цепочки
│   ├── client.py            # Клиентские команды
│   ├── compromise.py        # Компрометация ключей
│   ├── crl.py               # Генерация CRL
│   ├── crypto_utils.py      # PEM, ключи, подписи
│   ├── csr.py               # CSR генерация
│   ├── database.py          # SQLite
│   ├── logger.py            # Логирование
│   ├── ocsp.py              # OCSP (RFC 6960)
│   ├── ocsp_responder.py    # OCSP HTTP сервер
│   ├── policy.py            # Политики безопасности
│   ├── ratelimit.py         # Rate limiting
│   ├── repo.py              # Repository HTTP сервер
│   ├── repository.py        # CRUD сертификатов
│   ├── revocation.py        # Отзыв сертификатов
│   ├── revocation_check.py  # OCSP/CRL fallback
│   ├── serial.py            # Серийные номера
│   ├── templates.py         # server, client, code_signing, ocsp, vpn, ipsec
│   ├── transparency.py      # Certificate Transparency
│   └── validation.py        # RFC 5280 path validation
├── tests/                   # pytest test suite
├── demo/
│   └── demo.py              # Автоматический демо-скрипт
├── .github/workflows/
│   └── ci.yml               # GitHub Actions CI
├── requirements.txt
├── pyproject.toml
├── Makefile
├── LICENSE
└── README.md
```

## Лицензия

MIT License. См. файл LICENSE.
```
