```markdown
```
# MicroPKI

Легковесный инструмент для создания инфраструктуры открытых ключей (PKI) в образовательных целях.

## Описание

MicroPKI - это консольный инструмент, реализующий базовый центр сертификации (CA) для образовательных целей. Он создает самоподписанные корневые сертификаты с безопасным хранением ключей, расширениями X.509 v3 и подробным аудитом операций.

## Возможности первого спринта

- Генерация ключевых пар RSA (4096 бит) и ECC (P-384)
- Создание самоподписанных корневых сертификатов X.509 v3
- Шифрованное хранение приватных ключей (PKCS#8 с AES-256)
- Корректные расширения X.509 (Basic Constraints, Key Usage, SKI, AKI)
- Детальное логирование всех операций
- Генерация документа политики сертификации
- Полный набор тестов (позитивные и негативные сценарии)
- Совместимость с OpenSSL

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone <repository-url>
   cd micropki
   ```

2. Создайте и активируйте виртуальное окружение:
   ```bash
   python -m venv venv
   # В Windows:
   venv\Scripts\activate
   # В Unix/MacOS:
   source venv/bin/activate
   ```

3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

## Зависимости

- Python 3.8 или выше
- cryptography >= 41.0.0
- pytest >= 7.0.0 (для разработки и тестирования)

## Использование

### Инициализация корневого центра сертификации

Создание RSA-центра:
```bash
python -m micropki.cli ca init \
    --subject "/CN=Мой корневой CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./passphrase.txt \
    --out-dir ./pki \
    --validity-days 3650
```

Создание ECC-центра (P-384):
```bash
python -m micropki.cli ca init \
    --subject "CN=ECC корневой CA,O=Демо,C=RU" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file ./passphrase.txt \
    --out-dir ./pki \
    --validity-days 365
```

### Параметры команды

| Параметр | Описание | Обязательный | Значение по умолчанию |
|----------|----------|--------------|----------------------|
| `--subject` | Distinguished Name (например, "/CN=Test CA" или "CN=Test CA,O=Demo") | Да | - |
| `--key-type` | Тип ключа: `rsa` или `ecc` | Нет | `rsa` |
| `--key-size` | Размер ключа в битах (4096 для RSA, 384 для ECC) | Нет | 4096 |
| `--passphrase-file` | Путь к файлу с парольной фразой | Да | - |
| `--out-dir` | Директория для выходных файлов | Нет | `./pki` |
| `--validity-days` | Срок действия в днях | Нет | 3650 |
| `--log-file` | Путь к файлу лога | Нет | Вывод в stderr |
| `--force` | Перезаписывать существующие файлы | Нет | - |

## Структура выходных файлов

После успешной инициализации CA создается следующая структура:

```
<out-dir>/
├── private/
│   └── ca.key.pem      # Зашифрованный приватный ключ
├── certs/
│   └── ca.cert.pem     # Самоподписанный сертификат
└── policy.txt          # Документ политики сертификации
```

## Проверка результатов

### Просмотр информации о сертификате (с OpenSSL):
```bash
openssl x509 -in pki/certs/ca.cert.pem -text -noout
```

### Проверка самоподписанного сертификата:
```bash
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
```

### Запуск тестов:
```bash
# Запустить все тесты
pytest tests/ -v

# Запустить конкретный тест
pytest tests/test_ca.py -v
```

## Примеры использования

### Пример 1: Создание CA с записью лога в файл
```bash
python -m micropki.cli ca init \
    --subject "/CN=Промышленный корневой CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./production/pki \
    --validity-days 7300 \
    --log-file ./logs/ca-init.log
```

### Пример 2: Создание ECC CA с явным указанием всех параметров
```bash
python -m micropki.cli ca init \
    --subject "CN=Тестовый ECC CA,O=Лаборатория,C=RU" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file ./passphrase.txt \
    --out-dir ./test_ca \
    --validity-days 365
```

## Тестирование

Проект включает в себя следующие тесты:

- **Позитивные тесты**: проверка генерации ключей, парсинга DN, создания сертификатов
- **Негативные тесты**: проверка обработки ошибочных параметров
- **Тесты совместимости**: проверка работы с OpenSSL (опционально)

## Известные ограничения

- В Windows могут быть проблемы с установкой прав доступа к файлам (chmod)
- Для работы тестов OpenSSL требуется установленный OpenSSL в системе
- Поддерживаются только NIST P-384 для ECC и 4096 бит для RSA

## Разработка

### Запуск тестов в режиме разработки:
```bash
# С покрытием кода
pip install pytest-cov
pytest tests/ --cov=micropki

# С подробным выводом
pytest tests/ -v -s
```