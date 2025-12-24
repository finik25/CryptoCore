# CryptoCore Документация API
*Версия 1.0.0 | Последнее обновление: Декабрь 2025*

## Содержание

1. [Обзор](#обзор)
2. [Установка и настройка](#установка-и-настройка)
3. [Справочник модулей](#справочник-модулей)
   - [3.1. Режимы работы](#31-режимы-работы)
   - [3.2. Хэш-функции](#32-хэш-функции)
   - [3.3. Коды аутентификации сообщений](#33-коды-аутентификации-сообщений)
   - [3.4. Функции генерации ключей](#34-функции-генерации-ключей)
   - [3.5. Вспомогательные модули](#35-вспомогательные-модули)
4. [Интерфейс командной строки](#интерфейс-командной-строки)
5. [Обработка ошибок и исключения](#обработка-ошибок-и-исключения)
6. [Вопросы безопасности](#вопросы-безопасности)
7. [Тестирование и валидация](#тестирование-и-валидация)
8. [Примеры и варианты использования](#примеры-и-варианты-использования)
9. [Заметки о совместимости](#заметки-о-совместимости)

---

## Обзор

CryptoCore — это комплексная криптографическая библиотека, реализованная на Python, разработанная с учетом как образовательной ясности, так и практической полезности. Библиотека предоставляет реализации основных криптографических алгоритмов при сохранении строгой совместимости с отраслевыми стандартами, такими как спецификации NIST и OpenSSL.

### Принципы проектирования
- **Образовательная прозрачность**: Чистый, читаемый код, подходящий для изучения криптографических реализаций
- **Соответствие стандартам**: Соблюдение спецификаций NIST, RFC и FIPS
- **Безопасность прежде всего**: Следование криптографическим рекомендациям и безопасным шаблонам программирования
- **Совместимость**: Совместимость с CLI OpenSSL для перекрестной проверки
- **Модульная архитектура**: Независимые, повторно используемые компоненты с четкими интерфейсами

### Поддерживаемые алгоритмы
| Категория | Алгоритмы | Стандарты |
|----------|------------|-----------|
| Блочный шифр | AES-128 | FIPS 197 |
| Режимы шифрования | ECB, CBC, CFB, OFB, CTR, GCM | NIST SP 800-38A, 800-38D |
| Хэш-функции | SHA-256, SHA3-256 | FIPS 180-4, FIPS 202 |
| MAC-алгоритмы | HMAC-SHA256 | RFC 2104, RFC 4231 |
| Генерация ключей | PBKDF2-HMAC-SHA256, HKDF | RFC 2898, RFC 5869 |
| Генерация случайных чисел | CSPRNG (через ОС) | NIST SP 800-90A |

## Установка и настройка

### Предварительные требования
- Python 3.8 или выше
- Менеджер пакетов pip

### Методы установки

#### Из исходного кода
```bash
# Клонировать репозиторий
git clone https://github.com/yourusername/CryptoCore.git
cd CryptoCore

# Установить в режиме разработки
pip install -e .

# Проверить установку
cryptocore --version
```

#### Прямая установка пакета
```bash
# Установить из локального источника
pip install path/to/CryptoCore

# Или при публикации в PyPI
pip install cryptocore
```

### Зависимости
- **Обязательные**: `pycryptodome>=3.20.0` (для основных операций AES)
- **Опциональные**: `pytest` (для запуска набора тестов)

### Проверка
```python
import cryptocore
print(f"CryptoCore version: {cryptocore.__version__}")

# Проверить базовую функциональность
from cryptocore.utils.csprng import generate_random_key
key = generate_random_key()
print(f"Generated random key: {key.hex()}")
```

---

## Справочник модулей

### 3.1. Режимы работы
*Расположение: `cryptocore.modes`*

Этот модуль реализует различные режимы работы для шифрования AES-128. Каждый режим предоставляет различные свойства безопасности и характеристики производительности.

#### Режим ECB (Electronic Codebook)
```python
from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
```

**`encrypt_ecb(plaintext: bytes, key: bytes) -> bytes`**
Шифрует открытый текст с использованием AES-128 в режиме ECB с дополнением PKCS#7.

| Параметр | Тип | Описание | Ограничения |
|-----------|------|-------------|-------------|
| `plaintext` | `bytes` | Данные для шифрования | Любая длина |
| `key` | `bytes` | Ключ шифрования AES-128 | Ровно 16 байт |

**Возвращает:** `bytes` - Зашифрованный шифротекст (дополненный до границы 16 байт)

**Вызывает:**
- `ValueError`: Если длина ключа не равна 16 байтам

**Пример:**
```python
key = bytes.fromhex("00112233445566778899aabbccddeeff")
plaintext = b"Hello, CryptoCore!"
ciphertext = encrypt_ecb(plaintext, key)
# ciphertext составляет 32 байта (дополнено до ближайшей границы 16 байт)
```

**`decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes`**
Дешифрует шифротекст с использованием AES-128 в режиме ECB и удаляет дополнение PKCS#7.

| Параметр | Тип | Описание | Ограничения |
|-----------|------|-------------|-------------|
| `ciphertext` | `bytes` | Зашифрованные данные | Кратно 16 байтам |
| `key` | `bytes` | Ключ шифрования AES-128 | Ровно 16 байт |

**Возвращает:** `bytes` - Дешифрованный открытый текст (дополнение удалено)

**Вызывает:**
- `ValueError`: Если длина ключа ≠ 16 байт или неверная длина шифротекста
- `ValueError`: Если дополнение PKCS#7 недействительно

**Примечание по безопасности:** Режим ECB не рекомендуется для шифрования нескольких блоков похожих данных, так как идентичные блоки открытого текста производят идентичные блоки шифротекста. Используйте только для одноблочного шифрования или в образовательных целях.

#### Режим CBC (Cipher Block Chaining)
```python
from cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
```

**`encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes`**
Шифрует открытый текст с использованием AES-128 в режиме CBC.

| Параметр | Тип | Описание | Ограничения |
|-----------|------|-------------|-------------|
| `plaintext` | `bytes` | Данные для шифрования | Любая длина |
| `key` | `bytes` | Ключ шифрования AES-128 | Ровно 16 байт |
| `iv` | `bytes` | Вектор инициализации | Ровно 16 байт |

**Возвращает:** `bytes` - Зашифрованный шифротекст

**Вызывает:**
- `ValueError`: Если длина ключа или IV неверна

**Свойства:**
- Использует дополнение PKCS#7
- IV должен быть криптографически случайным
- Сцепление предотвращает создание идентичных шифротекстов из идентичных блоков открытого текста

**`decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes`**
Дешифрует шифротекст с использованием AES-128 в режиме CBC.

| Параметр | Тип | Описание | Ограничения |
|-----------|------|-------------|-------------|
| `ciphertext` | `bytes` | Зашифрованные данные | Кратно 16 байтам |
| `key` | `bytes` | Ключ шифрования AES-128 | Ровно 16 байт |
| `iv` | `bytes` | Вектор инициализации | Ровно 16 байт |

**Возвращает:** `bytes` - Дешифрованный открытый текст (дополнение автоматически удалено)

**Важно:** Тот же IV, который использовался для шифрования, должен использоваться для дешифрования.

#### Режим CFB (Cipher Feedback)
```python
from cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
```

**`encrypt_cfb(plaintext: bytes, key: bytes, iv: bytes) -> bytes`**
Шифрует открытый текст с использованием AES-128 в режиме CFB.

**`decrypt_cfb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes`**
Дешифрует шифротекст с использованием AES-128 в режиме CFB.

| Параметр | Ограничения |
|-----------|-------------|
| `key`, `iv` | Ровно 16 байт каждый |

**Особенности:**
- Самосинхронизирующийся поточный шифр
- Не требует дополнения
- Может обрабатывать данные меньшего размера, чем размер блока

**Примечание по безопасности:** Никогда не используйте повторно IV с тем же ключом.

#### Режим OFB (Output Feedback)
```python
from cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
```

**`encrypt_ofb(plaintext: bytes, key: bytes, iv: bytes) -> bytes`**
Шифрует открытый текст с использованием AES-128 в режиме OFB.

**`decrypt_ofb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes`**
Дешифрует шифротекст с использованием AES-128 в режиме OFB (идентично шифрованию).

**Свойства:**
- Синхронный поточный шифр
- Генерация потока ключей независима от открытого текста/шифротекста
- Нет распространения ошибок

#### Режим CTR (Counter)
```python
from cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr
```

**`encrypt_ctr(plaintext: bytes, key: bytes, iv: bytes) -> bytes`**
Шифрует открытый текст с использованием AES-128 в режиме CTR.

**`decrypt_ctr(ciphertext: bytes, key: bytes, iv: bytes) -> bytes`**
Дешифрует шифротекст с использованием AES-128 в режиме CTR (идентично шифрованию).

| Параметр | Описание |
|-----------|-------------|
| `iv` | 16 байт (8-байтовый нонс + 8-байтовый счетчик, начинающийся с 0) |

**Преимущества:**
- Параллелизуемое шифрование/дешифрование
- Не требует дополнения
- Произвольный доступ к шифротексту

#### Режим GCM (Galois/Counter Mode)
```python
from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm, GCM, AuthenticationError
```

**Класс: `GCM(key: bytes, nonce: Optional[bytes] = None)`**
Создает контекст GCM для аутентифицированного шифрования.

| Параметр | Описание | По умолчанию |
|-----------|-------------|---------|
| `key` | Ключ AES (16, 24 или 32 байта) | Обязательно |
| `nonce` | Нонс/IV (рекомендуется 12 байт) | Генерируется случайно |

**Методы:**

**`encrypt(plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]`**
Шифрует открытый текст с аутентификацией.

| Параметр | Описание |
|-----------|-------------|
| `plaintext` | Данные для шифрования |
| `aad` | Дополнительные аутентифицированные данные (не шифруются) |

**Возвращает:** `(nonce, ciphertext, tag)` где:
- `nonce`: Использованный нонс (12 байт)
- `ciphertext`: Зашифрованные данные
- `tag`: 16-байтовый тег аутентификации

**`decrypt(ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes`**
Дешифрует шифротекст с проверкой аутентификации.

| Параметр | Описание | Ограничения |
|-----------|-------------|-------------|
| `ciphertext` | Зашифрованные данные | Любая длина |
| `tag` | Тег аутентификации | Ровно 16 байт |
| `nonce` | Нонс, использованный при шифровании | Ровно 12 байт |
| `aad` | Дополнительные аутентифицированные данные | Должен соответствовать шифрованию |

**Возвращает:** `bytes` - Дешифрованный открытый текст

**Вызывает:**
- `AuthenticationError`: Если проверка тега не удалась
- `ValueError`: Если длины параметров недействительны

**Удобные функции:**

**`encrypt_gcm(plaintext: bytes, key: bytes, nonce: Optional[bytes] = None, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]`**
Одноразовое шифрование GCM.

**`decrypt_gcm(ciphertext: bytes, tag: bytes, nonce: bytes, key: bytes, aad: bytes = b"") -> bytes`**
Одноразовое дешифрование GCM с проверкой.

**Критично для безопасности:** Никогда не используйте нонс повторно с тем же ключом. Повторное использование нонса полностью нарушает безопасность GCM.

#### Шифрование-затем-MAC
```python
from cryptocore.modes.encrypt_then_mac import (
    EncryptThenMAC, 
    encrypt_etm, 
    decrypt_etm,
    new_etm,
    AuthenticationError
)
```

**Класс: `EncryptThenMAC(master_key: bytes, mode: str = 'cbc')`**
Реализует аутентифицированное шифрование с использованием парадигмы Шифрование-затем-MAC.

| Параметр | Описание | Допустимые значения |
|-----------|-------------|--------------|
| `master_key` | Мастер-ключ для генерации | ≥ 32 байт рекомендуется |
| `mode` | Базовый режим шифрования | 'cbc', 'ctr', 'cfb', 'ofb', 'ecb' |

**Генерация ключей:** Генерирует отдельные ключи шифрования и MAC из мастер-ключа с использованием HMAC-основанного KDF.

**Методы:**

**`encrypt(plaintext: bytes, iv: Optional[bytes] = None, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]`**
Шифрует и аутентифицирует открытый текст.

**`decrypt(ciphertext: bytes, tag: bytes, iv: bytes, aad: bytes = b"") -> bytes`**
Дешифрует и проверяет аутентификацию.

**Операции с файлами:**

**`encrypt_to_bytes(plaintext: bytes, master_key: bytes, mode: str = 'cbc', aad: bytes = b"", iv: Optional[bytes] = None) -> bytes`**
Шифрует и возвращает в виде единой строки байтов (формат: ДЛИНА_IV || IV || Шифротекст || Тег).

**`decrypt_from_bytes(data: bytes, master_key: bytes, mode: str = 'cbc', aad: bytes = b"") -> bytes`**
Дешифрует из объединенной строки байтов.

**`encrypt_file(input_path: str, output_path: str, master_key: bytes, mode: str = 'cbc', aad: bytes = b"", iv: Optional[bytes] = None) -> bytes`**
Шифрует файл с аутентифицированным шифрованием.

**`decrypt_file(input_path: str, output_path: str, master_key: bytes, mode: str = 'cbc', aad: bytes = b"") -> None`**
Дешифрует файл с проверкой аутентификации.

### 3.2. Хэш-функции
*Расположение: `cryptocore.hash`*

#### Реализация SHA-256
```python
from cryptocore.hash.sha256 import SHA256
```

**Класс: `SHA256()`**
Реализует алгоритм хэширования SHA-256 в соответствии с FIPS 180-4.

**Методы:**

**`update(data: bytes) -> None`**
Обновляет хэш дополнительными данными.

**`digest() -> bytes`**
Возвращает хэш-дайджест в виде 32 байт.

**`hexdigest() -> str`**
Возвращает хэш-дайджест в виде 64-символьной шестнадцатеричной строки.

**`reset() -> None`**
Сбрасывает вычисление хэша в начальное состояние.

**Методы класса:**

**`SHA256.hash(data: bytes) -> bytes`**
Статический метод для одноразового хэширования.

**`SHA256.hash_hex(data: bytes) -> str`**
Статический метод для одноразового хэширования, возвращающий шестнадцатеричную строку.

**Пример:**
```python
# Потоковый интерфейс
hasher = SHA256()
hasher.update(b"Hello, ")
hasher.update(b"CryptoCore!")
hash_bytes = hasher.digest()  # 32 байта

# Одноразовый интерфейс
hash_result = SHA256.hash(b"Hello, CryptoCore!")
hash_hex = SHA256.hash_hex(b"Hello, CryptoCore!")

# Хэширование файлов
hasher = SHA256()
with open("large_file.bin", "rb") as f:
    while chunk := f.read(8192):
        hasher.update(chunk)
file_hash = hasher.hexdigest()
```

#### Реализация SHA3-256
```python
from cryptocore.hash.sha3_256 import SHA3_256
```

**Класс: `SHA3_256()`**
Реализует алгоритм хэширования SHA3-256 в соответствии с FIPS 202 с использованием встроенного `hashlib` Python.

**Интерфейс:** Идентичен классу `SHA256` с теми же методами.

**Примечание:** Использует `hashlib.sha3_256` Python для реализации производственного уровня при сохранении согласованного API.

### 3.3. Коды аутентификации сообщений
*Расположение: `cryptocore.mac`*

#### HMAC-SHA256
```python
from cryptocore.mac.hmac import HMAC, compute_hmac, compute_hmac_hex, new
```

**Класс: `HMAC(key: bytes)`**
Реализует HMAC с SHA-256 в соответствии с RFC 2104.

| Параметр | Описание | Обработка |
|-----------|-------------|------------|
| `key` | Ключ HMAC | Если >64 байта: хэшируется; если <64 байта: дополняется нулями |

**Методы:**

**`compute(message: bytes) -> bytes`**
Вычисляет HMAC-SHA256 для сообщения.

**Возвращает:** `bytes` - 32-байтовое значение HMAC

**`compute_hex(message: bytes) -> str`**
Вычисляет HMAC-SHA256, возвращает шестнадцатеричную строку.

**Возвращает:** `str` - 64-символьная шестнадцатеричная строка

**`verify(message: bytes, hmac_to_check: Union[bytes, str]) -> bool`**
Проверяет HMAC для сообщения.

| Параметр | Описание |
|-----------|-------------|
| `hmac_to_check` | Ожидаемый HMAC в виде байтов или шестнадцатеричной строки |

**Возвращает:** `bool` - True, если HMAC совпадает

**`update_compute(message_chunks: Iterable[bytes]) -> bytes`**
Вычисляет HMAC из последовательности фрагментов (для больших файлов).

**Методы класса:**

**`HMAC.compute_hmac(key: bytes, message: bytes) -> bytes`**
Статический метод для одноразового вычисления HMAC.

**`HMAC.compute_hmac_hex(key: bytes, message: bytes) -> str`**
Статический метод для одноразового вычисления HMAC, возвращающий шестнадцатеричную строку.

**Функции модуля:**

**`new(key: bytes) -> HMAC`**
Фабричная функция, создающая экземпляр HMAC.

**`compute_hmac(key: bytes, message: bytes) -> bytes`**
Вычислить HMAC напрямую.

**`compute_hmac_hex(key: bytes, message: bytes) -> str`**
Вычислить HMAC напрямую, возвращая шестнадцатеричную строку.

**Пример:**
```python
key = bytes.fromhex("00112233445566778899aabbccddeeff")
message = b"Important transaction data"

# На основе класса
hmac = HMAC(key)
mac = hmac.compute(message)
is_valid = hmac.verify(message, mac)

# Одноразовый
mac = HMAC.compute_hmac(key, message)
mac_hex = HMAC.compute_hmac_hex(key, message)

# Аутентификация файлов
hmac = HMAC(key)
with open("document.pdf", "rb") as f:
    chunks = []
    while chunk := f.read(8192):
        chunks.append(chunk)
file_mac = hmac.update_compute(chunks)
```

### 3.4. Функции генерации ключей
*Расположение: `cryptocore.kdf`*

#### PBKDF2-HMAC-SHA256
```python
from cryptocore.kdf.pbkdf2 import pbkdf2_hmac_sha256, derive_from_password
```

**`pbkdf2_hmac_sha256(password: Union[str, bytes], salt: Union[str, bytes], iterations: int, dklen: int) -> bytes`**
Генерирует ключ из пароля с использованием PBKDF2 с HMAC-SHA256 в соответствии с RFC 2898.

| Параметр | Тип | Описание | Ограничения |
|-----------|------|-------------|-------------|
| `password` | `Union[str, bytes]` | Пароль | Не пустой |
| `salt` | `Union[str, bytes]` | Значение соли | Не пустое |
| `iterations` | `int` | Количество итераций | ≥ 1 |
| `dklen` | `int` | Длина генерируемого ключа | ≥ 1 |

**Возвращает:** `bytes` - Генерируемый ключ длины `dklen`

**Вызывает:**
- `ValueError`: Если параметры недействительны

**Обработка соли:**
- Строковый ввод: Интерпретируется как hex, если допустимый hex, в противном случае кодируется в UTF-8
- Hex-строки: Могут содержать префикс `0x` и пробелы (автоматически очищаются)

**`derive_from_password(password: str, salt_hex: str = None, iterations: int = 100000, keylen: int = 32) -> tuple[bytes, bytes]`**
Удобная функция для генерации ключей на основе пароля.

| Параметр | По умолчанию | Описание |
|-----------|---------|-------------|
| `salt_hex` | `None` | Если None, генерирует случайную 16-байтовую соль |
| `iterations` | `100000` | Рекомендуется: ≥ 100,000 |
| `keylen` | `32` | Длина генерируемого ключа в байтах |

**Возвращает:** `(derived_key, salt_used)`

**Пример:**
```python
# С указанной солью
derived_key = pbkdf2_hmac_sha256(
    password="MySecurePassword!123",
    salt="a1b2c3d4e5f601234567890123456789",
    iterations=100000,
    dklen=32
)

# С автоматически сгенерированной солью
derived_key, salt = derive_from_password(
    password="AnotherPassword",
    iterations=200000,
    keylen=16
)
print(f"Salt: {salt.hex()}")
print(f"Key: {derived_key.hex()}")
```

#### HKDF (HMAC-based Key Derivation)
```python
from cryptocore.kdf.hkdf import derive_key, derive_key_hierarchy
```

**`derive_key(master_key: bytes, context: Union[str, bytes], length: int = 32) -> bytes`**
Генерирует ключ из мастер-ключа с использованием HMAC-основанного KDF.

| Параметр | Описание | Ограничения |
|-----------|-------------|-------------|
| `master_key` | Мастер-ключ | ≥ 16 байт рекомендуется |
| `context` | Контекст для разделения доменов | Строка или байты |
| `length` | Желаемая длина ключа | ≥ 1 |

**Возвращает:** `bytes` - Генерируемый ключ

**Алгоритм:** `HMAC(master_key, context || counter)` итеративно до достижения желаемой длины

**`derive_key_hierarchy(master_key: bytes, contexts: list[str], key_length: int = 32) -> dict[str, bytes]`**
Генерирует несколько ключей для разных контекстов.

| Параметр | Описание |
|-----------|-------------|
| `contexts` | Список строк контекста |
| `key_length` | Длина для каждого генерируемого ключа |

**Возвращает:** `dict[str, bytes]` - Отображение из контекста в генерируемый ключ

**Пример:**
```python
master_key = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

# Генерация одного ключа
enc_key = derive_key(master_key, "encryption", 16)
mac_key = derive_key(master_key, "authentication", 32)

# Несколько ключей
keys = derive_key_hierarchy(
    master_key=master_key,
    contexts=["encryption", "mac", "iv_generation"],
    key_length=32
)
# keys = {"encryption": ..., "mac": ..., "iv_generation": ...}
```

### 3.5. Вспомогательные модули
*Расположение: `cryptocore.utils`*

#### Криптографически стойкая генерация случайных чисел
```python
from cryptocore.utils.csprng import (
    generate_random_bytes,
    generate_random_key,
    generate_random_iv
)
```

**`generate_random_bytes(num_bytes: int) -> bytes`**
Генерирует криптографически стойкие случайные байты с использованием RNG операционной системы.

| Параметр | Ограничения |
|-----------|-------------|
| `num_bytes` | ≥ 1 |

**Возвращает:** `bytes` - Случайные байты

**Реализация:** Использует `os.urandom()` (или эквивалент на Windows)

**Вызывает:**
- `ValueError`: Если `num_bytes ≤ 0`
- `OSError`: Если системный RNG не сработал

**`generate_random_key() -> bytes`**
Генерирует случайный 16-байтовый ключ AES-128.

**Возвращает:** `bytes` - 16 случайных байт

**`generate_random_iv() -> bytes`**
Генерирует случайный 16-байтовый вектор инициализации.

**Возвращает:** `bytes` - 16 случайных байт

**Пример:**
```python
# Генерировать криптографические материалы
key = generate_random_key()        # 16 байт для AES-128
iv = generate_random_iv()          # 16 байт для IV
nonce = generate_random_bytes(12)  # 12 байт для GCM
salt = generate_random_bytes(16)   # 16 байт для PBKDF2
```

#### Вспомогательные функции дополнения
```python
from cryptocore.utils.padding import apply_padding, remove_padding
```

**`apply_padding(data: bytes, block_size: int = 16) -> bytes`**
Применяет дополнение PKCS#7 к данным.

| Параметр | По умолчанию | Описание |
|-----------|---------|-------------|
| `block_size` | `16` | Размер блока для дополнения |

**Возвращает:** `bytes` - Дополненные данные (длина = кратна `block_size`)

**`remove_padding(padded_data: bytes, block_size: int = 16) -> bytes`**
Удаляет дополнение PKCS#7 из данных.

**Возвращает:** `bytes` - Исходные данные без дополнения

**Вызывает:**
- `ValueError`: Если дополнение недействительно (неверная длина или байты)

**Пример:**
```python
data = b"Hello"
padded = apply_padding(data, 16)  # b'Hello\x0b\x0b...' (11 байт дополнения)
original = remove_padding(padded, 16)  # b'Hello'
```

#### Вспомогательные функции ввода/вывода файлов
```python
from cryptocore.utils.file_io import (
    read_file,
    write_file,
    read_file_with_iv,
    write_file_with_iv,
    read_gcm_file,
    write_gcm_file,
    derive_output_filename
)
```

**`read_file(file_path: str) -> bytes`**
Читает файл как двоичные данные.

**`write_file(file_path: str, data: bytes, overwrite: bool = False) -> None`**
Записывает двоичные данные в файл.

**`read_file_with_iv(file_path: str) -> Tuple[bytes, bytes]`**
Читает файл с предшествующим IV (первые 16 байт).

**`write_file_with_iv(file_path: str, iv: bytes, data: bytes, overwrite: bool = False) -> None`**
Записывает IV и данные в файл (IV предшествует).

**`read_gcm_file(file_path: str) -> Tuple[bytes, bytes, bytes]`**
Читает файл в формате GCM (нонс + шифротекст + тег).

**Формат:** 12-байтовый нонс | шифротекст | 16-байтовый тег

**`write_gcm_file(file_path: str, nonce: bytes, ciphertext: bytes, tag: bytes, overwrite: bool = False) -> None`**
Записывает файл в формате GCM.

**`derive_output_filename(input_path: str, operation: str, algorithm: str, mode: str) -> str`**
Определяет имя выходного файла на основе операции и режима.

| Операция | Вход | Выход | Пример |
|-----------|-------|--------|---------|
| encrypt | file.txt | file.txt.enc | (GCM: file.txt.gcm) |
| decrypt | file.txt.enc | file.dec.txt | |
| hash | file.txt | (stdout) | |

#### Вспомогательные функции хэширования
```python
from cryptocore.utils.hash_utils import HashCalculator
```

**Класс: `HashCalculator`**
Вспомогательный класс для вычисления хэшей файлов и данных.

**Методы класса:**

**`hash_data(data: bytes, algorithm: str = 'sha256') -> bytes`**
Хэшировать данные в памяти.

**`hash_data_hex(data: bytes, algorithm: str = 'sha256') -> str`**
Хэшировать данные, вернуть шестнадцатеричную строку.

**`hash_file(file_path: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> bytes`**
Хэшировать файл с использованием потоковой обработки.

**`hash_file_hex(file_path: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> str`**
Хэшировать файл, вернуть шестнадцатеричную строку.

**`verify_file_hash(file_path: str, expected_hash: Union[str, bytes], algorithm: str = 'sha256') -> bool`**
Проверить хэш файла по отношению к ожидаемому значению.

**Поддерживаемые алгоритмы:** 'sha256', 'sha3-256'

#### Арифметика поля Галуа
```python
from cryptocore.utils.galois_field import (
    GaloisField,
    gf_multiply,
    gf_multiply_gcm,
    gf_add
)
```

**Класс: `GaloisField`**
Реализует арифметику в GF(2^128) для режима GCM.

**Статические методы:**

**`multiply(x: Union[int, bytes, bytearray], y: Union[int, bytes, bytearray]) -> Union[int, bytes]`**
Умножает в GF(2^128).

**`multiply_gcm(h_bytes: bytes, y_bytes: bytes) -> bytes`**
Умножение, оптимизированное для GCM (H в представлении с обратным порядком битов).

**`add(x: Union[int, bytes, bytearray], y: Union[int, bytes, bytearray]) -> Union[int, bytes]`**
Сложение в GF(2^128) (XOR).

**Функции модуля:**

**`gf_multiply()`, `gf_multiply_gcm()`, `gf_add()`**
Удобные функции для доступа на уровне модуля.

#### Инструмент тестирования NIST
```python
from cryptocore.utils.nist_tool import generate_nist_test_file
```

**`generate_nist_test_file(output_path: str, size_mb: float = 10.0) -> None`**
Генерирует файл со случайными данными для набора статистических тестов NIST.

| Параметр | По умолчанию | Описание |
|-----------|---------|-------------|
| `size_mb` | `10.0` | Размер файла в мегабайтах |

**Доступ через CLI:** `cryptocore-nist output.bin --size 100.0`

---

## Интерфейс командной строки

Интерфейс командной строки `cryptocore` предоставляет унифицированный доступ ко всей функциональности библиотеки. Он поддерживает как устаревший синтаксис одной команды, так и современный синтаксис подкоманд.

### Базовый синтаксис
```
cryptocore <command> [options]
```

### Обзор команд

#### `crypto` - Шифрование и дешифрование
Шифрует или дешифрует файлы с использованием различных режимов AES.

**Базовое шифрование:**
```bash
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plain.txt --output encrypted.bin
```

**С автоматически сгенерированным ключом:**
```bash
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --input plain.txt
# Ключ генерируется и отображается
```

**GCM с AAD:**
```bash
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "database_version_2.0" \
  --input data.db --output data.db.gcm
```

#### `dgst` - Вычисление хэша и HMAC
Вычисляет хэши или HMAC файлов.

**Вычисление хэша:**
```bash
cryptocore dgst --algorithm sha256 --input document.pdf
# Вывод: sha256-hash document.pdf
```

**Вычисление HMAC:**
```bash
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input sensitive.txt --output signature.hmac
```

**Проверка HMAC:**
```bash
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input sensitive.txt --verify expected.hmac
# Код завершения 0 при успехе, 1 при неудаче
```

#### `derive` - Генерация ключей
Генерирует ключи из паролей.

**Базовая генерация:**
```bash
cryptocore derive --password "MySecurePassword" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 --length 32
```

**С автоматически сгенерированной солью:**
```bash
cryptocore derive --password "AnotherPassword" \
  --iterations 500000
```

**Пароль из файла:**
```bash
cryptocore derive --password-file password.txt \
  --salt fixedappsalt --iterations 10000
```

### Общие опции
| Опция | Сокращение | Описание | Пример |
|--------|-------|-------------|---------|
| `--input` | `-i` | Входной файл | `--input data.txt` |
| `--output` | `-o` | Выходной файл | `--output result.bin` |
| `--force` | `-f` | Перезаписать существующий | `--force` |
| `--key` | `-k` | Ключ в виде hex | `--key 0011...eeff` |
| `--iv` | | IV/нонс в виде hex | `--iv aabb...ccdd` |
| `--aad` | | AAD для GCM | `--aad metadata` |

### Обработка ввода/вывода
- **Stdin/Stdout**: Используйте `-` для `--input` или опустите `--output`
- **Именование файлов**: Автоматическое определение на основе операции
- **Обработка IV**: Автоматически добавляется в начало файлов шифротекста
- **Защита от перезаписи**: По умолчанию существующие файлы не перезаписываются

---

## Обработка ошибок и исключения

CryptoCore использует согласованную иерархию исключений для сообщений об ошибках.

### Иерархия исключений
```
Exception
├── ValueError
│   ├── Invalid key length
│   ├── Invalid IV/nonce length
│   ├── Invalid ciphertext length
│   └── Invalid padding
├── AuthenticationError
│   └── GCM/MAC verification failed
├── IOError
│   ├── FileNotFoundError
│   ├── PermissionError
│   └── FileExistsError
└── RuntimeError
    └── Internal consistency errors
```

### Распространенные сценарии ошибок

#### Недействительные параметры
```python
try:
    encrypt_cbc(plaintext, b"short_key", iv)  # Ключ слишком короткий
except ValueError as e:
    print(f"Parameter error: {e}")
```

#### Ошибка аутентификации
```python
try:
    plaintext = decrypt_gcm(tampered_ciphertext, tag, nonce, key)
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
    # КРИТИЧЕСКИ: Открытый текст не выводится
```

#### Операции с файлами
```python
try:
    data = read_file("/nonexistent/path/file.txt")
except FileNotFoundError as e:
    print(f"File not found: {e}")
except PermissionError as e:
    print(f"Permission denied: {e}")
```

### Рекомендации
1. **Всегда перехватывайте конкретные исключения**, а не общее `Exception`
2. **Обрабатывайте ошибки аутентификации корректно**, не раскрывая конфиденциальную информацию
3. **Проверяйте пользовательский ввод** перед передачей в криптографические функции
4. **Очищайте конфиденциальные данные** из памяти после использования

---

## Вопросы безопасности

### Критические правила безопасности

#### 1. Управление ключами
- **Никогда не встраивайте ключи жестко** в исходный код
- **Используйте криптографически стойкие генераторы случайных чисел** для генерации ключей
- **Храните ключи безопасно** (аппаратные модули безопасности, системы управления ключами)
- **Регулярно меняйте ключи** в зависимости от чувствительности данных

#### 2. Использование IV/нонса
- **Никогда не используйте повторно IV/нонс** с тем же ключом (особенно критично для GCM, CTR)
- **Используйте криптографически случайные IV** (кроме детерминированных алгоритмов)
- **Для GCM**: рекомендуется 12-байтовый случайный нонс

#### 3. Рекомендации по выбору режима
| Вариант использования | Рекомендуемый режим | Примечания |
|----------|-----------------|-------|
| Общее шифрование | GCM | Аутентифицированное шифрование |
| Обратная совместимость | CBC с HMAC | Шифрование-затем-MAC |
| Шифрование дисков | XTS (не реализован) | Для блоков фиксированного размера |
| Обучение/тестирование | ECB | Только одиночные блоки |

#### 4. Генерация ключей на основе паролей
- **Минимальное количество итераций**: 100,000 для PBKDF2
- **Используйте уникальную соль** для каждого пароля
- **Храните соль** вместе с генерируемым ключом (соль не является секретной)
- **Рассмотрите функции с высокой сложностью по памяти** (Argon2, scrypt) для высокозащищенных приложений

### Безопасность реализации

#### Операции с постоянным временем
Там, где это практично, CryptoCore использует алгоритмы с постоянным временем:
- Проверка HMAC
- Проверка дополнения
- Сравнение тегов GCM

#### Управление памятью
- **Очистка конфиденциальных данных**: Ключи и пароли обнуляются после использования, где это возможно
- **Безопасность буфера**: Управление памятью Python предотвращает переполнение буфера
- **Отсутствие логирования секретов**: Отладочная информация исключает конфиденциальные данные

#### Проверка ввода
Все функции проверяют:
- Длины ключей (AES: 16/24/32 байта)
- Длины IV/нонсов (CBC/CFB/OFB: 16 байт, GCM: 12 байт рекомендуется)
- Длины шифротекстов (должны быть кратны размеру блока, где требуется)
- Диапазоны параметров (итерации > 0, длины ключей > 0)

### Контрольный список безопасности для пользователей
- [ ] Используйте GCM или Шифрование-затем-MAC для аутентифицированного шифрования
- [ ] Генерируйте случайные ключи с помощью `generate_random_key()`
- [ ] Генерируйте случайные IV с помощью `generate_random_iv()`
- [ ] Используйте не менее 100,000 итераций для PBKDF2
- [ ] Проверяйте теги HMAC/GCM перед использованием дешифрованных данных
- [ ] Никогда не используйте нонс/IV повторно с тем же ключом
- [ ] Храните соли вместе с генерируемыми ключами
- [ ] Очищайте конфиденциальные переменные после использования
- [ ] Проверяйте весь пользовательский ввод перед криптографическими операциями

---

## Тестирование и валидация

### Структура набора тестов
```
tests/
├── unit/                    # Модульные тесты для отдельных функций
│   ├── test_csprng.py      # Тесты генерации случайных чисел
│   ├── test_hash_sha256.py # Тесты реализации SHA-256
│   ├── test_hmac.py        # Тесты реализации HMAC
│   ├── test_ecb.py         # Тесты режима ECB
│   ├── test_cbc.py         # Тесты режима CBC
│   ├── test_cfb.py         # Тесты режима CFB
│   ├── test_ofb.py         # Тесты режима OFB
│   ├── test_ctr.py         # Тесты режима CTR
│   ├── test_gcm.py         # Тесты режима GCM
│   ├── test_padding.py     # Тесты дополнения
│   └── test_file_io.py     # Тесты ввода/вывода файлов
├── integration/             # Интеграционные тесты
│   ├── test_integration.py # Сквозные тесты
│   └── test_openssl_compatibility.py # Совместимость с OpenSSL
└── vectors/                # Тестовые векторы с известными ответами
    └── nist_kat/           # Тесты NIST Known Answer Tests
```

### Запуск тестов
```bash
# Запустить все тесты
python -m pytest tests/ -v

# Запустить определенные категории тестов
python -m pytest tests/unit/ -v
python -m pytest tests/integration/ -v

# Запустить с отчетом о покрытии
python -m pytest tests/ --cov=cryptocore --cov-report=html
```

### Покрытие тестами
- **Модульные тесты**: 160+ тестов, охватывающих все публичные функции
- **Тесты с известными ответами**: Тестовые векторы NIST для всех алгоритмов
- **Интеграционные тесты**: Использование CLI, операции с файлами, кросс-режимная совместимость
- **Негативные тесты**: Ошибочные условия, недействительный ввод, граничные случаи
- **Тесты производительности**: Бенчмарки для критических операций

### Совместимость с NIST
Все реализации проверены по тестовым векторам NIST:
- **AES**: Тестовые векторы NIST SP 800-38A
- **GCM**: Тестовые векторы NIST SP 800-38D
- **SHA-256**: Тестовые векторы FIPS 180-4
- **HMAC**: Тестовые векторы RFC 4231
- **PBKDF2**: Тестовые векторы RFC 6070

### Совместимость с OpenSSL
```bash
# Тестировать совместимость шифрования
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt --output test.enc

openssl enc -aes-128-cbc -d \
  -K 00112233445566778899aabbccddeeff \
  -iv $(head -c 16 test.enc | xxd -p) \
  -in <(tail -c +17 test.enc) \
  -out test.dec

diff test.txt test.dec  # Должны быть идентичны
```

---

## Примеры и варианты использования

### Пример 1: Безопасное шифрование файлов с аутентификацией
```python
from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm
from cryptocore.utils.csprng import generate_random_key
from cryptocore.utils.file_io import read_file, write_file
import os

def encrypt_file_with_metadata(input_path, output_path, metadata):
    """Шифрует файл с аутентифицированными метаданными."""
    # Генерировать или загрузить ключ (на практике используйте безопасное хранилище ключей)
    key = generate_random_key()
    
    # Прочитать открытый текст
    plaintext = read_file(input_path)
    
    # Зашифровать с метаданными как AAD
    nonce, ciphertext, tag = encrypt_gcm(
        plaintext=plaintext,
        key=key,
        aad=metadata.encode()
    )
    
    # Сохранить зашифрованный файл
    with open(output_path, 'wb') as f:
        f.write(nonce + ciphertext + tag)
    
    return key, nonce

def decrypt_and_verify(input_path, output_path, key, expected_metadata):
    """Дешифрует файл и проверяет метаданные."""
    # Прочитать зашифрованный файл
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Извлечь компоненты
    nonce = data[:12]
    ciphertext = data[12:-16]
    tag = data[-16:]
    
    # Дешифровать с проверкой
    try:
        plaintext = decrypt_gcm(
            ciphertext=ciphertext,
            tag=tag,
            nonce=nonce,
            key=key,
            aad=expected_metadata.encode()
        )
        
        # Записать дешифрованный файл
        write_file(output_path, plaintext, overwrite=True)
        print("Decryption successful - integrity verified")
        return True
        
    except AuthenticationError:
        print("ERROR: Authentication failed - file may be tampered")
        return False

# Использование
key, nonce = encrypt_file_with_metadata(
    "sensitive.docx",
    "sensitive.docx.enc",
    "user:alice|timestamp:2024-12-21|version:2"
)

success = decrypt_and_verify(
    "sensitive.docx.enc",
    "sensitive_decrypted.docx",
    key,
    "user:alice|timestamp:2024-12-21|version:2"
)
```

### Пример 2: Система шифрования на основе пароля
```python
from cryptocore.kdf.pbkdf2 import derive_from_password
from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm
from cryptocore.utils.csprng import generate_random_bytes
import getpass
import json

class PasswordVault:
    def __init__(self, password, iterations=200000):
        """Инициализирует хранилище с паролем пользователя."""
        self.iterations = iterations
        self.salt = generate_random_bytes(16)
        self.encryption_key, _ = derive_from_password(
            password, self.salt.hex(), iterations, 32
        )
    
    def encrypt_entry(self, service, username, password, metadata=""):
        """Шифрует запись пароля."""
        entry = {
            "service": service,
            "username": username,
            "password": password,
            "timestamp": "2024-12-21"
        }
        plaintext = json.dumps(entry).encode()
        
        nonce, ciphertext, tag = encrypt_gcm(
            plaintext=plaintext,
            key=self.encryption_key[:16],
            aad=metadata.encode()
        )
        
        return {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex(),
            "metadata": metadata
        }
    
    def decrypt_entry(self, encrypted_entry):
        """Дешифрует и проверяет запись пароля."""
        nonce = bytes.fromhex(encrypted_entry["nonce"])
        ciphertext = bytes.fromhex(encrypted_entry["ciphertext"])
        tag = bytes.fromhex(encrypted_entry["tag"])
        
        plaintext = decrypt_gcm(
            ciphertext=ciphertext,
            tag=tag,
            nonce=nonce,
            key=self.encryption_key[:16],
            aad=encrypted_entry["metadata"].encode()
        )
        
        return json.loads(plaintext.decode())

# Использование
password = getpass.getpass("Enter vault password: ")
vault = PasswordVault(password, iterations=300000)

# Сохранить учетные данные
encrypted = vault.encrypt_entry(
    service="github",
    username="alice",
    password="s3cr3tP@ssw0rd!",
    metadata="personal account"
)

# Получить учетные данные
decrypted = vault.decrypt_entry(encrypted)
print(f"Service: {decrypted['service']}")
print(f"Username: {decrypted['username']}")
print(f"Password: {decrypted['password']}")
```

### Пример 3: Пакетная обработка файлов с целостностью
```python
from cryptocore.hash.sha256 import SHA256
from cryptocore.mac.hmac import HMAC
from cryptocore.utils.file_io import read_file, write_file
import os

def process_files_with_integrity(input_dir, output_dir, hmac_key):
    """Обрабатывает файлы с защитой целостности HMAC."""
    os.makedirs(output_dir, exist_ok=True)
    
    hmac = HMAC(hmac_key)
    integrity_log = []
    
    for filename in os.listdir(input_dir):
        input_path = os.path.join(input_dir, filename)
        
        if not os.path.isfile(input_path):
            continue
        
        # Прочитать и обработать файл
        data = read_file(input_path)
        processed_data = data.upper()  # Пример обработки
        
        # Вычислить HMAC для целостности
        file_hmac = hmac.compute_hex(processed_data)
        
        # Записать обработанный файл
        output_path = os.path.join(output_dir, filename)
        write_file(output_path, processed_data, overwrite=True)
        
        # Записать файл HMAC
        hmac_path = output_path + ".hmac"
        with open(hmac_path, 'w') as f:
            f.write(f"{file_hmac}  {filename}\n")
        
        integrity_log.append({
            "file": filename,
            "hmac": file_hmac,
            "size": len(processed_data)
        })
    
    return integrity_log

def verify_processed_files(output_dir, hmac_key):
    """Проверяет целостность обработанных файлов."""
    hmac = HMAC(hmac_key)
    results = []
    
    for filename in os.listdir(output_dir):
        if filename.endswith(".hmac"):
            continue
        
        file_path = os.path.join(output_dir, filename)
        hmac_path = file_path + ".hmac"
        
        if not os.path.exists(hmac_path):
            results.append((filename, "MISSING_HMAC", False))
            continue
        
        # Прочитать ожидаемый HMAC
        with open(hmac_path, 'r') as f:
            expected_hmac = f.read().strip().split()[0]
        
        # Вычислить фактический HMAC
        data = read_file(file_path)
        actual_hmac = hmac.compute_hex(data)
        
        # Проверить
        is_valid = (actual_hmac == expected_hmac)
        results.append((filename, "VERIFIED" if is_valid else "TAMPERED", is_valid))
    
    return results
```

---

## Заметки о совместимости

### Версии Python
- **Основная поддержка**: Python 3.8, 3.9, 3.10, 3.11, 3.12
- **Протестировано на**: CPython (эталонная реализация)
- **Может работать на**: PyPy, но официально не тестировалось

### Операционные системы
- **Linux**: Полная поддержка, использует `/dev/urandom`
- **macOS**: Полная поддержка, использует `/dev/urandom`
- **Windows**: Полная поддержка, использует `CryptGenRandom` через `os.urandom` Python
- **Другие Unix-подобные**: Должно работать с CSPRNG, предоставляемым ОС

### Соответствие криптографическим стандартам
| Стандарт | Соответствие | Примечания |
|----------|------------|-------|
| FIPS 197 (AES) | Полное | Только AES-128 |
| NIST SP 800-38A | Полное | Режимы: ECB, CBC, CFB, OFB, CTR |
| NIST SP 800-38D | Полное | Режим GCM |
| FIPS 180-4 | Полное | SHA-256 |
| FIPS 202 | Полное | SHA3-256 (через hashlib) |
| RFC 2104 | Полное | HMAC |
| RFC 2898 | Полное | PBKDF2 |
| RFC 4231 | Полное | Тестовые векторы HMAC |

### Совместимость с OpenSSL
CryptoCore поддерживает совместимость с CLI OpenSSL для проверки:

```bash
# Совместимость шифрования
openssl enc -aes-128-cbc -K <key_hex> -iv <iv_hex> -in file.txt

# Совместимость хэширования
openssl dgst -sha256 file.txt

# Совместимость HMAC  
openssl dgst -sha256 -hmac <key> file.txt

# Совместимость PBKDF2
openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt iter:100000 \
  -kdfopt salt:hex:<salt> PBKDF2 <password>
```

### Характеристики производительности
- **Шифрование AES**: ~10-50 МБ/с (накладные расходы Python)
- **Хэширование SHA-256**: ~20-100 МБ/с
- **Шифрование GCM**: ~5-30 МБ/с (включает аутентификацию)
- **PBKDF2**: Настраивается через количество итераций