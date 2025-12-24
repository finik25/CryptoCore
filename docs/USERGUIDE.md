# CryptoCore Руководство пользователя для ОС Ubuntu/Linux

## Быстрая установка

### 1. Предварительные требования
```bash
# Обновить список пакетов
sudo apt update

# Установить Python и инструменты
sudo apt install -y python3-venv python3-pip python3-full git

# Проверить версию Python (требуется 3.8+)
python3 --version
```

### 2. Клонирование и настройка
```bash
# Клонировать репозиторий
git clone https://github.com/finik25/CryptoCore.git
cd CryptoCore

# Создать виртуальное окружение
python3 -m venv venv

# Активировать виртуальное окружение
source venv/bin/activate

# Установить CryptoCore
pip install .
```

### 3. Проверка установки
```bash
# Проверить установку
cryptocore --help

# Запустить набор тестов
python -m unittest discover tests -v
# Ожидается: Все тесты проходят (210+ тестов)
```

## Основные понятия

### Структура команд
CryptoCore поддерживает два синтаксиса команд:

**Современный (рекомендуется):**
```bash
cryptocore <command> [options]
# Пример: cryptocore crypto --algorithm aes --mode cbc --encrypt --input file.txt
```

**Устаревший (обратная совместимость):**
```bash
cryptocore [options]
# Пример: cryptocore --algorithm aes --mode cbc --encrypt --input file.txt
```

### Соглашение об именах файлов
CryptoCore автоматически называет выходные файлы:
- **Шифрование**: `file.txt` → `file.txt.enc` (GCM: `file.txt.gcm`)
- **Дешифрование**: `file.txt.enc` → `file.dec.txt`
- **Хэш/HMAC**: По умолчанию вывод в stdout, или в файл с `--output`

### Формат ключа и вектора инициализации (IV)
- **Ключи**: 32 шестнадцатеричных символа (16 байт) для AES-128
  Пример: `00112233445566778899aabbccddeeff`
- **IV**: 32 шестнадцатеричных символа (16 байт)
  Пример: `aabbccddeeff00112233445566778899`
- **Нонс GCM**: 24 шестнадцатеричных символа (12 байт)
  Пример: `112233445566778899aabbcc`

---

## Шифрование и дешифрование файлов

### 1. Базовое AES шифрование (автоматически сгенерированный ключ)
```bash
# Создать тестовый файл
echo "This is a secret message for encryption testing" > secret.txt

# Зашифровать с автоматически сгенерированным ключом (ключ будет показан)
cryptocore crypto --algorithm aes --mode cbc --encrypt --input secret.txt
# Вывод показывает: Generated random key: 1a2b3c4d5e6f7890abcdef1234567890

# Зашифрованный файл сохраняется как: secret.txt.enc
ls -la secret.txt.enc
```

### 2. Шифрование с указанным ключом
```bash
# Сгенерировать ключ (альтернатива: использовать свой)
python3 -c "import os; print('Key:', os.urandom(16).hex())"

# Зашифровать с конкретным ключом
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt \
  --output encrypted.bin

# Проверить, что файл содержит IV + шифротекст
echo "File size: $(wc -c < encrypted.bin) bytes"
# Должно быть: исходный размер + дополнение + 16 байт IV
```

### 3. Дешифрование
```bash
# Дешифровать с использованием того же ключа
cryptocore crypto --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input encrypted.bin \
  --output decrypted.txt

# Проверить дешифрование
diff secret.txt decrypted.txt
echo $?  # Должен быть 0 (нет различий)
cat decrypted.txt
```

### 4. Использование устаревшего режима
```bash
# Та же операция с использованием устаревшего синтаксиса
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt

cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt.enc
```

### 5. Перезапись файлов (--force)
```bash
# Создать существующий выходной файл
echo "old content" > output.txt

# Шифрование завершится неудачей без --force
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt \
  --output output.txt
# Ошибка: File exists. Use --force to overwrite.

# Использовать --force для перезаписи
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt \
  --output output.txt \
  --force
# Успех: Файл перезаписан
```

---

## Работа с различными режимами шифрования

### 1. Режим ECB (Только для обучения)
```bash
# Предупреждение: ECB раскрывает паттерны в данных
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > pattern.txt  # 32 буквы A

cryptocore crypto --algorithm aes --mode ecb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input pattern.txt \
  --output ecb_encrypted.bin

# Посмотреть hex-дамп, чтобы увидеть паттерн
hexdump -C ecb_encrypted.bin | head -5
```

### 2. Режим CTR (Поточный шифр)
```bash
# CTR не требует дополнения, может зашифровать любой размер
echo -n "Short" > short.txt  # 5 байт

cryptocore crypto --algorithm aes --mode ctr --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv 00000000000000000000000000000001 \
  --input short.txt \
  --output short.ctr.enc

# Проверить соответствие размеров (дополнение не добавлено)
echo "Original: $(wc -c < short.txt) bytes"
echo "Encrypted: $(wc -c < short.ctr.enc) bytes"  # Должно быть 5 + 16 IV
```

### 3. Режим CFB (Самосинхронизирующийся)
```bash
# CFB может обрабатывать частичные блоки
cryptocore crypto --algorithm aes --mode cfb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input /etc/passwd \
  --output passwd.enc
```

### 4. Режим OFB (Независимый поток ключей)
```bash
cryptocore crypto --algorithm aes --mode ofb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input secret.txt \
  --output secret.ofb.enc
```

---

## Аутентифицированное шифрование с GCM

### 1. Базовое GCM шифрование
```bash
# Создать файл с важными данными
echo "Database connection string: postgresql://user:pass@localhost/db" > config.env

# GCM шифрование (нонс генерируется автоматически)
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input config.env \
  --output config.env.gcm

# Файл содержит: нонс(12) + шифротекст + тег(16)
echo "GCM file size: $(wc -c < config.env.gcm) bytes"
```

### 2. GCM дешифрование с проверкой
```bash
# Дешифровать с проверкой
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input config.env.gcm \
  --output config_decrypted.env

# Проверить успешное дешифрование
diff config.env config_decrypted.env
echo "Exit code: $?"  # Должен быть 0
```

### 3. GCM с ассоциированными данными (AAD)
```bash
# Зашифровать с метаданными как AAD
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "version:2.1|user:alice|env:production" \
  --input config.env \
  --output config_prod.gcm

# Дешифровать с правильным AAD (успешно)
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "version:2.1|user:alice|env:production" \
  --input config_prod.gcm \
  --output config_verified.env

# Дешифровать с неправильным AAD (завершается неудачей)
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "version:1.0|user:eve|env:test" \
  --input config_prod.gcm \
  --output config_tampered.env 2>&1
# Вывод: AuthenticationError - файл не создан
```

### 4. Демонстрация обнаружения подделки
```bash
# Создать исходный файл
echo "Transfer $1000 to account 123456" > transfer.txt

# Зашифровать
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input transfer.txt \
  --output transfer.gcm

# Подделать шифротекст
python3 -c "
data = open('transfer.gcm', 'rb').read()
# Изменить один байт в шифротексте (после нонса)
tampered = data[:12] + bytes([data[12] ^ 0x01]) + data[13:]
open('transfer_tampered.gcm', 'wb').write(tampered)
"

# Попытаться дешифровать подделанный файл
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input transfer_tampered.gcm \
  --output transfer_recovered.txt 2>&1 || true
# Вывод: AuthenticationError - GCM tag verification failed
```

---

## Хэширование и целостность данных

### 1. Базовое хэширование файлов
```bash
# Создать тестовый файл
echo "Hello, CryptoCore! This is a test file." > document.txt

# SHA-256 хэш
cryptocore dgst --algorithm sha256 --input document.txt
# Вывод: hash_hex document.txt

# SHA3-256 хэш
cryptocore dgst --algorithm sha3-256 --input document.txt

# Сохранить хэш в файл
cryptocore dgst --algorithm sha256 --input document.txt --output document.sha256
cat document.sha256
```

### 2. Проверка хэша
```bash
# Вычислить хэш
hash1=$(cryptocore dgst --algorithm sha256 --input document.txt | cut -d' ' -f1)
echo "Original hash: $hash1"

# Изменить файл
echo "Modified content" >> document.txt

# Вычислить новый хэш
hash2=$(cryptocore dgst --algorithm sha256 --input document.txt | cut -d' ' -f1)
echo "Modified hash: $hash2"

# Хэши должны различаться
if [ "$hash1" != "$hash2" ]; then
    echo "✓ File modification detected"
fi
```

### 3. Хэширование больших файлов
```bash
# Создать большой файл (10MB)
dd if=/dev/urandom of=large_file.bin bs=1M count=10 status=progress

# Хэширование с потоковой обработкой (использует минимальную память)
time cryptocore dgst --algorithm sha256 --input large_file.bin

# Сравнить с системной утилитой sha256sum
time sha256sum large_file.bin
```

### 4. Хэширование из stdin
```bash
# Хэширование данных из конвейера
echo "Data from pipe" | cryptocore dgst --algorithm sha256 --input -

# Хэширование вывода команды
ls -la | cryptocore dgst --algorithm sha256 --input -
```

---

## Коды аутентификации сообщений (HMAC)

### 1. Генерация HMAC
```bash
# Создать конфиденциальный файл
echo "Credit Card: 4111-1111-1111-1111" > payment.csv

# Сгенерировать HMAC
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv \
  --output payment.hmac

cat payment.hmac
# Формат: hmac_hex filename
```

### 2. Проверка HMAC
```bash
# Сначала сохранить ожидаемый HMAC
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv > expected.hmac

# Проверить (успешно)
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv \
  --verify expected.hmac
echo "Exit code: $?"  # Должен быть 0

# Изменить файл и проверить (неудачно)
echo "tampered" >> payment.csv
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv \
  --verify expected.hmac
echo "Exit code: $?"  # Должен быть 1
```

### 3. Обнаружение неправильного ключа
```bash
# Сгенерировать HMAC с key1
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv > hmac_key1.txt

# Проверить с неправильным ключом (неудачно)
cryptocore dgst --algorithm sha256 --hmac \
  --key ffeeddccbbaa99887766554433221100 \
  --input payment.csv \
  --verify hmac_key1.txt
echo "Wrong key detection: $?"  # Должен быть 1
```

### 4. HMAC для больших файлов
```bash
# Создать тестовый файл 100MB
dd if=/dev/zero of=large_data.bin bs=1M count=100 status=progress

# Сгенерировать HMAC (потоковая обработка, эффективно по памяти)
time cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input large_data.bin \
  --output large_data.hmac
```

---

## Генерация ключей из паролей

### 1. Базовая генерация ключей
```bash
# Сгенерировать ключ из пароля с указанной солью
cryptocore derive --password "MySecurePassword123!" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 \
  --length 32
# Вывод: derived_key salt

# Сохранить в переменную
result=$(cryptocore derive --password "MySecurePassword123!" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 \
  --length 32)

key=$(echo $result | cut -d' ' -f1)
salt=$(echo $result | cut -d' ' -f2)
echo "Key: $key"
echo "Salt: $salt"
```

### 2. Автоматически сгенерированная соль
```bash
# Автоматически сгенерировать соль (рекомендуется для новых паролей)
cryptocore derive --password "AnotherSecurePassword" \
  --iterations 200000 \
  --length 16
# Вывод включает сгенерированную соль
```

### 3. Сохранение сгенерированного ключа в файл
```bash
# Сгенерировать и сохранить в файл
cryptocore derive --password "ApplicationSecretKey" \
  --iterations 150000 \
  --length 32 \
  --output app_key.bin

# Посмотреть ключ (hex)
hexdump -C app_key.bin
```

### 4. Пароль из файла
```bash
# Сохранить пароль в файле
echo -n "FileBasedPassword456!" > password.txt
chmod 600 password.txt

# Использовать файл с паролем
cryptocore derive --password-file password.txt \
  --salt fixedappsalt123456 \
  --iterations 100000
```

### 5. Пароль из переменной окружения
```bash
# Установить переменную окружения
export DB_PASSWORD="DatabaseSecret789!"

# Использовать переменную окружения
cryptocore derive --env-var DB_PASSWORD \
  --salt dbsalt1234567890 \
  --iterations 100000
```

### 6. Полный рабочий процесс от пароля до шифрования
```bash
# Шаг 1: Создать конфиденциальные данные
echo "API_KEY=sk_live_1234567890abcdef" > secrets.env

# Шаг 2: Сгенерировать ключ шифрования из пароля
result=$(cryptocore derive --password "MasterPasswordForSecrets" \
  --iterations 300000 \
  --length 32)
key=$(echo $result | cut -d' ' -f1)
salt=$(echo $result | cut -d' ' -f2)

echo "Salt (save this): $salt"

# Шаг 3: Зашифровать сгенерированным ключом
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key $(echo $key | cut -c1-32) \
  --aad "secrets_env_v1" \
  --input secrets.env \
  --output secrets.env.enc

# Шаг 4: Для дешифрования повторно сгенерировать ключ, используя ту же соль
key2=$(cryptocore derive --password "MasterPasswordForSecrets" \
  --salt $salt \
  --iterations 300000 \
  --length 32 | cut -d' ' -f1)

# Шаг 5: Дешифровать
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key $(echo $key2 | cut -c1-32) \
  --aad "secrets_env_v1" \
  --input secrets.env.enc \
  --output secrets_decrypted.env

# Проверить
diff secrets.env secrets_decrypted.env && echo "✓ Success"
```

---

## Продвинутые примеры использования

### 1. Шифрование содержимого каталога
```bash
# Создать тестовый каталог
mkdir -p test_data
echo "File 1 content" > test_data/file1.txt
echo "File 2 content" > test_data/file2.txt
echo "File 3 content" > test_data/file3.txt

# Зашифровать все файлы
key="00112233445566778899aabbccddeeff"
for file in test_data/*.txt; do
    cryptocore crypto --algorithm aes --mode ctr --encrypt \
      --key $key \
      --iv aabbccddeeff00112233445566778899 \
      --input "$file" \
      --output "${file}.enc" \
      --force
done

ls -la test_data/*.enc
```

### 2. Пакетная проверка HMAC
```bash
# Создать скрипт проверки
cat > verify_hmacs.sh << 'EOF'
#!/bin/bash
KEY="00112233445566778899aabbccddeeff"
ALL_VALID=true

for file in *.hmac; do
    data_file="${file%.hmac}"
    if [ -f "$data_file" ]; then
        cryptocore dgst --algorithm sha256 --hmac \
          --key $KEY \
          --input "$data_file" \
          --verify "$file" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo "✓ $data_file: Valid"
        else
            echo "✗ $data_file: INVALID or tampered"
            ALL_VALID=false
        fi
    fi
done

if $ALL_VALID; then
    echo "All files verified successfully"
    exit 0
else
    echo "Some files failed verification"
    exit 1
fi
EOF

chmod +x verify_hmacs.sh
```

### 3. Имитация безопасной передачи файлов
```bash
# Сторона отправителя
echo "Confidential report data" > report.txt
key=$(python3 -c "import os; print(os.urandom(16).hex())")
echo "Key (share securely): $key"

cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key $key \
  --aad "report_2024_q4_final" \
  --input report.txt \
  --output report.txt.gcm

# Имитировать передачу
cp report.txt.gcm /tmp/

# Сторона получателя
cd /tmp
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key $key \
  --aad "report_2024_q4_final" \
  --input report.txt.gcm \
  --output received_report.txt

cat received_report.txt
```

### 4. Скрипт мониторинга целостности
```bash
# Мониторинг изменений файлов с HMAC
cat > monitor_integrity.sh << 'EOF'
#!/bin/bash
KEY="00112233445566778899aabbccddeeff"
LOG_FILE="integrity.log"
FILES=("important.conf" "data.bin" "script.py")

# Начальная генерация HMAC
echo "$(date): Initial HMAC generation" >> "$LOG_FILE"
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        cryptocore dgst --algorithm sha256 --hmac \
          --key $KEY \
          --input "$file" > "${file}.hmac"
        echo "  Generated HMAC for $file" >> "$LOG_FILE"
    fi
done

# Функция проверки
verify_files() {
    echo "$(date): Verifying files" >> "$LOG_FILE"
    ALL_OK=true
    
    for file in "${FILES[@]}"; do
        if [ -f "$file" ] && [ -f "${file}.hmac" ]; then
            cryptocore dgst --algorithm sha256 --hmac \
              --key $KEY \
              --input "$file" \
              --verify "${file}.hmac" > /dev/null 2>&1
            
            if [ $? -eq 0 ]; then
                echo "  ✓ $file: OK" >> "$LOG_FILE"
            else
                echo "  ✗ $file: TAMPERED!" >> "$LOG_FILE"
                ALL_OK=false
            fi
        fi
    done
    
    if $ALL_OK; then
        return 0
    else
        return 1
    fi
}

# Запустить проверку
verify_files
EOF

chmod +x monitor_integrity.sh
```

---

## Устранение неполадок

### Распространенные проблемы и решения

#### 1. Ошибка "File exists"
```bash
# Ошибка: Выходной файл уже существует
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt \
  --output existing.txt
# Решение: Использовать --force или выбрать другое имя выходного файла

cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt \
  --output existing.txt \
  --force
```

#### 2. Ошибка "Key must be 16 bytes"
```bash
# Неправильно: 15 байт
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddee \
  --input data.txt
# Ошибка: Key must be 16 bytes

# Правильно: 16 байт (32 шестнадцатеричных символа)
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt
```

#### 3. Проблемы совместимости с OpenSSL
```bash
# Если дешифрование OpenSSL завершается неудачей, проверить извлечение IV
encrypted_file="secret.txt.enc"
iv=$(head -c 16 "$encrypted_file" | xxd -p)
ciphertext=$(tail -c +17 "$encrypted_file")

echo "IV: $iv"
echo "Ciphertext length: $(echo -n "$ciphertext" | wc -c) bytes"
```

#### 4. Отказано в доступе
```bash
# Запуск от имени не-root пользователя на защищенных файлах
sudo cryptocore dgst --algorithm sha256 --input /etc/shadow
# Альтернатива: Сначала скопировать файл
sudo cp /etc/shadow /tmp/
cryptocore dgst --algorithm sha256 --input /tmp/shadow
```

### Режим отладки
```bash
# Включить подробный вывод для отладки
export PYTHONPATH=src:$PYTHONPATH
python3 -m cryptocore.cli crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt -v
```

### Тестирование производительности
```bash
# Создать тестовый файл 100MB
dd if=/dev/urandom of=perf_test.bin bs=1M count=100

# Засечь время шифрования
time cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input perf_test.bin \
  --output perf_test.enc

# Засечь время дешифрования
time cryptocore crypto --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input perf_test.enc \
  --output perf_test.dec

# Очистить
rm perf_test.*
```

---

## Краткая памятка

### Базовые действия
```bash
# Шифрование
cryptocore crypto --algorithm aes --mode MODE --encrypt --key HEX_KEY --input FILE

# Дешифрование  
cryptocore crypto --algorithm aes --mode MODE --decrypt --key HEX_KEY --input FILE

# Хэширование
cryptocore dgst --algorithm {sha256|sha3-256} --input FILE

# HMAC
cryptocore dgst --algorithm sha256 --hmac --key HEX_KEY --input FILE

# Генерация ключей
cryptocore derive --password PASS --salt HEX_SALT --iterations N --length N
```

### Команды CLI
```
--input, -i     Входной файл (использовать - для stdin)
--output, -o    Выходной файл (stdout, если не указан)
--force, -f     Перезаписать существующие файлы
--key, -k       Ключ в виде hex-строки (32 символа для AES-128)
--iv            IV в виде hex-строки (32 символа для 16 байт)
--aad           Ассоциированные данные для GCM
--hmac          Вычислить HMAC вместо хэша
--verify        Проверить HMAC по отношению к файлу
```

### Сравнение режимов
| Режим | Требуется IV | Дополнение | Лучше всего для |
|------|------------|---------|----------|
| ECB  | Нет         | Да     | Только обучение |
| CBC  | Да (16B)  | Да     | Общее шифрование |
| CTR  | Да (16B)  | Нет      | Поточное шифрование |
| CFB  | Да (16B)  | Нет      | Самосинхронизирующиеся потоки |
| OFB  | Да (16B)  | Нет      | Устойчивость к ошибкам |
| GCM  | Да (12B)  | Нет      | Аутентифицированное шифрование |

### Генерация ключей
```bash
# Сгенерировать случайный ключ
python3 -c "import os; print(os.urandom(16).hex())"

# Сгенерировать случайный IV
python3 -c "import os; print(os.urandom(16).hex())"

# Сгенерировать нонс GCM
python3 -c "import os; print(os.urandom(12).hex())"
```

---

## Рекомендации по безопасности

### 1. Управление ключами
```bash
# Хранить ключи безопасно (не в скриптах)
export ENCRYPTION_KEY=$(cat /path/to/secure/key.txt)

# Использовать в командах
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key "$ENCRYPTION_KEY" \
  --input sensitive.data
```

### 2. Безопасность паролей
```bash
# Использовать надежные пароли
cryptocore derive --password "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9!@#$%^&*' | head -c 32)" \
  --iterations 300000

# Никогда не хранить пароли в истории команд
unset HISTFILE
```

### 3. Права доступа к файлам
```bash
# Установить правильные права доступа
chmod 600 encrypted_file.bin
chmod 400 key.txt
chmod 700 scripts/
```

### 4. Всегда проверять
```bash
# Всегда проверять перед использованием
cryptocore dgst --algorithm sha256 --hmac \
  --key "$KEY" \
  --input downloaded_file.iso \
  --verify expected.hmac || exit 1
```

---

## Получение помощи

### Проверить версию
```bash
cryptocore --version
python3 -c "import cryptocore; print(cryptocore.__version__)"
```

### Просмотр справки
```bash
# Общая справка
cryptocore --help

# Справка по конкретной команде
cryptocore crypto --help
cryptocore dgst --help  
cryptocore derive --help
```

### Проверить установку
```bash
# Запустить все тесты
cd /path/to/CryptoCore
python -m unittest discover tests -v

# Запустить конкретный тест
python -m unittest tests.unit.test_aes -v
```

---

*Руководство пользователя для CryptoCore v1.0.0 на Ubuntu/Linux. Все команды протестированы на Ubuntu 22.04 LTS.*