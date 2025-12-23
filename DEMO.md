
# Установка пакета в виртуальное окружение
python -m pip install -e .

# Проверка установки
cryptocore --version
```

### 2. Подготовка тестового файла
```bash
# Создание демонстрационного файла
echo "Это секретный файл для демонстрации CryptoCore." > secret.txt
echo "Вторая строка с данными." >> secret.txt
echo "Файл создан, размер:"
wc -c secret.txt
```

### 3. Шифрование/дешифрование (современный стиль)
```bash
# Шифрование с явным указанием ключа
cryptocore crypto --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input secret.txt --output encrypted.cbc

# Дешифрование
cryptocore crypto --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input encrypted.cbc --output decrypted.txt

# Проверка совпадения
diff secret.txt decrypted.txt && echo "✓ Шифрование/дешифрование работает!"
```

### 4. Шифрование/дешифрование (легаси стиль)
```bash
# Автоматическая генерация ключа (ключ будет показан)
cryptocore --algorithm aes --mode cbc --encrypt --input secret.txt

# Дешифрование сгенерированным ключом (подставить ваш ключ)
cryptocore --algorithm aes --mode cbc --decrypt --key ВАШ_СГЕНЕРИРОВАННЫЙ_КЛЮЧ --input secret.txt.enc --output decrypted_legacy.txt

# Проверка
diff secret.txt decrypted_legacy.txt && echo "✓ Легаси режим работает!"
```

### 5. Демонстрация --force флага
```bash
# Попытка перезаписи БЕЗ --force (должна завершиться ошибкой)
cryptocore crypto --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input secret.txt --output encrypted.cbc

# Перезапись С --force
cryptocore crypto --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input secret.txt --output encrypted.cbc --force
echo "✓ Флаг --force работает!"
```

### 6. Демонстрация HMAC
```bash
# Генерация HMAC-SHA256 для файла
cryptocore dgst --algorithm sha256 --hmac --key aabbccddeeff00112233445566778899 --input secret.txt

# Сохранение HMAC в файл
cryptocore dgst --algorithm sha256 --hmac --key aabbccddeeff00112233445566778899 --input secret.txt --output secret.hmac

# Проверка HMAC
cryptocore dgst --algorithm sha256 --hmac --key aabbccddeeff00112233445566778899 --input secret.txt --verify secret.hmac && echo "✓ HMAC проверка успешна!"
```

### 7. Демонстрация вывода ключей (PBKDF2)
```bash
# Вывод ключа из пароля с указанной солью
cryptocore derive --password "MyStrongPassword123!" --salt 66778899aabbccdd --iterations 100000 --length 32

# Автоматическая генерация соли
cryptocore derive --password "AnotherSecretPass" --iterations 50000 --length 16

# Сохранение результата в файл
cryptocore derive --password "AppKey" --salt fixedappsalt123 --iterations 200000 --length 32 --output derived_key.bin
```

### 8. Быстрая полная демонстрация (все в одном)
```bash
# Создать файл, зашифровать, расшифровать, проверить HMAC
echo "Демо" > demo.txt
cryptocore crypto --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input demo.txt
cryptocore crypto --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input demo.txt.enc --output demo_dec.txt
diff demo.txt demo_dec.txt && echo "✓ Шифрование работает!"
cryptocore dgst --algorithm sha256 --hmac --key aabbccddeeff00112233445566778899 --input demo.txt
echo "Демонстрация завершена!"
```

### 9. Очистка после демонстрации
```bash
# Удаление тестовых файлов
rm -f secret.txt encrypted.cbc decrypted.txt *.enc *.hmac derived_key.bin demo*.txt