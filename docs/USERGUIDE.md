
# CryptoCore User Guide for Ubuntu/Linux

## Quick Installation

### 1. Prerequisites
```bash
# Update package list
sudo apt update

# Install Python and tools
sudo apt install -y python3-venv python3-pip python3-full git

# Verify Python version (requires 3.8+)
python3 --version
```

### 2. Clone and Setup
```bash
# Clone the repository
git clone https://github.com/finik25/CryptoCore.git
cd CryptoCore

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install CryptoCore
pip install .
```

### 3. Verify Installation
```bash
# Check installation
cryptocore --help

# Run test suite
python -m unittest discover tests -v
# Expected: All tests pass (210+ tests)
```

## Basic Concepts

### Command Structure
CryptoCore supports two command syntaxes:

**Modern (recommended):**
```bash
cryptocore <command> [options]
# Example: cryptocore crypto --algorithm aes --mode cbc --encrypt --input file.txt
```

**Legacy (backward compatible):**
```bash
cryptocore [options]
# Example: cryptocore --algorithm aes --mode cbc --encrypt --input file.txt
```

### File Naming Convention
CryptoCore automatically names output files:
- **Encryption**: `file.txt` → `file.txt.enc` (GCM: `file.txt.gcm`)
- **Decryption**: `file.txt.enc` → `file.dec.txt`
- **Hash/HMAC**: Output to stdout by default, or file with `--output`

### Key and IV Format
- **Keys**: 32 hexadecimal characters (16 bytes) for AES-128
  Example: `00112233445566778899aabbccddeeff`
- **IVs**: 32 hexadecimal characters (16 bytes)
  Example: `aabbccddeeff00112233445566778899`
- **GCM Nonce**: 24 hexadecimal characters (12 bytes)
  Example: `112233445566778899aabbcc`

---

## File Encryption & Decryption

### 1. Basic AES Encryption (Auto-generated Key)
```bash
# Create a test file
echo "This is a secret message for encryption testing" > secret.txt

# Encrypt with auto-generated key (key will be displayed)
cryptocore crypto --algorithm aes --mode cbc --encrypt --input secret.txt
# Output shows: Generated random key: 1a2b3c4d5e6f7890abcdef1234567890

# The encrypted file is saved as: secret.txt.enc
ls -la secret.txt.enc
```

### 2. Encryption with Specified Key
```bash
# Generate a key (alternative: use your own)
python3 -c "import os; print('Key:', os.urandom(16).hex())"

# Encrypt with specific key
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt \
  --output encrypted.bin

# Verify file contains IV + ciphertext
echo "File size: $(wc -c < encrypted.bin) bytes"
# Should be: original size + padding + 16 bytes IV
```

### 3. Decryption
```bash
# Decrypt using the same key
cryptocore crypto --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input encrypted.bin \
  --output decrypted.txt

# Verify decryption
diff secret.txt decrypted.txt
echo $?  # Should be 0 (no difference)
cat decrypted.txt
```

### 4. Using Legacy Mode
```bash
# Same operation using legacy syntax
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt

cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt.enc
```

### 5. Overwriting Files (--force)
```bash
# Create existing output file
echo "old content" > output.txt

# Encryption will fail without --force
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt \
  --output output.txt
# Error: File exists. Use --force to overwrite.

# Use --force to overwrite
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt \
  --output output.txt \
  --force
# Success: File overwritten
```

---

## Working with Different Encryption Modes

### 1. ECB Mode (Educational Only)
```bash
# Warning: ECB reveals patterns in data
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > pattern.txt  # 32 As

cryptocore crypto --algorithm aes --mode ecb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input pattern.txt \
  --output ecb_encrypted.bin

# View hex dump to see pattern
hexdump -C ecb_encrypted.bin | head -5
```

### 2. CTR Mode (Stream Cipher)
```bash
# CTR doesn't require padding, can encrypt any size
echo -n "Short" > short.txt  # 5 bytes

cryptocore crypto --algorithm aes --mode ctr --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv 00000000000000000000000000000001 \
  --input short.txt \
  --output short.ctr.enc

# Verify size matches (no padding added)
echo "Original: $(wc -c < short.txt) bytes"
echo "Encrypted: $(wc -c < short.ctr.enc) bytes"  # Should be 5 + 16 IV
```

### 3. CFB Mode (Self-Synchronizing)
```bash
# CFB can process partial blocks
cryptocore crypto --algorithm aes --mode cfb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input /etc/passwd \
  --output passwd.enc
```

### 4. OFB Mode (Keystream Independent)
```bash
cryptocore crypto --algorithm aes --mode ofb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input secret.txt \
  --output secret.ofb.enc
```

---

## Authenticated Encryption with GCM

### 1. Basic GCM Encryption
```bash
# Create important data file
echo "Database connection string: postgresql://user:pass@localhost/db" > config.env

# GCM encryption (nonce auto-generated)
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input config.env \
  --output config.env.gcm

# File contains: nonce(12) + ciphertext + tag(16)
echo "GCM file size: $(wc -c < config.env.gcm) bytes"
```

### 2. GCM Decryption with Verification
```bash
# Decrypt with verification
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input config.env.gcm \
  --output config_decrypted.env

# Verify successful decryption
diff config.env config_decrypted.env
echo "Exit code: $?"  # Should be 0
```

### 3. GCM with Associated Data (AAD)
```bash
# Encrypt with metadata as AAD
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "version:2.1|user:alice|env:production" \
  --input config.env \
  --output config_prod.gcm

# Decrypt with correct AAD (succeeds)
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "version:2.1|user:alice|env:production" \
  --input config_prod.gcm \
  --output config_verified.env

# Decrypt with wrong AAD (fails catastrophically)
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "version:1.0|user:eve|env:test" \
  --input config_prod.gcm \
  --output config_tampered.env 2>&1
# Output: AuthenticationError - no file created
```

### 4. Tamper Detection Demonstration
```bash
# Create original file
echo "Transfer $1000 to account 123456" > transfer.txt

# Encrypt
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input transfer.txt \
  --output transfer.gcm

# Tamper with the ciphertext
python3 -c "
data = open('transfer.gcm', 'rb').read()
# Change one byte in ciphertext (after nonce)
tampered = data[:12] + bytes([data[12] ^ 0x01]) + data[13:]
open('transfer_tampered.gcm', 'wb').write(tampered)
"

# Try to decrypt tampered file
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input transfer_tampered.gcm \
  --output transfer_recovered.txt 2>&1 || true
# Output: AuthenticationError - GCM tag verification failed
```

---

## Hashing and Data Integrity

### 1. Basic File Hashing
```bash
# Create test file
echo "Hello, CryptoCore! This is a test file." > document.txt

# SHA-256 hash
cryptocore dgst --algorithm sha256 --input document.txt
# Output: hash_hex document.txt

# SHA3-256 hash
cryptocore dgst --algorithm sha3-256 --input document.txt

# Save hash to file
cryptocore dgst --algorithm sha256 --input document.txt --output document.sha256
cat document.sha256
```

### 2. Hash Verification
```bash
# Compute hash
hash1=$(cryptocore dgst --algorithm sha256 --input document.txt | cut -d' ' -f1)
echo "Original hash: $hash1"

# Modify file
echo "Modified content" >> document.txt

# Compute new hash
hash2=$(cryptocore dgst --algorithm sha256 --input document.txt | cut -d' ' -f1)
echo "Modified hash: $hash2"

# Hashes should be different
if [ "$hash1" != "$hash2" ]; then
    echo "✓ File modification detected"
fi
```

### 3. Hash Large Files
```bash
# Create large file (10MB)
dd if=/dev/urandom of=large_file.bin bs=1M count=10 status=progress

# Hash with streaming (uses minimal memory)
time cryptocore dgst --algorithm sha256 --input large_file.bin

# Compare with system sha256sum
time sha256sum large_file.bin
```

### 4. Hash from stdin
```bash
# Hash piped data
echo "Data from pipe" | cryptocore dgst --algorithm sha256 --input -

# Hash command output
ls -la | cryptocore dgst --algorithm sha256 --input -
```

---

## Message Authentication Codes (HMAC)

### 1. HMAC Generation
```bash
# Create sensitive file
echo "Credit Card: 4111-1111-1111-1111" > payment.csv

# Generate HMAC
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv \
  --output payment.hmac

cat payment.hmac
# Format: hmac_hex filename
```

### 2. HMAC Verification
```bash
# First, save expected HMAC
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv > expected.hmac

# Verify (succeeds)
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv \
  --verify expected.hmac
echo "Exit code: $?"  # Should be 0

# Modify file and verify (fails)
echo "tampered" >> payment.csv
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv \
  --verify expected.hmac
echo "Exit code: $?"  # Should be 1
```

### 3. Wrong Key Detection
```bash
# Generate HMAC with key1
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input payment.csv > hmac_key1.txt

# Verify with wrong key (fails)
cryptocore dgst --algorithm sha256 --hmac \
  --key ffeeddccbbaa99887766554433221100 \
  --input payment.csv \
  --verify hmac_key1.txt
echo "Wrong key detection: $?"  # Should be 1
```

### 4. HMAC for Large Files
```bash
# Create 100MB test file
dd if=/dev/zero of=large_data.bin bs=1M count=100 status=progress

# Generate HMAC (streaming, memory efficient)
time cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input large_data.bin \
  --output large_data.hmac
```

---

## Key Derivation from Passwords

### 1. Basic Key Derivation
```bash
# Derive key from password with specified salt
cryptocore derive --password "MySecurePassword123!" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 \
  --length 32
# Output: derived_key salt

# Save to variable
result=$(cryptocore derive --password "MySecurePassword123!" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 \
  --length 32)

key=$(echo $result | cut -d' ' -f1)
salt=$(echo $result | cut -d' ' -f2)
echo "Key: $key"
echo "Salt: $salt"
```

### 2. Auto-generated Salt
```bash
# Auto-generate salt (recommended for new passwords)
cryptocore derive --password "AnotherSecurePassword" \
  --iterations 200000 \
  --length 16
# Output includes generated salt
```

### 3. Save Derived Key to File
```bash
# Derive and save to file
cryptocore derive --password "ApplicationSecretKey" \
  --iterations 150000 \
  --length 32 \
  --output app_key.bin

# View key (hex)
hexdump -C app_key.bin
```

### 4. Password from File
```bash
# Store password in file
echo -n "FileBasedPassword456!" > password.txt
chmod 600 password.txt

# Use password file
cryptocore derive --password-file password.txt \
  --salt fixedappsalt123456 \
  --iterations 100000
```

### 5. Password from Environment Variable
```bash
# Set environment variable
export DB_PASSWORD="DatabaseSecret789!"

# Use environment variable
cryptocore derive --env-var DB_PASSWORD \
  --salt dbsalt1234567890 \
  --iterations 100000
```

### 6. Complete Password-to-Encryption Workflow
```bash
# Step 1: Create secret data
echo "API_KEY=sk_live_1234567890abcdef" > secrets.env

# Step 2: Derive encryption key from password
result=$(cryptocore derive --password "MasterPasswordForSecrets" \
  --iterations 300000 \
  --length 32)
key=$(echo $result | cut -d' ' -f1)
salt=$(echo $result | cut -d' ' -f2)

echo "Salt (save this): $salt"

# Step 3: Encrypt with derived key
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key $(echo $key | cut -c1-32) \
  --aad "secrets_env_v1" \
  --input secrets.env \
  --output secrets.env.enc

# Step 4: For decryption, re-derive key using same salt
key2=$(cryptocore derive --password "MasterPasswordForSecrets" \
  --salt $salt \
  --iterations 300000 \
  --length 32 | cut -d' ' -f1)

# Step 5: Decrypt
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key $(echo $key2 | cut -c1-32) \
  --aad "secrets_env_v1" \
  --input secrets.env.enc \
  --output secrets_decrypted.env

# Verify
diff secrets.env secrets_decrypted.env && echo "✓ Success"
```

---

## Advanced Usage Examples

### 1. Encrypt Directory Contents
```bash
# Create test directory
mkdir -p test_data
echo "File 1 content" > test_data/file1.txt
echo "File 2 content" > test_data/file2.txt
echo "File 3 content" > test_data/file3.txt

# Encrypt all files
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

### 2. Batch HMAC Verification
```bash
# Create verification script
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

### 3. Secure File Transfer Simulation
```bash
# Sender side
echo "Confidential report data" > report.txt
key=$(python3 -c "import os; print(os.urandom(16).hex())")
echo "Key (share securely): $key"

cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key $key \
  --aad "report_2024_q4_final" \
  --input report.txt \
  --output report.txt.gcm

# Simulate transfer
cp report.txt.gcm /tmp/

# Receiver side
cd /tmp
cryptocore crypto --algorithm aes --mode gcm --decrypt \
  --key $key \
  --aad "report_2024_q4_final" \
  --input report.txt.gcm \
  --output received_report.txt

cat received_report.txt
```

### 4. Integrity Monitoring Script
```bash
# Monitor file changes with HMAC
cat > monitor_integrity.sh << 'EOF'
#!/bin/bash
KEY="00112233445566778899aabbccddeeff"
LOG_FILE="integrity.log"
FILES=("important.conf" "data.bin" "script.py")

# Initial HMAC generation
echo "$(date): Initial HMAC generation" >> "$LOG_FILE"
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        cryptocore dgst --algorithm sha256 --hmac \
          --key $KEY \
          --input "$file" > "${file}.hmac"
        echo "  Generated HMAC for $file" >> "$LOG_FILE"
    fi
done

# Verification function
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

# Run verification
verify_files
EOF

chmod +x monitor_integrity.sh
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. "File exists" Error
```bash
# Error: Output file already exists
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt \
  --output existing.txt
# Solution: Use --force or choose different output name

cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt \
  --output existing.txt \
  --force
```

#### 2. "Key must be 16 bytes" Error
```bash
# Wrong: 15 bytes
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddee \
  --input data.txt
# Error: Key must be 16 bytes

# Correct: 16 bytes (32 hex characters)
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt
```

#### 3. OpenSSL Compatibility Issues
```bash
# If OpenSSL decryption fails, check IV extraction
encrypted_file="secret.txt.enc"
iv=$(head -c 16 "$encrypted_file" | xxd -p)
ciphertext=$(tail -c +17 "$encrypted_file")

echo "IV: $iv"
echo "Ciphertext length: $(echo -n "$ciphertext" | wc -c) bytes"
```

#### 4. Permission Denied
```bash
# Running as non-root on protected files
sudo cryptocore dgst --algorithm sha256 --input /etc/shadow
# Alternative: Copy file first
sudo cp /etc/shadow /tmp/
cryptocore dgst --algorithm sha256 --input /tmp/shadow
```

### Debug Mode
```bash
# Enable verbose output for debugging
export PYTHONPATH=src:$PYTHONPATH
python3 -m cryptocore.cli crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt -v
```

### Performance Testing
```bash
# Create 100MB test file
dd if=/dev/urandom of=perf_test.bin bs=1M count=100

# Time encryption
time cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input perf_test.bin \
  --output perf_test.enc

# Time decryption
time cryptocore crypto --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input perf_test.enc \
  --output perf_test.dec

# Clean up
rm perf_test.*
```

---

## Quick Reference Cheat Sheet

### Basic Commands
```bash
# Encryption
cryptocore crypto --algorithm aes --mode MODE --encrypt --key HEX_KEY --input FILE

# Decryption  
cryptocore crypto --algorithm aes --mode MODE --decrypt --key HEX_KEY --input FILE

# Hashing
cryptocore dgst --algorithm {sha256|sha3-256} --input FILE

# HMAC
cryptocore dgst --algorithm sha256 --hmac --key HEX_KEY --input FILE

# Key derivation
cryptocore derive --password PASS --salt HEX_SALT --iterations N --length N
```

### Common Options
```
--input, -i     Input file (use - for stdin)
--output, -o    Output file (stdout if omitted)
--force, -f     Overwrite existing files
--key, -k       Key as hex string (32 chars for AES-128)
--iv            IV as hex string (32 chars for 16 bytes)
--aad           Associated data for GCM
--hmac          Compute HMAC instead of hash
--verify        Verify HMAC against file
```

### Mode Comparison
| Mode | IV Required | Padding | Best For |
|------|------------|---------|----------|
| ECB  | No         | Yes     | Education only |
| CBC  | Yes (16B)  | Yes     | General encryption |
| CTR  | Yes (16B)  | No      | Stream encryption |
| CFB  | Yes (16B)  | No      | Self-sync streams |
| OFB  | Yes (16B)  | No      | Error-resistant |
| GCM  | Yes (12B)  | No      | Authenticated encryption |

### Key Generation
```bash
# Generate random key
python3 -c "import os; print(os.urandom(16).hex())"

# Generate random IV
python3 -c "import os; print(os.urandom(16).hex())"

# Generate GCM nonce
python3 -c "import os; print(os.urandom(12).hex())"
```

---

## Security Best Practices

### 1. Key Management
```bash
# Store keys securely (not in scripts)
export ENCRYPTION_KEY=$(cat /path/to/secure/key.txt)

# Use in commands
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key "$ENCRYPTION_KEY" \
  --input sensitive.data
```

### 2. Password Security
```bash
# Use strong passwords
cryptocore derive --password "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9!@#$%^&*' | head -c 32)" \
  --iterations 300000

# Never store passwords in command history
unset HISTFILE
```

### 3. File Permissions
```bash
# Set proper permissions
chmod 600 encrypted_file.bin
chmod 400 key.txt
chmod 700 scripts/
```

### 4. Verification Always
```bash
# Always verify before use
cryptocore dgst --algorithm sha256 --hmac \
  --key "$KEY" \
  --input downloaded_file.iso \
  --verify expected.hmac || exit 1
```

---

## Getting Help

### Check Version
```bash
cryptocore --version
python3 -c "import cryptocore; print(cryptocore.__version__)"
```

### View Help
```bash
# General help
cryptocore --help

# Command-specific help
cryptocore crypto --help
cryptocore dgst --help  
cryptocore derive --help
```

### Test Installation
```bash
# Run all tests
cd /path/to/CryptoCore
python -m unittest discover tests -v

# Run specific test
python -m unittest tests.unit.test_aes -v
```

### Report Issues
If you encounter bugs or have questions:
1. Check this user guide
2. Run tests to verify installation
3. Check Python version (`python3 --version`)
4. Provide error messages and command used

---

*User Guide for CryptoCore v1.0.0 on Ubuntu/Linux. All commands tested on Ubuntu 22.04 LTS.*
