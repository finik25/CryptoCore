
# CryptoCore

Minimalist cryptographic provider in Python. Educational project focused on understanding cryptographic algorithms and protocols.

## Features

- **AES-128 encryption/decryption** in multiple modes
- **Five supported modes**: ECB, CBC, CFB, OFB, CTR
- **PKCS#7 padding** for modes that require it
- **IV (Initialization Vector) handling** with secure generation
- **Binary file handling** - works with any file type
- **OpenSSL compatibility** - verified against industry standard
- **Command-line interface** with comprehensive validation

## Requirements

- Python 3.6+
- pycryptodome 3.20.0+

## Installation

Install from source:

```powershell
# Clone the repository
git clone <repository-url>
cd CryptoCore

# Install in development mode
pip install -e .
```

Verify installation:

```powershell
# Check command availability
cryptocore --help

# Verify package installation  
pip list | Select-String cryptocore
```

## Usage

### Basic Operations

#### ECB Mode (no IV):
```powershell
# Encryption
cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt

# Decryption
cryptocore --algorithm aes --mode ecb --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin
```

#### CBC Mode (with IV):
```powershell
# Encryption (IV auto-generated)
cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt

# Decryption with provided IV
cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --iv aabbccddeeff00112233445566778899 --input ciphertext.bin

# Decryption (IV read from file)
cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin
```

#### CFB, OFB, CTR Modes (stream modes):
```powershell
# CFB mode
cryptocore --algorithm aes --mode cfb --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt
cryptocore --algorithm aes --mode cfb --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin

# OFB mode  
cryptocore --algorithm aes --mode ofb --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt

# CTR mode
cryptocore --algorithm aes --mode ctr --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt
```

### Advanced Options

#### Custom Output File:
```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input data.bin --output encrypted.data
```

#### Force Overwrite:
```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output encrypted.bin --force
```

### File Naming Convention

- **Encryption:** `filename.ext` → `filename.ext.enc`
- **Decryption:** `filename.ext.enc` → `filename.dec.ext`

### Supported Modes

| Mode | IV Required | Padding | Description |
|------|-------------|---------|-------------|
| **ECB** | No | PKCS#7 | Electronic Codebook - basic block mode |
| **CBC** | Yes | PKCS#7 | Cipher Block Chaining - chained blocks |
| **CFB** | Yes | No | Cipher Feedback - stream mode |
| **OFB** | Yes | No | Output Feedback - stream mode |
| **CTR** | Yes | No | Counter - stream mode |

## OpenSSL Compatibility

CryptoCore is fully compatible with OpenSSL for interoperability testing.

### Example: CBC Mode Compatibility

```powershell
# 1. Encrypt with OpenSSL, decrypt with CryptoCore
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 000102030405060708090a0b0c0d0e0f -in plain.txt -out openssl_encrypted.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --iv 000102030405060708090a0b0c0d0e0f --input openssl_encrypted.bin --output decrypted.txt

# 2. Encrypt with CryptoCore, decrypt with OpenSSL
cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input plain.txt --output cryptocore_encrypted.bin

# Extract IV from first 16 bytes (for OpenSSL decryption)
$iv = (Get-Content cryptocore_encrypted.bin -AsByteStream -TotalCount 16 | ForEach-Object {$_.ToString("X2")}) -join ""
$iv_lower = $iv.ToLower()

# Create file without IV for OpenSSL
Get-Content cryptocore_encrypted.bin -AsByteStream | Select-Object -Skip 16 | Set-Content ciphertext_only.bin -AsByteStream

# Decrypt with OpenSSL
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -iv $iv_lower -in ciphertext_only.bin -out openssl_decrypted.txt
```

### IV Handling Notes

- **Encryption:** IV is automatically generated using cryptographically secure random numbers and prepended to the output file
- **Decryption with `--iv`:** Use when the input file does NOT contain IV (e.g., OpenSSL output)
- **Decryption without `--iv`:** IV is read from the first 16 bytes of the input file (CryptoCore format)

## Testing

### Run Test Suite
```powershell
python -m unittest discover tests -v
```

### OpenSSL Compatibility Tests
To run full OpenSSL compatibility tests, ensure OpenSSL is installed and in your PATH:

```powershell
# Check OpenSSL availability
openssl version

# Run compatibility tests
python -m unittest tests.test_openssl_compatibility -v
```

### Quick Verification Example
```powershell
# Create test file
echo "Hello CryptoCore!" > test.txt

# Test all modes
$key = "00112233445566778899aabbccddeeff"

# ECB
cryptocore --algorithm aes --mode ecb --encrypt --key $key --input test.txt --force
cryptocore --algorithm aes --mode ecb --decrypt --key $key --input test.txt.enc --force

# CBC
cryptocore --algorithm aes --mode cbc --encrypt --key $key --input test.txt --force
cryptocore --algorithm aes --mode cbc --decrypt --key $key --input test.txt.enc --force

# Verify integrity
Get-FileHash test.txt
Get-FileHash test.dec.txt
```

## Project Structure

```
CryptoCore/
├── src/cryptocore/
│   ├── modes/
│   │   ├── ecb.py          # ECB mode implementation
│   │   ├── cbc.py          # CBC mode implementation
│   │   ├── cfb.py          # CFB mode implementation
│   │   ├── ofb.py          # OFB mode implementation
│   │   └── ctr.py          # CTR mode implementation
│   ├── utils/
│   │   ├── padding.py      # PKCS#7 padding
│   │   └── keys.py
│   ├── cli.py              # Command-line interface
│   └── file_io.py          # File handling with IV support
├── tests/                  # Comprehensive test suite
│   ├── test_cli.py
│   ├── test_ecb.py
│   ├── test_cbc.py
│   ├── test_cfb.py
│   ├── test_ofb.py
│   ├── test_ctr.py
│   ├── test_padding.py
│   ├── test_file_io.py
│   └── test_openssl_compatibility.py
├── setup.py               # Package configuration
└── README.md
```

## Technical Details

### Implemented Standards

- **AES-128** (using pycryptodome for core operations)
- **ECB, CBC, CFB, OFB, CTR** modes with manual implementation
- **PKCS#7 padding** with full validation
- **Binary data handling** (no encoding assumptions)

### Security Notes

- Core AES operations delegated to pycryptodome (industry standard)
- IV generation uses cryptographically secure random numbers (`secrets.token_bytes`)
- Educational focus - not for production cryptographic use
- All file operations in binary mode

## Troubleshooting

### Common Issues

**OpenSSL not found in PATH:**
```powershell
# Use full path to OpenSSL
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" version

# Or add to PATH temporarily
$env:Path += ";C:\Program Files\OpenSSL-Win64\bin"
openssl version
```

**File not found errors:**
- Ensure input file exists in current directory
- Use absolute paths if needed: `--input C:\full\path\to\file`

**IV-related errors:**
- ECB mode does not support `--iv` argument
- For decryption without `--iv`, ensure file contains IV in first 16 bytes
- IV must be 16 bytes (32 hex characters)

**Permission errors:**
- Run PowerShell as Administrator if writing to protected directories
- Use `--force` flag to overwrite existing files


