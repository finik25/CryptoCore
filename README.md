
# CryptoCore

Minimalist cryptographic provider in Python. Educational project focused on understanding cryptographic algorithms and protocols.

## Features

- **AES-128 encryption/decryption** in multiple modes (ECB, CBC, CFB, OFB, CTR, GCM)
- **Authenticated Encryption** with GCM mode (NIST SP 800-38D)
- **Associated Authenticated Data (AAD)** support for GCM
- **Catastrophic failure handling** - no plaintext output on authentication failure
- **SHA-256 and SHA3-256 hashing** with optional file output
- **HMAC-SHA256 authentication** for data integrity and authenticity
- **PBKDF2-HMAC-SHA256 key derivation** from passwords (RFC 2898)
- **Key hierarchy functions** for deterministic key derivation
- **Automatic key generation** for encryption operations
- **Weak key detection** with warnings for insecure keys
- **HMAC verification** with tamper detection
- **NIST STS test file generator** for CSPRNG verification
- **PKCS#7 padding** for modes that require it
- **IV/Nonce handling** with secure generation and storage
- **Binary file handling** - works with any file type
- **OpenSSL compatibility** - verified against industry standard
- **Command-line interface** with comprehensive validation
- **Comprehensive test suite** - 220+ tests covering edge cases and interoperability

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
cryptocore-nist --help

# Verify package installation
pip list | Select-String cryptocore
```

## Usage

CryptoCore supports three command modes: subcommands (recommended) and legacy mode.

### Subcommands Mode (Recommended)

#### Encryption and Decryption:
```powershell
# ECB mode encryption with auto-generated key
cryptocore crypto --algorithm aes --mode ecb --encrypt --input plaintext.txt

# CBC mode decryption with provided key
cryptocore crypto --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin

# GCM mode encryption with AAD
cryptocore crypto --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input sensitive.txt

# GCM mode decryption with AAD verification
cryptocore crypto --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input sensitive.txt.gcm
```

#### Hash Computation:
```powershell
# SHA-256 hash to stdout
cryptocore dgst --algorithm sha256 --input document.pdf

# SHA3-256 hash to stdout
cryptocore dgst --algorithm sha3-256 --input document.pdf

# SHA-256 hash to file
cryptocore dgst --algorithm sha256 --input document.pdf --output hash.txt

# Hash from stdin
echo -n "Hello World" | cryptocore dgst --algorithm sha256 --input -
```

#### HMAC Authentication:
```powershell
# Generate HMAC-SHA256 for a file
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf

# Generate HMAC and save to file
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf --output document.hmac

# Verify HMAC against stored value
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf --verify document.hmac

# HMAC from stdin
echo -n "Authenticate this" | cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input -
```

#### Key Derivation
```powershell
# Basic key derivation with specified salt
cryptocore derive --password "MySecurePassword123!" --salt a1b2c3d4e5f601234567890123456789

# Key derivation with auto-generated salt
cryptocore derive --password "AnotherPassword" --iterations 50000 --length 16

# Read password from file
cryptocore derive --password-file password.txt --salt fixedappsalt --iterations 10000

# Derive key and save to file
cryptocore derive --password "app_key" --output derived_key.bin

# Use environment variable
$env:MY_PASSWORD = "Secret123"
cryptocore derive --env-var MY_PASSWORD --iterations 10000
```

#### Output File Support:
- **Without `--output`**: Hash/HMAC/Key is printed to stdout
- **With `--output`**: Result is written to specified file
- **Key Derivation Format**: `{KEY_HEX} {SALT_HEX}` (both as hexadecimal strings)

### Legacy Mode

For backward compatibility, you can still use the old syntax:

```powershell
# Encryption (legacy mode)
cryptocore --algorithm aes --mode ecb --encrypt --input plaintext.txt

# Note: Legacy mode doesn't support hash, HMAC, GCM, or derive operations
```

## Key Derivation

### PBKDF2-HMAC-SHA256
CryptoCore implements PBKDF2-HMAC-SHA256 for deriving cryptographic keys from passwords, following RFC 2898 specification.

### Security Considerations:
- **Minimum iterations**: 100,000 recommended for production use
- **Salt size**: 16 bytes (128 bits) minimum, automatically generated if not provided
- **Password handling**: Use `--password-file` or `--env-var` for sensitive passwords
- **Memory security**: Password cleared from memory after use
- **Deterministic**: Same password+salt+iterations always produces same key

### Key Hierarchy
The library also provides deterministic key derivation from master keys:
```python
from cryptocore.kdf import derive_key

master_key = os.urandom(32)
encryption_key = derive_key(master_key, "encryption", 32)
auth_key = derive_key(master_key, "authentication", 32)
# Different contexts produce completely different keys
```

## Authenticated Encryption (GCM Mode)

CryptoCore supports **Galois/Counter Mode (GCM)** for authenticated encryption with associated data (AEAD).

### GCM Features:
- **Authenticated encryption** with AES-128 in GCM mode
- **Associated Authenticated Data (AAD)** - arbitrary length metadata
- **12-byte nonce** (recommended size, randomly generated)
- **16-byte authentication tag** (128-bit)
- **Catastrophic failure** - no plaintext output if authentication fails
- **NIST SP 800-38D compliance** - follows standard specification

### GCM File Format:
Encrypted files follow format: `nonce(12 bytes) | ciphertext | tag(16 bytes)`

### Security Warning:
- **Nonce reuse is catastrophic** - must be unique for each encryption with same key
- **Authentication failure** causes immediate abort without plaintext output
- **AAD mismatch** or **ciphertext tampering** is detected and prevented
- **Large AAD supported** - handles AAD up to gigabytes in size

### GCM Usage Examples:
```powershell
# GCM Encryption with auto-generated key and random nonce
cryptocore crypto --algorithm aes --mode gcm --encrypt --input secret.txt

# GCM Encryption with AAD (metadata authentication)
cryptocore crypto --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input data.txt

# GCM Decryption with correct AAD
cryptocore crypto --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input data.txt.gcm

# GCM Decryption failure example (wrong AAD)
cryptocore crypto --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --aad wrongaad123 --input data.txt.gcm
> [ERROR] Authentication failed: AAD mismatch or ciphertext tampered
> Exit code: 1
```

## Examples

### Basic Operations

#### Key Derivation Examples:
```powershell
# Basic derivation with specified salt
cryptocore derive --password "MySecurePassword123!" --salt a1b2c3d4e5f601234567890123456789
> 10ce3b9b49f63847bf57b4edf9a176b1f5ebfc0ab51832f814749e6ff2ed6ed6 a1b2c3d4e5f601234567890123456789

# Derivation with auto-generated salt
cryptocore derive --password "AnotherPassword" --iterations 500000 --length 16
[INFO] Generated random salt: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
> 8d969eef6ecad3c29a3a629280e686cf e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# Save derived key to file
cryptocore derive --password "app_key" --output derived_key.bin
[INFO] Generated random salt: 8f1b8e7d6c5b4a392817263544332211
Success: Key derivation completed
  Output file: derived_key.bin
  Derived key (hex): 7d4e3b2a1f0e9d8c7b6a594837261504f3e2d1c0bfae9d8c7b6a594837261504
  Salt (hex): 8f1b8e7d6c5b4a392817263544332211
  Iterations: 100000
  Key length: 32 bytes
```

#### Encryption with Auto-generated Key:
```powershell
# Encryption without --key (key will be generated automatically)
cryptocore crypto --algorithm aes --mode ecb --encrypt --input plaintext.txt
[INFO] Generated random key: 7d0776fd22695814da56760ed31aa7e2
Success: encrypt completed
  Output file: plaintext.txt.enc
  Key (hex): 7d0776fd22695814da56760ed31aa7e2 (auto-generated)

# Decryption (key is always required)
cryptocore crypto --algorithm aes --mode ecb --decrypt --key 7d0776fd22695814da56760ed31aa7e2 --input plaintext.txt.enc
```

#### GCM Encryption with AAD:
```powershell
# GCM encryption with Associated Authenticated Data
cryptocore crypto --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --aad "metadata123" --input secret.txt
Success: GCM encryption completed
  Output file: secret.txt.gcm
  Nonce (hex): 56f3f747d5cf8778954b5177
  AAD (hex): 6d65746164617461313233

# GCM decryption (verifies AAD)
cryptocore crypto --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --aad "metadata123" --input secret.txt.gcm
Success: GCM decryption completed
  Output file: secret.dec.txt

# GCM decryption with wrong AAD (catastrophic failure)
cryptocore crypto --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --aad "wrongmetadata" --input secret.txt.gcm
[ERROR] Authentication failed: AAD mismatch or ciphertext tampered
> Exit code: 1
```

## Testing

### Run Test Suite
```powershell
python -m unittest discover tests -v
```

### Specific Test Categories
```powershell
# Run KDF tests (M7)
python -m unittest tests.test_pbkdf2_vectors -v
python -m unittest tests.test_hkdf -v
python -m unittest tests.test_derive_cli -v

# Run GCM tests
python -m unittest tests.test_gcm -v
python -m unittest tests.test_gcm_cli -v
python -m unittest tests.test_gcm_catastrophic_failure -v

# Run hash tests
python -m unittest tests.test_dgst -v

# Run HMAC tests
python -m unittest tests.test_hmac -v
python -m unittest tests.test_hmac_cli -v

# Test OpenSSL compatibility (requires OpenSSL installed)
python -m unittest tests.test_openssl_compatibility -v

# Run integration tests
python -m unittest tests.test_integration -v
```

### Performance Testing (Separate Run)
```powershell
# Run performance tests (takes time)
$env:RUN_PERFORMANCE_TESTS=1
python -m unittest tests.test_pbkdf2_performance -v
```

## Project Structure

```
CryptoCore/
├── src/cryptocore/
│   ├── aead/
│   │   ├── __init__.py
│   │   ├── encrypt_then_mac.py
│   ├── kdf/                  
│   │   ├── __init__.py
│   │   ├── pbkdf2.py          
│   │   └── hkdf.py            
│   ├── modes/
│   │   ├── __init__.py
│   │   ├── ecb.py
│   │   ├── cbc.py
│   │   ├── cfb.py
│   │   ├── ofb.py
│   │   ├── ctr.py
│   │   └── gcm.py         
│   ├── hash/
│   │   ├── __init__.py
│   │   ├── sha256.py
│   │   └── sha3_256.py
│   ├── mac/
│   │   ├── __init__.py
│   │   └── hmac.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── padding.py
│   │   ├── csprng.py
│   │   ├── nist_tool.py
│   │   └── galois_field.py
│   ├── __init__.py
│   ├── cli.py                  
│   ├── file_io.py
│   └── hash_utils.py
├── tests/                    
│   ├── test_cli.py
│   ├── test_csprng.py
│   ├── test_dgst.py
│   ├── test_hash_sha256.py
│   ├── test_hmac.py
│   ├── test_hmac_cli.py
│   ├── test_hmac_integration.py
│   ├── test_gcm.py
│   ├── test_gcm_cli.py
│   ├── test_gcm_catastrophic_failure.py
│   ├── test_gcm_aad_comprehensive.py
│   ├── test_galois_field.py
│   ├── test_ecb.py
│   ├── test_cbc.py
│   ├── test_cfb.py
│   ├── test_ofb.py
│   ├── test_ctr.py
│   ├── test_padding.py
│   ├── test_file_io.py
│   ├── test_encrypt_then_mac.py
│   ├── test_dgst_edge_cases.py
│   ├── test_pbkdf2_vectors.py  
│   ├── test_hkdf.py           
│   ├── test_derive_cli.py      
│   ├── test_pbkdf2_performance.py  
│   ├── test_integration.py
│   └── test_openssl_compatibility.py
├── setup.py
├── requirements.txt
└── README.md
```

## Technical Details

### Implemented Standards

- **AES-128** (using pycryptodome for core operations)
- **SHA-256** (custom implementation following NIST FIPS 180-4)
- **SHA3-256** (using Python's hashlib)
- **HMAC-SHA256** (RFC 2104 implementation)
- **GCM mode** (NIST SP 800-38D with Galois Field multiplication)
- **PBKDF2-HMAC-SHA256** (RFC 2898 implementation)
- **ECB, CBC, CFB, OFB, CTR** modes with manual implementation
- **PKCS#7 padding** with full validation
- **CSPRNG** using `os.urandom()` for cryptographic security
- **Binary data handling** (no encoding assumptions)

### GCM Implementation Details

The GCM implementation follows NIST SP 800-38D specification:
- **Nonce**: 12-byte recommended size (96 bits)
- **Tag**: 16-byte authentication tag (128 bits)
- **AAD**: Arbitrary length Associated Authenticated Data
- **Galois Field**: GF(2^128) with irreducible polynomial `x^128 + x^7 + x^2 + x + 1`
- **GHASH**: Custom implementation using optimized Galois Field multiplication
- **Security**: Catastrophic failure on authentication error

### PBKDF2 Implementation Details

The PBKDF2 implementation follows RFC 2898:
- **Password handling**: Any length, converted to bytes with UTF-8 encoding
- **Salt handling**: 16-byte minimum, hex input or auto-generation
- **Iterations**: Configurable, default 100,000 for security
- **Key length**: Arbitrary bytes output, truncated to exact requested length
- **Algorithm**: HMAC-SHA256 as the pseudorandom function

### Security Notes

- Core AES operations delegated to pycryptodome (industry standard)
- SHA-256 implementation follows NIST FIPS 180-4 specification
- SHA3-256 uses Python's built-in hashlib
- HMAC implementation follows RFC 2104 with proper key processing
- GCM implementation follows NIST SP 800-38D with custom Galois Field arithmetic
- PBKDF2 implementation follows RFC 2898 specification
- IV/Nonce generation uses cryptographically secure random numbers
- Automatic key generation uses CSPRNG (`os.urandom()`)
- Weak key detection warns about obviously insecure keys
- HMAC verification uses constant-time comparison
- GCM provides catastrophic failure - no plaintext output on auth error
- PBKDF2 clears password from memory after use
- Educational focus - not for production cryptographic use
- All file operations in binary mode

## Troubleshooting

### Common Issues

**OpenSSL compatibility test skips:**
```powershell
# Ensure OpenSSL is installed and in PATH
# Windows: Install from https://slproweb.com/products/Win32OpenSSL.html
# Add OpenSSL to PATH or specify full path in test configuration

# Use full path to OpenSSL
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" version

# Or add to PATH temporarily
$env:Path += ";C:\Program Files\OpenSSL-Win64\bin"
openssl version
```

**PBKDF2 performance:**
- 100,000 iterations take ~60 seconds on modern hardware (by design)
- For testing, use lower iteration counts (1,000-10,000)
- Performance test can be skipped: `$env:RUN_PERFORMANCE_TESTS=0`

**File not found errors:**
- Ensure input file exists in current directory
- Use absolute paths if needed: `--input C:\full\path\to\file`

**IV-related errors:**
- ECB mode does not support `--iv` argument
- For decryption without `--iv`, ensure file contains IV in first 16 bytes
- IV must be 16 bytes (32 hex characters)
- CryptoCore stores IV at beginning of encrypted file; OpenSSL requires separate -iv parameter
- When decrypting OpenSSL-encrypted files, you must prepend IV to ciphertext or use `--iv` flag

**GCM-specific errors:**
- GCM uses 12-byte nonce (24 hex characters), not 16-byte IV
- Authentication failure is catastrophic - no output file created
- AAD mismatch causes immediate abort
- Large AAD (>100KB) should be provided via file, not command line

**HMAC-related errors:**
- `--hmac` requires `--key` argument
- HMAC currently only supports SHA-256 algorithm
- Verification files must contain HMAC in format: `HMAC_VALUE  FILENAME`
- Ensure verification file exists and is readable

**Key derivation errors:**
- `--password`, `--password-file`, or `--env-var` required (exactly one)
- Invalid salt format (must be hex string)
- Iterations must be ≥ 1
- Key length must be ≥ 1 byte
- Output file exists (use `--force` to overwrite)

**Permission errors:**
- Run PowerShell as Administrator if writing to protected directories
- Use `--force` flag to overwrite existing files

**Unicode filename limitations:**
- Some systems may have limitations with Unicode characters in filenames
- Tests automatically skip when system doesn't support specific Unicode characters

**Test failures on protected directories:**
- Writing to system-protected directories (e.g., /root, C:\Windows) requires administrator privileges
- Related tests are skipped in normal execution
