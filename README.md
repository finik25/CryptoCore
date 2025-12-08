# CryptoCore

Minimalist cryptographic provider in Python. Educational project focused on understanding cryptographic algorithms and protocols.

## Features

- **AES-128 encryption/decryption** in multiple modes
- **SHA-256 and SHA3-256 hashing** with optional file output
- **HMAC-SHA256 authentication** for data integrity and authenticity
- **Five supported AES modes**: ECB, CBC, CFB, OFB, CTR
- **Automatic key generation** for encryption operations
- **Weak key detection** with warnings for insecure keys
- **HMAC verification** with tamper detection
- **NIST STS test file generator** for CSPRNG verification
- **PKCS#7 padding** for modes that require it
- **IV (Initialization Vector) handling** with secure generation and storage
- **Binary file handling** - works with any file type
- **OpenSSL compatibility** - verified against industry standard
- **Command-line interface** with comprehensive validation
- **Comprehensive test suite** - 161+ tests covering edge cases and interoperability

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

CryptoCore supports two command modes: subcommands (recommended) and legacy mode.

### Subcommands Mode (Recommended)

#### Encryption and Decryption:
```powershell
# Encryption with auto-generated key
cryptocore crypto --algorithm aes --mode ecb --encrypt --input plaintext.txt

# Decryption with provided key
cryptocore crypto --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin
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

#### Output File Support:
- **Without `--output`**: Hash/HMAC is printed to stdout
- **With `--output`**: Hash/HMAC is written to specified file
- Format: `{hash/hmac}  {filename}` (or `{hash/hmac} -` for stdin)

### Legacy Mode

For backward compatibility, you can still use the old syntax:

```powershell
# Encryption (legacy mode)
cryptocore --algorithm aes --mode ecb --encrypt --input plaintext.txt

# Note: Legacy mode doesn't support hash or HMAC operations
```

## Examples

### Basic Operations

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

#### Encryption with Explicit IV:
```powershell
# Encryption with specified IV (CBC, CFB, OFB, CTR modes)
cryptocore crypto --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --iv 000102030405060708090a0b0c0d0e0f --input data.txt

# Note: If --iv is omitted, a random IV will be generated and included in the output file
# For decryption, if IV is stored in the file (CryptoCore default), don't use --iv flag
# If decrypting OpenSSL-encrypted files (IV not in file), provide --iv explicitly
```

#### Hash Operations:
```powershell
# SHA-256 of a file (stdout)
cryptocore dgst --algorithm sha256 --input data.txt
d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592  data.txt

# SHA3-256 of a file (stdout)
cryptocore dgst --algorithm sha3-256 --input data.txt
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a  data.txt

# SHA-256 to file
cryptocore dgst --algorithm sha256 --input data.txt --output hash.txt
Hash written to: hash.txt

# Verify file content
cat hash.txt
d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592  data.txt

# Hash from stdin
echo -n "Hello World" | cryptocore dgst --algorithm sha256 --input -
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e  -
```

#### HMAC Operations:
```powershell
# Generate HMAC for a file
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf
b1a2c3d4e5f6012345678901234567890123456789012345678901234567890123  document.pdf

# Save HMAC to file
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf --output document.hmac
HMAC written to: document.hmac

# Verify HMAC (successful)
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf --verify document.hmac
[OK] HMAC verification successful for document.pdf

# Verify HMAC with tampered file (fails)
echo "tampered" >> document.pdf
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf --verify document.hmac
[ERROR] HMAC verification failed for document.pdf

# HMAC with wrong key (fails)
cryptocore dgst --algorithm sha256 --hmac --key ffeeffeeddccddaabbcc112233445566 --input document.pdf --verify document.hmac
[ERROR] HMAC verification failed for document.pdf
```

## HMAC Features (Milestone 5)

CryptoCore now supports HMAC (Hash-based Message Authentication Code) for verifying data authenticity and integrity.

### Key Features:
- **HMAC-SHA256** implementation following RFC 2104 specification
- **Variable-length keys** - any key length supported (automatically processed per RFC)
- **Tamper detection** - changing one bit in file or key causes verification failure
- **Streaming support** - handles large files efficiently with chunked processing
- **Cross-platform** - works on Windows, Linux, macOS
- **OpenSSL compatible** - produces identical HMAC values as OpenSSL
- **RFC 4231 compliance** - passes all standard test vectors

### Security Implementation:
- **Key processing**: Keys longer than 64 bytes are hashed, shorter keys are padded
- **Constant-time comparison** for verification (resistant to timing attacks)
- **Uses secure SHA-256** implementation from Milestone 4
- **Educational focus** - demonstrates HMAC construction and security principles

## Testing

### Run Test Suite
```powershell
python -m unittest discover tests -v
```

### Specific Test Categories
```powershell
# Run hash tests
python -m unittest tests.test_dgst -v

# Run HMAC tests
python -m unittest tests.test_hmac -v
python -m unittest tests.test_hmac_cli -v

# Run SHA-256 implementation tests
python -m unittest tests.test_hash_sha256 -v

# Test OpenSSL compatibility (requires OpenSSL installed)
python -m unittest tests.test_openssl_compatibility -v

# Run integration tests
python -m unittest tests.test_hmac_integration -v
python -m unittest tests.test_integration -v
```

### OpenSSL Compatibility Testing
CryptoCore has been verified for interoperability with OpenSSL 3.x:
- **CBC mode**: Full bidirectional compatibility (CryptoCore ↔ OpenSSL)
- **ECB mode**: Direct file compatibility
- **Hash algorithms**: SHA-256 and SHA3-256 produce identical results
- **HMAC-SHA256**: Produces identical HMAC values as OpenSSL
- **IV handling**: CryptoCore stores IV in file, OpenSSL requires separate -iv parameter

## Project Structure

```
CryptoCore/
├── src/cryptocore/
│   ├── modes/
│   │   ├── __init__.py
│   │   ├── ecb.py           # ECB mode implementation
│   │   ├── cbc.py           # CBC mode implementation
│   │   ├── cfb.py           # CFB mode implementation
│   │   ├── ofb.py           # OFB mode implementation
│   │   └── ctr.py           # CTR mode implementation
│   ├── hash/
│   │   ├── __init__.py
│   │   ├── sha256.py        # SHA-256 implementation
│   │   └── sha3_256.py      # SHA3-256 implementation
│   ├── mac/                 # Message Authentication Codes (M5)
│   │   ├── __init__.py
│   │   └── hmac.py          # HMAC-SHA256 implementation (RFC 2104)
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── padding.py       # PKCS#7 padding
│   │   ├── csprng.py        # Cryptographically secure pseudorandom number generator
│   │   └── nist_tool.py     # NIST test file generator
│   ├── __init__.py
│   ├── cli.py               # Command-line interface
│   └── file_io.py           # File handling with IV support
├── tests/                   # Comprehensive test suite (161+ tests)
│   ├── test_cli.py
│   ├── test_csprng.py       # CSPRNG tests
│   ├── test_dgst.py         # Hash command tests
│   ├── test_hash_sha256.py  # SHA-256 implementation tests
│   ├── test_hmac.py         # HMAC implementation tests
│   ├── test_hmac_cli.py     # HMAC CLI tests
│   ├── test_hmac_integration.py # HMAC integration tests
│   ├── test_ecb.py
│   ├── test_cbc.py
│   ├── test_cfb.py
│   ├── test_ofb.py
│   ├── test_ctr.py
│   ├── test_padding.py
│   ├── test_file_io.py
│   ├── test_dgst_edge_cases.py
│   ├── test_integration.py  # End-to-end integration tests
│   └── test_openssl_compatibility.py
├── setup.py                 # Package configuration
└── README.md
```

## Technical Details

### Implemented Standards

- **AES-128** (using pycryptodome for core operations)
- **SHA-256** (custom implementation following NIST FIPS 180-4)
- **SHA3-256** (using Python's hashlib)
- **HMAC-SHA256** (RFC 2104 implementation)
- **ECB, CBC, CFB, OFB, CTR** modes with manual implementation
- **PKCS#7 padding** with full validation
- **CSPRNG** using `os.urandom()` for cryptographic security
- **Binary data handling** (no encoding assumptions)

### Security Notes

- Core AES operations delegated to pycryptodome (industry standard)
- SHA-256 implementation follows NIST FIPS 180-4 specification
- SHA3-256 uses Python's built-in hashlib
- HMAC implementation follows RFC 2104 with proper key processing
- IV generation uses cryptographically secure random numbers
- Automatic key generation uses CSPRNG (`os.urandom()`)
- Weak key detection warns about obviously insecure keys
- HMAC verification uses constant-time comparison
- **Educational focus** - not for production cryptographic use
- All file operations in binary mode

### HMAC Implementation Details

The HMAC-SHA256 implementation follows RFC 2104 precisely:
```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
```
Where:
- `H` is SHA-256 hash function
- `K` is the secret key (any length, processed per RFC)
- `opad` = 0x5c repeated 64 times
- `ipad` = 0x36 repeated 64 times
- Keys longer than 64 bytes are hashed first
- Keys shorter than 64 bytes are padded with zeros

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

**File not found errors:**
- Ensure input file exists in current directory
- Use absolute paths if needed: `--input C:\full\path\to\file`

**IV-related errors:**
- ECB mode does not support `--iv` argument
- For decryption without `--iv`, ensure file contains IV in first 16 bytes
- IV must be 16 bytes (32 hex characters)
- CryptoCore stores IV at beginning of encrypted file; OpenSSL requires separate -iv parameter
- When decrypting OpenSSL-encrypted files, you must prepend IV to ciphertext or use `--iv` flag

**HMAC-related errors:**
- `--hmac` requires `--key` argument
- HMAC currently only supports SHA-256 algorithm
- Verification files must contain HMAC in format: `HMAC_VALUE  FILENAME`
- Ensure verification file exists and is readable

**Permission errors:**
- Run PowerShell as Administrator if writing to protected directories
- Use `--force` flag to overwrite existing files

**Auto-generated key not displayed:**
- Ensure you're not providing `--key` argument for encryption
- Check console output for `[INFO] Generated random key:` message

**Unicode filename limitations:**
- Some systems may have limitations with Unicode characters in filenames
- Tests automatically skip when system doesn't support specific Unicode characters

**Test failures on protected directories:**
- Writing to system-protected directories (e.g., /root, C:\Windows) requires administrator privileges
- Related tests are skipped in normal execution
