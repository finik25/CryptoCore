
# CryptoCore API Documentation
*Version 1.0.0 | Last updated: December 2025*

## Table of Contents

1. [Overview](#overview)
2. [Installation and Setup](#installation-and-setup)
3. [Module Reference](#module-reference)
   - [3.1. Modes of Operation](#31-modes-of-operation)
   - [3.2. Hash Functions](#32-hash-functions)
   - [3.3. Message Authentication Codes](#33-message-authentication-codes)
   - [3.4. Key Derivation Functions](#34-key-derivation-functions)
   - [3.5. Utility Modules](#35-utility-modules)
4. [Command Line Interface](#command-line-interface)
5. [Error Handling and Exceptions](#error-handling-and-exceptions)
6. [Security Considerations](#security-considerations)
7. [Testing and Validation](#testing-and-validation)
8. [Examples and Use Cases](#examples-and-use-cases)
9. [Compatibility Notes](#compatibility-notes)

---

## Overview

CryptoCore is a comprehensive cryptographic library implemented in Python, designed with both educational clarity and practical utility in mind. The library provides implementations of essential cryptographic algorithms while maintaining strict compatibility with industry standards like NIST specifications and OpenSSL.

### Design Principles
- **Educational Transparency**: Clean, readable code suitable for studying cryptographic implementations
- **Standards Compliance**: Adherence to NIST, RFC, and FIPS specifications
- **Security First**: Follows cryptographic best practices and secure coding patterns
- **Interoperability**: Compatible with OpenSSL CLI for cross-validation
- **Modular Architecture**: Independent, reusable components with clear interfaces

### Supported Algorithms
| Category | Algorithms | Standards |
|----------|------------|-----------|
| Block Cipher | AES-128 | FIPS 197 |
| Encryption Modes | ECB, CBC, CFB, OFB, CTR, GCM | NIST SP 800-38A, 800-38D |
| Hash Functions | SHA-256, SHA3-256 | FIPS 180-4, FIPS 202 |
| MAC Algorithms | HMAC-SHA256 | RFC 2104, RFC 4231 |
| Key Derivation | PBKDF2-HMAC-SHA256, HKDF | RFC 2898, RFC 5869 |
| Random Generation | CSPRNG (via OS) | NIST SP 800-90A |

## Installation and Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation Methods

#### From Source Code
```bash
# Clone repository
git clone https://github.com/yourusername/CryptoCore.git
cd CryptoCore

# Install in development mode
pip install -e .

# Verify installation
cryptocore --version
```

#### Direct Package Installation
```bash
# Install from local source
pip install path/to/CryptoCore

# Or when published to PyPI
pip install cryptocore
```

### Dependencies
- **Required**: `pycryptodome>=3.20.0` (for AES core operations)
- **Optional**: `pytest` (for running test suite)

### Verification
```python
import cryptocore
print(f"CryptoCore version: {cryptocore.__version__}")

# Test basic functionality
from cryptocore.utils.csprng import generate_random_key
key = generate_random_key()
print(f"Generated random key: {key.hex()}")
```

---

## Module Reference

### 3.1. Modes of Operation
*Location: `cryptocore.modes`*

This module implements various modes of operation for AES-128 encryption. Each mode provides different security properties and performance characteristics.

#### ECB Mode (Electronic Codebook)
```python
from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
```

**`encrypt_ecb(plaintext: bytes, key: bytes) -> bytes`**
Encrypts plaintext using AES-128 in ECB mode with PKCS#7 padding.

| Parameter | Type | Description | Constraints |
|-----------|------|-------------|-------------|
| `plaintext` | `bytes` | Data to encrypt | Any length |
| `key` | `bytes` | AES-128 encryption key | Exactly 16 bytes |

**Returns:** `bytes` - Encrypted ciphertext (padded to 16-byte boundary)

**Raises:**
- `ValueError`: If key length is not 16 bytes

**Example:**
```python
key = bytes.fromhex("00112233445566778899aabbccddeeff")
plaintext = b"Hello, CryptoCore!"
ciphertext = encrypt_ecb(plaintext, key)
# ciphertext is 32 bytes (padded to nearest 16-byte boundary)
```

**`decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes`**
Decrypts ciphertext using AES-128 in ECB mode and removes PKCS#7 padding.

| Parameter | Type | Description | Constraints |
|-----------|------|-------------|-------------|
| `ciphertext` | `bytes` | Encrypted data | Multiple of 16 bytes |
| `key` | `bytes` | AES-128 encryption key | Exactly 16 bytes |

**Returns:** `bytes` - Decrypted plaintext (padding removed)

**Raises:**
- `ValueError`: If key length ≠ 16 bytes or ciphertext length invalid
- `ValueError`: If PKCS#7 padding is invalid

**Security Note:** ECB mode is not recommended for encrypting multiple blocks of similar data, as identical plaintext blocks produce identical ciphertext blocks. Use only for single-block encryption or educational purposes.

#### CBC Mode (Cipher Block Chaining)
```python
from cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
```

**`encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes`**
Encrypts plaintext using AES-128 in CBC mode.

| Parameter | Type | Description | Constraints |
|-----------|------|-------------|-------------|
| `plaintext` | `bytes` | Data to encrypt | Any length |
| `key` | `bytes` | AES-128 encryption key | Exactly 16 bytes |
| `iv` | `bytes` | Initialization Vector | Exactly 16 bytes |

**Returns:** `bytes` - Encrypted ciphertext

**Raises:**
- `ValueError`: If key or IV length is incorrect

**Properties:**
- Uses PKCS#7 padding
- IV should be cryptographically random
- Chaining prevents identical plaintext blocks from producing identical ciphertext

**`decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes`**
Decrypts ciphertext using AES-128 in CBC mode.

| Parameter | Type | Description | Constraints |
|-----------|------|-------------|-------------|
| `ciphertext` | `bytes` | Encrypted data | Multiple of 16 bytes |
| `key` | `bytes` | AES-128 encryption key | Exactly 16 bytes |
| `iv` | `bytes` | Initialization Vector | Exactly 16 bytes |

**Returns:** `bytes` - Decrypted plaintext (padding automatically removed)

**Important:** The same IV used for encryption must be used for decryption.

#### CFB Mode (Cipher Feedback)
```python
from cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
```

**`encrypt_cfb(plaintext: bytes, key: bytes, iv: bytes) -> bytes`**
Encrypts plaintext using AES-128 in CFB mode.

**`decrypt_cfb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes`**
Decrypts ciphertext using AES-128 in CFB mode.

| Parameter | Constraints |
|-----------|-------------|
| `key`, `iv` | Exactly 16 bytes each |

**Features:**
- Self-synchronizing stream cipher
- No padding required
- Can process data smaller than block size

**Security Note:** Never reuse IV with the same key.

#### OFB Mode (Output Feedback)
```python
from cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
```

**`encrypt_ofb(plaintext: bytes, key: bytes, iv: bytes) -> bytes`**
Encrypts plaintext using AES-128 in OFB mode.

**`decrypt_ofb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes`**
Decrypts ciphertext using AES-128 in OFB mode (identical to encryption).

**Properties:**
- Synchronous stream cipher
- Keystream generation independent of plaintext/ciphertext
- No error propagation

#### CTR Mode (Counter)
```python
from cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr
```

**`encrypt_ctr(plaintext: bytes, key: bytes, iv: bytes) -> bytes`**
Encrypts plaintext using AES-128 in CTR mode.

**`decrypt_ctr(ciphertext: bytes, key: bytes, iv: bytes) -> bytes`**
Decrypts ciphertext using AES-128 in CTR mode (identical to encryption).

| Parameter | Description |
|-----------|-------------|
| `iv` | 16 bytes (8-byte nonce + 8-byte counter starting at 0) |

**Advantages:**
- Parallelizable encryption/decryption
- No padding required
- Random access to ciphertext

#### GCM Mode (Galois/Counter Mode)
```python
from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm, GCM, AuthenticationError
```

**Class: `GCM(key: bytes, nonce: Optional[bytes] = None)`**
Creates a GCM context for authenticated encryption.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `key` | AES key (16, 24, or 32 bytes) | Required |
| `nonce` | Nonce/IV (12 bytes recommended) | Randomly generated |

**Methods:**

**`encrypt(plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]`**
Encrypts plaintext with authentication.

| Parameter | Description |
|-----------|-------------|
| `plaintext` | Data to encrypt |
| `aad` | Additional Authenticated Data (not encrypted) |

**Returns:** `(nonce, ciphertext, tag)` where:
- `nonce`: The nonce used (12 bytes)
- `ciphertext`: Encrypted data
- `tag`: 16-byte authentication tag

**`decrypt(ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes`**
Decrypts ciphertext with authentication verification.

| Parameter | Description | Constraints |
|-----------|-------------|-------------|
| `ciphertext` | Encrypted data | Any length |
| `tag` | Authentication tag | Exactly 16 bytes |
| `nonce` | Nonce used during encryption | Exactly 12 bytes |
| `aad` | Additional Authenticated Data | Must match encryption |

**Returns:** `bytes` - Decrypted plaintext

**Raises:**
- `AuthenticationError`: If tag verification fails
- `ValueError`: If parameter lengths are invalid

**Convenience Functions:**

**`encrypt_gcm(plaintext: bytes, key: bytes, nonce: Optional[bytes] = None, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]`**
One-shot GCM encryption.

**`decrypt_gcm(ciphertext: bytes, tag: bytes, nonce: bytes, key: bytes, aad: bytes = b"") -> bytes`**
One-shot GCM decryption with verification.

**Security Critical:** Never reuse a nonce with the same key. Nonce reuse completely breaks GCM security.

#### Encrypt-then-MAC
```python
from cryptocore.modes.encrypt_then_mac import (
    EncryptThenMAC, 
    encrypt_etm, 
    decrypt_etm,
    new_etm,
    AuthenticationError
)
```

**Class: `EncryptThenMAC(master_key: bytes, mode: str = 'cbc')`**
Implements authenticated encryption using the Encrypt-then-MAC paradigm.

| Parameter | Description | Valid Values |
|-----------|-------------|--------------|
| `master_key` | Master key for derivation | ≥ 32 bytes recommended |
| `mode` | Underlying encryption mode | 'cbc', 'ctr', 'cfb', 'ofb', 'ecb' |

**Key Derivation:** Derives separate encryption and MAC keys from master key using HMAC-based KDF.

**Methods:**

**`encrypt(plaintext: bytes, iv: Optional[bytes] = None, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]`**
Encrypts and authenticates plaintext.

**`decrypt(ciphertext: bytes, tag: bytes, iv: bytes, aad: bytes = b"") -> bytes`**
Decrypts and verifies authentication.

**File Operations:**

**`encrypt_to_bytes(plaintext: bytes, master_key: bytes, mode: str = 'cbc', aad: bytes = b"", iv: Optional[bytes] = None) -> bytes`**
Encrypts and returns as single byte string (format: IV_LENGTH || IV || Ciphertext || Tag).

**`decrypt_from_bytes(data: bytes, master_key: bytes, mode: str = 'cbc', aad: bytes = b"") -> bytes`**
Decrypts from combined byte string.

**`encrypt_file(input_path: str, output_path: str, master_key: bytes, mode: str = 'cbc', aad: bytes = b"", iv: Optional[bytes] = None) -> bytes`**
Encrypts file with authenticated encryption.

**`decrypt_file(input_path: str, output_path: str, master_key: bytes, mode: str = 'cbc', aad: bytes = b"") -> None`**
Decrypts file with authentication verification.

### 3.2. Hash Functions
*Location: `cryptocore.hash`*

#### SHA-256 Implementation
```python
from cryptocore.hash.sha256 import SHA256
```

**Class: `SHA256()`**
Implements SHA-256 hash algorithm per FIPS 180-4.

**Methods:**

**`update(data: bytes) -> None`**
Updates the hash with additional data.

**`digest() -> bytes`**
Returns the hash digest as 32 bytes.

**`hexdigest() -> str`**
Returns the hash digest as 64-character hexadecimal string.

**`reset() -> None`**
Resets hash computation to initial state.

**Class Methods:**

**`SHA256.hash(data: bytes) -> bytes`**
Static method for one-shot hashing.

**`SHA256.hash_hex(data: bytes) -> str`**
Static method for one-shot hashing returning hex string.

**Example:**
```python
# Streaming interface
hasher = SHA256()
hasher.update(b"Hello, ")
hasher.update(b"CryptoCore!")
hash_bytes = hasher.digest()  # 32 bytes

# One-shot interface
hash_result = SHA256.hash(b"Hello, CryptoCore!")
hash_hex = SHA256.hash_hex(b"Hello, CryptoCore!")

# File hashing
hasher = SHA256()
with open("large_file.bin", "rb") as f:
    while chunk := f.read(8192):
        hasher.update(chunk)
file_hash = hasher.hexdigest()
```

#### SHA3-256 Implementation
```python
from cryptocore.hash.sha3_256 import SHA3_256
```

**Class: `SHA3_256()`**
Implements SHA3-256 hash algorithm per FIPS 202 using Python's built-in `hashlib`.

**Interface:** Identical to `SHA256` class with same methods.

**Note:** Uses Python's `hashlib.sha3_256` for production-grade implementation while maintaining consistent API.

### 3.3. Message Authentication Codes
*Location: `cryptocore.mac`*

#### HMAC-SHA256
```python
from cryptocore.mac.hmac import HMAC, compute_hmac, compute_hmac_hex, new
```

**Class: `HMAC(key: bytes)`**
Implements HMAC with SHA-256 as per RFC 2104.

| Parameter | Description | Processing |
|-----------|-------------|------------|
| `key` | HMAC key | If >64 bytes: hashed; if <64 bytes: zero-padded |

**Methods:**

**`compute(message: bytes) -> bytes`**
Computes HMAC-SHA256 for message.

**Returns:** `bytes` - 32-byte HMAC value

**`compute_hex(message: bytes) -> str`**
Computes HMAC-SHA256, returns hex string.

**Returns:** `str` - 64-character hexadecimal string

**`verify(message: bytes, hmac_to_check: Union[bytes, str]) -> bool`**
Verifies HMAC for message.

| Parameter | Description |
|-----------|-------------|
| `hmac_to_check` | Expected HMAC as bytes or hex string |

**Returns:** `bool` - True if HMAC matches

**`update_compute(message_chunks: Iterable[bytes]) -> bytes`**
Computes HMAC from sequence of chunks (for large files).

**Class Methods:**

**`HMAC.compute_hmac(key: bytes, message: bytes) -> bytes`**
Static method for one-shot HMAC computation.

**`HMAC.compute_hmac_hex(key: bytes, message: bytes) -> str`**
Static method for one-shot HMAC computation returning hex.

**Module Functions:**

**`new(key: bytes) -> HMAC`**
Factory function creating HMAC instance.

**`compute_hmac(key: bytes, message: bytes) -> bytes`**
Compute HMAC directly.

**`compute_hmac_hex(key: bytes, message: bytes) -> str`**
Compute HMAC directly returning hex.

**Example:**
```python
key = bytes.fromhex("00112233445566778899aabbccddeeff")
message = b"Important transaction data"

# Class-based
hmac = HMAC(key)
mac = hmac.compute(message)
is_valid = hmac.verify(message, mac)

# One-shot
mac = HMAC.compute_hmac(key, message)
mac_hex = HMAC.compute_hmac_hex(key, message)

# File authentication
hmac = HMAC(key)
with open("document.pdf", "rb") as f:
    chunks = []
    while chunk := f.read(8192):
        chunks.append(chunk)
file_mac = hmac.update_compute(chunks)
```

### 3.4. Key Derivation Functions
*Location: `cryptocore.kdf`*

#### PBKDF2-HMAC-SHA256
```python
from cryptocore.kdf.pbkdf2 import pbkdf2_hmac_sha256, derive_from_password
```

**`pbkdf2_hmac_sha256(password: Union[str, bytes], salt: Union[str, bytes], iterations: int, dklen: int) -> bytes`**
Derives key from password using PBKDF2 with HMAC-SHA256 per RFC 2898.

| Parameter | Type | Description | Constraints |
|-----------|------|-------------|-------------|
| `password` | `Union[str, bytes]` | Password | Non-empty |
| `salt` | `Union[str, bytes]` | Salt value | Non-empty |
| `iterations` | `int` | Iteration count | ≥ 1 |
| `dklen` | `int` | Derived key length | ≥ 1 |

**Returns:** `bytes` - Derived key of length `dklen`

**Raises:**
- `ValueError`: If parameters are invalid

**Salt Processing:**
- String input: Treated as hex if valid hex, otherwise UTF-8 encoded
- Hex strings: Can include `0x` prefix and spaces (automatically cleaned)

**`derive_from_password(password: str, salt_hex: str = None, iterations: int = 100000, keylen: int = 32) -> tuple[bytes, bytes]`**
Convenience function for password-based key derivation.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `salt_hex` | `None` | If None, generates random 16-byte salt |
| `iterations` | `100000` | Recommended: ≥ 100,000 |
| `keylen` | `32` | Derived key length in bytes |

**Returns:** `(derived_key, salt_used)`

**Example:**
```python
# With specified salt
derived_key = pbkdf2_hmac_sha256(
    password="MySecurePassword!123",
    salt="a1b2c3d4e5f601234567890123456789",
    iterations=100000,
    dklen=32
)

# With auto-generated salt
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
Derives key from master key using HMAC-based KDF.

| Parameter | Description | Constraints |
|-----------|-------------|-------------|
| `master_key` | Master key | ≥ 16 bytes recommended |
| `context` | Context for domain separation | String or bytes |
| `length` | Desired key length | ≥ 1 |

**Returns:** `bytes` - Derived key

**Algorithm:** `HMAC(master_key, context || counter)` iterated until desired length

**`derive_key_hierarchy(master_key: bytes, contexts: list[str], key_length: int = 32) -> dict[str, bytes]`**
Derives multiple keys for different contexts.

| Parameter | Description |
|-----------|-------------|
| `contexts` | List of context strings |
| `key_length` | Length for each derived key |

**Returns:** `dict[str, bytes]` - Mapping from context to derived key

**Example:**
```python
master_key = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

# Single key derivation
enc_key = derive_key(master_key, "encryption", 16)
mac_key = derive_key(master_key, "authentication", 32)

# Multiple keys
keys = derive_key_hierarchy(
    master_key=master_key,
    contexts=["encryption", "mac", "iv_generation"],
    key_length=32
)
# keys = {"encryption": ..., "mac": ..., "iv_generation": ...}
```

### 3.5. Utility Modules
*Location: `cryptocore.utils`*

#### Cryptographically Secure Random Number Generation
```python
from cryptocore.utils.csprng import (
    generate_random_bytes,
    generate_random_key,
    generate_random_iv
)
```

**`generate_random_bytes(num_bytes: int) -> bytes`**
Generates cryptographically secure random bytes using OS RNG.

| Parameter | Constraints |
|-----------|-------------|
| `num_bytes` | ≥ 1 |

**Returns:** `bytes` - Random bytes

**Implementation:** Uses `os.urandom()` (or equivalent on Windows)

**Raises:**
- `ValueError`: If `num_bytes ≤ 0`
- `OSError`: If system RNG fails

**`generate_random_key() -> bytes`**
Generates random 16-byte AES-128 key.

**Returns:** `bytes` - 16 random bytes

**`generate_random_iv() -> bytes`**
Generates random 16-byte initialization vector.

**Returns:** `bytes` - 16 random bytes

**Example:**
```python
# Generate cryptographic materials
key = generate_random_key()        # 16 bytes for AES-128
iv = generate_random_iv()          # 16 bytes for IV
nonce = generate_random_bytes(12)  # 12 bytes for GCM
salt = generate_random_bytes(16)   # 16 bytes for PBKDF2
```

#### Padding Utilities
```python
from cryptocore.utils.padding import apply_padding, remove_padding
```

**`apply_padding(data: bytes, block_size: int = 16) -> bytes`**
Applies PKCS#7 padding to data.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `block_size` | `16` | Block size for padding |

**Returns:** `bytes` - Padded data (length = multiple of `block_size`)

**`remove_padding(padded_data: bytes, block_size: int = 16) -> bytes`**
Removes PKCS#7 padding from data.

**Returns:** `bytes` - Original data without padding

**Raises:**
- `ValueError`: If padding is invalid (wrong length or bytes)

**Example:**
```python
data = b"Hello"
padded = apply_padding(data, 16)  # b'Hello\x0b\x0b...' (11 bytes padding)
original = remove_padding(padded, 16)  # b'Hello'
```

#### File I/O Utilities
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
Reads file as binary data.

**`write_file(file_path: str, data: bytes, overwrite: bool = False) -> None`**
Writes binary data to file.

**`read_file_with_iv(file_path: str) -> Tuple[bytes, bytes]`**
Reads file with IV prepended (first 16 bytes).

**`write_file_with_iv(file_path: str, iv: bytes, data: bytes, overwrite: bool = False) -> None`**
Writes IV and data to file (IV prepended).

**`read_gcm_file(file_path: str) -> Tuple[bytes, bytes, bytes]`**
Reads GCM-formatted file (nonce + ciphertext + tag).

**Format:** 12-byte nonce | ciphertext | 16-byte tag

**`write_gcm_file(file_path: str, nonce: bytes, ciphertext: bytes, tag: bytes, overwrite: bool = False) -> None`**
Writes GCM-formatted file.

**`derive_output_filename(input_path: str, operation: str, algorithm: str, mode: str) -> str`**
Derives output filename based on operation and mode.

| Operation | Input | Output | Example |
|-----------|-------|--------|---------|
| encrypt | file.txt | file.txt.enc | (GCM: file.txt.gcm) |
| decrypt | file.txt.enc | file.dec.txt | |
| hash | file.txt | (stdout) | |

#### Hash Utilities
```python
from cryptocore.utils.hash_utils import HashCalculator
```

**Class: `HashCalculator`**
Utility class for calculating hashes of files and data.

**Class Methods:**

**`hash_data(data: bytes, algorithm: str = 'sha256') -> bytes`**
Hash data in memory.

**`hash_data_hex(data: bytes, algorithm: str = 'sha256') -> str`**
Hash data, return hex string.

**`hash_file(file_path: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> bytes`**
Hash file using streaming.

**`hash_file_hex(file_path: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> str`**
Hash file, return hex string.

**`verify_file_hash(file_path: str, expected_hash: Union[str, bytes], algorithm: str = 'sha256') -> bool`**
Verify file hash against expected value.

**Supported Algorithms:** 'sha256', 'sha3-256'

#### Galois Field Arithmetic
```python
from cryptocore.utils.galois_field import (
    GaloisField,
    gf_multiply,
    gf_multiply_gcm,
    gf_add
)
```

**Class: `GaloisField`**
Implements arithmetic in GF(2^128) for GCM mode.

**Static Methods:**

**`multiply(x: Union[int, bytes, bytearray], y: Union[int, bytes, bytearray]) -> Union[int, bytes]`**
Multiplies in GF(2^128).

**`multiply_gcm(h_bytes: bytes, y_bytes: bytes) -> bytes`**
Multiplication optimized for GCM (H in bit-reversed representation).

**`add(x: Union[int, bytes, bytearray], y: Union[int, bytes, bytearray]) -> Union[int, bytes]`**
Addition in GF(2^128) (XOR).

**Module Functions:**

**`gf_multiply()`, `gf_multiply_gcm()`, `gf_add()`**
Convenience functions for module-level access.

#### NIST Test Tool
```python
from cryptocore.utils.nist_tool import generate_nist_test_file
```

**`generate_nist_test_file(output_path: str, size_mb: float = 10.0) -> None`**
Generates random data file for NIST Statistical Test Suite.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `size_mb` | `10.0` | File size in megabytes |

**CLI Access:** `cryptocore-nist output.bin --size 100.0`

---

## Command Line Interface

The `cryptocore` CLI provides unified access to all library functionality. It supports both legacy single-command syntax and modern subcommand syntax.

### Basic Syntax
```
cryptocore <command> [options]
```

### Commands Overview

#### `crypto` - Encryption and Decryption
Encrypts or decrypts files using various AES modes.

**Basic Encryption:**
```bash
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plain.txt --output encrypted.bin
```

**With Auto-generated Key:**
```bash
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --input plain.txt
# Key is generated and displayed
```

**GCM with AAD:**
```bash
cryptocore crypto --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "database_version_2.0" \
  --input data.db --output data.db.gcm
```

#### `dgst` - Hash and HMAC Computation
Computes hashes or HMACs of files.

**Hash Computation:**
```bash
cryptocore dgst --algorithm sha256 --input document.pdf
# Output: sha256-hash document.pdf
```

**HMAC Computation:**
```bash
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input sensitive.txt --output signature.hmac
```

**HMAC Verification:**
```bash
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input sensitive.txt --verify expected.hmac
# Exit code 0 on success, 1 on failure
```

#### `derive` - Key Derivation
Derives keys from passwords.

**Basic Derivation:**
```bash
cryptocore derive --password "MySecurePassword" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 --length 32
```

**With Auto-generated Salt:**
```bash
cryptocore derive --password "AnotherPassword" \
  --iterations 500000
```

**Password from File:**
```bash
cryptocore derive --password-file password.txt \
  --salt fixedappsalt --iterations 10000
```

### Common Options
| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--input` | `-i` | Input file | `--input data.txt` |
| `--output` | `-o` | Output file | `--output result.bin` |
| `--force` | `-f` | Overwrite existing | `--force` |
| `--key` | `-k` | Key as hex | `--key 0011...eeff` |
| `--iv` | | IV/nonce as hex | `--iv aabb...ccdd` |
| `--aad` | | AAD for GCM | `--aad metadata` |

### Input/Output Handling
- **Stdin/Stdout**: Use `-` for `--input` or omit `--output`
- **File Naming**: Automatic derivation based on operation
- **IV Handling**: Automatically prepended to ciphertext files
- **Overwrite Protection**: By default, existing files are not overwritten

---

## Error Handling and Exceptions

CryptoCore uses a consistent exception hierarchy for error reporting.

### Exception Hierarchy
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

### Common Error Scenarios

#### Invalid Parameters
```python
try:
    encrypt_cbc(plaintext, b"short_key", iv)  # Key too short
except ValueError as e:
    print(f"Parameter error: {e}")
```

#### Authentication Failure
```python
try:
    plaintext = decrypt_gcm(tampered_ciphertext, tag, nonce, key)
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
    # CRITICAL: No plaintext is output
```

#### File Operations
```python
try:
    data = read_file("/nonexistent/path/file.txt")
except FileNotFoundError as e:
    print(f"File not found: {e}")
except PermissionError as e:
    print(f"Permission denied: {e}")
```

### Best Practices
1. **Always catch specific exceptions** rather than generic `Exception`
2. **Handle authentication failures gracefully** without revealing sensitive information
3. **Validate user inputs** before passing to cryptographic functions
4. **Clean up sensitive data** from memory after use

---

## Security Considerations

### Critical Security Rules

#### 1. Key Management
- **Never hardcode keys** in source code
- **Use cryptographically secure random generators** for key generation
- **Store keys securely** (hardware security modules, key management systems)
- **Rotate keys periodically** based on data sensitivity

#### 2. IV/Nonce Usage
- **Never reuse IV/nonce** with the same key (especially critical for GCM, CTR)
- **Use cryptographically random IVs** (except for deterministic algorithms)
- **For GCM**: 12-byte random nonce is recommended

#### 3. Mode Selection Guidelines
| Use Case | Recommended Mode | Notes |
|----------|-----------------|-------|
| General encryption | GCM | Authenticated encryption |
| Legacy compatibility | CBC with HMAC | Encrypt-then-MAC |
| Disk encryption | XTS (not implemented) | For fixed-size blocks |
| Educational/testing | ECB | Single blocks only |

#### 4. Password-Based Key Derivation
- **Minimum iterations**: 100,000 for PBKDF2
- **Use unique salt** for each password
- **Store salt** alongside derived key (salt is not secret)
- **Consider memory-hard functions** (Argon2, scrypt) for high-security applications

### Implementation Security

#### Constant-Time Operations
Where practical, CryptoCore uses constant-time algorithms:
- HMAC verification
- Padding verification
- GCM tag comparison

#### Memory Management
- **Sensitive data clearing**: Keys and passwords are zeroed after use where possible
- **Buffer safety**: Python's memory management prevents buffer overflows
- **No secret logging**: Debug information excludes sensitive data

#### Input Validation
All functions validate:
- Key lengths (AES: 16/24/32 bytes)
- IV/nonce lengths (CBC/CFB/OFB: 16 bytes, GCM: 12 bytes recommended)
- Ciphertext lengths (must be multiples of block size where required)
- Parameter ranges (iterations > 0, key lengths > 0)

### Security Checklist for Users
- [ ] Use GCM or Encrypt-then-MAC for authenticated encryption
- [ ] Generate random keys with `generate_random_key()`
- [ ] Generate random IVs with `generate_random_iv()`
- [ ] Use at least 100,000 iterations for PBKDF2
- [ ] Verify HMAC/GCM tags before using decrypted data
- [ ] Never reuse nonce/IV with same key
- [ ] Store salts with derived keys
- [ ] Clear sensitive variables after use
- [ ] Validate all user inputs before cryptographic operations

---

## Testing and Validation

### Test Suite Structure
```
tests/
├── unit/                    # Unit tests for individual functions
│   ├── test_csprng.py      # Random number generation tests
│   ├── test_hash_sha256.py # SHA-256 implementation tests
│   ├── test_hmac.py        # HMAC implementation tests
│   ├── test_ecb.py         # ECB mode tests
│   ├── test_cbc.py         # CBC mode tests
│   ├── test_cfb.py         # CFB mode tests
│   ├── test_ofb.py         # OFB mode tests
│   ├── test_ctr.py         # CTR mode tests
│   ├── test_gcm.py         # GCM mode tests
│   ├── test_padding.py     # Padding tests
│   └── test_file_io.py     # File I/O tests
├── integration/             # Integration tests
│   ├── test_integration.py # End-to-end tests
│   └── test_openssl_compatibility.py # OpenSSL compatibility
└── vectors/                # Known-answer test vectors
    └── nist_kat/           # NIST Known Answer Tests
```

### Running Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/unit/ -v
python -m pytest tests/integration/ -v

# Run with coverage report
python -m pytest tests/ --cov=cryptocore --cov-report=html
```

### Test Coverage
- **Unit Tests**: 160+ tests covering all public functions
- **Known-Answer Tests**: NIST test vectors for all algorithms
- **Integration Tests**: CLI usage, file operations, cross-mode compatibility
- **Negative Tests**: Error conditions, invalid inputs, edge cases
- **Performance Tests**: Benchmarks for critical operations

### NIST Compatibility
All implementations are validated against NIST test vectors:
- **AES**: NIST SP 800-38A test vectors
- **GCM**: NIST SP 800-38D test vectors
- **SHA-256**: FIPS 180-4 test vectors
- **HMAC**: RFC 4231 test vectors
- **PBKDF2**: RFC 6070 test vectors

### OpenSSL Compatibility
```bash
# Test encryption compatibility
cryptocore crypto --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt --output test.enc

openssl enc -aes-128-cbc -d \
  -K 00112233445566778899aabbccddeeff \
  -iv $(head -c 16 test.enc | xxd -p) \
  -in <(tail -c +17 test.enc) \
  -out test.dec

diff test.txt test.dec  # Should be identical
```

---

## Examples and Use Cases

### Example 1: Secure File Encryption with Authentication
```python
from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm
from cryptocore.utils.csprng import generate_random_key
from cryptocore.utils.file_io import read_file, write_file
import os

def encrypt_file_with_metadata(input_path, output_path, metadata):
    """Encrypt file with authenticated metadata."""
    # Generate or load key (in practice, use secure key storage)
    key = generate_random_key()
    
    # Read plaintext
    plaintext = read_file(input_path)
    
    # Encrypt with metadata as AAD
    nonce, ciphertext, tag = encrypt_gcm(
        plaintext=plaintext,
        key=key,
        aad=metadata.encode()
    )
    
    # Save encrypted file
    with open(output_path, 'wb') as f:
        f.write(nonce + ciphertext + tag)
    
    return key, nonce

def decrypt_and_verify(input_path, output_path, key, expected_metadata):
    """Decrypt file and verify metadata."""
    # Read encrypted file
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Extract components
    nonce = data[:12]
    ciphertext = data[12:-16]
    tag = data[-16:]
    
    # Decrypt with verification
    try:
        plaintext = decrypt_gcm(
            ciphertext=ciphertext,
            tag=tag,
            nonce=nonce,
            key=key,
            aad=expected_metadata.encode()
        )
        
        # Write decrypted file
        write_file(output_path, plaintext, overwrite=True)
        print("Decryption successful - integrity verified")
        return True
        
    except AuthenticationError:
        print("ERROR: Authentication failed - file may be tampered")
        return False

# Usage
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

### Example 2: Password-Based Encryption System
```python
from cryptocore.kdf.pbkdf2 import derive_from_password
from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm
from cryptocore.utils.csprng import generate_random_bytes
import getpass
import json

class PasswordVault:
    def __init__(self, password, iterations=200000):
        """Initialize vault with user password."""
        self.iterations = iterations
        self.salt = generate_random_bytes(16)
        self.encryption_key, _ = derive_from_password(
            password, self.salt.hex(), iterations, 32
        )
    
    def encrypt_entry(self, service, username, password, metadata=""):
        """Encrypt a password entry."""
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
        """Decrypt and verify a password entry."""
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

# Usage
password = getpass.getpass("Enter vault password: ")
vault = PasswordVault(password, iterations=300000)

# Store credentials
encrypted = vault.encrypt_entry(
    service="github",
    username="alice",
    password="s3cr3tP@ssw0rd!",
    metadata="personal account"
)

# Retrieve credentials
decrypted = vault.decrypt_entry(encrypted)
print(f"Service: {decrypted['service']}")
print(f"Username: {decrypted['username']}")
print(f"Password: {decrypted['password']}")
```

### Example 3: Batch File Processing with Integrity
```python
from cryptocore.hash.sha256 import SHA256
from cryptocore.mac.hmac import HMAC
from cryptocore.utils.file_io import read_file, write_file
import os

def process_files_with_integrity(input_dir, output_dir, hmac_key):
    """Process files with HMAC integrity protection."""
    os.makedirs(output_dir, exist_ok=True)
    
    hmac = HMAC(hmac_key)
    integrity_log = []
    
    for filename in os.listdir(input_dir):
        input_path = os.path.join(input_dir, filename)
        
        if not os.path.isfile(input_path):
            continue
        
        # Read and process file
        data = read_file(input_path)
        processed_data = data.upper()  # Example processing
        
        # Compute HMAC for integrity
        file_hmac = hmac.compute_hex(processed_data)
        
        # Write processed file
        output_path = os.path.join(output_dir, filename)
        write_file(output_path, processed_data, overwrite=True)
        
        # Write HMAC file
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
    """Verify integrity of processed files."""
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
        
        # Read expected HMAC
        with open(hmac_path, 'r') as f:
            expected_hmac = f.read().strip().split()[0]
        
        # Compute actual HMAC
        data = read_file(file_path)
        actual_hmac = hmac.compute_hex(data)
        
        # Verify
        is_valid = (actual_hmac == expected_hmac)
        results.append((filename, "VERIFIED" if is_valid else "TAMPERED", is_valid))
    
    return results
```

---

## Compatibility Notes

### Python Versions
- **Primary Support**: Python 3.8, 3.9, 3.10, 3.11, 3.12
- **Tested On**: CPython (reference implementation)
- **May Work On**: PyPy, but not officially tested

### Operating Systems
- **Linux**: Full support, uses `/dev/urandom`
- **macOS**: Full support, uses `/dev/urandom`
- **Windows**: Full support, uses `CryptGenRandom` via Python's `os.urandom`
- **Other Unix-like**: Should work with OS-provided CSPRNG

### Cryptographic Standards Compliance
| Standard | Compliance | Notes |
|----------|------------|-------|
| FIPS 197 (AES) | Full | AES-128 only |
| NIST SP 800-38A | Full | Modes: ECB, CBC, CFB, OFB, CTR |
| NIST SP 800-38D | Full | GCM mode |
| FIPS 180-4 | Full | SHA-256 |
| FIPS 202 | Full | SHA3-256 (via hashlib) |
| RFC 2104 | Full | HMAC |
| RFC 2898 | Full | PBKDF2 |
| RFC 4231 | Full | HMAC test vectors |

### OpenSSL Compatibility
CryptoCore maintains compatibility with OpenSSL CLI for validation:

```bash
# Encryption compatibility
openssl enc -aes-128-cbc -K <key_hex> -iv <iv_hex> -in file.txt

# Hash compatibility
openssl dgst -sha256 file.txt

# HMAC compatibility  
openssl dgst -sha256 -hmac <key> file.txt

# PBKDF2 compatibility
openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt iter:100000 \
  -kdfopt salt:hex:<salt> PBKDF2 <password>
```

### Performance Characteristics
- **AES Encryption**: ~10-50 MB/s (Python overhead)
- **SHA-256 Hashing**: ~20-100 MB/s
- **GCM Encryption**: ~5-30 MB/s (includes authentication)
- **PBKDF2**: Configurable via iteration count
