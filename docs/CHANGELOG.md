
# Changelog

All notable changes to the CryptoCore project are documented in this file.

## [1.0.0] - 2025-12-21

### Added
- Complete cryptographic library with 8 milestone implementations
- Comprehensive API documentation covering all modules and functions
- Full CLI tool with three main subcommands: `crypto`, `dgst`, and `derive`
- 210+ comprehensive tests covering unit, integration, and compatibility testing

### Milestone 8: Final Integration, Testing, and Documentation
- **Documentation**: Complete API.md, CHANGELOG.md and USERGUIDE.md
- **Testing**: Enhanced test suite with NIST test vectors and interoperability tests
- **Quality Assurance**: Security audit, code cleanup, and performance optimization
- **Project Structure**: Finalized package structure with setup.py and configuration files

## [0.7.0] - 2025-12-20

### Milestone 7: Key Derivation and Protocol Foundation
#### Added
- **PBKDF2-HMAC-SHA256** implementation from scratch (RFC 2898)
- **Key hierarchy** function using deterministic HMAC-based derivation
- **New CLI command** `derive` with comprehensive parameter support
- **Multiple password input methods**: command line, file, or environment variable
- **Automatic salt generation**: 16-byte random salt when not provided
- **RFC 6070 test vectors** (adapted for SHA-256) for PBKDF2 verification
- **Security features**: Password memory clearing, weak parameter validation

#### Features
- Configurable iteration count (default: 100,000) and key length (default: 32 bytes)
- Support for arbitrary password and salt lengths
- OpenSSL compatibility for key derivation operations
- Integrated with build system and test suite

## [0.6.0]

### Milestone 6: Authenticated Encryption
#### Added
- **Galois/Counter Mode (GCM)** implementation from scratch (NIST SP 800-38D)
- **Galois Field GF(2^128)** arithmetic for GHASH operations
- **GCM CLI support**: `--mode gcm` and `--aad` parameter for authenticated encryption
- **Associated Data (AAD)** support with efficient chunked processing
- **Catastrophic failure handling**: No plaintext output on authentication errors
- **GCM file format**: `nonce(12) | ciphertext | tag(16)` with proper parsing

#### Security
- Authentication-before-decryption paradigm
- Nonce uniqueness enforcement (12-byte random nonce)
- Tamper detection for ciphertext and AAD modifications
- Full compliance with NIST SP 800-38D specifications

## [0.5.0]

### Milestone 5: Message Authentication Codes
#### Added
- **HMAC-SHA256** implementation from scratch (RFC 2104)
- **Extended CLI**: `dgst` command with `--hmac`, `--key`, and `--verify` options
- **Variable-length key support** with automatic hashing/padding per RFC
- **Tamper detection system** with file modification and wrong key scenarios
- **Verification system** with proper exit codes and user feedback
- **RFC 4231 test vectors** for HMAC validation

#### Features
- Support for any key length with proper RFC 2104 processing
- File processing with chunked streaming for large files
- Consistent output format compatible with standard hash tools
- Integration with existing hash and encryption systems

## [0.4.0]

### Milestone 4: Cryptographic Hash Functions
#### Added
- **SHA-256 implementation** from scratch following NIST FIPS 180-4
- **SHA3-256 support** via Python's hashlib library
- **New CLI subcommand** `dgst` with algorithm selection
- **File/stdin support** with chunked processing for large files
- **Avalanche effect testing** and performance benchmarks
- **NIST test vectors** for hash algorithm validation

#### Features
- Merkle-Damgård construction for SHA-256
- Support for arbitrary length input data
- Binary chunked processing with error handling
- OpenSSL compatibility for hash verification
- Output file support and consistent formatting

## [0.3.0] 

### Milestone 3: Cryptographically Secure Random Number Generation
#### Added
- **CSPRNG module** using `os.urandom()` for secure randomness
- **Automatic key generation** when `--key` is omitted for encryption
- **Weak key detection** with warnings for insecure keys
- **NIST STS test file generator** utility (`cryptocore-nist`)
- **Display generated key** in hex format for user to save
- **Proper error handling** for missing keys in decryption

#### Features
- Secure random bytes generation for keys and IVs
- Integration with all encryption modes
- Statistical tests for randomness quality
- Backward compatibility with existing encryption/decryption

## [0.2.0] 

### Milestone 2: Modes of Operation and IV Handling
#### Added
- **Four confidential modes**: CBC, CFB, OFB, CTR implementations
- **Secure IV generation** using cryptographically secure RNG
- **IV handling system**: Automatic generation and file storage
- **File format**: `<16-byte IV><ciphertext>` for IV-based modes
- **Comprehensive mode testing** with edge cases and error conditions

#### Features
- Full OpenSSL compatibility for all modes
- Proper padding for block modes (CBC) and stream processing for others
- Unique IV enforcement for security
- Integration with existing ECB implementation

## [0.1.0] 

### Milestone 1: Project Foundation and Basic Blocks
#### Added
- **AES-128 ECB mode** implementation with PKCS#7 padding
- **CLI interface** with full argument validation and error handling
- **Binary file handling** with automatic naming conventions
- **Project structure** with modular organization
- **Comprehensive test suite** (28 initial tests)
- **OpenSSL compatibility** verification

#### Features
- Basic encryption/decryption round-trip functionality
- File I/O with proper error handling
- PowerShell examples and documentation
- Build system with setup.py configuration

## Technical Specifications

### Cryptographic Standards Compliance
- **AES**: FIPS 197 (AES-128)
- **Modes**: NIST SP 800-38A (ECB, CBC, CFB, OFB, CTR)
- **GCM**: NIST SP 800-38D
- **SHA-256**: FIPS 180-4
- **SHA3-256**: FIPS 202
- **HMAC**: RFC 2104, RFC 4231
- **PBKDF2**: RFC 2898, RFC 6070

### Test Coverage
- **Milestone 1**: 28 tests
- **Milestone 2**: 61 tests (+33)
- **Milestone 3**: 67 tests (+6)
- **Milestone 4**: 126 tests (+59)
- **Milestone 5**: 161 tests (+35)
- **Milestone 6**: Enhanced with GCM tests
- **Milestone 7**: Enhanced with KDF tests
- **Total**: 210+ comprehensive tests

### Dependencies
- Python 3.8+
- pycryptodome>=3.20.0 (for AES core operations)

### Platform Support
- **Operating Systems**: Linux, macOS, Windows
- **Python Implementations**: CPython (primary), PyPy (compatible)
- **Architectures**: x86_64, ARM64 (where Python is supported)

## Security Advisories

### Version 1.0.0
- This is an educational implementation and not audited for production use
- Always use cryptographically secure random numbers for keys and IVs
- Never reuse nonces/IVs with the same key in GCM or CTR modes
- Use appropriate iteration counts for PBKDF2 (≥100,000 recommended)
- Verify authentication tags before using decrypted data

### Backward Compatibility
Version 1.0.0 maintains full backward compatibility with all previous milestone implementations. Encrypted files from earlier versions can be decrypted with this version using the same keys and parameters.
