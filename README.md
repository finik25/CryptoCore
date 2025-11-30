# CryptoCore

Minimalist cryptographic provider in Python. Educational project focused on understanding cryptographic algorithms and protocols.

## Features

- AES-128 encryption/decryption in ECB mode
- PKCS#7 padding standard implementation  
- Binary file handling - works with any file type
- OpenSSL compatibility - verified against industry standard
- Command-line interface

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

Encrypt a file (auto-generates output filename):

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input document.txt
```

Decrypt a file:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 00112233445566778899aabbccddeeff --input document.txt.enc
```

With custom output filename:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input data.bin --output encrypted.data
```

### File Naming

- Encryption: filename.ext → filename.ext.enc
- Decryption: filename.ext.enc → filename.dec.ext

### Examples

Create test file and perform encryption/decryption cycle:

```powershell
# Create test file
echo "Hello CryptoCore!" > test.txt

# Encrypt
cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input test.txt

# List files to verify
Get-ChildItem test.*

# Decrypt
cryptocore --algorithm aes --mode ecb --decrypt --key 00112233445566778899aabbccddeeff --input test.txt.enc

# Verify file integrity
Get-FileHash test.txt
Get-FileHash test.dec.txt
```

## Testing

Run test suite:

```powershell
python -m unittest discover tests
```

OpenSSL compatibility verification:

```powershell
# Encrypt with OpenSSL
openssl enc -aes-128-ecb -in test.txt -out openssl_encrypted.bin -K 00112233445566778899aabbccddeeff

# Encrypt with CryptoCore
cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output our_encrypted.bin

# Compare results
Get-FileHash openssl_encrypted.bin
Get-FileHash our_encrypted.bin
```

## Project Structure

```
CryptoCore/
├── src/cryptocore/
│   ├── modes/
│   │   ├── ecb.py          # ECB mode implementation
│   ├── utils/
│   │   ├── padding.py      # PKCS#7 padding
│   ├── cli.py              # Command-line interface
│   └── file_io.py          # File handling
├── tests/                  # Test suite
├── setup.py               # Package configuration
└── README.md
```

## Technical Details

### Implemented Standards

- AES-128 (using pycryptodome for core operations)
- ECB mode with manual block processing
- PKCS#7 padding with validation
- Binary data handling

### Security Notes

- Core AES operations delegated to pycryptodome
- Educational focus - not for production use
- All file operations in binary mode

## Troubleshooting

### Common Issues

OpenSSL not found in PATH:

```powershell
# Use full path to OpenSSL
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" version
```

File not found errors:

- Ensure input file exists in current directory
- Use absolute paths if needed


