import argparse
import sys
import os
from typing import Optional, List
import logging

logger = logging.getLogger('cryptocore')
logger.setLevel(logging.WARNING)

try:
    from cryptocore.utils.csprng import generate_random_key, generate_random_iv
    from cryptocore.file_io import read_file, write_file, derive_output_filename, read_file_with_iv, write_file_with_iv
    from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
    from cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
    from cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
    from cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
    from cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr

    _imported_as_package = True

except ImportError:
    import sys
    import os

    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(current_dir))

    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    try:
        from src.cryptocore.utils.csprng import generate_random_key, generate_random_iv
        from src.cryptocore.file_io import read_file, write_file, derive_output_filename, read_file_with_iv, \
            write_file_with_iv
        from src.cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
        from src.cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
        from src.cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
        from src.cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
        from src.cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr

        _imported_as_package = False

    except ImportError as e:
        print(f"Failed to import CryptoCore modules:", file=sys.stderr)
        print(f"  Package import failed, trying src import...", file=sys.stderr)
        print(f"  Final error: {e}", file=sys.stderr)
        print(f"  Current sys.path:", file=sys.stderr)
        for p in sys.path:
            print(f"    {p}", file=sys.stderr)
        sys.exit(1)


def import_optional_module(module_name, import_func):
    try:
        if _imported_as_package:
            import_func(package_prefix='cryptocore')
        else:
            import_func(package_prefix='src.cryptocore')
        return True
    except ImportError:
        return False


# Hash functions
def import_hash_modules(package_prefix):
    exec(f"""
from {package_prefix}.hash.sha256 import SHA256
from {package_prefix}.hash.sha3_256 import SHA3_256
""", globals())


_hash_available = import_optional_module('hash', import_hash_modules)


# HMAC
def import_hmac_modules(package_prefix):
    exec(f"""
from {package_prefix}.mac.hmac import HMAC, compute_hmac_hex
""", globals())


_hmac_available = import_optional_module('hmac', import_hmac_modules)


# GCM
def import_gcm_modules(package_prefix):
    exec(f"""
from {package_prefix}.modes.gcm import encrypt_gcm, decrypt_gcm
""", globals())


_gcm_available = import_optional_module('gcm', import_gcm_modules)


# PBKDF2
def import_kdf_modules(package_prefix):
    exec(f"""
from {package_prefix}.kdf.pbkdf2 import pbkdf2_hmac_sha256
""", globals())


_kdf_available = import_optional_module('pbkdf2', import_kdf_modules)

if not _hash_available:
    SHA256 = None
    SHA3_256 = None

if not _hmac_available:
    HMAC = None
    compute_hmac_hex = None

if not _gcm_available:
    encrypt_gcm = None
    decrypt_gcm = None

if not _kdf_available:
    pbkdf2_hmac_sha256 = None

if logger.isEnabledFor(logging.DEBUG):
    logger.debug(f"Imports successful. Package mode: {_imported_as_package}")
    logger.debug(f"Modules available: hash={_hash_available}, hmac={_hmac_available}, "
                 f"gcm={_gcm_available}, kdf={_kdf_available}")


def parse_arguments(args=None):
    if args is None:
        args = sys.argv[1:]

    has_subcommand = args and not args[0].startswith('--')

    if has_subcommand:
        return _parse_with_subcommands(args)
    else:
        return _parse_legacy(args)


def _parse_with_subcommands(args):
    parser = argparse.ArgumentParser(
        description="CryptoCore - Minimalist Cryptographic Provider",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Encryption with subcommand (recommended)
  cryptocore crypto --algorithm aes --mode cbc --encrypt --input plaintext.txt

  # GCM Encryption with AAD
  cryptocore crypto --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input plaintext.txt

  # Hash computation (stdout)
  cryptocore dgst --algorithm sha256 --input document.pdf

  # HMAC computation
  cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf

  # Key derivation from password
  cryptocore derive --password "MySecurePassword123!" --salt a1b2c3d4e5f601234567890123456789 --iterations 100000 --length 32

  # Key derivation with auto-generated salt
  cryptocore derive --password "AnotherPassword" --iterations 500000 --length 16

  # Legacy mode (for backward compatibility)
  cryptocore --algorithm aes --mode cbc --encrypt --input plaintext.txt
"""
    )

    subparsers = parser.add_subparsers(
        dest='command',
        title='commands',
        description='Available commands',
        help='Command to execute',
        required=True
    )

    # 'crypto' command
    crypto_parser = subparsers.add_parser('crypto', help='Encryption and decryption operations')
    _add_crypto_arguments(crypto_parser)

    # 'dgst' command (only if hashing is available)
    if _hash_available:
        dgst_parser = subparsers.add_parser('dgst', help='Compute hash or HMAC of files')
        _add_dgst_arguments(dgst_parser)

    # 'derive' command (only if KDF is available)
    if _kdf_available:
        derive_parser = subparsers.add_parser('derive', help='Derive keys from passwords')
        _add_derive_arguments(derive_parser)

    return parser.parse_args(args)


def _parse_legacy(args):
    parser = argparse.ArgumentParser(
        description="CryptoCore - Minimalist Cryptographic Provider (legacy mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Note: This is legacy mode. For new features like hashing, HMAC, and GCM, use subcommands.
"""
    )

    _add_crypto_arguments(parser)
    parsed_args = parser.parse_args(args)
    parsed_args.command = 'crypto'
    return parsed_args


def _add_crypto_arguments(parser):
    parser.add_argument('--algorithm', required=True, choices=['aes'], help='Cryptographic algorithm')

    # Build mode choices dynamically based on availability
    mode_choices = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']
    if _gcm_available:
        mode_choices.append('gcm')

    parser.add_argument('--mode', required=True, choices=mode_choices, help='Mode of operation')

    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--encrypt', action='store_true')
    operation_group.add_argument('--decrypt', action='store_true')

    parser.add_argument('--key', required=False, help='Encryption key as hexadecimal string')
    parser.add_argument('--iv', required=False,
                        help='Initialization Vector as hexadecimal string (16 bytes for modes except GCM, 12 bytes for GCM)')
    parser.add_argument('--aad', required=False,
                        help='Associated Authenticated Data as hexadecimal string (for GCM mode only)')
    parser.add_argument('--input', required=True, help='Input file path')
    parser.add_argument('--output', required=False, help='Output file path')
    parser.add_argument('--force', action='store_true', help='Overwrite output file if it exists')


def _add_dgst_arguments(parser):
    parser.add_argument('--algorithm', required=True, choices=['sha256', 'sha3-256'], help='Hash algorithm')
    parser.add_argument('--input', required=True, help='Input file path (use - for stdin)')
    parser.add_argument('--output', required=False, help='Output file for hash (optional)')
    parser.add_argument('--force', action='store_true',
                        help='Overwrite output file if it exists (optional)')

    parser.add_argument('--hmac', action='store_true',
                        help='Compute HMAC instead of plain hash (requires --key)')
    parser.add_argument('--key', required=False,
                        help='Key for HMAC as hexadecimal string (required when --hmac is used)')
    parser.add_argument('--verify', required=False,
                        help='Verify HMAC against file containing expected HMAC')


def _add_derive_arguments(parser):
    """
    Add arguments for the derive command.
    """
    # Password source - exactly one required
    password_group = parser.add_argument_group('password source (required)')
    password_source = password_group.add_mutually_exclusive_group(required=True)
    password_source.add_argument('--password',
                                 help='Password string (use quotes for special characters)')
    password_source.add_argument('--password-file',
                                 help='Read password from file instead of command line')
    password_source.add_argument('--env-var',
                                 help='Read password from environment variable')

    parser.add_argument('--salt',
                        help='Salt as hexadecimal string (default: random 16 bytes)')
    parser.add_argument('--iterations', type=int, default=100000,
                        help='Iteration count (default: 100000)')
    parser.add_argument('--length', type=int, default=32,
                        help='Derived key length in bytes (default: 32)')
    parser.add_argument('--algorithm', default='pbkdf2',
                        choices=['pbkdf2'],  # For now only PBKDF2
                        help='KDF algorithm (default: pbkdf2)')
    parser.add_argument('--output',
                        help='Output file for derived key (optional)')
    parser.add_argument('--force', action='store_true',
                        help='Overwrite output file if it exists')

    parser.epilog = """\
Examples:
  # Basic key derivation with specified salt
  cryptocore derive --password "MySecurePassword123!" --salt a1b2c3d4e5f601234567890123456789

  # Auto-generated salt
  cryptocore derive --password "AnotherPassword" --iterations 500000 --length 16

  # Read password from file
  cryptocore derive --password-file password.txt --salt fixedappsalt --iterations 10000

  # Save derived key to file
  cryptocore derive --password "app_key" --output derived_key.bin

  # Use environment variable
  $env:MY_PASSWORD = "Secret123"
  cryptocore derive --env-var MY_PASSWORD --iterations 100000
"""

def validate_key_hex(key_hex: str, hmac_mode: bool = False) -> bytes:
    try:
        clean_key = key_hex.lower().replace('0x', '').replace('\\x', '').replace(' ', '')
        key_bytes = bytes.fromhex(clean_key)

        if not hmac_mode:
            # For AES encryption, key must be 16 bytes for AES-128
            if len(key_bytes) != 16:
                raise ValueError(f"Key must be 16 bytes, got {len(key_bytes)} bytes")

        return key_bytes

    except ValueError as e:
        if "non-hexadecimal number" in str(e):
            raise ValueError(f"Invalid key format: '{key_hex}'. Must be valid hex")
        else:
            raise e


def validate_key(key_hex: str) -> bytes:
    return validate_key_hex(key_hex, hmac_mode=False)


def validate_iv(iv_hex: str, mode: str = 'cbc') -> bytes:
    try:
        clean_iv = iv_hex.lower().replace('0x', '').replace('\\x', '').replace(' ', '')

        if mode == 'gcm':
            # GCM: 12 bytes nonce (24 hex chars)
            if len(clean_iv) != 24:
                raise ValueError(
                    f"GCM nonce must be 12 bytes (24 hex chars), got {len(clean_iv) // 2} bytes"
                )
            iv_bytes = bytes.fromhex(clean_iv)
        else:
            # Other modes: 16 bytes IV (32 hex chars)
            if len(clean_iv) != 32:
                raise ValueError(
                    f"IV must be 16 bytes (32 hex chars) for {mode} mode, got {len(clean_iv) // 2} bytes"
                )
            iv_bytes = bytes.fromhex(clean_iv)

        return iv_bytes

    except ValueError as e:
        if "non-hexadecimal number" in str(e):
            raise ValueError(f"Invalid format: '{iv_hex}'. Must be valid hex")
        else:
            raise e


def check_weak_key(key: bytes):
    warnings = []

    if all(b == 0 for b in key):
        warnings.append("Key consists of all zero bytes")

    if all(key[i] == i for i in range(len(key))):
        warnings.append("Key consists of sequential bytes (0, 1, 2, ...)")

    if all(b == key[0] for b in key):
        warnings.append("Key consists of all identical bytes")

    if len(key) >= 4:
        pattern = key[:4]
        repeats_cleanly = True
        for i in range(0, len(key), 4):
            if i + 4 <= len(key) and key[i:i + 4] != pattern:
                repeats_cleanly = False
                break
        if repeats_cleanly:
            warnings.append("Key appears to be a repeating 4-byte pattern")

    if warnings:
        warning_msg = "Warning: Potential weak key detected - "
        if len(warnings) == 1:
            warning_msg += warnings[0]
        else:
            warning_msg += "; ".join(warnings)
        print(f"{warning_msg}", file=sys.stderr)
        print(f"  Key (hex): {key.hex()}", file=sys.stderr)


def compute_hmac_for_data(data: bytes, key: bytes) -> str:
    if not _hmac_available:
        raise RuntimeError("HMAC functionality not available")

    return compute_hmac_hex(key, data)


def compute_hmac_for_file(file_obj, key: bytes, chunk_size: int = 8192) -> str:
    if not _hmac_available:
        raise RuntimeError("HMAC functionality not available")

    hmac = HMAC(key)
    chunks = []

    # Read file in chunks
    while chunk := file_obj.read(chunk_size):
        chunks.append(chunk)

    # Compute HMAC from chunks
    return hmac.update_compute(chunks).hex()


def verify_hmac_from_file(data_or_filename, key: bytes, hmac_file: str) -> bool:
    if not _hmac_available:
        raise RuntimeError("HMAC functionality not available")

    # Read expected HMAC from file
    try:
        with open(hmac_file, 'r') as f:
            expected_line = f.read().strip()
    except FileNotFoundError:
        print(f"Error: HMAC verification file not found: {hmac_file}", file=sys.stderr)
        return False

    # Parse expected HMAC (format: "HMAC_VALUE  FILENAME" or just "HMAC_VALUE")
    expected_parts = expected_line.split()
    if not expected_parts:
        print(f"Error: Empty HMAC verification file: {hmac_file}", file=sys.stderr)
        return False

    expected_hmac_hex = expected_parts[0]

    # Compute HMAC
    if isinstance(data_or_filename, bytes):
        # Data provided directly
        hmac = HMAC(key)
        computed_hmac = hmac.compute_hex(data_or_filename)
    else:
        # Filename provided - compute from file
        with open(data_or_filename, 'rb') as f:
            computed_hmac = compute_hmac_for_file(f, key)

    # Compare
    return computed_hmac == expected_hmac_hex


def output_hash_result(output_line: str, output_file: Optional[str], force: bool, is_hmac: bool = False):
    if output_file:
        try:
            # Create directory if it doesn't exist
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            # Write to file with appropriate mode
            mode = 'w' if force else 'x'  # 'x' mode fails if file exists
            with open(output_file, mode) as f:
                f.write(output_line)

            output_type = "HMAC" if is_hmac else "Hash"
            print(f"{output_type} written to: {output_file}", file=sys.stdout)

        except FileExistsError:
            # This should not happen since we checked above, but just in case
            print(f"Error: File exists: {output_file}. Use --force to overwrite", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied writing to: {output_file}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdout.isatty():
            print(output_line, end='')
        else:
            sys.stdout.write(output_line)


def perform_hmac_operation(args):
    if not _hash_available:
        print("Error: Hash functionality not available", file=sys.stderr)
        sys.exit(1)

    if not _hmac_available:
        print("Error: HMAC functionality not available", file=sys.stderr)
        sys.exit(1)

    # Validate HMAC-specific arguments
    if not args.key:
        print("Error: --key is required when using --hmac", file=sys.stderr)
        sys.exit(1)

    if args.algorithm != 'sha256':
        print("Error: HMAC currently only supports SHA-256 algorithm", file=sys.stderr)
        sys.exit(1)

    # Parse and validate key
    try:
        key = validate_key_hex(args.key, hmac_mode=True)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Check if output file exists and --force is not specified
    if args.output and os.path.exists(args.output) and not args.force:
        print(f"Error: File exists: {args.output}. Use --force to overwrite", file=sys.stderr)
        sys.exit(1)

    if args.input == '-':
        # Read from stdin
        import sys as global_sys
        try:
            data = global_sys.stdin.buffer.read()

            if args.verify:
                # Verify against provided file
                verification_result = verify_hmac_from_file(data, key, args.verify)
                if verification_result:
                    print(f"[OK] HMAC verification successful", file=global_sys.stdout)
                    global_sys.exit(0)
                else:
                    print(f"[ERROR] HMAC verification failed", file=global_sys.stderr)
                    global_sys.exit(1)
            else:
                # Output HMAC
                hmac_value = compute_hmac_for_data(data, key)
                output_line = f"{hmac_value} -\n"
                output_hash_result(output_line, args.output, args.force, is_hmac=True)

        except Exception as e:
            print(f"Error: {e}", file=global_sys.stderr)
            global_sys.exit(1)
    else:
        # Process file
        try:
            if args.verify:
                # Compute and verify HMAC for file
                verification_result = verify_hmac_from_file(args.input, key, args.verify)
                if verification_result:
                    print(f"[OK] HMAC verification successful for {args.input}", file=sys.stdout)
                    sys.exit(0)
                else:
                    print(f"[ERROR] HMAC verification failed for {args.input}", file=sys.stderr)
                    sys.exit(1)
            else:
                # Compute HMAC for file
                with open(args.input, 'rb') as f:
                    hmac_value = compute_hmac_for_file(f, key)

                output_line = f"{hmac_value}  {args.input}\n"
                output_hash_result(output_line, args.output, args.force, is_hmac=True)

        except FileNotFoundError:
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied: {args.input}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


def perform_dgst_operation(args):
    if not _hash_available:
        print("Error: Hash functionality not available", file=sys.stderr)
        sys.exit(1)

    # M5: Check if HMAC mode is requested
    if args.hmac:
        return perform_hmac_operation(args)

    # Original hash logic from M4
    if args.algorithm == 'sha256':
        hash_class = SHA256
    elif args.algorithm == 'sha3-256':
        hash_class = SHA3_256
    else:
        print(f"Error: Unsupported algorithm: {args.algorithm}", file=sys.stderr)
        sys.exit(1)

    # Check if output file exists and --force is not specified
    if args.output and os.path.exists(args.output) and not args.force:
        print(f"Error: File exists: {args.output}. Use --force to overwrite", file=sys.stderr)
        sys.exit(1)

    if args.input == '-':
        import sys as global_sys
        try:
            data = global_sys.stdin.buffer.read()
            hasher = hash_class()
            hasher.update(data)
            hash_hex = hasher.hexdigest()
            output_line = f"{hash_hex} -\n"
        except Exception as e:
            print(f"Error reading from stdin: {e}", file=global_sys.stderr)
            global_sys.exit(1)
    else:
        try:
            hasher = hash_class()
            with open(args.input, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            hash_hex = hasher.hexdigest()
            output_line = f"{hash_hex}  {args.input}\n"
        except FileNotFoundError:
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied: {args.input}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error processing file: {e}", file=sys.stderr)
            sys.exit(1)

    output_hash_result(output_line, args.output, args.force, is_hmac=False)


def perform_crypto_operation(args):
    operation = 'encrypt' if args.encrypt else 'decrypt'

    # Handle GCM mode specially
    if args.mode == 'gcm':
        if not _gcm_available:
            print("Error: GCM mode not available", file=sys.stderr)
            sys.exit(1)

        return _perform_gcm_operation(args, operation)

    # Original logic for other modes (ECB, CBC, CFB, OFB, CTR)
    generated_key = None
    if operation == 'encrypt':
        if args.key is None:
            generated_key = generate_random_key()
            key = generated_key
            print(f"[INFO] Generated random key: {key.hex()}", file=sys.stdout)
        else:
            try:
                key = validate_key(args.key)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            check_weak_key(key)
    else:
        if args.key is None:
            print(f"Error: --key is required for decryption", file=sys.stderr)
            sys.exit(1)

        try:
            key = validate_key(args.key)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        check_weak_key(key)

    if args.mode == 'ecb' and args.iv:
        print(f"Error: --iv not supported for ECB mode", file=sys.stderr)
        sys.exit(1)

    iv = None
    input_data = None

    if operation == 'encrypt':
        try:
            input_data = read_file(args.input)
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(f"Error reading input file: {e}", file=sys.stderr)
            sys.exit(1)

        if args.iv:
            print(f"Warning: --iv is ignored during encryption", file=sys.stderr)

        if args.mode != 'ecb':
            iv = generate_random_iv()

    else:
        if args.iv:
            try:
                iv = validate_iv(args.iv, args.mode)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

            try:
                input_data = read_file(args.input)
            except (FileNotFoundError, PermissionError, IOError) as e:
                print(f"Error reading input file: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.mode != 'ecb':
            try:
                iv, input_data = read_file_with_iv(args.input)
            except (FileNotFoundError, PermissionError, IOError, ValueError) as e:
                print(f"Error reading input file: {e}", file=sys.stderr)
                sys.exit(1)

        else:
            try:
                input_data = read_file(args.input)
            except (FileNotFoundError, PermissionError, IOError) as e:
                print(f"Error reading input file: {e}", file=sys.stderr)
                sys.exit(1)

    try:
        if args.mode == 'ecb':
            if operation == 'encrypt':
                output_data = encrypt_ecb(input_data, key)
            else:
                output_data = decrypt_ecb(input_data, key)

        elif args.mode == 'cbc':
            if iv is None:
                raise ValueError("IV required for CBC mode")

            if operation == 'encrypt':
                output_data = encrypt_cbc(input_data, key, iv)
            else:
                output_data = decrypt_cbc(input_data, key, iv)

        elif args.mode == 'cfb':
            if iv is None:
                raise ValueError("IV required for CFB mode")

            if operation == 'encrypt':
                output_data = encrypt_cfb(input_data, key, iv)
            else:
                output_data = decrypt_cfb(input_data, key, iv)

        elif args.mode == 'ofb':
            if iv is None:
                raise ValueError("IV required for OFB mode")

            if operation == 'encrypt':
                output_data = encrypt_ofb(input_data, key, iv)
            else:
                output_data = decrypt_ofb(input_data, key, iv)

        elif args.mode == 'ctr':
            if iv is None:
                raise ValueError("IV required for CTR mode")

            if operation == 'encrypt':
                output_data = encrypt_ctr(input_data, key, iv)
            else:
                output_data = decrypt_ctr(input_data, key, iv)

        else:
            print(f"Error: Unknown mode {args.mode}", file=sys.stderr)
            sys.exit(1)

    except ValueError as e:
        print(f"Cryptographic error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error during {operation}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = args.output
    else:
        output_path = derive_output_filename(args.input, operation, args.algorithm, args.mode)

    try:
        if operation == 'encrypt' and iv is not None:
            write_file_with_iv(output_path, iv, output_data, overwrite=args.force)

            print(f"Success: {operation} completed", file=sys.stdout)
            print(f"  Output file: {output_path}", file=sys.stdout)
            print(f"  IV (hex): {iv.hex()}", file=sys.stdout)
            if generated_key:
                print(f"  Key (hex): {key.hex()} (auto-generated)", file=sys.stdout)
        else:
            write_file(output_path, output_data, overwrite=args.force)

            print(f"Success: {operation} completed", file=sys.stdout)
            print(f"  Output file: {output_path}", file=sys.stdout)
            if generated_key:
                print(f"  Key (hex): {key.hex()} (auto-generated)", file=sys.stdout)
    except (FileExistsError, PermissionError, IOError) as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)


def _perform_gcm_operation(args, operation):
    # Parse and validate key
    if operation == 'encrypt':
        if args.key is None:
            key = generate_random_key()
            print(f"[INFO] Generated random key: {key.hex()}", file=sys.stdout)
        else:
            try:
                key = validate_key(args.key)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            check_weak_key(key)
    else:  # decryption
        if args.key is None:
            print(f"Error: --key is required for GCM decryption", file=sys.stderr)
            sys.exit(1)

        try:
            key = validate_key(args.key)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        check_weak_key(key)

    # Parse AAD if provided
    aad = b""
    if args.aad:
        try:
            clean_aad = args.aad.lower().replace('0x', '').replace('\\x', '').replace(' ', '')
            aad = bytes.fromhex(clean_aad)
        except ValueError as e:
            print(f"Error: Invalid AAD format: {e}", file=sys.stderr)
            sys.exit(1)
    elif operation == 'encrypt':
        # AAD is optional for encryption
        pass
    # Note: For decryption, empty AAD is valid if encryption also used empty AAD

    # Parse nonce if provided (via --iv for backward compatibility)
    nonce = None
    if args.iv:
        try:
            nonce = validate_iv(args.iv, 'gcm')
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    # Read input data
    try:
        input_data = read_file(args.input)
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"Error reading input file: {e}", file=sys.stderr)
        sys.exit(1)

    if operation == 'encrypt':
        try:
            # Perform GCM encryption
            nonce_out, ciphertext, tag = encrypt_gcm(
                plaintext=input_data,
                key=key,
                nonce=nonce,  # если None, будет сгенерирован автоматически
                aad=aad
            )

            # Output format: nonce(12) + ciphertext + tag(16)
            output_data = nonce_out + ciphertext + tag

            # Determine output filename
            if args.output:
                output_path = args.output
            else:
                # Use custom derivation for GCM
                base_name = os.path.basename(args.input)
                output_path = f"{base_name}.gcm"

            # Write output file
            write_file(output_path, output_data, overwrite=args.force)

            print(f"Success: GCM encryption completed", file=sys.stdout)
            print(f"  Output file: {output_path}", file=sys.stdout)
            print(f"  Nonce (hex): {nonce_out.hex()}", file=sys.stdout)
            if not args.key:
                print(f"  Key (hex): {key.hex()} (auto-generated)", file=sys.stdout)
            if args.aad:
                print(f"  AAD (hex): {args.aad}", file=sys.stdout)

        except Exception as e:
            print(f"GCM encryption error: {e}", file=sys.stderr)
            sys.exit(1)

    else:  # decryption
        try:
            # Check minimum size: nonce(12) + tag(16) = 28 bytes
            if len(input_data) < 28:
                raise ValueError(
                    f"Input too short for GCM format (need at least 28 bytes, got {len(input_data)})"
                )

            # Extract components: nonce(12) | ciphertext | tag(16)
            nonce_in = input_data[:12]
            tag_in = input_data[-16:]
            ciphertext_in = input_data[12:-16]

            # Perform GCM decryption with tag verification
            plaintext = decrypt_gcm(
                ciphertext=ciphertext_in,
                tag=tag_in,
                nonce=nonce_in,
                key=key,
                aad=aad
            )

            # Determine output filename
            if args.output:
                output_path = args.output
            else:
                # Derive filename: file.txt.gcm -> file.dec.txt
                base_name = os.path.basename(args.input)
                name, ext = os.path.splitext(base_name)
                if ext == '.gcm':
                    original_name, original_ext = os.path.splitext(name)
                    if original_ext:
                        output_path = f"{original_name}.dec{original_ext}"
                    else:
                        output_path = f"{name}.dec"
                else:
                    output_path = f"{base_name}.dec"

            # Write output file
            write_file(output_path, plaintext, overwrite=args.force)

            print(f"Success: GCM decryption completed", file=sys.stdout)
            print(f"  Output file: {output_path}", file=sys.stdout)
            print(f"  Nonce (hex): {nonce_in.hex()}", file=sys.stdout)
            if args.aad:
                print(f"  AAD (hex): {args.aad}", file=sys.stdout)

        except Exception as e:
            # Catastrophic failure: different error messages for authentication failure
            if "AuthenticationError" in str(type(e).__name__) or "verification" in str(e).lower():
                print(f"[ERROR] Authentication failed: {e}", file=sys.stderr)
                print(f"  No plaintext was output due to authentication failure.", file=sys.stderr)
            else:
                print(f"GCM decryption error: {e}", file=sys.stderr)
            sys.exit(1)


def perform_derive_operation(args):

    if not _kdf_available:
        print("Error: Key derivation functionality not available", file=sys.stderr)
        sys.exit(1)

    # Get password from appropriate source
    password = None
    password_source = "command line"

    if args.password_file:
        # Read password from file
        try:
            with open(args.password_file, 'r') as f:
                password = f.read().strip()
            password_source = f"file: {args.password_file}"
        except Exception as e:
            print(f"Error reading password file: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.env_var:
        # Read password from environment variable
        password = os.getenv(args.env_var)
        if password is None:
            print(f"Error: Environment variable '{args.env_var}' not set", file=sys.stderr)
            sys.exit(1)
        password_source = f"env var: {args.env_var}"
    else:
        # Use password from command line
        password = args.password

    # Validate parameters
    if args.iterations < 1:
        print(f"Error: Iterations must be at least 1, got {args.iterations}", file=sys.stderr)
        sys.exit(1)

    if args.length < 1:
        print(f"Error: Key length must be at least 1 byte, got {args.length}", file=sys.stderr)
        sys.exit(1)

    # Handle salt
    salt = None
    salt_hex = None
    salt_source = "provided"

    if args.salt:
        # Use provided salt
        try:
            # Clean hex string
            clean_salt = args.salt.lower().replace('0x', '').replace('\\x', '').replace(' ', '')
            if not all(c in '0123456789abcdef' for c in clean_salt):
                print(f"Error: Salt must be valid hexadecimal string", file=sys.stderr)
                sys.exit(1)

            salt = bytes.fromhex(clean_salt)
            salt_hex = clean_salt
        except ValueError as e:
            print(f"Error: Invalid salt format: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Generate random salt
        try:
            from cryptocore.utils.csprng import generate_random_bytes
            salt = generate_random_bytes(16)  # 16 bytes = 128 bits
            salt_hex = salt.hex()
            salt_source = "generated"
        except ImportError:
            # Fallback to os.urandom
            salt = os.urandom(16)
            salt_hex = salt.hex()
            salt_source = "generated (fallback)"

    # Check if output file exists and --force is not specified
    if args.output and os.path.exists(args.output) and not args.force:
        print(f"Error: File exists: {args.output}. Use --force to overwrite", file=sys.stderr)
        sys.exit(1)

    try:
        # Derive key using PBKDF2
        derived_key = pbkdf2_hmac_sha256(
            password=password,
            salt=salt,
            iterations=args.iterations,
            dklen=args.length
        )

        # Clear password from memory
        password = "X" * len(password) if password else None

    except Exception as e:
        print(f"Error during key derivation: {e}", file=sys.stderr)
        sys.exit(1)

        # Output format: KEY_HEX SALT_HEX (always compact format)
    key_hex = derived_key.hex()
    compact_output = f"{key_hex} {salt_hex}\n"

    # Handle output
    if args.output:
        try:
            # Create directory if it doesn't exist
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            # Write compact format to file
            mode = 'w' if args.force else 'x'
            with open(args.output, mode) as f:
                f.write(compact_output)

            # Also print to stdout for consistency
            sys.stdout.write(compact_output)

        except FileExistsError:
            print(f"Error: File exists: {args.output}. Use --force to overwrite", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied writing to: {args.output}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # No output file: write compact format to stdout
        sys.stdout.write(compact_output)

    # Security: Clear sensitive data
    derived_key = None
    salt = None


def main():
    try:
        args = parse_arguments()

        if args.command == 'crypto':
            perform_crypto_operation(args)
        elif args.command == 'dgst':
            perform_dgst_operation(args)
        elif args.command == 'derive':
            perform_derive_operation(args)
        else:
            print(f"Error: Unknown command: {args.command}", file=sys.stderr)
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()