import argparse
import sys
import os
from typing import Optional, List

try:
    # When the package is installed
    from cryptocore.utils.csprng import generate_random_key, generate_random_iv
    from cryptocore.file_io import read_file, write_file, derive_output_filename, read_file_with_iv, write_file_with_iv
    from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
    from cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
    from cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
    from cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
    from cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr

    _import_from_package = True
except ImportError:
    try:
        # When we launch from source
        from src.cryptocore.utils.csprng import generate_random_key, generate_random_iv
        from src.cryptocore.file_io import read_file, write_file, derive_output_filename, read_file_with_iv, \
            write_file_with_iv
        from src.cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
        from src.cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
        from src.cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
        from src.cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
        from src.cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr

        _import_from_package = False
    except ImportError as e:
        print(f"Error importing cryptocore modules: {e}", file=sys.stderr)
        sys.exit(1)

try:
    if _import_from_package:
        from cryptocore.hash.sha256 import SHA256
        from cryptocore.hash.sha3_256 import SHA3_256
    else:
        from src.cryptocore.hash.sha256 import SHA256
        from src.cryptocore.hash.sha3_256 import SHA3_256
    _hash_available = True
except ImportError:
    _hash_available = False
    SHA256 = None
    SHA3_256 = None


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
        epilog="""
Examples:
  # Encryption with subcommand (recommended)
  cryptocore crypto --algorithm aes --mode cbc --encrypt --input plaintext.txt

  # Hash computation (stdout)
  cryptocore dgst --algorithm sha256 --input document.pdf

  # Hash computation to file
  cryptocore dgst --algorithm sha256 --input document.pdf --output hash.txt

  # Hash computation with force overwrite
  cryptocore dgst --algorithm sha256 --input document.pdf --output hash.txt --force

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
        dgst_parser = subparsers.add_parser('dgst', help='Compute cryptographic hash of files')
        _add_dgst_arguments(dgst_parser)

    return parser.parse_args(args)


def _parse_legacy(args):
    parser = argparse.ArgumentParser(
        description="CryptoCore - Minimalist Cryptographic Provider (legacy mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Note: This is legacy mode. For new features like hashing, use subcommands.
"""
    )

    _add_crypto_arguments(parser)
    parsed_args = parser.parse_args(args)
    parsed_args.command = 'crypto'
    return parsed_args


def _add_crypto_arguments(parser):
    parser.add_argument('--algorithm', required=True, choices=['aes'], help='Cryptographic algorithm')
    parser.add_argument('--mode', required=True, choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'], help='Mode of operation')

    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--encrypt', action='store_true')
    operation_group.add_argument('--decrypt', action='store_true')

    parser.add_argument('--key', required=False, help='Encryption key as hexadecimal string')
    parser.add_argument('--iv', required=False, help='Initialization Vector as hexadecimal string')
    parser.add_argument('--input', required=True, help='Input file path')
    parser.add_argument('--output', required=False, help='Output file path')
    parser.add_argument('--force', action='store_true', help='Overwrite output file if it exists')


def _add_dgst_arguments(parser):
    parser.add_argument('--algorithm', required=True, choices=['sha256', 'sha3-256'], help='Hash algorithm')
    parser.add_argument('--input', required=True, help='Input file path (use - for stdin)')
    parser.add_argument('--output', required=False, help='Output file for hash (optional)')
    parser.add_argument('--force', action='store_true',
                        help='Overwrite output file if it exists (optional)')


def validate_key(key_hex: str) -> bytes:
    try:
        clean_key = key_hex.lower().replace('0x', '').replace('\\x', '').replace(' ', '')
        key_bytes = bytes.fromhex(clean_key)

        if len(key_bytes) != 16:
            raise ValueError(f"Key must be 16 bytes, got {len(key_bytes)} bytes")

        return key_bytes

    except ValueError as e:
        if "non-hexadecimal number" in str(e):
            raise ValueError(f"Invalid key format: '{key_hex}'. Must be 32 hex chars")
        else:
            raise e


def validate_iv(iv_hex: str) -> bytes:
    try:
        clean_iv = iv_hex.lower().replace('0x', '').replace('\\x', '').replace(' ', '')
        iv_bytes = bytes.fromhex(clean_iv)

        if len(iv_bytes) != 16:
            raise ValueError(f"IV must be 16 bytes, got {len(iv_bytes)} bytes")

        return iv_bytes

    except ValueError as e:
        if "non-hexadecimal number" in str(e):
            raise ValueError(f"Invalid IV format: '{iv_hex}'. Must be 32 hex chars")
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


def perform_crypto_operation(args):
    operation = 'encrypt' if args.encrypt else 'decrypt'

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
                iv = validate_iv(args.iv)
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


def perform_dgst_operation(args):
    if not _hash_available:
        print("Error: Hash functionality not available", file=sys.stderr)
        sys.exit(1)

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

    if args.output:
        try:
            # Create directory if it doesn't exist
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            # Write to file with appropriate mode
            mode = 'w' if args.force else 'x'  # 'x' mode fails if file exists
            with open(args.output, mode) as f:
                f.write(output_line)
            print(f"Hash written to: {args.output}", file=sys.stdout)
        except FileExistsError:
            # This should not happen since we checked above, but just in case
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
        if sys.stdout.isatty():
            print(output_line, end='')
        else:
            sys.stdout.write(output_line)


def main():
    try:
        args = parse_arguments()

        if args.command == 'crypto':
            perform_crypto_operation(args)
        elif args.command == 'dgst':
            perform_dgst_operation(args)
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