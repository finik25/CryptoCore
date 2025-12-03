import argparse
import sys
import os
import secrets
from typing import Optional

# Add path for correct imports when running directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from cryptocore.file_io import read_file, write_file, derive_output_filename, read_file_with_iv, write_file_with_iv
    from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
    from cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
    from cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
    from cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
    from cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr
    from cryptocore.utils.csprng import generate_random_key, generate_random_iv
except ImportError:
    # Alternative path for direct execution
    from src.cryptocore.file_io import read_file, write_file, derive_output_filename, read_file_with_iv, \
        write_file_with_iv
    from src.cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
    from src.cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
    from src.cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
    from src.cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
    from src.cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr
    from src.cryptocore.utils.csprng import generate_random_key, generate_random_iv


def parse_arguments(args=None):
    parser = argparse.ArgumentParser(
        description="CryptoCore - Minimalist Cryptographic Provider",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # ECB Encryption with provided key
  cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt

  # CBC Encryption with auto-generated key
  cryptocore --algorithm aes --mode cbc --encrypt --input plaintext.txt
  # Output will display the generated key

  # CBC Decryption with provided IV
  cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --iv aabbccddeeff00112233445566778899 --input ciphertext.bin

  # CBC Decryption (IV read from file)
  cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin

  # Encryption with weak key warning
  cryptocore --algorithm aes --mode cbc --encrypt --key 00000000000000000000000000000000 --input plaintext.txt
  # Warning will be displayed about weak key

Key generation rules:
  - Encryption: --key is optional. If not provided, a secure random key will be generated and displayed.
  - Decryption: --key is mandatory. Must provide the key used for encryption.
"""
    )

    # Required arguments
    parser.add_argument(
        '--algorithm',
        required=True,
        choices=['aes'],
        help='Cryptographic algorithm (only aes supported for now)'
    )

    parser.add_argument(
        '--mode',
        required=True,
        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
        help='Mode of operation'
    )

    # Operation mode (exactly one required)
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--encrypt', action='store_true', help='Encrypt operation')
    operation_group.add_argument('--decrypt', action='store_true', help='Decrypt operation')

    # Key argument (optional for encryption, required for decryption)
    parser.add_argument(
        '--key',
        required=False,
        help='Encryption key as hexadecimal string (16 bytes for AES-128). '
             'For encryption: optional (random key generated if not provided). '
             'For decryption: mandatory.'
    )

    # IV argument (optional for decryption, ignored for encryption)
    parser.add_argument(
        '--iv',
        required=False,
        help='Initialization Vector as hexadecimal string (16 bytes). '
             'Only used for decryption when IV is not stored in the file. '
             'Ignored for encryption (IV is auto-generated).'
    )

    # File arguments
    parser.add_argument(
        '--input',
        required=True,
        help='Input file path'
    )

    parser.add_argument(
        '--output',
        required=False,
        help='Output file path (auto-generated if not provided)'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Overwrite output file if it exists'
    )

    return parser.parse_args(args)


def validate_key(key_hex: str) -> bytes:
    try:
        # Clean up hex string (remove 0x, \x prefixes, spaces)
        clean_key = key_hex.lower().replace('0x', '').replace('\\x', '').replace(' ', '')

        # Convert hex to bytes
        key_bytes = bytes.fromhex(clean_key)

        # Check length for AES-128
        if len(key_bytes) != 16:
            raise ValueError(f"Key must be 16 bytes (128 bits) for AES-128, got {len(key_bytes)} bytes")

        return key_bytes

    except ValueError as e:
        if "non-hexadecimal number" in str(e):
            raise ValueError(f"Invalid key format: '{key_hex}'. Key must be a hexadecimal string (32 hex chars)")
        else:
            raise e


def validate_iv(iv_hex: str) -> bytes:
    try:
        # Clean up hex string
        clean_iv = iv_hex.lower().replace('0x', '').replace('\\x', '').replace(' ', '')
        iv_bytes = bytes.fromhex(clean_iv)

        # Check length
        if len(iv_bytes) != 16:
            raise ValueError(f"IV must be 16 bytes, got {len(iv_bytes)} bytes")

        return iv_bytes

    except ValueError as e:
        if "non-hexadecimal number" in str(e):
            raise ValueError(f"Invalid IV format: '{iv_hex}'. IV must be a hexadecimal string (32 hex chars)")
        else:
            raise e


def check_weak_key(key: bytes):
    warnings = []

    # Check for all zero bytes
    if all(b == 0 for b in key):
        warnings.append("Key consists of all zero bytes")

    # Check for sequential bytes (0, 1, 2, 3, ...)
    if all(key[i] == i for i in range(len(key))):
        warnings.append("Key consists of sequential bytes (0, 1, 2, ...)")

    # Check for all same bytes
    if all(b == key[0] for b in key):
        warnings.append("Key consists of all identical bytes")

    # Check for repeating patterns (e.g., 012301230123...)
    if len(key) >= 4:
        pattern = key[:4]
        # Check if pattern repeats throughout the key
        repeats_cleanly = True
        for i in range(0, len(key), 4):
            if i + 4 <= len(key) and key[i:i + 4] != pattern:
                repeats_cleanly = False
                break
        if repeats_cleanly:
            warnings.append("Key appears to be a repeating 4-byte pattern")

    # Print warnings if any
    if warnings:
        warning_msg = "Warning: Potential weak key detected - "
        if len(warnings) == 1:
            warning_msg += warnings[0]
        else:
            warning_msg += "; ".join(warnings)
        print(f"{warning_msg}", file=sys.stderr)
        print(f"  Key (hex): {key.hex()}", file=sys.stderr)


def perform_operation(args):
    operation = 'encrypt' if args.encrypt else 'decrypt'

    # Key handling logic
    generated_key = None
    if operation == 'encrypt':
        if args.key is None:
            # Generate random key for encryption
            generated_key = generate_random_key()
            key = generated_key
            print(f"[INFO] Generated random key: {key.hex()}", file=sys.stdout)
        else:
            # Validate provided key
            try:
                key = validate_key(args.key)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

            # Check for weak keys
            check_weak_key(key)
    else:  # decryption
        if args.key is None:
            print(f"Error: --key is required for decryption", file=sys.stderr)
            sys.exit(1)

        # Validate provided key
        try:
            key = validate_key(args.key)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        # Check for weak keys (warning only for decryption)
        check_weak_key(key)

    # Validate IV usage for ECB mode
    if args.mode == 'ecb' and args.iv:
        print(f"Error: --iv not supported for ECB mode", file=sys.stderr)
        sys.exit(1)

    # Handle IV based on operation
    iv = None
    input_data = None

    if operation == 'encrypt':
        # Read plaintext for encryption
        try:
            input_data = read_file(args.input)
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(f"Error reading input file: {e}", file=sys.stderr)
            sys.exit(1)

        # Warn if IV provided during encryption
        if args.iv:
            print(f"Warning: --iv is ignored during encryption. IV will be generated randomly.", file=sys.stderr)

        # Generate IV for modes that need it
        if args.mode != 'ecb':
            iv = generate_random_iv()

    else:  # decryption
        if args.iv:
            # IV provided as argument - file does NOT contain IV
            try:
                iv = validate_iv(args.iv)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

            # Read ciphertext WITHOUT IV
            try:
                input_data = read_file(args.input)
            except (FileNotFoundError, PermissionError, IOError) as e:
                print(f"Error reading input file: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.mode != 'ecb':
            # No IV provided - read IV from first 16 bytes of file
            try:
                iv, input_data = read_file_with_iv(args.input)
            except (FileNotFoundError, PermissionError, IOError, ValueError) as e:
                print(f"Error reading input file: {e}", file=sys.stderr)
                sys.exit(1)

        else:
            # ECB decryption, no IV needed
            try:
                input_data = read_file(args.input)
            except (FileNotFoundError, PermissionError, IOError) as e:
                print(f"Error reading input file: {e}", file=sys.stderr)
                sys.exit(1)

    # Perform cryptographic operation
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

    # Determine output filename
    if args.output:
        output_path = args.output
    else:
        output_path = derive_output_filename(args.input, operation, args.algorithm, args.mode)

    # Write output file as binary
    try:
        if operation == 'encrypt' and iv is not None:
            # Write IV + ciphertext for encryption with IV modes
            write_file_with_iv(output_path, iv, output_data, overwrite=args.force)

            # Print summary information
            print(f"Success: {operation} completed", file=sys.stdout)
            print(f"  Output file: {output_path}", file=sys.stdout)
            print(f"  IV (hex): {iv.hex()}", file=sys.stdout)
            if generated_key:
                print(f"  Key (hex): {key.hex()} (auto-generated)", file=sys.stdout)
        else:
            # Write just ciphertext/plaintext
            write_file(output_path, output_data, overwrite=args.force)

            # Print summary information
            print(f"Success: {operation} completed", file=sys.stdout)
            print(f"  Output file: {output_path}", file=sys.stdout)
            if generated_key:
                print(f"  Key (hex): {key.hex()} (auto-generated)", file=sys.stdout)
    except (FileExistsError, PermissionError, IOError) as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    try:
        args = parse_arguments()
        perform_operation(args)
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