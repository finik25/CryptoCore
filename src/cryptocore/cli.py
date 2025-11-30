import argparse
import sys
import os

# Добавляем путь для корректных импортов при прямом запуске
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from cryptocore.file_io import read_file, write_file, derive_output_filename
    from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
except ImportError:
    # Альтернативный путь для прямого запуска
    from src.cryptocore.file_io import read_file, write_file, derive_output_filename
    from src.cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb


def parse_arguments(args=None):
    parser = argparse.ArgumentParser(
        description="CryptoCore - Minimalist Cryptographic Provider",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encryption
  cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin

  # Decryption  
  cryptocore --algorithm aes --mode ecb --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt

  # Auto-generated output filename
  cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input data.txt
        """
    )

    # Required arguments
    parser.add_argument(
        '--algorithm',
        required=True,
        choices=['aes'],
        help='Cryptographic algorithm (only aes supported)'
    )

    parser.add_argument(
        '--mode',
        required=True,
        choices=['ecb'],
        help='Mode of operation (only ecb supported)'
    )

    # Operation mode (exactly one required)
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--encrypt', action='store_true', help='Encrypt operation')
    operation_group.add_argument('--decrypt', action='store_true', help='Decrypt operation')

    # Key and file arguments
    parser.add_argument(
        '--key',
        required=True,
        help='Encryption key as hexadecimal string (16 bytes for AES-128)'
    )

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
        clean_key = key_hex.lower().replace('0x', '').replace('\\x', '')
        key_bytes = bytes.fromhex(clean_key)

        if len(key_bytes) != 16:
            raise ValueError(f"Key must be 16 bytes (128 bits) for AES-128, got {len(key_bytes)} bytes")

        return key_bytes

    except ValueError as e:
        if "non-hexadecimal number" in str(e):
            raise ValueError(f"Invalid key format: '{key_hex}'. Key must be a hexadecimal string")
        else:
            raise e


def perform_operation(args):
    try:
        key = validate_key(args.key)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    operation = 'encrypt' if args.encrypt else 'decrypt'

    try:
        input_data = read_file(args.input)
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"Error reading input file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        if operation == 'encrypt':
            output_data = encrypt_ecb(input_data, key)
        else:
            output_data = decrypt_ecb(input_data, key)
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
        write_file(output_path, output_data, overwrite=args.force)
        print(f"Success: {operation} completed -> {output_path}")
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