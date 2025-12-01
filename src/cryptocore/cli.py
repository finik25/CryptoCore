import argparse
import sys
import os
import secrets

# Добавляем путь для корректных импортов при прямом запуске
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from cryptocore.file_io import read_file, write_file, derive_output_filename, read_file_with_iv, write_file_with_iv
    from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
    from cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
    from cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
    from cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
    from cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr
except ImportError:
    # Альтернативный путь для прямого запуска
    from src.cryptocore.file_io import read_file, write_file, derive_output_filename, read_file_with_iv, \
        write_file_with_iv
    from src.cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
    from src.cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
    from src.cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
    from src.cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
    from src.cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr


def parse_arguments(args=None):
    parser = argparse.ArgumentParser(
        description="CryptoCore - Minimalist Cryptographic Provider",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # ECB Encryption (no IV)
  cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt

  # CBC Encryption (IV auto-generated)
  cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt

  # CBC Decryption with provided IV
  cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --iv aabbccddeeff00112233445566778899 --input ciphertext.bin

  # CBC Decryption (IV read from file)
  cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin
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
        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
        help='Mode of operation'
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
        '--iv',
        required=False,
        help='Initialization Vector as hexadecimal string (16 bytes, only for decryption)'
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


def validate_iv(iv_hex: str) -> bytes:
    try:
        clean_iv = iv_hex.lower().replace('0x', '').replace('\\x', '')
        iv_bytes = bytes.fromhex(clean_iv)

        if len(iv_bytes) != 16:
            raise ValueError(f"IV must be 16 bytes, got {len(iv_bytes)} bytes")

        return iv_bytes

    except ValueError as e:
        if "non-hexadecimal number" in str(e):
            raise ValueError(f"Invalid IV format: '{iv_hex}'. IV must be a hexadecimal string")
        else:
            raise e


def generate_random_iv() -> bytes:
    return secrets.token_bytes(16)


def perform_operation(args):

    operation = 'encrypt' if args.encrypt else 'decrypt'

    # Validate and convert key
    try:
        key = validate_key(args.key)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

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
            # IV provided as argument - значит файл НЕ содержит IV
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
            print(f"Success: {operation} completed with generated IV -> {output_path}")
            print(f"IV (hex): {iv.hex()}")
        else:
            # Write just ciphertext/plaintext
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