import unittest
import tempfile
import os
import sys
import io
from contextlib import redirect_stderr, redirect_stdout

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(project_root, 'src'))

from src.cryptocore.cli import main, parse_arguments, validate_key, perform_operation


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_data = b"Hello, CryptoCore! This is test data for CLI."

        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def capture_main_output(self, args):
        # Capture stdout and stderr when running main
        stderr_capture = io.StringIO()
        stdout_capture = io.StringIO()

        # Replace sys.argv for testing
        original_argv = sys.argv
        try:
            sys.argv = ['cryptocore'] + args
            with redirect_stderr(stderr_capture), redirect_stdout(stdout_capture):
                try:
                    main()
                    exit_code = 0
                except SystemExit as e:
                    exit_code = e.code if e.code is not None else 0
        finally:
            sys.argv = original_argv

        return exit_code, stdout_capture.getvalue(), stderr_capture.getvalue()

    def test_cli_encrypt_decrypt_roundtrip(self):
        # Test full encrypt/decrypt cycle
        key = "00112233445566778899aabbccddeeff"

        # Encrypt
        encrypt_args = [
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", key,
            "--input", self.test_file,
            "--output", os.path.join(self.temp_dir, "test.enc"),
            "--force"
        ]

        exit_code, stdout, stderr = self.capture_main_output(encrypt_args)
        self.assertEqual(exit_code, 0, f"Encryption failed: {stderr}")

        encrypted_file = os.path.join(self.temp_dir, "test.enc")
        self.assertTrue(os.path.exists(encrypted_file))

        # Decrypt
        decrypt_args = [
            "--algorithm", "aes",
            "--mode", "ecb",
            "--decrypt",
            "--key", key,
            "--input", encrypted_file,
            "--output", os.path.join(self.temp_dir, "test.dec.txt"),
            "--force"
        ]

        exit_code, stdout, stderr = self.capture_main_output(decrypt_args)
        self.assertEqual(exit_code, 0, f"Decryption failed: {stderr}")

        decrypted_file = os.path.join(self.temp_dir, "test.dec.txt")
        self.assertTrue(os.path.exists(decrypted_file))

        # Verify content matches original
        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, self.test_data)

    def test_cli_binary_file_support(self):
        # Test with binary data
        binary_file = os.path.join(self.temp_dir, "binary.bin")
        binary_data = bytes(range(256))  # All possible byte values
        with open(binary_file, 'wb') as f:
            f.write(binary_data)

        key = "00112233445566778899aabbccddeeff"

        # Encrypt binary file
        encrypt_args = [
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", key, "--input", binary_file,
            "--output", os.path.join(self.temp_dir, "binary.enc"),
            "--force"
        ]

        exit_code, stdout, stderr = self.capture_main_output(encrypt_args)
        self.assertEqual(exit_code, 0, f"Binary encryption failed: {stderr}")

        # Decrypt binary file
        encrypted_file = os.path.join(self.temp_dir, "binary.enc")
        decrypt_args = [
            "--algorithm", "aes", "--mode", "ecb", "--decrypt",
            "--key", key, "--input", encrypted_file,
            "--output", os.path.join(self.temp_dir, "binary.dec.bin"),
            "--force"
        ]

        exit_code, stdout, stderr = self.capture_main_output(decrypt_args)
        self.assertEqual(exit_code, 0, f"Binary decryption failed: {stderr}")

        # Verify binary data integrity
        decrypted_file = os.path.join(self.temp_dir, "binary.dec.bin")
        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, binary_data)

    def test_cli_invalid_key_length(self):
        # Test with invalid key length
        args = [
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", "001122",  # Too short
            "--input", self.test_file
        ]

        exit_code, stdout, stderr = self.capture_main_output(args)
        self.assertNotEqual(exit_code, 0)
        self.assertIn("Key must be 16 bytes", stderr)

    def test_cli_invalid_key_format(self):
        # Test with non-hex key
        args = [
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", "invalid_key_format",
            "--input", self.test_file
        ]

        exit_code, stdout, stderr = self.capture_main_output(args)
        self.assertNotEqual(exit_code, 0)
        self.assertIn("Invalid key format", stderr)

    def test_cli_missing_required_args(self):
        # Test missing algorithm
        args = ["--mode", "ecb", "--encrypt", "--key", "00112233445566778899aabbccddeeff"]
        exit_code, stdout, stderr = self.capture_main_output(args)
        self.assertNotEqual(exit_code, 0)

    def test_cli_nonexistent_input_file(self):
        args = [
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", "00112233445566778899aabbccddeeff",
            "--input", "/nonexistent/file.txt"
        ]

        exit_code, stdout, stderr = self.capture_main_output(args)
        self.assertNotEqual(exit_code, 0)
        self.assertIn("Input file not found", stderr)

    def test_cli_conflicting_operations(self):
        # Test both encrypt and decrypt flags
        args = [
            "--algorithm", "aes", "--mode", "ecb",
            "--encrypt", "--decrypt",  # Conflict
            "--key", "00112233445566778899aabbccddeeff",
            "--input", self.test_file
        ]

        exit_code, stdout, stderr = self.capture_main_output(args)
        self.assertNotEqual(exit_code, 0)

    def test_validate_key_function(self):
        # Test valid key
        key_bytes = validate_key("00112233445566778899aabbccddeeff")
        self.assertEqual(len(key_bytes), 16)

        # Test invalid hex
        with self.assertRaises(ValueError):
            validate_key("invalid")

        # Test wrong length
        with self.assertRaises(ValueError):
            validate_key("001122")

    def test_parse_arguments_function(self):
        # Test valid arguments
        args = parse_arguments([
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", "00112233445566778899aabbccddeeff",
            "--input", "test.txt", "--output", "out.bin"
        ])
        self.assertEqual(args.algorithm, "aes")
        self.assertEqual(args.mode, "ecb")
        self.assertTrue(args.encrypt)
        self.assertFalse(args.decrypt)


if __name__ == "__main__":
    unittest.main()