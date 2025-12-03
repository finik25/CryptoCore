import unittest
import tempfile
import os
import sys
import io
from contextlib import redirect_stderr, redirect_stdout
import subprocess

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(project_root, 'src'))

from src.cryptocore.cli import main, parse_arguments


class TestCLIMilestone3(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_data = b"Test data for milestone 3 CLI tests."

        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def capture_main_output(self, args):
        stderr_capture = io.StringIO()
        stdout_capture = io.StringIO()

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

    def run_cryptocore_cmd(self, args):
        cmd = [sys.executable, "-m", "cryptocore.cli"] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def test_encryption_without_key_generates_key(self):
        encrypt_args = [
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--input", self.test_file,
            "--output", os.path.join(self.temp_dir, "test.enc"),
            "--force"
        ]

        exit_code, stdout, stderr = self.capture_main_output(encrypt_args)

        # Should succeed
        self.assertEqual(exit_code, 0, f"Encryption failed: {stderr}")

        # Should contain key generation message
        self.assertIn("[INFO] Generated random key:", stdout)

        # Should contain hex key (32 hex chars)
        import re
        key_match = re.search(r'Generated random key: ([0-9a-f]{32})', stdout)
        self.assertIsNotNone(key_match, "No hex key found in output")

        # Extract the key for decryption test
        generated_key = key_match.group(1)

        # Verify the encrypted file exists
        encrypted_file = os.path.join(self.temp_dir, "test.enc")
        self.assertTrue(os.path.exists(encrypted_file))

        # Now decrypt with the generated key
        decrypt_args = [
            "--algorithm", "aes",
            "--mode", "ecb",
            "--decrypt",
            "--key", generated_key,
            "--input", encrypted_file,
            "--output", os.path.join(self.temp_dir, "test.dec.txt"),
            "--force"
        ]

        exit_code, stdout, stderr = self.capture_main_output(decrypt_args)
        self.assertEqual(exit_code, 0, f"Decryption failed: {stderr}")

        # Verify decrypted content matches original
        decrypted_file = os.path.join(self.temp_dir, "test.dec.txt")
        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()

        self.assertEqual(decrypted_data, self.test_data)

    def test_decryption_without_key_fails(self):
        # First encrypt with a known key
        key = "00112233445566778899aabbccddeeff"
        encrypt_args = [
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", key, "--input", self.test_file,
            "--output", os.path.join(self.temp_dir, "encrypted.bin"),
            "--force"
        ]

        exit_code, stdout, stderr = self.capture_main_output(encrypt_args)
        self.assertEqual(exit_code, 0)

        # Try to decrypt without key (should fail)
        decrypt_args = [
            "--algorithm", "aes",
            "--mode", "ecb",
            "--decrypt",  # No --key argument!
            "--input", os.path.join(self.temp_dir, "encrypted.bin"),
            "--force"
        ]

        exit_code, stdout, stderr = self.capture_main_output(decrypt_args)
        self.assertNotEqual(exit_code, 0)
        self.assertIn("--key is required for decryption", stderr)

    def test_weak_key_warnings(self):
        weak_keys = [
            ("00000000000000000000000000000000", "all zero bytes"),
            ("000102030405060708090a0b0c0d0e0f", "sequential bytes"),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "all identical bytes"),
            ("01230123012301230123012301230123", "repeating pattern"),
        ]

        for key_hex, description in weak_keys:
            with self.subTest(key_type=description):
                args = [
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--key", key_hex, "--input", self.test_file,
                    "--output", os.path.join(self.temp_dir, f"test_{description}.enc"),
                    "--force"
                ]

                exit_code, stdout, stderr = self.capture_main_output(args)

                # Should succeed (just warning, not error)
                self.assertEqual(exit_code, 0, f"Failed with key {key_hex}")

                # Should contain warning about weak key
                self.assertIn("Warning: Potential weak key detected", stderr)
                print(f"✓ Weak key warning for {description}: {stderr.strip()}")

    def test_encryption_with_auto_key_different_each_time(self):
        keys = set()

        for i in range(5):
            # Create a unique test file each time
            test_file = os.path.join(self.temp_dir, f"test_{i}.txt")
            with open(test_file, 'wb') as f:
                f.write(f"Test data {i}".encode())

            encrypt_args = [
                "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                "--input", test_file,
                "--output", os.path.join(self.temp_dir, f"test_{i}.enc"),
                "--force"
            ]

            result = self.run_cryptocore_cmd(encrypt_args)
            self.assertEqual(result.returncode, 0)

            # Extract key from output
            import re
            key_match = re.search(r'Generated random key: ([0-9a-f]{32})', result.stdout)
            if key_match:
                key = key_match.group(1)
                keys.add(key)

        # All 5 keys should be unique
        self.assertEqual(len(keys), 5, f"Not all keys were unique: {keys}")

    def test_csprng_used_for_iv_generation(self):
        # Encrypt with CBC mode (requires IV)
        result = self.run_cryptocore_cmd([
            "--algorithm", "aes", "--mode", "cbc", "--encrypt",
            "--input", self.test_file,
            "--output", os.path.join(self.temp_dir, "test_cbc.enc"),
            "--force"
        ])

        self.assertEqual(result.returncode, 0)

        # Should show generated IV
        self.assertIn("IV (hex):", result.stdout)

        # Verify file contains IV + ciphertext
        encrypted_file = os.path.join(self.temp_dir, "test_cbc.enc")
        with open(encrypted_file, 'rb') as f:
            data = f.read()

        # First 16 bytes should be IV
        self.assertGreaterEqual(len(data), 16)
        iv = data[:16]

        # IV should not be all zeros (very unlikely with CSPRNG)
        self.assertNotEqual(iv, bytes(16))

        print(f"✓ Generated IV: {iv.hex()}")

    def test_encryption_with_provided_key_no_generation_message(self):
        key = "00112233445566778899aabbccddeeff"

        result = self.run_cryptocore_cmd([
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", key,
            "--input", self.test_file,
            "--output", os.path.join(self.temp_dir, "test_provided.enc"),
            "--force"
        ])

        self.assertEqual(result.returncode, 0)

        # Should NOT show key generation message when key is provided
        self.assertNotIn("[INFO] Generated random key:", result.stdout)

    def test_invalid_key_format_error(self):
        invalid_keys = [
            "nothex",  # Not hex
            "001122",  # Too short
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",  # Too long
            "gggggggggggggggggggggggggggggggg",  # Invalid hex chars
        ]

        for key in invalid_keys:
            with self.subTest(key=key):
                result = self.run_cryptocore_cmd([
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--key", key,
                    "--input", self.test_file
                ])

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Error:", result.stderr)

    def test_compatibility_with_existing_functionality(self):
        # Test all modes with auto-generated key
        modes = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']

        for mode in modes:
            with self.subTest(mode=mode):
                # Encryption with auto-generated key
                encrypt_result = self.run_cryptocore_cmd([
                    "--algorithm", "aes", "--mode", mode, "--encrypt",
                    "--input", self.test_file,
                    "--output", os.path.join(self.temp_dir, f"test_{mode}.enc"),
                    "--force"
                ])

                self.assertEqual(encrypt_result.returncode, 0,
                                 f"Encryption failed for mode {mode}: {encrypt_result.stderr}")

                # Extract generated key
                import re
                key_match = re.search(r'Generated random key: ([0-9a-f]{32})', encrypt_result.stdout)
                self.assertIsNotNone(key_match, f"No key generated for mode {mode}")
                generated_key = key_match.group(1)

                # For modes with IV, we need to handle IV extraction
                encrypted_file = os.path.join(self.temp_dir, f"test_{mode}.enc")

                if mode == 'ecb':
                    # ECB: no IV in file
                    decrypt_result = self.run_cryptocore_cmd([
                        "--algorithm", "aes", "--mode", mode, "--decrypt",
                        "--key", generated_key,
                        "--input", encrypted_file,
                        "--output", os.path.join(self.temp_dir, f"test_{mode}.dec"),
                        "--force"
                    ])
                else:
                    # Other modes: IV in file
                    decrypt_result = self.run_cryptocore_cmd([
                        "--algorithm", "aes", "--mode", mode, "--decrypt",
                        "--key", generated_key,
                        "--input", encrypted_file,
                        "--output", os.path.join(self.temp_dir, f"test_{mode}.dec"),
                        "--force"
                    ])

                self.assertEqual(decrypt_result.returncode, 0,
                                 f"Decryption failed for mode {mode}: {decrypt_result.stderr}")

                # Verify round-trip
                decrypted_file = os.path.join(self.temp_dir, f"test_{mode}.dec")
                with open(decrypted_file, 'rb') as f:
                    decrypted_data = f.read()

                self.assertEqual(decrypted_data, self.test_data,
                                 f"Round-trip failed for mode {mode}")


if __name__ == "__main__":
    unittest.main()