import unittest
import tempfile
import os
import subprocess
import sys


class TestGCMCLI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run_cryptocore(self, args):
        cmd = [sys.executable, '-m', 'src.cryptocore.cli'] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            cwd=self.project_root
        )
        result.stdout = result.stdout.decode('utf-8', errors='ignore')
        result.stderr = result.stderr.decode('utf-8', errors='ignore')
        return result

    def test_gcm_basic_encrypt_decrypt(self):
        """Test basic GCM encryption and decryption via CLI."""
        # Create binary test file
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, 'wb') as f:
            f.write(b"Hello GCM world!" * 10)

        key = "00112233445566778899aabbccddeeff"

        # Encrypt with GCM
        encrypted_file = os.path.join(self.temp_dir, "test.gcm")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--encrypt',
            '--key', key,
            '--input', test_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0,
                         f"GCM encryption failed: {result.stderr}")
        self.assertIn("Success: GCM encryption completed", result.stdout)

        # Verify output file exists and has correct format
        self.assertTrue(os.path.exists(encrypted_file))
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        # Should have at least nonce(12) + tag(16) = 28 bytes
        self.assertGreaterEqual(len(encrypted_data), 28)

        # Decrypt
        decrypted_file = os.path.join(self.temp_dir, "decrypted.bin")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--decrypt',
            '--key', key,
            '--input', encrypted_file,
            '--output', decrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0,
                         f"GCM decryption failed: {result.stderr}")
        self.assertIn("Success: GCM decryption completed", result.stdout)

        # Compare files byte by byte
        with open(test_file, 'rb') as f:
            original = f.read()
        with open(decrypted_file, 'rb') as f:
            decrypted = f.read()

        self.assertEqual(original, decrypted,
                         "Decrypted data doesn't match original")

    def test_gcm_with_aad_success(self):
        """Test GCM with correct Associated Authenticated Data."""
        test_file = os.path.join(self.temp_dir, "secret.bin")
        with open(test_file, 'wb') as f:
            f.write(b"Top secret message" * 5)

        key = "00112233445566778899aabbccddeeff"
        aad = "aabbccddeeff00112233445566778899"

        # Encrypt with AAD
        encrypted_file = os.path.join(self.temp_dir, "secret.gcm")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--encrypt',
            '--key', key,
            '--aad', aad,
            '--input', test_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0)

        # Decrypt with correct AAD (should succeed)
        decrypted_file = os.path.join(self.temp_dir, "decrypted.bin")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--decrypt',
            '--key', key,
            '--aad', aad,
            '--input', encrypted_file,
            '--output', decrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0)

        # Verify decryption
        with open(test_file, 'rb') as f:
            original = f.read()
        with open(decrypted_file, 'rb') as f:
            decrypted = f.read()

        self.assertEqual(original, decrypted)

    def test_gcm_with_wrong_aad_failure(self):
        """Test GCM fails with wrong Associated Authenticated Data."""
        test_file = os.path.join(self.temp_dir, "data.bin")
        with open(test_file, 'wb') as f:
            f.write(b"Important data")

        key = "00112233445566778899aabbccddeeff"
        correct_aad = "aabbccddeeff00112233445566778899"
        wrong_aad = "ffeeddccbbaa99887766554433221100"

        # Encrypt with correct AAD
        encrypted_file = os.path.join(self.temp_dir, "data.gcm")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--encrypt',
            '--key', key,
            '--aad', correct_aad,
            '--input', test_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0)

        # Try to decrypt with wrong AAD (should fail catastrophically)
        should_fail_file = os.path.join(self.temp_dir, "should_fail.bin")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--decrypt',
            '--key', key,
            '--aad', wrong_aad,
            '--input', encrypted_file,
            '--output', should_fail_file,
            '--force'
        ])

        self.assertNotEqual(result.returncode, 0,
                            "Should fail with wrong AAD")
        self.assertIn("Authentication failed", result.stderr)

        # Verify that no output file was created (catastrophic failure)
        self.assertFalse(os.path.exists(should_fail_file),
                         "Output file should not be created on auth failure")

    def test_gcm_tamper_detection(self):
        """Test that ciphertext tampering is detected."""
        test_file = os.path.join(self.temp_dir, "important.bin")
        with open(test_file, 'wb') as f:
            f.write(b"Very important data that must not be tampered")

        key = "00112233445566778899aabbccddeeff"

        # Encrypt
        encrypted_file = os.path.join(self.temp_dir, "important.gcm")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--encrypt',
            '--key', key,
            '--input', test_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0)

        # Tamper with the encrypted file
        with open(encrypted_file, 'rb') as f:
            data = f.read()

        # Flip one bit in the ciphertext (after nonce)
        tampered = bytearray(data)
        if len(tampered) > 20:  # Ensure we're past the 12-byte nonce
            tampered[15] ^= 0x01  # Flip a bit in the ciphertext

        tampered_file = os.path.join(self.temp_dir, "tampered.gcm")
        with open(tampered_file, 'wb') as f:
            f.write(tampered)

        # Try to decrypt tampered file (should fail)
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--decrypt',
            '--key', key,
            '--input', tampered_file,
            '--output', os.path.join(self.temp_dir, "should_fail.bin"),
            '--force'
        ])

        self.assertNotEqual(result.returncode, 0,
                            "Should fail with tampered ciphertext")
        self.assertIn("Authentication failed", result.stderr)

    def test_gcm_empty_aad(self):
        """Test GCM works with empty AAD."""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, 'wb') as f:
            f.write(b"Data without AAD")

        key = "00112233445566778899aabbccddeeff"

        # Encrypt without AAD (empty AAD)
        encrypted_file = os.path.join(self.temp_dir, "test.gcm")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--encrypt',
            '--key', key,
            # No --aad flag means empty AAD
            '--input', test_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0)

        # Decrypt without AAD (empty AAD)
        decrypted_file = os.path.join(self.temp_dir, "decrypted.bin")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--decrypt',
            '--key', key,
            # No --aad flag means empty AAD
            '--input', encrypted_file,
            '--output', decrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0)

        # Verify
        with open(test_file, 'rb') as f:
            original = f.read()
        with open(decrypted_file, 'rb') as f:
            decrypted = f.read()

        self.assertEqual(original, decrypted)

    def test_gcm_auto_key_generation(self):
        """Test that GCM generates random key when --key is not provided."""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, 'wb') as f:
            f.write(b"Test auto key generation")

        # Encrypt without --key (should generate random key)
        encrypted_file = os.path.join(self.temp_dir, "test.gcm")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--encrypt',
            # No --key flag
            '--input', test_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0)
        self.assertIn("[INFO] Generated random key:", result.stdout)
        self.assertIn("Success: GCM encryption completed", result.stdout)

        # Extract the generated key from output
        import re
        key_match = re.search(r'Key \(hex\): ([0-9a-f]+)', result.stdout)
        self.assertIsNotNone(key_match, "Key should be displayed in output")
        generated_key = key_match.group(1)

        # Now decrypt with the generated key
        decrypted_file = os.path.join(self.temp_dir, "decrypted.bin")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--decrypt',
            '--key', generated_key,
            '--input', encrypted_file,
            '--output', decrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0)

        # Verify
        with open(test_file, 'rb') as f:
            original = f.read()
        with open(decrypted_file, 'rb') as f:
            decrypted = f.read()

        self.assertEqual(original, decrypted)

    def test_gcm_iv_not_supported_message(self):
        """Test that --iv is not supported for GCM encryption."""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, 'wb') as f:
            f.write(b"Test data")

        key = "00112233445566778899aabbccddeeff"

        # Try to encrypt with --iv (should show warning)
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--encrypt',
            '--key', key,
            '--iv', '000102030405060708090a0b',
            '--input', test_file,
            '--output', os.path.join(self.temp_dir, "test.gcm"),
            '--force'
        ])

        # Should still succeed, but IV will be used as nonce
        self.assertEqual(result.returncode, 0)

    def test_gcm_invalid_nonce_length(self):
        """Test that invalid nonce length is rejected."""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, 'wb') as f:
            f.write(b"Test data")

        key = "00112233445566778899aabbccddeeff"

        # Try to decrypt with wrong nonce length (16 bytes instead of 12)
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'gcm',
            '--decrypt',
            '--key', key,
            '--iv', '000102030405060708090a0b0c0d0e0f',  # 16 bytes, not 12
            '--input', test_file,
            '--output', os.path.join(self.temp_dir, "output.bin"),
            '--force'
        ])

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be 12 bytes", result.stderr)


if __name__ == "__main__":
    unittest.main()