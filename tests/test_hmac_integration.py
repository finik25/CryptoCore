import unittest
import tempfile
import os
import sys
import subprocess

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(project_root, 'src'))


class TestHMACIntegration(unittest.TestCase):
    """Integration tests for HMAC functionality"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run_cryptocore(self, args):
        """Run CryptoCore CLI command"""
        cmd = [sys.executable, '-m', 'src.cryptocore.cli'] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            cwd=project_root
        )
        # Decode output
        result.stdout = result.stdout.decode('utf-8', errors='ignore')
        result.stderr = result.stderr.decode('utf-8', errors='ignore')
        return result

    def test_full_hmac_workflow(self):
        """Test complete HMAC workflow: generate, verify, tamper detection"""
        # 1. Create test file
        test_file = os.path.join(self.temp_dir, "document.txt")
        with open(test_file, 'w') as f:
            f.write("Important document content\n" * 10)

        # 2. Generate HMAC
        key = "00112233445566778899aabbccddeeff"
        hmac_file = os.path.join(self.temp_dir, "document.hmac")

        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', key,
            '--input', test_file,
            '--output', hmac_file
        ])

        self.assertEqual(result.returncode, 0, f"HMAC generation failed: {result.stderr}")
        self.assertIn("HMAC written to:", result.stdout)

        # 3. Verify HMAC (should succeed)
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', key,
            '--input', test_file,
            '--verify', hmac_file
        ])

        self.assertEqual(result.returncode, 0, f"HMAC verification failed: {result.stderr}")
        self.assertIn("[OK] HMAC verification successful", result.stdout)

        # 4. Tamper with file and verify (should fail)
        with open(test_file, 'a') as f:
            f.write("TAMPERED DATA")

        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', key,
            '--input', test_file,
            '--verify', hmac_file
        ])

        self.assertNotEqual(result.returncode, 0, "Should fail for tampered file")
        self.assertIn("[ERROR] HMAC verification failed", result.stderr)

        # 5. Use wrong key (should fail)
        wrong_key = "ffeeddccbbaa99887766554433221100"
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', wrong_key,
            '--input', test_file,
            '--verify', hmac_file
        ])

        self.assertNotEqual(result.returncode, 0, "Should fail with wrong key")
        self.assertIn("[ERROR] HMAC verification failed", result.stderr)

    def test_hmac_with_encryption_workflow(self):
        """Test HMAC used together with encryption workflow"""
        # 1. Create test file
        plaintext_file = os.path.join(self.temp_dir, "secret.txt")
        with open(plaintext_file, 'w') as f:
            f.write("Top secret message!\n" * 5)

        # 2. Compute HMAC of plaintext
        key = "00112233445566778899aabbccddeeff"
        hmac_file = os.path.join(self.temp_dir, "secret.hmac")

        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', key,
            '--input', plaintext_file,
            '--output', hmac_file
        ])

        self.assertEqual(result.returncode, 0)

        # 3. Encrypt the file
        encrypted_file = os.path.join(self.temp_dir, "secret.enc")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'cbc',
            '--encrypt',
            '--key', key,
            '--input', plaintext_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0, f"Encryption failed: {result.stderr}")

        # 4. Decrypt the file
        decrypted_file = os.path.join(self.temp_dir, "secret.dec.txt")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'cbc',
            '--decrypt',
            '--key', key,
            '--input', encrypted_file,
            '--output', decrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0, f"Decryption failed: {result.stderr}")

        # 5. Verify HMAC of decrypted file (should match original)
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', key,
            '--input', decrypted_file,
            '--verify', hmac_file
        ])

        self.assertEqual(result.returncode, 0,
                         f"HMAC verification of decrypted file failed: {result.stderr}")
        self.assertIn("[OK] HMAC verification successful", result.stdout)

    def test_legacy_mode_still_works(self):
        """Test that legacy encryption mode still works alongside new HMAC features"""
        # 1. Create test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("Test data\n")

        # 2. Use legacy mode for encryption (without subcommand)
        encrypted_file = os.path.join(self.temp_dir, "test.enc")
        key = "00112233445566778899aabbccddeeff"

        result = self.run_cryptocore([
            '--algorithm', 'aes',
            '--mode', 'ecb',
            '--encrypt',
            '--key', key,
            '--input', test_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0, f"Legacy mode encryption failed: {result.stderr}")

        # 3. Use new HMAC feature on the same file
        hmac_file = os.path.join(self.temp_dir, "test.hmac")
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', key,
            '--input', test_file,
            '--output', hmac_file
        ])

        self.assertEqual(result.returncode, 0, f"HMAC with legacy mode failed: {result.stderr}")

    def test_error_handling_integration(self):
        """Test error handling across different commands"""
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("Test")

        # Test 1: HMAC without key
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--input', test_file
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--key is required", result.stderr)

        # Test 2: HMAC with SHA3-256 (not supported)
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha3-256',
            '--hmac',
            '--key', '00112233445566778899aabbccddeeff',
            '--input', test_file
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only supports SHA-256", result.stderr)

        # Test 3: Regular hash still works
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha3-256',
            '--input', test_file
        ])
        self.assertEqual(result.returncode, 0)

        # Test 4: Crypto operations still work
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'cbc',
            '--encrypt',
            '--input', test_file,
            '--output', os.path.join(self.temp_dir, "test.enc"),
            '--force'
        ])
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()