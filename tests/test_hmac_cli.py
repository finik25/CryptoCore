import unittest
import tempfile
import os
import sys
import subprocess
import hashlib
import hmac as builtin_hmac

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(project_root, 'src'))


class TestHMACCli(unittest.TestCase):
    """Test HMAC CLI functionality (M5)"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_data = b"Test data for HMAC CLI tests. " * 10

        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)

        # Test key for HMAC
        self.test_key = "00112233445566778899aabbccddeeff"
        self.test_key_bytes = bytes.fromhex(self.test_key)

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
        # Decode output with error handling for cross-platform compatibility
        result.stdout = result.stdout.decode('utf-8', errors='ignore')
        result.stderr = result.stderr.decode('utf-8', errors='ignore')
        return result

    def test_hmac_basic_computation(self):
        """Test basic HMAC computation"""
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file
        ])

        self.assertEqual(result.returncode, 0, f"HMAC computation failed: {result.stderr}")

        # Parse output (format: "HMAC_VALUE  FILENAME")
        output_lines = result.stdout.strip().split('\n')
        self.assertEqual(len(output_lines), 1)

        hmac_hex, filename = output_lines[0].split()
        self.assertEqual(filename, self.test_file)
        self.assertEqual(len(hmac_hex), 64)  # 32 bytes = 64 hex chars

        # Verify against Python's built-in HMAC
        expected_hmac = builtin_hmac.new(
            self.test_key_bytes,
            self.test_data,
            hashlib.sha256
        ).hexdigest()

        self.assertEqual(hmac_hex, expected_hmac,
                         f"HMAC mismatch\nComputed: {hmac_hex}\nExpected: {expected_hmac}")

    def test_hmac_with_output_file(self):
        """Test HMAC computation with output to file"""
        output_file = os.path.join(self.temp_dir, "hmac_output.txt")

        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file,
            '--output', output_file
        ])

        self.assertEqual(result.returncode, 0, f"HMAC with output failed: {result.stderr}")

        # Check that file was created
        self.assertTrue(os.path.exists(output_file))

        # Read and verify content
        with open(output_file, 'r') as f:
            content = f.read().strip()

        hmac_hex, filename = content.split()
        self.assertEqual(filename, self.test_file)

        # Verify HMAC value
        expected_hmac = builtin_hmac.new(
            self.test_key_bytes,
            self.test_data,
            hashlib.sha256
        ).hexdigest()

        self.assertEqual(hmac_hex, expected_hmac)

    def test_hmac_with_force_flag(self):
        """Test HMAC with --force flag to overwrite existing file"""
        output_file = os.path.join(self.temp_dir, "hmac_output.txt")

        # Create file first
        with open(output_file, 'w') as f:
            f.write("old content")

        # Try without --force (should fail)
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file,
            '--output', output_file
        ])

        self.assertNotEqual(result.returncode, 0, "Should fail without --force")
        self.assertIn("File exists", result.stderr)

        # Try with --force (should succeed)
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file,
            '--output', output_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0, f"HMAC with --force failed: {result.stderr}")

        # Verify file was overwritten
        with open(output_file, 'r') as f:
            content = f.read().strip()

        self.assertNotEqual(content, "old content")
        self.assertIn(" ", content)  # Should have space between HMAC and filename

    def test_hmac_verification_success(self):
        """Test HMAC verification with correct HMAC"""
        # First compute HMAC and save to file
        hmac_file = os.path.join(self.temp_dir, "expected.hmac")

        compute_result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file,
            '--output', hmac_file
        ])

        self.assertEqual(compute_result.returncode, 0)

        # Now verify
        verify_result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file,
            '--verify', hmac_file
        ])

        self.assertEqual(verify_result.returncode, 0, f"HMAC verification failed: {verify_result.stderr}")
        self.assertIn("[OK] HMAC verification successful", verify_result.stdout)

    def test_hmac_verification_failure_tampered_file(self):
        """Test HMAC verification fails when file is tampered"""
        # First compute HMAC for original file
        hmac_file = os.path.join(self.temp_dir, "expected.hmac")

        compute_result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file,
            '--output', hmac_file
        ])

        self.assertEqual(compute_result.returncode, 0)

        # Tamper with the file
        tampered_file = os.path.join(self.temp_dir, "tampered.txt")
        with open(tampered_file, 'wb') as f:
            f.write(self.test_data + b"TAMPERED")

        # Verify with tampered file (should fail)
        verify_result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', tampered_file,
            '--verify', hmac_file
        ])

        self.assertNotEqual(verify_result.returncode, 0, "Should fail for tampered file")
        self.assertIn("[ERROR] HMAC verification failed", verify_result.stderr)

    def test_hmac_verification_failure_wrong_key(self):
        """Test HMAC verification fails with wrong key"""
        # Compute HMAC with key1
        hmac_file = os.path.join(self.temp_dir, "expected.hmac")

        compute_result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,  # Key1
            '--input', self.test_file,
            '--output', hmac_file
        ])

        self.assertEqual(compute_result.returncode, 0)

        # Verify with different key (should fail)
        wrong_key = "ffeeddccbbaa99887766554433221100"
        verify_result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', wrong_key,  # Different key
            '--input', self.test_file,
            '--verify', hmac_file
        ])

        self.assertNotEqual(verify_result.returncode, 0, "Should fail with wrong key")
        self.assertIn("[ERROR] HMAC verification failed", verify_result.stderr)

    def test_hmac_without_key_error(self):
        """Test that HMAC requires --key argument"""
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',  # No --key!
            '--input', self.test_file
        ])

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--key is required when using --hmac", result.stderr)

    def test_hmac_with_sha3_256_error(self):
        """Test that HMAC only supports SHA-256"""
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha3-256',  # Not supported for HMAC
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file
        ])

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HMAC currently only supports SHA-256 algorithm", result.stderr)

    def test_hmac_key_various_lengths(self):
        """Test HMAC with keys of various lengths"""
        test_cases = [
            ("01", "1-byte key"),
            ("00112233445566778899aabbccddeeff", "16-byte key"),
            ("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "32-byte key"),
            ("00" * 100, "100-byte key (will be hashed)"),
        ]

        for key_hex, description in test_cases:
            with self.subTest(description=description):
                result = self.run_cryptocore([
                    'dgst',
                    '--algorithm', 'sha256',
                    '--hmac',
                    '--key', key_hex,
                    '--input', self.test_file
                ])

                self.assertEqual(result.returncode, 0,
                                 f"HMAC failed with {description}: {result.stderr}")

                # Verify against Python's built-in HMAC
                key_bytes = bytes.fromhex(key_hex)
                expected_hmac = builtin_hmac.new(
                    key_bytes,
                    self.test_data,
                    hashlib.sha256
                ).hexdigest()

                hmac_hex = result.stdout.strip().split()[0]
                self.assertEqual(hmac_hex, expected_hmac,
                                 f"HMAC mismatch for {description}")

    def test_hmac_stdin_input(self):
        """Test HMAC computation from stdin"""
        # Use subprocess.run with input parameter (cross-platform)
        result = subprocess.run(
            [sys.executable, '-m', 'src.cryptocore.cli',
             'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', self.test_key,
             '--input', '-'],
            input=b'Hello from stdin',
            capture_output=True,
            cwd=project_root
        )

        self.assertEqual(result.returncode, 0,
                         f"HMAC from stdin failed: {result.stderr.decode('utf-8', errors='ignore')}")

        # Verify HMAC
        expected_hmac = builtin_hmac.new(
            self.test_key_bytes,
            b'Hello from stdin',
            hashlib.sha256
        ).hexdigest()

        output = result.stdout.decode('utf-8', errors='ignore').strip()
        hmac_hex = output.split()[0]
        self.assertEqual(hmac_hex, expected_hmac,
                         f"HMAC mismatch from stdin\nGot: {hmac_hex}\nExpected: {expected_hmac}")

    def test_hmac_large_file(self):
        """Test HMAC computation with large file"""
        # Create a 2MB file
        large_file = os.path.join(self.temp_dir, "large.bin")
        chunk = b"X" * 1024  # 1KB

        with open(large_file, 'wb') as f:
            for _ in range(2048):  # 2048 * 1KB = 2MB
                f.write(chunk)

        # Compute HMAC
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', large_file
        ])

        self.assertEqual(result.returncode, 0, f"HMAC for large file failed: {result.stderr}")

        # Compute expected HMAC using Python's built-in
        with open(large_file, 'rb') as f:
            file_data = f.read()

        expected_hmac = builtin_hmac.new(
            self.test_key_bytes,
            file_data,
            hashlib.sha256
        ).hexdigest()

        hmac_hex = result.stdout.strip().split()[0]
        self.assertEqual(hmac_hex, expected_hmac,
                         "HMAC mismatch for large file")

    def test_hmac_output_format_consistency(self):
        """Test that HMAC output format is consistent with hash output"""
        # Compute regular hash
        hash_result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--input', self.test_file
        ])

        # Compute HMAC
        hmac_result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', self.test_key,
            '--input', self.test_file
        ])

        self.assertEqual(hash_result.returncode, 0)
        self.assertEqual(hmac_result.returncode, 0)

        # Parse outputs
        hash_line = hash_result.stdout.strip()
        hmac_line = hmac_result.stdout.strip()

        hash_parts = hash_line.split()
        hmac_parts = hmac_line.split()

        # Both should have same format: VALUE FILENAME
        self.assertEqual(len(hash_parts), 2)
        self.assertEqual(len(hmac_parts), 2)

        # Filenames should match
        self.assertEqual(hash_parts[1], hmac_parts[1])

        # Values should be different (hash vs HMAC)
        self.assertNotEqual(hash_parts[0], hmac_parts[0])

        # Both values should be 64 hex chars
        self.assertEqual(len(hash_parts[0]), 64)
        self.assertEqual(len(hmac_parts[0]), 64)


class TestHMACRFCVectorsCli(unittest.TestCase):
    """Test HMAC CLI with RFC 4231 test vectors"""

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
        # Decode output with error handling for cross-platform compatibility
        result.stdout = result.stdout.decode('utf-8', errors='ignore')
        result.stderr = result.stderr.decode('utf-8', errors='ignore')
        return result

    def test_rfc_4231_case_1_cli(self):
        """RFC 4231 Test Case 1 via CLI"""
        # Create test file
        test_file = os.path.join(self.temp_dir, "test1.txt")
        with open(test_file, 'wb') as f:
            f.write(b"Hi There")

        # Key = 0x0b repeated 20 times
        key = "0b" * 20

        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', key,
            '--input', test_file
        ])

        self.assertEqual(result.returncode, 0, f"RFC 4231 case 1 failed: {result.stderr}")

        hmac_hex = result.stdout.strip().split()[0]
        expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

        self.assertEqual(hmac_hex, expected,
                         f"RFC 4231 case 1 mismatch\nGot: {hmac_hex}\nExpected: {expected}")

    def test_rfc_4231_case_2_cli(self):
        """RFC 4231 Test Case 2 via CLI"""
        # Create test file
        test_file = os.path.join(self.temp_dir, "test2.txt")
        with open(test_file, 'wb') as f:
            f.write(b"what do ya want for nothing?")

        # Key = "Jefe" (hex: 4a656665)
        key = "4a656665"

        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--hmac',
            '--key', key,
            '--input', test_file
        ])

        self.assertEqual(result.returncode, 0, f"RFC 4231 case 2 failed: {result.stderr}")

        hmac_hex = result.stdout.strip().split()[0]
        expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

        self.assertEqual(hmac_hex, expected,
                         f"RFC 4231 case 2 mismatch\nGot: {hmac_hex}\nExpected: {expected}")


if __name__ == "__main__":
    unittest.main()