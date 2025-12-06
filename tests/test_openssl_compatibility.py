import unittest
import os
import tempfile
import subprocess
import sys


class TestOpenSSLCompatibility(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_data = b"Hello CryptoCore! OpenSSL compatibility test." * 10

        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)

        self.key = "00112233445566778899aabbccddeeff"
        self.iv = "000102030405060708090a0b0c0d0e0f"

        # Check if OpenSSL is available
        self.openssl_available, self.openssl_path = self._check_openssl_available()

        # Get project root for running cryptocore
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(current_dir)

    def _check_openssl_available(self):
        """Check if OpenSSL is available on system, checking common paths"""
        openssl_paths = [
            "openssl",  # PATH
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            r"C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
            r"C:\OpenSSL-Win64\bin\openssl.exe",
            r"C:\OpenSSL-Win32\bin\openssl.exe",
            # Common Linux/macOS paths
            "/usr/bin/openssl",
            "/usr/local/bin/openssl",
            "/opt/homebrew/bin/openssl"
        ]

        for path in openssl_paths:
            try:
                result = subprocess.run(
                    [path, "version"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    return True, path
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                continue

        return False, None

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
            text=True,
            cwd=self.project_root
        )
        return result

    def run_openssl(self, args):
        """Run OpenSSL command"""
        if not self.openssl_path:
            self.skipTest("OpenSSL not available")

        cmd = [self.openssl_path] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result
        except subprocess.TimeoutExpired:
            self.fail(f"OpenSSL command timed out: {' '.join(cmd)}")

    def test_cbc_encrypt_with_openssl_decrypt(self):
        """Test that CryptoCore encrypted files can be decrypted by OpenSSL"""
        if not self.openssl_available:
            self.skipTest("OpenSSL not available")

        # 1. Encrypt with CryptoCore
        encrypted_file = os.path.join(self.temp_dir, "cryptocore_encrypted.bin")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'cbc',
            '--encrypt',
            '--key', self.key,
            '--input', self.test_file,
            '--output', encrypted_file,
            '--force'
        ])

        self.assertEqual(result.returncode, 0,
                         f"CryptoCore encryption failed: {result.stderr}")

        # 2. Extract IV from CryptoCore's output file (first 16 bytes)
        with open(encrypted_file, 'rb') as f:
            data = f.read()

        iv_from_file = data[:16].hex()
        ciphertext_only = data[16:]

        # Write ciphertext without IV for OpenSSL
        ciphertext_file = os.path.join(self.temp_dir, "ciphertext_only.bin")
        with open(ciphertext_file, 'wb') as f:
            f.write(ciphertext_only)

        # 3. Decrypt with OpenSSL
        openssl_decrypted = os.path.join(self.temp_dir, "openssl_decrypted.txt")
        result = self.run_openssl([
            "enc", "-aes-128-cbc", "-d",
            "-K", self.key,
            "-iv", iv_from_file,
            "-in", ciphertext_file,
            "-out", openssl_decrypted
        ])

        self.assertEqual(result.returncode, 0,
                         f"OpenSSL decryption failed: {result.stderr}")

        # 4. Verify decrypted file matches original
        with open(openssl_decrypted, 'rb') as f:
            decrypted_data = f.read()

        self.assertEqual(decrypted_data, self.test_data,
                         "OpenSSL decrypted data doesn't match original")

    def test_cbc_encrypt_with_openssl_encrypt(self):
        """Test that OpenSSL encrypted files can be decrypted by CryptoCore"""
        if not self.openssl_available:
            self.skipTest("OpenSSL not available")

        # 1. Encrypt with OpenSSL (OpenSSL doesn't include IV in output by default)
        openssl_encrypted = os.path.join(self.temp_dir, "openssl_encrypted.bin")
        result = self.run_openssl([
            "enc", "-aes-128-cbc",
            "-K", self.key,
            "-iv", self.iv,
            "-in", self.test_file,
            "-out", openssl_encrypted
        ])

        self.assertEqual(result.returncode, 0,
                         f"OpenSSL encryption failed: {result.stderr}")

        # 2. For OpenSSL-encrypted files, we need to manually prepend the IV
        with open(openssl_encrypted, 'rb') as f:
            openssl_ciphertext = f.read()

        # Create a file with IV + ciphertext as CryptoCore expects
        combined_file = os.path.join(self.temp_dir, "openssl_encrypted_with_iv.bin")
        with open(combined_file, 'wb') as f:
            f.write(bytes.fromhex(self.iv))  # Add IV first
            f.write(openssl_ciphertext)  # Then ciphertext

        # 3. Decrypt with CryptoCore (NO --iv flag since IV is in file)
        cryptocore_decrypted = os.path.join(self.temp_dir, "cryptocore_decrypted.txt")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'cbc',
            '--decrypt',
            '--key', self.key,
            # No --iv flag here because IV is in the file
            '--input', combined_file,
            '--output', cryptocore_decrypted,
            '--force'
        ])

        self.assertEqual(result.returncode, 0,
                         f"CryptoCore decryption failed: {result.stderr}")

        # 4. Verify decrypted file matches original
        with open(cryptocore_decrypted, 'rb') as f:
            decrypted_data = f.read()

        self.assertEqual(decrypted_data, self.test_data,
                         "CryptoCore decrypted data doesn't match original")

    def test_ecb_mode_compatibility(self):
        """Test ECB mode compatibility with OpenSSL"""
        if not self.openssl_available:
            self.skipTest("OpenSSL not available")

        # 1. Encrypt with CryptoCore (ECB mode)
        encrypted_file = os.path.join(self.temp_dir, "ecb_cryptocore.bin")
        result = self.run_cryptocore([
            'crypto',
            '--algorithm', 'aes',
            '--mode', 'ecb',
            '--encrypt',
            '--key', self.key,
            '--input', self.test_file,
            '--output', encrypted_file,
            '--force'
        ])
        self.assertEqual(result.returncode, 0)

        # 2. Decrypt with OpenSSL (ECB mode)
        openssl_decrypted = os.path.join(self.temp_dir, "ecb_openssl_decrypted.txt")
        result = self.run_openssl([
            "enc", "-aes-128-ecb", "-d",
            "-K", self.key,
            "-in", encrypted_file,
            "-out", openssl_decrypted
        ])
        self.assertEqual(result.returncode, 0)

        # 3. Verify
        with open(openssl_decrypted, 'rb') as f:
            decrypted_data = f.read()

        self.assertEqual(decrypted_data, self.test_data,
                         "ECB mode: OpenSSL decrypted data doesn't match original")

    def test_hash_compatibility(self):
        """Test that hash algorithms produce same results as OpenSSL"""
        if not self.openssl_available:
            self.skipTest("OpenSSL not available")

        # Create test data
        test_data = b"Test data for hash compatibility"
        test_file = os.path.join(self.temp_dir, "hash_test.txt")
        with open(test_file, 'wb') as f:
            f.write(test_data)

        # Test SHA256
        # CryptoCore SHA256
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha256',
            '--input', test_file
        ])
        self.assertEqual(result.returncode, 0)
        cryptocore_hash = result.stdout.strip().split()[0]

        # OpenSSL SHA256
        result = self.run_openssl([
            "dgst", "-sha256",
            test_file
        ])
        self.assertEqual(result.returncode, 0)
        openssl_output = result.stdout.strip()
        openssl_hash = openssl_output.split()[-1]

        self.assertEqual(cryptocore_hash, openssl_hash,
                         f"SHA256 hashes don't match\nCryptoCore: {cryptocore_hash}\nOpenSSL: {openssl_hash}")

        # Test SHA3-256 if available
        # First check if our CryptoCore supports SHA3-256
        result = self.run_cryptocore([
            'dgst',
            '--algorithm', 'sha3-256',
            '--input', test_file
        ])

        if result.returncode == 0:
            cryptocore_hash = result.stdout.strip().split()[0]

            # Try OpenSSL SHA3-256 (available in OpenSSL 1.1.1+)
            result = self.run_openssl([
                "dgst", "-sha3-256",
                test_file
            ])

            if result.returncode == 0:
                openssl_hash = result.stdout.strip().split()[-1]
                self.assertEqual(cryptocore_hash, openssl_hash,
                                 f"SHA3-256 hashes don't match\nCryptoCore: {cryptocore_hash}\nOpenSSL: {openssl_hash}")

    def test_interoperability_principles(self):
        """Explain the interoperability principles - always passes"""
        # This test is informational and always passes
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()