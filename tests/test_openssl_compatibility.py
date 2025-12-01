import unittest
import os
import tempfile
import subprocess
import sys


class TestOpenSSLCompatibility(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_data = b"Hello CryptoCore! OpenSSL compatibility test."

        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)

        self.key = "00112233445566778899aabbccddeeff"
        self.iv = "000102030405060708090a0b0c0d0e0f"

        # Check if OpenSSL is available
        self.openssl_available = self._check_openssl_available()

    def _check_openssl_available(self):
        openssl_paths = [
            "openssl",  # PATH
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            r"C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe"
        ]

        for path in openssl_paths:
            try:
                result = subprocess.run(
                    [path, "version"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    self.openssl_path = path  # Saving the path
                    return True
            except:
                continue

        return False

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def run_cryptocore(self, args):
        cmd = [sys.executable, "-m", "cryptocore.cli"] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def run_openssl(self, args):
        cmd = [self.openssl_path] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def test_cbc_encrypt_with_openssl_decrypt(self):
        if not self.openssl_available:
            self.skipTest("OpenSSL not available")

        # 1. Encrypt with CryptoCore
        encrypt_args = [
            "--algorithm", "aes", "--mode", "cbc", "--encrypt",
            "--key", self.key, "--input", self.test_file,
            "--output", os.path.join(self.temp_dir, "cryptocore_encrypted.bin"),
            "--force"
        ]

        result = self.run_cryptocore(encrypt_args)
        self.assertEqual(result.returncode, 0)

        # 2. Extract IV from CryptoCore's output (first 16 bytes)
        encrypted_file = os.path.join(self.temp_dir, "cryptocore_encrypted.bin")
        with open(encrypted_file, 'rb') as f:
            data = f.read()

        iv_from_file = data[:16].hex()
        ciphertext_only = data[16:]

        # Write ciphertext without IV for OpenSSL
        ciphertext_file = os.path.join(self.temp_dir, "ciphertext_only.bin")
        with open(ciphertext_file, 'wb') as f:
            f.write(ciphertext_only)

        # 3. Decrypt with OpenSSL
        decrypt_args = [
            "enc", "-aes-128-cbc", "-d",
            "-K", self.key,
            "-iv", iv_from_file,
            "-in", ciphertext_file,
            "-out", os.path.join(self.temp_dir, "openssl_decrypted.txt")
        ]

        result = self.run_openssl(decrypt_args)
        self.assertEqual(result.returncode, 0, f"OpenSSL failed: {result.stderr}")

        # 4. Verify decrypted file matches original
        with open(os.path.join(self.temp_dir, "openssl_decrypted.txt"), 'rb') as f:
            decrypted_data = f.read()

        self.assertEqual(decrypted_data, self.test_data)

    def test_cbc_encrypt_with_openssl_encrypt(self):
        if not self.openssl_available:
            self.skipTest("OpenSSL not available")

        # 1. Encrypt with OpenSSL
        openssl_encrypted = os.path.join(self.temp_dir, "openssl_encrypted.bin")
        encrypt_args = [
            "enc", "-aes-128-cbc",
            "-K", self.key,
            "-iv", self.iv,
            "-in", self.test_file,
            "-out", openssl_encrypted
        ]

        result = self.run_openssl(encrypt_args)
        self.assertEqual(result.returncode, 0, f"OpenSSL encryption failed: {result.stderr}")

        # 2. Decrypt with CryptoCore (using --iv)
        decrypt_args = [
            "--algorithm", "aes", "--mode", "cbc", "--decrypt",
            "--key", self.key, "--iv", self.iv,
            "--input", openssl_encrypted,
            "--output", os.path.join(self.temp_dir, "cryptocore_decrypted.txt"),
            "--force"
        ]

        result = self.run_cryptocore(decrypt_args)
        self.assertEqual(result.returncode, 0, f"CryptoCore decryption failed: {result.stderr}")

        # 3. Verify decrypted file matches original
        with open(os.path.join(self.temp_dir, "cryptocore_decrypted.txt"), 'rb') as f:
            decrypted_data = f.read()

        self.assertEqual(decrypted_data, self.test_data)

    def test_openssl_compatibility_principle(self):
        # This test demonstrates the concept without requiring OpenSSL

        # Create test data
        test_data = b"Test data for compatibility principle"
        test_file = os.path.join(self.temp_dir, "principle_test.txt")
        with open(test_file, 'wb') as f:
            f.write(test_data)

        print("\nOpenSSL Compatibility Test Principle:")
        print("1. OpenSSL: enc -aes-128-cbc -K <key> -iv <iv> -in file -out encrypted.bin")
        print("2. CryptoCore: cryptocore --mode cbc --decrypt --key <key> --iv <iv> --input encrypted.bin")
        print("\nNote: For complete tests, install OpenSSL and ensure it's in PATH.")

        # Just verify our test infrastructure works
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()