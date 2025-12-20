# tests/test_pbkdf2_vectors.py

import unittest
import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

from cryptocore.kdf.pbkdf2 import pbkdf2_hmac_sha256


class TestPBKDF2Vectors(unittest.TestCase):
    """Test PBKDF2 with correct test vectors for HMAC-SHA256"""

    def test_vector1(self):
        """password="password", salt="salt", iterations=1, dklen=20"""
        password = b"password"
        salt = b"salt"
        iterations = 1
        dklen = 20
        # Correct vector for PBKDF2-HMAC-SHA256
        expected_hex = "120fb6cffcf8b32c43e7225256c4f837a86548c9"
        expected = bytes.fromhex(expected_hex)

        result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        self.assertEqual(result, expected,
                         f"Vector 1 failed. Expected: {expected_hex}, Got: {result.hex()}")

    def test_vector2(self):
        """password="password", salt="salt", iterations=2, dklen=20"""
        password = b"password"
        salt = b"salt"
        iterations = 2
        dklen = 20
        expected_hex = "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"
        expected = bytes.fromhex(expected_hex)

        result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        self.assertEqual(result, expected,
                         f"Vector 2 failed. Expected: {expected_hex}, Got: {result.hex()}")

    def test_vector3(self):
        """password="password", salt="salt", iterations=4096, dklen=20"""
        password = b"password"
        salt = b"salt"
        iterations = 4096
        dklen = 20
        expected_hex = "c5e478d59288c841aa530db6845c4c8d962893a0"
        expected = bytes.fromhex(expected_hex)

        result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        self.assertEqual(result, expected,
                         f"Vector 3 failed. Expected: {expected_hex}, Got: {result.hex()}")

    def test_vector4(self):
        """long password and salt"""
        password = b"passwordPASSWORDpassword"
        salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt"
        iterations = 4096
        dklen = 25
        expected_hex = "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c"
        expected = bytes.fromhex(expected_hex)

        result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        self.assertEqual(result, expected,
                         f"Vector 4 failed. Expected: {expected_hex[:50]}..., Got: {result.hex()[:50]}...")

    def test_vector5(self):
        """with null bytes"""
        password = b"pass\x00word"
        salt = b"sa\x00lt"
        iterations = 4096
        dklen = 16
        expected_hex = "89b69d0516f829893c696226650a8687"
        expected = bytes.fromhex(expected_hex)

        result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        self.assertEqual(result, expected,
                         f"Vector 5 failed. Expected: {expected_hex}, Got: {result.hex()}")


class TestPBKDF2Properties(unittest.TestCase):
    """Test PBKDF2 properties"""

    def test_deterministic(self):
        """Same inputs should produce same output"""
        password = "testpassword"
        salt = "testsalt"
        iterations = 1000
        dklen = 32

        result1 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        result2 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)

        self.assertEqual(result1, result2, "PBKDF2 should be deterministic")

    def test_various_lengths(self):
        """Test various key lengths"""
        password = "test"
        salt = "salt"
        iterations = 100

        for dklen in [1, 16, 32, 64, 100]:
            result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
            self.assertEqual(len(result), dklen,
                             f"Key length {dklen} failed: got {len(result)} bytes")

    def test_different_salts(self):
        """Different salts should produce different keys"""
        password = "password"
        iterations = 100
        dklen = 32

        key1 = pbkdf2_hmac_sha256(password, "salt1", iterations, dklen)
        key2 = pbkdf2_hmac_sha256(password, "salt2", iterations, dklen)

        self.assertNotEqual(key1, key2, "Different salts should produce different keys")


if __name__ == "__main__":
    unittest.main()