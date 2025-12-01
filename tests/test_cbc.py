import unittest
import os
import tempfile
from src.cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc


class TestCBC(unittest.TestCase):
    def setUp(self):
        self.key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        self.iv = b'\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00'
        self.plaintext = b"Hello CBC mode! This is a test."

    def test_encrypt_decrypt_roundtrip(self):
        ciphertext = encrypt_cbc(self.plaintext, self.key, self.iv)
        decrypted = decrypt_cbc(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, self.plaintext)

    def test_cbc_iv_effect(self):
        # Different IV should produce different ciphertext
        iv2 = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        ciphertext1 = encrypt_cbc(self.plaintext, self.key, self.iv)
        ciphertext2 = encrypt_cbc(self.plaintext, self.key, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_cbc_padding(self):
        # Test with data that needs padding
        data = b"short"
        ciphertext = encrypt_cbc(data, self.key, self.iv)
        self.assertEqual(len(ciphertext) % 16, 0)
        decrypted = decrypt_cbc(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, data)

    def test_cbc_exact_block(self):
        # Test with exact block size
        data = b"A" * 16
        ciphertext = encrypt_cbc(data, self.key, self.iv)
        self.assertEqual(len(ciphertext), 32)  # 16 + 16 padding
        decrypted = decrypt_cbc(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, data)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            encrypt_cbc(self.plaintext, b"short", self.iv)

    def test_invalid_iv_length(self):
        with self.assertRaises(ValueError):
            encrypt_cbc(self.plaintext, self.key, b"short")

    def test_invalid_ciphertext_length(self):
        with self.assertRaises(ValueError):
            decrypt_cbc(b"shortciphertext", self.key, self.iv)


if __name__ == "__main__":
    unittest.main()