import unittest
from src.cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb


class TestOFB(unittest.TestCase):
    def setUp(self):
        self.key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
        self.iv = b'\xff\xee\xdd\xcc\xbb\xaa\x99\x88wfeDU2\x11\x00'
        self.plaintext = b"Hello OFB mode! This is a test."

    def test_encrypt_decrypt_roundtrip(self):
        ciphertext = encrypt_ofb(self.plaintext, self.key, self.iv)
        decrypted = decrypt_ofb(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, self.plaintext)

    def test_ofb_symmetry(self):
        # OFB encryption and decryption use the same function
        data = b"Test data"
        ciphertext = encrypt_ofb(data, self.key, self.iv)
        # Verify decrypt_ofb is same as encrypt_ofb
        self.assertEqual(decrypt_ofb(ciphertext, self.key, self.iv), data)

    def test_ofb_no_padding(self):
        # OFB should not change data length
        data = b"short"
        ciphertext = encrypt_ofb(data, self.key, self.iv)
        self.assertEqual(len(ciphertext), len(data))
        decrypted = decrypt_ofb(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, data)

    def test_ofb_exact_block(self):
        # Test with exact block size
        data = b"A" * 16
        ciphertext = encrypt_ofb(data, self.key, self.iv)
        self.assertEqual(len(ciphertext), 16)  # No padding
        decrypted = decrypt_ofb(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, data)

    def test_ofb_partial_block(self):
        # Test with partial final block
        data = b"X" * 23  # Not multiple of 16
        ciphertext = encrypt_ofb(data, self.key, self.iv)
        self.assertEqual(len(ciphertext), 23)  # Same length
        decrypted = decrypt_ofb(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, data)

    def test_ofb_iv_effect(self):
        # Different IV should produce different ciphertext
        iv2 = b'\x00\x11"3DUfw\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        ciphertext1 = encrypt_ofb(self.plaintext, self.key, self.iv)
        ciphertext2 = encrypt_ofb(self.plaintext, self.key, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            encrypt_ofb(self.plaintext, b"short", self.iv)

    def test_invalid_iv_length(self):
        with self.assertRaises(ValueError):
            encrypt_ofb(self.plaintext, self.key, b"short")


if __name__ == "__main__":
    unittest.main()