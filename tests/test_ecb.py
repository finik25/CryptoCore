import unittest
from src.cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb


class TestECB(unittest.TestCase):
    def setUp(self):
        self.key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        self.plaintext = b"Hello, world! This is a test."

    def test_encrypt_decrypt_roundtrip(self):
        ciphertext = encrypt_ecb(self.plaintext, self.key)
        decrypted = decrypt_ecb(ciphertext, self.key)
        self.assertEqual(decrypted, self.plaintext)

    def test_ecb_characteristic(self):
        # ECB should produce identical ciphertext for identical plaintext blocks
        plaintext = b"AAAAAAAABBBBBBBB" * 2
        ciphertext = encrypt_ecb(plaintext, self.key)

        block1 = ciphertext[0:16]
        block2 = ciphertext[16:32]
        block3 = ciphertext[32:48]

        self.assertEqual(block1, block2)
        self.assertNotEqual(block1, block3)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            encrypt_ecb(self.plaintext, b"short")

    def test_invalid_ciphertext_length(self):
        with self.assertRaises(ValueError):
            decrypt_ecb(b"shortciphertext", self.key)

    def test_empty_plaintext(self):
        # Test with empty input
        ciphertext = encrypt_ecb(b"", self.key)
        decrypted = decrypt_ecb(ciphertext, self.key)
        self.assertEqual(decrypted, b"")

    def test_binary_data(self):
        # Test with binary data containing all byte values
        binary_data = bytes(range(256))
        ciphertext = encrypt_ecb(binary_data, self.key)
        decrypted = decrypt_ecb(ciphertext, self.key)
        self.assertEqual(decrypted, binary_data)


if __name__ == "__main__":
    unittest.main()