from Crypto.Cipher import AES
import struct
import unittest
from src.cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr


class TestCTR(unittest.TestCase):
    def setUp(self):
        self.key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
        # Use a valid 16-byte IV for CTR (8-byte nonce + 8-byte counter)
        self.iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x00\x00\x00\x00\x00\x00\x00\x00'
        self.plaintext = b"Hello CTR mode! This is a test."

    def test_encrypt_decrypt_roundtrip(self):
        ciphertext = encrypt_ctr(self.plaintext, self.key, self.iv)
        decrypted = decrypt_ctr(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, self.plaintext)

    def test_ctr_symmetry(self):
        # CTR encryption and decryption use the same function
        data = b"Test data"
        ciphertext = encrypt_ctr(data, self.key, self.iv)
        # Verify decrypt_ctr is same as encrypt_ctr
        self.assertEqual(decrypt_ctr(ciphertext, self.key, self.iv), data)

    def test_ctr_no_padding(self):
        # CTR should not change data length
        data = b"short"
        ciphertext = encrypt_ctr(data, self.key, self.iv)
        self.assertEqual(len(ciphertext), len(data))
        decrypted = decrypt_ctr(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, data)

    def test_ctr_exact_block(self):
        # Test with exact block size
        data = b"A" * 16
        ciphertext = encrypt_ctr(data, self.key, self.iv)
        self.assertEqual(len(ciphertext), 16)  # No padding
        decrypted = decrypt_ctr(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, data)

    def test_ctr_partial_block(self):
        # Test with partial final block
        data = b"X" * 23  # Not multiple of 16
        ciphertext = encrypt_ctr(data, self.key, self.iv)
        self.assertEqual(len(ciphertext), 23)  # Same length
        decrypted = decrypt_ctr(ciphertext, self.key, self.iv)
        self.assertEqual(decrypted, data)

    def test_ctr_counter_increment(self):
        # Verify counter increments correctly
        data = b"A" * 32  # Two blocks
        ciphertext = encrypt_ctr(data, self.key, self.iv)
        # Manually test second block with incremented counter
        cipher2 = AES.new(self.key, AES.MODE_ECB)

        # First block
        counter1 = self.iv[:8] + struct.pack('>Q', 0)
        keystream1 = cipher2.encrypt(counter1)

        # Second block
        counter2 = self.iv[:8] + struct.pack('>Q', 1)
        keystream2 = cipher2.encrypt(counter2)

        # Verify first block encryption
        block1 = data[:16]
        expected1 = bytes(a ^ b for a, b in zip(block1, keystream1))
        self.assertEqual(ciphertext[:16], expected1)

        # Verify second block encryption
        block2 = data[16:32]
        expected2 = bytes(a ^ b for a, b in zip(block2, keystream2))
        self.assertEqual(ciphertext[16:32], expected2)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            encrypt_ctr(self.plaintext, b"short", self.iv)

    def test_invalid_iv_length(self):
        with self.assertRaises(ValueError):
            encrypt_ctr(self.plaintext, self.key, b"short")


if __name__ == "__main__":
    unittest.main()