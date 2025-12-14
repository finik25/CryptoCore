import unittest
import os


class TestEncryptThenMACBasic(unittest.TestCase):

    def test_basic_encrypt_decrypt(self):
        from src.cryptocore.aead.encrypt_then_mac import EncryptThenMAC

        # Generate a master key (at least 32 bytes)
        master_key = os.urandom(32)

        # Initialize with CBC mode
        etm = EncryptThenMAC(master_key, mode='cbc')

        # Test data
        plaintext = b"Hello, Authenticated Encryption!"
        aad = b"metadata123"

        # Encrypt (IV будет сгенерирован автоматически)
        iv, ciphertext, tag = etm.encrypt(plaintext, aad=aad)

        # Decrypt with correct AAD
        decrypted = etm.decrypt(ciphertext, tag, iv, aad=aad)
        self.assertEqual(decrypted, plaintext)

        # Should fail with wrong AAD
        with self.assertRaises(Exception) as context:
            etm.decrypt(ciphertext, tag, iv, aad=b"wrong_aad")
        self.assertIn("MAC verification", str(context.exception))

        # Should fail with tampered ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01  # Flip one bit
        with self.assertRaises(Exception):
            etm.decrypt(bytes(tampered), tag, iv, aad=aad)

    def test_key_derivation(self):
        from src.cryptocore.aead.encrypt_then_mac import EncryptThenMAC

        master_key = os.urandom(32)

        # Create two instances with same master key and mode
        etm1 = EncryptThenMAC(master_key, mode='cbc')
        etm2 = EncryptThenMAC(master_key, mode='cbc')

        # They should have the same derived keys
        # Note: We need to check internal attributes or test through encryption
        # Since _enc_key and _mac_key are private, we test via encryption

        # Test with same IV to verify same keys produce same ciphertext
        iv = os.urandom(16)
        plaintext = b"Test message"
        aad = b""

        _, ciphertext1, tag1 = etm1.encrypt(plaintext, iv=iv, aad=aad)
        _, ciphertext2, tag2 = etm2.encrypt(plaintext, iv=iv, aad=aad)

        self.assertEqual(ciphertext1, ciphertext2)
        self.assertEqual(tag1, tag2)

        # Different modes should produce different keys
        etm3 = EncryptThenMAC(master_key, mode='ctr')
        _, ciphertext3, tag3 = etm3.encrypt(plaintext, iv=iv, aad=aad)

        # Should be different (very high probability)
        self.assertNotEqual(ciphertext1, ciphertext3)

    def test_different_modes(self):
        from src.cryptocore.aead.encrypt_then_mac import EncryptThenMAC

        master_key = os.urandom(32)
        plaintext = b"Testing different modes" * 10
        aad = b"associated data"
        iv = os.urandom(16)

        modes = ['cbc', 'ctr', 'cfb', 'ofb', 'ecb']

        for mode in modes:
            with self.subTest(mode=mode):
                etm = EncryptThenMAC(master_key, mode=mode)

                # Skip IV for ECB
                if mode == 'ecb':
                    iv_used = b""
                else:
                    iv_used = iv

                # Encrypt
                ciphertext_iv, ciphertext, tag = etm.encrypt(
                    plaintext, iv=iv_used, aad=aad
                )

                # Decrypt
                decrypted = etm.decrypt(ciphertext, tag, ciphertext_iv, aad=aad)

                self.assertEqual(decrypted, plaintext)

                # Test tamper detection
                tampered = bytearray(ciphertext)
                if len(tampered) > 0:
                    tampered[0] ^= 0x01
                    with self.assertRaises(Exception):
                        etm.decrypt(bytes(tampered), tag, ciphertext_iv, aad=aad)


if __name__ == "__main__":
    unittest.main()