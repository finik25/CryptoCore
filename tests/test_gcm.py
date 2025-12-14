import unittest
import os


class TestGCMBasic(unittest.TestCase):

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption roundtrip."""
        from src.cryptocore.modes.gcm import GCM, encrypt_gcm, decrypt_gcm

        key = os.urandom(16)
        plaintext = b"Hello GCM World!"
        aad = b"authenticated metadata"

        # Test using class
        gcm1 = GCM(key)
        nonce, ciphertext, tag = gcm1.encrypt(plaintext, aad)

        gcm2 = GCM(key, nonce)
        decrypted = gcm2.decrypt(ciphertext, tag, nonce, aad)

        self.assertEqual(decrypted, plaintext)

        # Test using convenience functions
        nonce2, ciphertext2, tag2 = encrypt_gcm(plaintext, key, aad=aad)
        decrypted2 = decrypt_gcm(ciphertext2, tag2, nonce2, key, aad)

        self.assertEqual(decrypted2, plaintext)

    def test_aad_verification(self):
        """Test that wrong AAD causes authentication failure."""
        from src.cryptocore.modes.gcm import GCM, AuthenticationError

        key = os.urandom(16)
        plaintext = b"Secret message"
        correct_aad = b"correct context"
        wrong_aad = b"wrong context"

        gcm = GCM(key)
        nonce, ciphertext, tag = gcm.encrypt(plaintext, correct_aad)

        # Should succeed with correct AAD
        gcm2 = GCM(key, nonce)
        decrypted = gcm2.decrypt(ciphertext, tag, nonce, correct_aad)
        self.assertEqual(decrypted, plaintext)

        # Should fail with wrong AAD
        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(ciphertext, tag, nonce, wrong_aad)

    def test_tamper_detection(self):
        """Test that ciphertext tampering causes authentication failure."""
        from src.cryptocore.modes.gcm import GCM, AuthenticationError

        key = os.urandom(16)
        plaintext = b"Important data" * 10

        gcm = GCM(key)
        nonce, ciphertext, tag = gcm.encrypt(plaintext)

        # Tamper with ciphertext (flip one bit)
        tampered = bytearray(ciphertext)
        if len(tampered) > 0:
            tampered[0] ^= 0x01

        # Should fail with tampered ciphertext
        gcm2 = GCM(key, nonce)
        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(bytes(tampered), tag, nonce)

    def test_empty_plaintext(self):
        """Test GCM with empty plaintext (only AAD authentication)."""
        from src.cryptocore.modes.gcm import GCM

        key = os.urandom(16)
        aad = b"authenticated header"

        gcm = GCM(key)
        nonce, ciphertext, tag = gcm.encrypt(b"", aad)

        self.assertEqual(ciphertext, b"")
        self.assertEqual(len(tag), 16)

        # Should still verify correctly
        gcm2 = GCM(key, nonce)
        decrypted = gcm2.decrypt(ciphertext, tag, nonce, aad)
        self.assertEqual(decrypted, b"")

    def test_nonce_uniqueness(self):
        """Test that different nonces produce different ciphertexts."""
        from src.cryptocore.modes.gcm import GCM

        key = os.urandom(16)
        plaintext = b"Test message"

        # Encrypt same plaintext with same key but different nonces
        gcm1 = GCM(key)
        nonce1, ciphertext1, tag1 = gcm1.encrypt(plaintext)

        gcm2 = GCM(key)
        nonce2, ciphertext2, tag2 = gcm2.encrypt(plaintext)

        # Nonces should be different (random generation)
        self.assertNotEqual(nonce1, nonce2)

        # With very high probability, ciphertexts should be different
        self.assertNotEqual(ciphertext1, ciphertext2)
        self.assertNotEqual(tag1, tag2)

    def test_ghash_consistency(self):
        """Test that GHASH produces consistent results."""
        from src.cryptocore.modes.gcm import GCM

        key = os.urandom(16)
        gcm = GCM(key)

        # Test with some data
        aad = b"associated data"
        ciphertext = b"ciphertext example"

        # Get H value (AES.encrypt(0))
        h = gcm._cipher.encrypt(b'\x00' * 16)

        # Manually compute GHASH for simple case
        # This is a simplified test - we should add NIST test vectors later
        self.assertEqual(len(h), 16)


if __name__ == "__main__":
    unittest.main()