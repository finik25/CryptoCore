import unittest
import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(project_root, 'src'))

from src.cryptocore.mac.hmac import HMAC


class TestHMAC(unittest.TestCase):
    """Test HMAC-SHA256 implementation"""

    def test_hmac_key_processing_short_key(self):
        """Test that short keys are padded with zeros"""
        key = b"short"
        hmac = HMAC(key)

        # Key should be padded to 64 bytes
        self.assertEqual(len(hmac.key), 64)
        self.assertEqual(hmac.key[:5], b"short")
        self.assertEqual(hmac.key[5:], bytes(59))  # 59 zeros

    def test_hmac_key_processing_long_key(self):
        """Test that long keys are hashed"""
        # Create a key longer than 64 bytes
        key = b"x" * 100
        hmac = HMAC(key)

        # Key should be hashed to 32 bytes then padded to 64
        self.assertEqual(len(hmac.key), 64)

        # First 32 bytes should be SHA256 hash of the key
        from src.cryptocore.hash.sha256 import SHA256
        expected_hash = SHA256.hash(key)
        self.assertEqual(hmac.key[:32], expected_hash)
        self.assertEqual(hmac.key[32:], bytes(32))  # 32 zeros

    def test_hmac_key_processing_exact_length(self):
        """Test key of exactly 64 bytes"""
        key = b"x" * 64
        hmac = HMAC(key)

        # Key should remain unchanged
        self.assertEqual(hmac.key, key)
        self.assertEqual(len(hmac.key), 64)

    def test_hmac_xor_bytes(self):
        """Test XOR operation"""
        hmac = HMAC(b"test")

        a = bytes([0b01010101, 0b00110011])
        b = bytes([0b10101010, 0b11001100])
        expected = bytes([0b11111111, 0b11111111])

        result = hmac._xor_bytes(a, b)
        self.assertEqual(result, expected)

    def test_hmac_xor_bytes_different_lengths(self):
        """Test XOR with different lengths raises error"""
        hmac = HMAC(b"test")

        a = b"abc"
        b = b"abcd"

        with self.assertRaises(ValueError):
            hmac._xor_bytes(a, b)

    def test_hmac_constants(self):
        """Test that IPAD and OPAD are correct"""
        hmac = HMAC(b"test")

        # IPAD should be 64 bytes of 0x36
        self.assertEqual(len(hmac.IPAD), 64)
        self.assertEqual(hmac.IPAD, bytes([0x36] * 64))

        # OPAD should be 64 bytes of 0x5c
        self.assertEqual(len(hmac.OPAD), 64)
        self.assertEqual(hmac.OPAD, bytes([0x5c] * 64))

    def test_hmac_compute_empty_message(self):
        """Test HMAC with empty message"""
        key = b"secret"
        message = b""

        hmac = HMAC(key)
        result = hmac.compute(message)

        # HMAC should be 32 bytes (SHA-256 output)
        self.assertEqual(len(result), 32)

        # Should be deterministic
        result2 = hmac.compute(message)
        self.assertEqual(result, result2)

    def test_hmac_compute_simple_message(self):
        """Test HMAC with simple message"""
        key = b"mykey"
        message = b"Hello, world!"

        hmac = HMAC(key)
        result = hmac.compute(message)

        self.assertEqual(len(result), 32)

        # Test hex output
        hex_result = hmac.compute_hex(message)
        self.assertEqual(len(hex_result), 64)  # 32 bytes = 64 hex chars
        self.assertEqual(hex_result, result.hex())

    def test_hmac_verify_correct(self):
        """Test HMAC verification with correct HMAC"""
        key = b"secret"
        message = b"test message"

        hmac = HMAC(key)
        computed_hmac = hmac.compute(message)

        # Verify with bytes
        self.assertTrue(hmac.verify(message, computed_hmac))

        # Verify with hex string
        self.assertTrue(hmac.verify(message, computed_hmac.hex()))

    def test_hmac_verify_incorrect(self):
        """Test HMAC verification with incorrect HMAC"""
        key = b"secret"
        message = b"test message"

        hmac = HMAC(key)
        computed_hmac = hmac.compute(message)

        # Wrong HMAC (different bytes)
        wrong_hmac = bytes([(b + 1) % 256 for b in computed_hmac])

        self.assertFalse(hmac.verify(message, wrong_hmac))
        self.assertFalse(hmac.verify(message, wrong_hmac.hex()))

        # Wrong message
        wrong_message = b"wrong message"
        self.assertFalse(hmac.verify(wrong_message, computed_hmac))

    def test_hmac_update_compute_chunks(self):
        """Test HMAC with chunked data"""
        key = b"chunked"
        message = b"This is a longer message that will be processed in chunks"

        # Process as single message
        hmac1 = HMAC(key)
        single_result = hmac1.compute(message)

        # Process as chunks
        hmac2 = HMAC(key)
        chunks = [b"This is a ", b"longer message ", b"that will be ", b"processed in chunks"]
        chunked_result = hmac2.update_compute(chunks)

        # Results should be identical
        self.assertEqual(single_result, chunked_result)

    def test_hmac_class_methods(self):
        """Test class methods for one-shot computation"""
        key = b"testkey"
        message = b"test message"

        # One-shot bytes
        result1 = HMAC.compute_hmac(key, message)
        self.assertEqual(len(result1), 32)

        # One-shot hex
        result2 = HMAC.compute_hmac_hex(key, message)
        self.assertEqual(len(result2), 64)
        self.assertEqual(result2, result1.hex())

        # Compare with instance method
        hmac = HMAC(key)
        instance_result = hmac.compute(message)
        self.assertEqual(result1, instance_result)

    def test_factory_function(self):
        """Test new() factory function"""
        from src.cryptocore.mac import new

        key = b"factory"
        message = b"test"

        hmac = new(key)
        result = hmac.compute(message)

        self.assertEqual(len(result), 32)


class TestHMACRFCVectors(unittest.TestCase):
    """Test HMAC with RFC 4231 test vectors"""

    def test_rfc_4231_test_case_1(self):
        """RFC 4231 Test Case 1 - Truncated key"""
        # Key = 0x0b repeated 20 times
        key = bytes([0x0b] * 20)
        # Data = "Hi There"
        data = b"Hi There"

        # Expected HMAC-SHA256
        expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

        hmac = HMAC(key)
        result = hmac.compute_hex(data)

        self.assertEqual(result, expected)

    def test_rfc_4231_test_case_2(self):
        """RFC 4231 Test Case 2 - Key with special chars"""
        key = b"Jefe"
        data = b"what do ya want for nothing?"

        expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

        hmac = HMAC(key)
        result = hmac.compute_hex(data)

        self.assertEqual(result, expected)

    def test_rfc_4231_test_case_3(self):
        """RFC 4231 Test Case 3 - 20 byte key"""
        # Key = 0xaa repeated 20 times
        key = bytes([0xaa] * 20)
        # Data = 0xdd repeated 50 times
        data = bytes([0xdd] * 50)

        # Expected HMAC-SHA256
        expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"

        hmac = HMAC(key)
        result = hmac.compute_hex(data)

        self.assertEqual(result, expected)

    def test_rfc_4231_test_case_4(self):
        """RFC 4231 Test Case 4 - 25 byte key"""
        # Key = 0x0102030405060708090a0b0c0d0e0f10111213141516171819
        key = bytes(range(1, 26))  # 0x01 to 0x19
        # Data = 0xcd repeated 50 times
        data = bytes([0xcd] * 50)

        # Expected HMAC-SHA256
        expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"

        hmac = HMAC(key)
        result = hmac.compute_hex(data)

        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()