import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cryptocore.kdf.hkdf import derive_key, derive_key_hierarchy


class TestHKDF(unittest.TestCase):
    """Test HKDF-like key hierarchy"""

    def test_deterministic(self):
        """Same inputs should produce same output"""
        master_key = b"0" * 32
        context = "encryption"
        length = 32

        key1 = derive_key(master_key, context, length)
        key2 = derive_key(master_key, context, length)

        self.assertEqual(key1, key2)

    def test_context_separation(self):
        """Different contexts should produce different keys"""
        master_key = b"1" * 32

        key1 = derive_key(master_key, "encryption", 32)
        key2 = derive_key(master_key, "authentication", 32)
        key3 = derive_key(master_key, "mac", 32)

        # All should be different
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key1, key3)
        self.assertNotEqual(key2, key3)

    def test_various_lengths(self):
        """Test various key lengths"""
        master_key = b"2" * 32
        context = "test"

        for length in [1, 16, 32, 64, 128]:
            key = derive_key(master_key, context, length)
            self.assertEqual(len(key), length)

    def test_key_hierarchy(self):
        """Test deriving multiple keys at once"""
        master_key = b"3" * 32
        contexts = ["encryption", "authentication", "mac", "iv_generation"]

        hierarchy = derive_key_hierarchy(master_key, contexts, 32)

        self.assertEqual(set(hierarchy.keys()), set(contexts))

        # All keys should be different
        keys = list(hierarchy.values())
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                self.assertNotEqual(keys[i], keys[j])


if __name__ == "__main__":
    unittest.main()