import unittest
import os
import tempfile
from src.cryptocore.hash.sha256 import SHA256


class TestSHA256(unittest.TestCase):

    def test_empty_string(self):
        # Test SHA-256 of empty string (NIST test vector)
        sha256 = SHA256()
        sha256.update(b"")
        result = sha256.hexdigest()
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(result, expected)

    def test_abc_string(self):
        # Test SHA-256 of 'abc' (NIST test vector)
        sha256 = SHA256()
        sha256.update(b"abc")
        result = sha256.hexdigest()
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(result, expected)

    def test_long_string(self):
        # Test SHA-256 of 1,000,000 repetitions of 'a'
        sha256 = SHA256()
        for _ in range(1000):
            sha256.update(b"a" * 1000)
        result = sha256.hexdigest()
        expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        self.assertEqual(result, expected)

    def test_avalanche_effect(self):
        # Test that changing one bit produces completely different hash
        original = b"Hello, world!"
        modified = b"Hello, world?"

        hash1 = SHA256.hash_hex(original)
        hash2 = SHA256.hash_hex(modified)

        # Convert to binary and count differing bits
        bin1 = bin(int(hash1, 16))[2:].zfill(256)
        bin2 = bin(int(hash2, 16))[2:].zfill(256)

        diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))

        # Avalanche effect: should be ~128 bits changed (50%)
        self.assertGreater(diff_count, 100, f"Avalanche effect weak: only {diff_count} bits changed")
        self.assertLess(diff_count, 156, f"Avalanche effect weak: {diff_count} bits changed")

    def test_chunk_processing(self):
        # Test that chunked processing produces same result as single update
        data = b"This is a test message for SHA-256 chunk processing."

        # Single update
        sha1 = SHA256()
        sha1.update(data)
        hash1 = sha1.hexdigest()

        # Multiple updates
        sha2 = SHA256()
        chunk_size = 10
        for i in range(0, len(data), chunk_size):
            sha2.update(data[i:i + chunk_size])
        hash2 = sha2.hexdigest()

        self.assertEqual(hash1, hash2)

    def test_reset_functionality(self):
        # Test reset() method
        sha256 = SHA256()
        sha256.update(b"test")
        hash1 = sha256.hexdigest()

        sha256.reset()
        sha256.update(b"test")
        hash2 = sha256.hexdigest()

        self.assertEqual(hash1, hash2)

    def test_file_hashing(self):
        # Test hashing of a file
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data for file hashing")
            temp_file = f.name

        try:
            # Use HashCalculator for file hashing
            from src.cryptocore.hash_utils import HashCalculator
            hash_hex = HashCalculator.hash_file_hex(temp_file, 'sha256')

            # Compare with direct hashing
            with open(temp_file, 'rb') as f:
                data = f.read()
            expected = SHA256.hash_hex(data)

            self.assertEqual(hash_hex, expected)
        finally:
            os.unlink(temp_file)