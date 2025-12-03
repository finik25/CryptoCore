import unittest
import tempfile
import os
from src.cryptocore.utils.csprng import generate_random_bytes, generate_random_key


class TestCSPRNG(unittest.TestCase):

    def test_generate_random_bytes(self):
        # Correct generation test
        data = generate_random_bytes(16)
        self.assertEqual(len(data), 16)

        # The test is of different sizes
        for size in [1, 10, 100, 1000]:
            data = generate_random_bytes(size)
            self.assertEqual(len(data), size)

    def test_generate_random_bytes_invalid_size(self):
        with self.assertRaises(ValueError):
            generate_random_bytes(0)

        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_generate_random_key(self):
        key = generate_random_key()
        self.assertEqual(len(key), 16)

    def test_key_uniqueness(self):
        # Generate 1000 keys and check their uniqueness
        num_keys = 1000
        keys = set()

        for i in range(num_keys):
            key = generate_random_key()
            key_hex = key.hex()

            # check that the key is unique
            self.assertNotIn(key_hex, keys, f"Duplicate key found at iteration {i}: {key_hex}")
            keys.add(key_hex)

        print(f"✓ Successfully generated {len(keys)} unique keys")

    def test_randomness_basic_statistics(self):
        total_bits = 0
        total_bytes = 10000
        bytes_data = generate_random_bytes(total_bytes)

        # Counting the set bits (should be around 50%)
        for byte in bytes_data:
            total_bits += bin(byte).count("1")

        total_possible_bits = total_bytes * 8
        bit_ratio = total_bits / total_possible_bits

        # Check that the ratio is close to 0.5 (50%)
        self.assertGreater(bit_ratio, 0.45, f"Bit ratio too low: {bit_ratio}")
        self.assertLess(bit_ratio, 0.55, f"Bit ratio too high: {bit_ratio}")

        print(f"✓ Bit ratio: {bit_ratio:.4f} (expected ~0.5)")

    def test_nist_test_file_generation(self):
        # Generating a file for NIST STS tests
        temp_dir = tempfile.mkdtemp()
        test_file = os.path.join(temp_dir, "nist_test_data.bin")

        total_size = 10_000_000  # 10 MB для тестов
        chunk_size = 4096

        try:
            with open(test_file, 'wb') as f:
                bytes_written = 0
                while bytes_written < total_size:
                    chunk = min(chunk_size, total_size - bytes_written)
                    random_chunk = generate_random_bytes(chunk)
                    f.write(random_chunk)
                    bytes_written += chunk

            # Check that the file is created and has the correct size
            self.assertTrue(os.path.exists(test_file))
            self.assertEqual(os.path.getsize(test_file), total_size)

            print(f"✓ Generated NIST test file: {test_file} ({total_size} bytes)")

        finally:
            # Clearing
            if os.path.exists(test_file):
                os.remove(test_file)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)

    def test_generate_large_amount(self):
        # The test of generating a large amount of data
        large_data = generate_random_bytes(1_000_000)  # 1 MB
        self.assertEqual(len(large_data), 1_000_000)

        # We check that the data is not all the same
        first_byte = large_data[0]
        all_same = all(b == first_byte for b in large_data)
        self.assertFalse(all_same, "All bytes are identical - RNG is broken")


if __name__ == "__main__":
    unittest.main()