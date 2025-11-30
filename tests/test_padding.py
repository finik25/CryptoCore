import unittest
from src.cryptocore.utils.padding import apply_padding, remove_padding


class TestPadding(unittest.TestCase):
    def test_apply_padding(self):
        # Test with data length not multiple of block size
        data = b"test"
        padded = apply_padding(data)
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[-1], 12)  # 16 - 4 = 12

        # Test with data length already multiple of block size
        data = b"test123456789012"  # 16 bytes
        padded = apply_padding(data)
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-1], 16)  # Full block added

    def test_remove_padding(self):
        # Test with padded data
        data = b"test"
        padded = apply_padding(data)
        original = remove_padding(padded)
        self.assertEqual(original, data)

        # Test with data already multiple of block size
        data = b"test123456789012"  # 16 bytes
        padded = apply_padding(data)
        original = remove_padding(padded)
        self.assertEqual(original, data)

    def test_invalid_padding(self):
        # Test with padding length greater than block size
        invalid_padded = b"test" + b"\x11" * 17  # 17 > 16
        with self.assertRaises(ValueError):
            remove_padding(invalid_padded)

        # Test with zero padding length
        invalid_padded = b"test" + b"\x00"
        with self.assertRaises(ValueError):
            remove_padding(invalid_padded)

        # Test with incorrect padding bytes
        invalid_padded = b"test" + b"\x04\x04\x04\x03"  # last byte should be 4
        with self.assertRaises(ValueError):
            remove_padding(invalid_padded)

        # Test with data shorter than padding length
        invalid_padded = b"test" + b"\x06"  # claims 6 bytes padding but only 1 available
        with self.assertRaises(ValueError):
            remove_padding(invalid_padded)

    def test_edge_cases(self):
        # Test empty data
        with self.assertRaises(ValueError):
            remove_padding(b"")

        # Test data shorter than block size but with valid padding
        data = b"short"
        padded = apply_padding(data)
        original = remove_padding(padded)
        self.assertEqual(original, data)

        # Test exact block size
        data = b"A" * 16
        padded = apply_padding(data)
        self.assertEqual(len(padded), 32)
        original = remove_padding(padded)
        self.assertEqual(original, data)

        # Test single byte with valid padding
        data = b"X"
        padded = apply_padding(data)
        self.assertEqual(len(padded), 16)
        original = remove_padding(padded)
        self.assertEqual(original, data)


if __name__ == "__main__":
    unittest.main()