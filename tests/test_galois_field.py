import unittest
from src.cryptocore.utils.galois_field import GaloisField


class TestGaloisField(unittest.TestCase):
    """
    Tests for Galois Field GF(2^128).

    Important: multiply() method expects different representations:
    - bytes: normal representation (automatically converted)
    - int: already in bit-reversed representation (not converted)
    """

    def test_identity_multiplication_bytes(self):
        test_bytes = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00'
        one_bytes = b'\x00' * 15 + b'\x01'
        result_bytes = GaloisField.multiply(test_bytes, one_bytes)
        self.assertEqual(result_bytes, test_bytes)

    def test_identity_multiplication_int_bit_reversed(self):
        # Number is already in bit-reversed representation
        test_val = 0x1234567890ABCDEF1234567890ABCDEF

        # 1 in bit-reversed representation is the most significant bit
        one_bit_reversed = 1 << 127

        result_val = GaloisField.multiply(test_val, one_bit_reversed)
        self.assertEqual(result_val, test_val)

    def test_zero_multiplication_bytes(self):
        test_bytes = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00'
        zero_bytes = b'\x00' * 16
        result_bytes = GaloisField.multiply(test_bytes, zero_bytes)
        self.assertEqual(result_bytes, zero_bytes)

    def test_zero_multiplication_int(self):
        test_val = 0x1234567890ABCDEF1234567890ABCDEF
        result_val = GaloisField.multiply(test_val, 0)
        self.assertEqual(result_val, 0)

    def test_addition_is_xor(self):
        a_bytes = bytes.fromhex("1234567890abcdef1234567890abcdef")
        b_bytes = bytes.fromhex("fedcba0987654321fedcba0987654321")

        result_bytes = GaloisField.add(a_bytes, b_bytes)
        xor_result = bytes(x ^ y for x, y in zip(a_bytes, b_bytes))

        self.assertEqual(result_bytes, xor_result)

    def test_distributive_law(self):
        # Use integers in bit-reversed representation
        a = 0x1234
        b = 0x5678
        c = 0x9ABC

        # Convert to bit-reversed representation
        a128 = GaloisField._reverse_bits_128(a << 112)
        b128 = GaloisField._reverse_bits_128(b << 112)
        c128 = GaloisField._reverse_bits_128(c << 112)

        # Left side: a * (b + c)
        left = GaloisField.multiply(a128, b128 ^ c128)

        # Right side: a*b + a*c
        right = GaloisField.multiply(a128, b128) ^ GaloisField.multiply(a128, c128)

        self.assertEqual(left, right, "Distributive law violation")

    def test_associative_law(self):
        # Use small values for reliability
        a = 0x1
        b = 0x2
        c = 0x3

        # Convert to bit-reversed representation
        a128 = GaloisField._reverse_bits_128(a << 120)
        b128 = GaloisField._reverse_bits_128(b << 120)
        c128 = GaloisField._reverse_bits_128(c << 120)

        # Left side: (a*b)*c
        ab = GaloisField.multiply(a128, b128)
        left = GaloisField.multiply(ab, c128)

        # Right side: a*(b*c)
        bc = GaloisField.multiply(b128, c128)
        right = GaloisField.multiply(a128, bc)

        self.assertEqual(left, right, "Associative law violation")

    def test_commutative_law(self):
        # Use small values
        a = 0x1234
        b = 0x5678

        # Convert to bit-reversed representation
        a128 = GaloisField._reverse_bits_128(a << 112)
        b128 = GaloisField._reverse_bits_128(b << 112)

        left = GaloisField.multiply(a128, b128)
        right = GaloisField.multiply(b128, a128)

        self.assertEqual(left, right, "Commutative law violation")

    def test_bytes_conversion(self):
        # Test with full 16-byte value
        data = bytes(range(16))
        value = GaloisField.bytes_to_int(data)
        result = GaloisField.int_to_bytes(value, 16)
        self.assertEqual(data, result)

        # Test with short data
        data = b"hello"
        value = GaloisField.bytes_to_int(data)
        result = GaloisField.int_to_bytes(value, 16)
        expected = b'\x00' * 11 + b'hello'
        self.assertEqual(expected, result)

    def test_bit_reversal(self):
        # Test conversion there and back
        test_values = [
            0x00000000000000000000000000000001,  # 1
            0x80000000000000000000000000000000,  # Most significant bit
            0x55555555555555555555555555555555,  # Alternating bits
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,  # All bits
        ]

        for val in test_values:
            reversed_val = GaloisField._reverse_bits_128(val)
            restored_val = GaloisField._reverse_bits_128(reversed_val)
            self.assertEqual(restored_val, val,
                             f"Incorrect bit-reversal for {val:032x}")

    def test_multiply_gcm_method_exists(self):
        # Just verify the method exists and can be called
        h = b'\x00' * 16
        y = b'\x00' * 16
        result = GaloisField.multiply_gcm(h, y)
        self.assertEqual(len(result), 16, "multiply_gcm should return 16 bytes")


def run_algebraic_tests():
    suite = unittest.TestSuite()

    # Add only algebraic tests
    algebraic_tests = [
        'test_identity_multiplication_bytes',
        'test_identity_multiplication_int_bit_reversed',
        'test_zero_multiplication_bytes',
        'test_zero_multiplication_int',
        'test_addition_is_xor',
        'test_distributive_law',
        'test_associative_law',
        'test_commutative_law',
        'test_bytes_conversion',
        'test_bit_reversal',
        'test_multiply_gcm_method_exists'
    ]

    for test_name in algebraic_tests:
        suite.addTest(TestGaloisField(test_name))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    print("TESTING ALGEBRAIC PROPERTIES OF GALOIS FIELD")
    success = run_algebraic_tests()

    if success:
        print("ALL ALGEBRAIC TESTS PASSED")
    else:
        print("SOME TESTS FAILED")