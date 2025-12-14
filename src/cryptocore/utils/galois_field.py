from typing import Union


class GaloisField:
    # Reduction constant for polynomial x^128 + x^7 + x^2 + x + 1
    R = 0xE1000000000000000000000000000000

    @staticmethod
    def _to_16_bytes(data: Union[bytes, bytearray]) -> bytes:
        if isinstance(data, bytearray):
            data = bytes(data)
        if len(data) == 16:
            return data
        elif len(data) < 16:
            return b'\x00' * (16 - len(data)) + data
        else:
            return data[:16]

    @staticmethod
    def bytes_to_int(data: Union[bytes, bytearray]) -> int:
        if isinstance(data, bytearray):
            data = bytes(data)
        return int.from_bytes(data, byteorder='big')

    @staticmethod
    def int_to_bytes(value: int, length: int = 16) -> bytes:
        return value.to_bytes(length, byteorder='big')

    @staticmethod
    def _reverse_bits_128(x: int) -> int:
        result = 0
        for i in range(128):
            if (x >> i) & 1:
                result |= 1 << (127 - i)
        return result

    @staticmethod
    def multiply(x: Union[int, bytes, bytearray], y: Union[int, bytes, bytearray]) -> Union[int, bytes]:
        # Determine return format
        return_bytes = isinstance(x, (bytes, bytearray)) or isinstance(y, (bytes, bytearray))

        # Convert inputs to integers
        if isinstance(x, (bytes, bytearray)):
            x_bytes = GaloisField._to_16_bytes(x)
            x_int = int.from_bytes(x_bytes, byteorder='big')
            x_int = GaloisField._reverse_bits_128(x_int)  # To bit-reversed
        else:
            x_int = x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        if isinstance(y, (bytes, bytearray)):
            y_bytes = GaloisField._to_16_bytes(y)
            y_int = int.from_bytes(y_bytes, byteorder='big')
            y_int = GaloisField._reverse_bits_128(y_int)  # To bit-reversed
        else:
            y_int = y & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        # Multiplication algorithm in bit-reversed representation
        z = 0
        v = y_int

        for i in range(127, -1, -1):
            if (x_int >> i) & 1:
                z ^= v

            if v & 1:
                v = (v >> 1) ^ GaloisField.R
            else:
                v >>= 1

        result = z & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        # Convert result back to required format
        if return_bytes:
            result = GaloisField._reverse_bits_128(result)  # From bit-reversed to normal
            return result.to_bytes(16, byteorder='big')
        else:
            return result

    @staticmethod
    def multiply_gcm(h_bytes: Union[bytes, bytearray], y_bytes: Union[bytes, bytearray]) -> bytes:
        # H is already in bit-reversed representation, do not convert!
        if isinstance(h_bytes, bytearray):
            h_bytes = bytes(h_bytes)
        if isinstance(y_bytes, bytearray):
            y_bytes = bytes(y_bytes)

        h_int = int.from_bytes(GaloisField._to_16_bytes(h_bytes), 'big')

        # Convert Y to bit-reversed representation
        y_int = int.from_bytes(GaloisField._to_16_bytes(y_bytes), 'big')
        y_rev = GaloisField._reverse_bits_128(y_int)

        # Multiplication in bit-reversed domain
        z = 0
        v = y_rev

        for i in range(127, -1, -1):
            if (h_int >> i) & 1:
                z ^= v

            if v & 1:
                v = (v >> 1) ^ GaloisField.R
            else:
                v >>= 1

        # Result is in bit-reversed domain, convert back
        result_rev = z & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        result_normal = GaloisField._reverse_bits_128(result_rev)

        return result_normal.to_bytes(16, byteorder='big')

    @staticmethod
    def add(x: Union[int, bytes, bytearray], y: Union[int, bytes, bytearray]) -> Union[int, bytes]:
        # Convert bytearray to bytes if needed
        if isinstance(x, bytearray):
            x = bytes(x)
        if isinstance(y, bytearray):
            y = bytes(y)

        if isinstance(x, bytes):
            x_bytes = GaloisField._to_16_bytes(x)
            x_int = int.from_bytes(x_bytes, byteorder='big')
        else:
            x_int = x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        if isinstance(y, bytes):
            y_bytes = GaloisField._to_16_bytes(y)
            y_int = int.from_bytes(y_bytes, byteorder='big')
        else:
            y_int = y & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        result = x_int ^ y_int

        if isinstance(x, bytes) or isinstance(y, bytes):
            return result.to_bytes(16, byteorder='big')
        else:
            return result


# Convenience functions
def gf_multiply(x: Union[int, bytes, bytearray], y: Union[int, bytes, bytearray]) -> Union[int, bytes]:
    # Multiply in GF(2^128) - general method.
    return GaloisField.multiply(x, y)


def gf_multiply_gcm(h: Union[bytes, bytearray], y: Union[bytes, bytearray]) -> bytes:
    # Multiply for GCM (H is already in bit-reversed representation)
    return GaloisField.multiply_gcm(h, y)


def gf_add(x: Union[int, bytes, bytearray], y: Union[int, bytes, bytearray]) -> Union[int, bytes]:
    return GaloisField.add(x, y)