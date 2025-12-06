import struct
import sys
from typing import List, Optional


class SHA256:
    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    _H0 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    )

    # Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    _K = (
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    )

    # Предварительно вычисленные маски для быстрого доступа
    _MASK_32 = 0xFFFFFFFF

    def __init__(self):
        # Initialize SHA-256 context
        self.reset()

    def reset(self):
        """Reset hash computation to initial state"""
        # Используем кортеж вместо списка для хеша
        self.h = list(self._H0)
        self.message_length = 0
        self.buffer = bytearray()

    @staticmethod
    def _right_rotate(x: int, n: int) -> int:
        """Right rotate 32-bit integer (optimized inline)"""
        return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF


    def _process_block_fast(self, block: bytes):
        if len(block) != 64:
            raise ValueError(f"Block must be 64 bytes, got {len(block)} bytes")

        w = [0] * 64

        w[0:16] = struct.unpack('>16I', block)

        for i in range(16, 64):
            w15 = w[i - 15]
            s0 = ((w15 >> 7) | (w15 << 25)) & 0xFFFFFFFF
            s0 ^= ((w15 >> 18) | (w15 << 14)) & 0xFFFFFFFF
            s0 ^= (w15 >> 3)

            w2 = w[i - 2]
            s1 = ((w2 >> 17) | (w2 << 15)) & 0xFFFFFFFF
            s1 ^= ((w2 >> 19) | (w2 << 13)) & 0xFFFFFFFF
            s1 ^= (w2 >> 10)

            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self.h

        k = self._K
        for i in range(64):
            # Embedded computing Σ1, Ch, Σ0, Maj
            # Σ1(e)
            s1 = ((e >> 6) | (e << 26)) & 0xFFFFFFFF
            s1 ^= ((e >> 11) | (e << 21)) & 0xFFFFFFFF
            s1 ^= ((e >> 25) | (e << 7)) & 0xFFFFFFFF

            # Ch(e, f, g)
            ch = (e & f) ^ ((~e) & g)

            # Temporary variable t1
            t1 = (h + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF

            # Σ0(a)
            s0 = ((a >> 2) | (a << 30)) & 0xFFFFFFFF
            s0 ^= ((a >> 13) | (a << 19)) & 0xFFFFFFFF
            s0 ^= ((a >> 22) | (a << 10)) & 0xFFFFFFFF

            # Maj(a, b, c)
            maj = (a & b) ^ (a & c) ^ (b & c)

            # Temporary variable t2
            t2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def _process_block(self, block: bytes):
        return self._process_block_fast(block)

    def update(self, data: bytes):
        if not data:
            return

        self.message_length += len(data)

        self.buffer.extend(data)

        while len(self.buffer) >= 64:
            block = self.buffer[:64]
            self._process_block_fast(bytes(block))
            del self.buffer[:64]

    def _pad_message(self):
        bit_length = self.message_length * 8

        self.buffer.append(0x80)

        while (len(self.buffer) % 64) != 56:
            self.buffer.append(0x00)

        # Add the original length as a 64-bit big-endian integer
        self.buffer.extend(struct.pack('>Q', bit_length))

    def digest(self) -> bytes:
        h_save = self.h[:]
        buffer_save = bytearray(self.buffer)
        length_save = self.message_length

        self._pad_message()

        while len(self.buffer) >= 64:
            block = self.buffer[:64]
            self._process_block_fast(bytes(block))
            del self.buffer[:64]

        result = bytearray()
        for h_val in self.h:
            result.extend(struct.pack('>I', h_val))

        self.h = h_save
        self.buffer = buffer_save
        self.message_length = length_save

        return bytes(result)

    def hexdigest(self) -> str:
        return self.digest().hex()

    @classmethod
    def hash(cls, data: bytes) -> bytes:
        sha256 = cls()
        sha256.update(data)
        return sha256.digest()

    @classmethod
    def hash_hex(cls, data: bytes) -> str:
        sha256 = cls()
        sha256.update(data)
        return sha256.hexdigest()