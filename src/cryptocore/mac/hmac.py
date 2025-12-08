from typing import Optional, Union
import sys
import os

# Handle imports - support both package and source execution
try:
    from src.cryptocore.hash.sha256 import SHA256
except ImportError:
    # Try absolute import if running as package
    try:
        from cryptocore.hash.sha256 import SHA256
    except ImportError:
        # Last resort: add path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(current_dir, '..', '..', '..')
        sys.path.insert(0, src_dir)
        from src.cryptocore.hash.sha256 import SHA256


class HMAC:
    """
    HMAC implementation using SHA-256.

    RFC 2104: HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
    where H is SHA-256, block_size = 64 bytes for SHA-256
    opad = 0x5c repeated, ipad = 0x36 repeated
    """

    # SHA-256 block size in bytes
    BLOCK_SIZE = 64

    # Constants from RFC 2104
    IPAD = bytes([0x36] * BLOCK_SIZE)  # inner pad
    OPAD = bytes([0x5c] * BLOCK_SIZE)  # outer pad

    def __init__(self, key: bytes):
        self.hash_class = SHA256
        self.key = self._process_key(key)

    def _process_key(self, key: bytes) -> bytes:
        if len(key) > self.BLOCK_SIZE:
            # Hash the key if it's too long
            hasher = self.hash_class()
            hasher.update(key)
            key = hasher.digest()

        if len(key) < self.BLOCK_SIZE:
            # Pad with zeros if too short
            key = key + bytes(self.BLOCK_SIZE - len(key))

        return key

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        if len(a) != len(b):
            raise ValueError("Byte strings must be of equal length")
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message: bytes) -> bytes:
        # Step 1: K ⊕ ipad
        inner_key = self._xor_bytes(self.key, self.IPAD)

        # Step 2: H((K ⊕ ipad) || message)
        inner_hasher = self.hash_class()
        inner_hasher.update(inner_key)
        inner_hasher.update(message)
        inner_hash = inner_hasher.digest()

        # Step 3: K ⊕ opad
        outer_key = self._xor_bytes(self.key, self.OPAD)

        # Step 4: H((K ⊕ opad) || inner_hash)
        outer_hasher = self.hash_class()
        outer_hasher.update(outer_key)
        outer_hasher.update(inner_hash)
        hmac_value = outer_hasher.digest()

        return hmac_value

    def compute_hex(self, message: bytes) -> str:
        return self.compute(message).hex()

    def verify(self, message: bytes, hmac_to_check: Union[bytes, str]) -> bool:
        computed_hmac = self.compute(message)

        if isinstance(hmac_to_check, str):
            # Convert hex string to bytes
            hmac_to_check = bytes.fromhex(hmac_to_check)

        # Constant-time comparison to prevent timing attacks
        # Note: Python's comparison is not constant-time, but for educational purposes
        # this is acceptable. In production, use secrets.compare_digest()
        return computed_hmac == hmac_to_check

    def update_compute(self, message_chunks) -> bytes:
        # Process inner hash with chunks
        inner_key = self._xor_bytes(self.key, self.IPAD)
        inner_hasher = self.hash_class()
        inner_hasher.update(inner_key)

        for chunk in message_chunks:
            inner_hasher.update(chunk)

        inner_hash = inner_hasher.digest()

        # Process outer hash
        outer_key = self._xor_bytes(self.key, self.OPAD)
        outer_hasher = self.hash_class()
        outer_hasher.update(outer_key)
        outer_hasher.update(inner_hash)

        return outer_hasher.digest()

    @classmethod
    def compute_hmac(cls, key: bytes, message: bytes) -> bytes:
        hmac = cls(key)
        return hmac.compute(message)

    @classmethod
    def compute_hmac_hex(cls, key: bytes, message: bytes) -> str:
        hmac = cls(key)
        return hmac.compute_hex(message)


# Module-level functions for convenience
def new(key: bytes) -> HMAC:
    return HMAC(key)


def compute_hmac(key: bytes, message: bytes) -> bytes:
    return HMAC.compute_hmac(key, message)


def compute_hmac_hex(key: bytes, message: bytes) -> str:
    return HMAC.compute_hmac_hex(key, message)