import hashlib


class SHA3_256:
    # SHA3-256 implementation using Python's built-in hashlib.
    # This uses the Keccak sponge construction as specified in NIST FIPS 202.

    def __init__(self):
        self._hasher = hashlib.sha3_256()

    def reset(self):
        # Reset hash computation.
        self._hasher = hashlib.sha3_256()

    def update(self, data: bytes):
        # Update hash with new data
        self._hasher.update(data)

    def digest(self) -> bytes:
        # Return final hash value as bytes
        return self._hasher.digest()

    def hexdigest(self) -> str:
        # Return final hash value as hexadecimal string
        return self._hasher.hexdigest()

    @classmethod
    def hash(cls, data: bytes) -> bytes:
        # One-shot hash function
        return hashlib.sha3_256(data).digest()

    @classmethod
    def hash_hex(cls, data: bytes) -> str:
        # One-shot hash function returning hex string
        return hashlib.sha3_256(data).hexdigest()