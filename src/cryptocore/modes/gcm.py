import os
import struct
from typing import Tuple, Optional
from Crypto.Cipher import AES

# Import our Galois Field implementation
try:
    from ..utils.galois_field import gf_multiply_gcm, gf_add
except ImportError:
    from cryptocore.utils.galois_field import gf_multiply_gcm, gf_add

class AuthenticationError(Exception):
    """Raised when GCM authentication (tag verification) fails."""
    pass

class GCM:
    """
    Galois/Counter Mode (GCM) for authenticated encryption with AES.

    Structure (per NIST SP 800-38D):
    1. Encryption: CTR mode using derived counters
    2. Authentication: GHASH in GF(2^128) over AAD and ciphertext

    Security properties:
    - Confidentiality: AES-CTR
    - Integrity/Authenticity: GHASH tag
    - Nonce reuse: CATASTROPHIC - must be unique for each encryption with same key
    """

    # Constants
    BLOCK_SIZE = 16  # bytes (AES block size)
    TAG_SIZE = 16    # bytes (128-bit authentication tag)
    RECOMMENDED_NONCE_SIZE = 12  # bytes (96 bits, most efficient)

    def __init__(self, key: bytes, nonce: Optional[bytes] = None):
        """
        Initialize GCM with encryption key.

        Args:
            key: AES key (16 bytes for AES-128)
            nonce: Nonce/IV (12 bytes recommended). If None, random is generated.

        Raises:
            ValueError: If key or nonce size is invalid
        """
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES key must be 16, 24 or 32 bytes, got {len(key)}")

        # Store key and create AES cipher for ECB operations
        self.key = key
        self._cipher = AES.new(key, AES.MODE_ECB)

        # Generate or validate nonce
        if nonce is None:
            # Generate random 12-byte nonce (recommended size)
            self.nonce = os.urandom(self.RECOMMENDED_NONCE_SIZE)
        else:
            if len(nonce) != self.RECOMMENDED_NONCE_SIZE:
                raise ValueError(
                    f"Nonce must be {self.RECOMMENDED_NONCE_SIZE} bytes, "
                    f"got {len(nonce)}"
                )
            self.nonce = nonce

        # Precompute H = AES.encrypt(0^128) for GHASH
        self._h = self._cipher.encrypt(b'\x00' * self.BLOCK_SIZE)

    def _ghash(self, aad: bytes, ciphertext: bytes) -> bytes:
        """
        Compute GHASH in GF(2^128) over AAD and ciphertext.

        GHASH formula: X = ( ( (0 * H ⊕ A1) * H ⊕ A2 ... ) * H ⊕ C1 ) ...

        Args:
            aad: Associated Authenticated Data (may be empty)
            ciphertext: Encrypted data

        Returns:
            16-byte GHASH value (before final encryption)
        """
        # Step 1: Prepare data blocks
        # Format: [AAD blocks] || [Ciphertext blocks] || [len(AAD)] || [len(Ciphertext)]

        blocks = bytearray()

        # Add AAD blocks (padded to 16 bytes)
        aad_len = len(aad)
        if aad_len > 0:
            blocks.extend(aad)
            # Padding for AAD
            pad_len = (16 - (aad_len % 16)) % 16
            blocks.extend(b'\x00' * pad_len)

        # Add ciphertext blocks (padded to 16 bytes)
        ct_len = len(ciphertext)
        if ct_len > 0:
            blocks.extend(ciphertext)
            # Padding for ciphertext
            pad_len = (16 - (ct_len % 16)) % 16
            blocks.extend(b'\x00' * pad_len)

        # Add lengths (64-bit each, big-endian)
        blocks.extend(struct.pack('>Q', aad_len * 8))  # Length in bits
        blocks.extend(struct.pack('>Q', ct_len * 8))   # Length in bits

        # Step 2: Process blocks with Galois Field multiplication
        # Start with zero
        result = b'\x00' * self.BLOCK_SIZE

        # Process each 16-byte block
        for i in range(0, len(blocks), self.BLOCK_SIZE):
            # Explicitly convert to bytes
            block = bytes(blocks[i:i + self.BLOCK_SIZE])
            # Ensure block is 16 bytes
            if len(block) < self.BLOCK_SIZE:
                block = block + b'\x00' * (self.BLOCK_SIZE - len(block))

            # XOR then multiply: result = (result ⊕ block) * H
            result = gf_add(result, block)
            result = gf_multiply_gcm(self._h, result)

        return result

    def _inc_32(self, counter_block: bytes) -> bytes:
        """
        Increment rightmost 32 bits of counter block (mod 2^32).

        This is used for CTR mode counters in GCM.
        """
        if len(counter_block) != self.BLOCK_SIZE:
            raise ValueError("Counter block must be 16 bytes")

        # Last 4 bytes (32 bits) are the counter
        counter = bytearray(counter_block)

        # Increment the 32-bit integer at the end
        for i in range(15, 11, -1):  # Bytes 12-15 (0-indexed)
            if counter[i] == 0xFF:
                counter[i] = 0
            else:
                counter[i] += 1
                break

        return bytes(counter)

    def _compute_tag(self, aad: bytes, ciphertext: bytes, j0: bytes) -> bytes:
        """
        Compute authentication tag for given AAD and ciphertext.

        Args:
            aad: Associated Authenticated Data
            ciphertext: Ciphertext to authenticate
            j0: Pre-counter block (nonce || 0x00000001 for 12-byte nonce)

        Returns:
            16-byte authentication tag
        """
        # Compute GHASH
        ghash_result = self._ghash(aad, ciphertext)

        # Encrypt GHASH to get tag: Tag = MSB_T(GCTR(J0, GHASH))
        tag_keystream = self._cipher.encrypt(j0)
        tag = bytes(a ^ b for a, b in zip(ghash_result, tag_keystream))

        return tag[:self.TAG_SIZE]

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext with authentication.

        Args:
            plaintext: Data to encrypt
            aad: Associated Authenticated Data (not encrypted)

        Returns:
            Tuple of (nonce, ciphertext, tag)
        """
        # Step 1: Generate J0 from nonce (NIST SP 800-38D, section 5.2.1.1)
        # For 12-byte nonce: J0 = nonce || 0x00000001
        if len(self.nonce) == 12:
            j0 = self.nonce + b'\x00\x00\x00\x01'
        else:
            raise ValueError("Only 12-byte nonce supported in current implementation")

        # Step 2: Generate initial counter for encryption (ICB = inc32(J0))
        icb = self._inc_32(j0)

        # Step 3: Encrypt using CTR mode
        ciphertext = bytearray()
        counter = icb

        for i in range(0, len(plaintext), self.BLOCK_SIZE):
            block = plaintext[i:i + self.BLOCK_SIZE]

            # Generate keystream block
            keystream = self._cipher.encrypt(counter)

            # XOR with plaintext block
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext.extend(cipher_block)

            # Increment counter for next block
            counter = self._inc_32(counter)

        ciphertext = bytes(ciphertext)

        # Step 4: Compute authentication tag
        tag = self._compute_tag(aad, ciphertext, j0)

        return self.nonce, ciphertext, tag

    def decrypt(self, ciphertext: bytes, tag: bytes, nonce: bytes,
                aad: bytes = b"") -> bytes:
        """
        Decrypt ciphertext and verify authentication tag.

        Args:
            ciphertext: Encrypted data
            tag: Authentication tag (16 bytes)
            nonce: Nonce used during encryption
            aad: Associated Authenticated Data

        Returns:
            Decrypted plaintext

        Raises:
            AuthenticationError: If tag verification fails
            ValueError: If inputs are invalid
        """
        if len(tag) != self.TAG_SIZE:
            raise ValueError(f"Tag must be {self.TAG_SIZE} bytes, got {len(tag)}")

        # Step 1: Verify tag BEFORE decryption (CRITICAL SECURITY)
        # Generate J0 from nonce (same as in encryption)
        if len(nonce) == 12:
            j0 = nonce + b'\x00\x00\x00\x01'
        else:
            raise ValueError("Only 12-byte nonce supported in current implementation")

        # Compute expected tag
        expected_tag = self._compute_tag(aad, ciphertext, j0)

        # Constant-time comparison (simplified for educational purposes)
        # In production, use hmac.compare_digest()
        if tag != expected_tag:
            raise AuthenticationError(
                "GCM tag verification failed - data may be tampered or AAD incorrect"
            )

        # Step 2: Only after successful verification, decrypt
        # Generate initial counter for decryption (same as encryption)
        icb = self._inc_32(j0)

        # Decrypt using CTR mode (same as encryption)
        plaintext = bytearray()
        counter = icb

        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]

            # Generate keystream block
            keystream = self._cipher.encrypt(counter)

            # XOR with ciphertext block
            plain_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            plaintext.extend(plain_block)

            # Increment counter for next block
            counter = self._inc_32(counter)

        return bytes(plaintext)


# Convenience functions for module-level access
def encrypt_gcm(plaintext: bytes, key: bytes, nonce: Optional[bytes] = None,
                aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    """One-shot GCM encryption."""
    gcm = GCM(key, nonce)
    return gcm.encrypt(plaintext, aad)

def decrypt_gcm(ciphertext: bytes, tag: bytes, nonce: bytes, key: bytes,
                aad: bytes = b"") -> bytes:
    """One-shot GCM decryption with tag verification."""
    gcm = GCM(key, nonce)
    return gcm.decrypt(ciphertext, tag, nonce, aad)