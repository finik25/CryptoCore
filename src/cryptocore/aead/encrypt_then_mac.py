"""
Encrypt-then-MAC implementation for authenticated encryption.
Follows: C = Encrypt(K_enc, P), T = MAC(K_mac, C || AAD), output = C || T

This provides a generic authenticated encryption scheme that can be used
with any block cipher mode from previous sprints combined with HMAC-SHA256.
"""

import os
import struct
from typing import Tuple, Optional

# Import existing components
try:
    from src.cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
    from src.cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr
    from src.cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
    from src.cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
    from src.cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
    from src.cryptocore.mac.hmac import HMAC
    from src.cryptocore.utils.padding import apply_padding, remove_padding
except ImportError:
    try:
        from cryptocore.modes.cbc import encrypt_cbc, decrypt_cbc
        from cryptocore.modes.ctr import encrypt_ctr, decrypt_ctr
        from cryptocore.modes.cfb import encrypt_cfb, decrypt_cfb
        from cryptocore.modes.ofb import encrypt_ofb, decrypt_ofb
        from cryptocore.modes.ecb import encrypt_ecb, decrypt_ecb
        from cryptocore.mac.hmac import HMAC
        from cryptocore.utils.padding import apply_padding, remove_padding
    except ImportError as e:
        raise ImportError(f"Cannot import required modules: {e}")


class AuthenticationError(Exception):
    """Exception raised when authentication fails."""
    pass


class EncryptThenMAC:
    """
    Authenticated encryption using Encrypt-then-MAC paradigm.

    Security properties:
    - Confidentiality: Provided by the underlying block cipher mode
    - Integrity/Authenticity: Provided by HMAC-SHA256
    - Nonce/IV reuse: IV must be unique for each encryption with the same key

    Format: IV || Ciphertext || Tag
    - IV: 16 bytes (for all modes except ECB)
    - Ciphertext: Variable length
    - Tag: 32 bytes (HMAC-SHA256 output)
    """

    # Block size for AES
    BLOCK_SIZE = 16

    def __init__(self, master_key: bytes, mode: str = 'cbc'):
        """
        Initialize Encrypt-then-MAC with a master key.

        Args:
            master_key: Master key (minimum 32 bytes recommended).
                       Will be split into encryption and MAC keys.
            mode: Encryption mode ('cbc', 'ctr', 'cfb', 'ofb', 'ecb')

        Raises:
            ValueError: If mode is unsupported or master key is too short
        """
        if len(master_key) < 32:
            raise ValueError("Master key should be at least 32 bytes for security")

        self.master_key = master_key
        self.mode = mode.lower()

        # Validate mode
        supported_modes = ['cbc', 'ctr', 'cfb', 'ofb', 'ecb']
        if self.mode not in supported_modes:
            raise ValueError(f"Unsupported mode: {mode}. Supported: {supported_modes}")

        # Derive separate keys from master key
        self.enc_key, self.mac_key = self._derive_keys(master_key, mode)

        # IV requirement
        self.requires_iv = (mode != 'ecb')

    def _derive_keys(self, master_key: bytes, mode: str) -> Tuple[bytes, bytes]:
        """
        Derive encryption and MAC keys from master key using HKDF-like approach.

        Args:
            master_key: Master key
            mode: Encryption mode (for domain separation)

        Returns:
            Tuple of (encryption_key, mac_key)
        """
        # Use HMAC as a simple KDF (will be replaced with proper HKDF in M7)
        hmac = HMAC(master_key)

        # Derive encryption key (16 bytes for AES-128)
        enc_key_info = f"EncryptionKey-{mode}-AES128".encode()
        enc_key_data = hmac.compute(enc_key_info)
        enc_key = enc_key_data[:16]  # AES-128 uses 16-byte keys

        # Derive MAC key (32 bytes for HMAC-SHA256)
        mac_key_info = f"MACKey-{mode}-HMAC-SHA256".encode()
        mac_key = hmac.compute(mac_key_info)

        return enc_key, mac_key

    def _get_encryption_function(self):
        if self.mode == 'cbc':
            return lambda plaintext, iv: encrypt_cbc(plaintext, self.enc_key, iv)
        elif self.mode == 'ctr':
            return lambda plaintext, iv: encrypt_ctr(plaintext, self.enc_key, iv)
        elif self.mode == 'cfb':
            return lambda plaintext, iv: encrypt_cfb(plaintext, self.enc_key, iv)
        elif self.mode == 'ofb':
            return lambda plaintext, iv: encrypt_ofb(plaintext, self.enc_key, iv)
        elif self.mode == 'ecb':
            # ECB doesn't use IV
            return lambda plaintext, iv: encrypt_ecb(plaintext, self.enc_key)
        else:
            raise ValueError(f"Mode {self.mode} not implemented")

    def _get_decryption_function(self):
        if self.mode == 'cbc':
            return lambda ciphertext, iv: decrypt_cbc(ciphertext, self.enc_key, iv)
        elif self.mode == 'ctr':
            return lambda ciphertext, iv: decrypt_ctr(ciphertext, self.enc_key, iv)
        elif self.mode == 'cfb':
            return lambda ciphertext, iv: decrypt_cfb(ciphertext, self.enc_key, iv)
        elif self.mode == 'ofb':
            return lambda ciphertext, iv: decrypt_ofb(ciphertext, self.enc_key, iv)
        elif self.mode == 'ecb':
            # ECB doesn't use IV
            return lambda ciphertext, iv: decrypt_ecb(ciphertext, self.enc_key)
        else:
            raise ValueError(f"Mode {self.mode} not implemented")

    def _compute_mac(self, data: bytes) -> bytes:
        hmac = HMAC(self.mac_key)
        return hmac.compute(data)

    def _verify_mac(self, data: bytes, expected_tag: bytes) -> bool:
        hmac = HMAC(self.mac_key)
        return hmac.verify(data, expected_tag)

    def _prepare_plaintext(self, plaintext: bytes) -> bytes:
        """
        Prepare plaintext for encryption (apply padding if needed).

        Note: Stream modes (CTR, CFB, OFB) don't require padding.
        """
        if self.mode in ['cbc', 'ecb']:
            # Block modes require padding
            return apply_padding(plaintext, self.BLOCK_SIZE)
        else:
            # Stream modes don't require padding
            return plaintext

    def _process_ciphertext(self, ciphertext: bytes) -> bytes:
        """
        Process ciphertext after decryption (remove padding if needed).

        Note: Stream modes (CTR, CFB, OFB) don't have padding.
        """
        if self.mode in ['cbc', 'ecb']:
            # Block modes have padding that needs to be removed
            return remove_padding(ciphertext, self.BLOCK_SIZE)
        else:
            # Stream modes don't have padding
            return ciphertext

    def encrypt(self, plaintext: bytes, iv: Optional[bytes] = None,
                aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext with authentication.

        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (optional, generated if not provided)
            aad: Associated Authenticated Data (optional, not encrypted)

        Returns:
            Tuple of (iv, ciphertext, tag)

        Raises:
            ValueError: If IV is required but not provided for ECB mode
        """
        # Generate IV if not provided (except for ECB)
        if self.requires_iv:
            if iv is None:
                iv = os.urandom(self.BLOCK_SIZE)
            elif len(iv) != self.BLOCK_SIZE:
                raise ValueError(f"IV must be {self.BLOCK_SIZE} bytes, got {len(iv)}")
        else:
            # ECB doesn't use IV
            iv = b""

        # Prepare plaintext (apply padding if needed)
        prepared_plaintext = self._prepare_plaintext(plaintext)

        # Encrypt the plaintext
        encrypt_func = self._get_encryption_function()
        ciphertext = encrypt_func(prepared_plaintext, iv)

        # Compute MAC over: IV || ciphertext || AAD
        # Note: Including IV in MAC prevents IV manipulation attacks
        mac_data = iv + ciphertext + aad
        tag = self._compute_mac(mac_data)

        return iv, ciphertext, tag

    def decrypt(self, ciphertext: bytes, tag: bytes, iv: bytes,
                aad: bytes = b"") -> bytes:
        """
        Decrypt ciphertext with authentication verification.

        Args:
            ciphertext: Encrypted data
            tag: Authentication tag (32 bytes)
            iv: Initialization vector
            aad: Associated Authenticated Data

        Returns:
            Decrypted plaintext

        Raises:
            AuthenticationError: If MAC verification fails
            ValueError: If inputs are invalid
        """
        # Validate inputs
        if len(tag) != 32:
            raise ValueError(f"Tag must be 32 bytes, got {len(tag)}")

        if self.requires_iv:
            if len(iv) != self.BLOCK_SIZE:
                raise ValueError(f"IV must be {self.BLOCK_SIZE} bytes, got {len(iv)}")
        elif iv != b"":
            # ECB doesn't use IV, but we accept empty IV for consistency
            raise ValueError(f"Mode {self.mode} does not use IV")

        # Verify MAC before decryption (constant-time comparison)
        mac_data = iv + ciphertext + aad
        if not self._verify_mac(mac_data, tag):
            raise AuthenticationError("MAC verification failed - data may be tampered")

        # Decrypt the ciphertext
        decrypt_func = self._get_decryption_function()
        decrypted = decrypt_func(ciphertext, iv)

        # Process decrypted data (remove padding if needed)
        plaintext = self._process_ciphertext(decrypted)

        return plaintext

    @classmethod
    def encrypt_to_bytes(cls, plaintext: bytes, master_key: bytes,
                         mode: str = 'cbc', aad: bytes = b"",
                         iv: Optional[bytes] = None) -> bytes:
        """
        Convenience method: Encrypt and return as single byte string.

        Format: IV_LENGTH (2 bytes) || IV || Ciphertext || Tag

        Args:
            plaintext: Data to encrypt
            master_key: Master key
            mode: Encryption mode
            aad: Associated Authenticated Data
            iv: Initialization vector (optional)

        Returns:
            Combined byte string
        """
        etm = cls(master_key, mode)
        iv, ciphertext, tag = etm.encrypt(plaintext, iv, aad)

        # Pack format: IV_LENGTH (2 bytes, big-endian) || IV || Ciphertext || Tag
        iv_length = len(iv)
        packed = struct.pack('>H', iv_length) + iv + ciphertext + tag

        return packed

    @classmethod
    def decrypt_from_bytes(cls, data: bytes, master_key: bytes,
                           mode: str = 'cbc', aad: bytes = b"") -> bytes:
        """
        Convenience method: Decrypt from combined byte string.

        Format: IV_LENGTH (2 bytes) || IV || Ciphertext || Tag

        Args:
            data: Combined byte string
            master_key: Master key
            mode: Encryption mode
            aad: Associated Authenticated Data

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If data format is invalid
        """
        # Minimum size: IV_LENGTH(2) + IV(0) + Tag(32) = 34 bytes
        if len(data) < 34:
            raise ValueError("Data too short")

        # Unpack IV length
        iv_length = struct.unpack('>H', data[:2])[0]

        # Check bounds
        if 2 + iv_length + 32 > len(data):
            raise ValueError("Invalid data format")

        # Extract components
        iv = data[2:2 + iv_length]
        ciphertext = data[2 + iv_length:-32]
        tag = data[-32:]

        # Decrypt
        etm = cls(master_key, mode)
        return etm.decrypt(ciphertext, tag, iv, aad)

    @classmethod
    def encrypt_file(cls, input_path: str, output_path: str,
                     master_key: bytes, mode: str = 'cbc',
                     aad: bytes = b"", iv: Optional[bytes] = None) -> bytes:
        """
        Encrypt a file with authenticated encryption.

        Args:
            input_path: Path to input file
            output_path: Path to output file
            master_key: Master key
            mode: Encryption mode
            aad: Associated Authenticated Data
            iv: Initialization vector (optional)

        Returns:
            The generated IV

        Raises:
            IOError: If file operations fail
        """
        # Read input file
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # Encrypt
        etm = cls(master_key, mode)
        iv, ciphertext, tag = etm.encrypt(plaintext, iv, aad)

        # Write output file: IV_LENGTH || IV || Ciphertext || Tag
        with open(output_path, 'wb') as f:
            iv_length = len(iv)
            f.write(struct.pack('>H', iv_length))
            f.write(iv)
            f.write(ciphertext)
            f.write(tag)

        return iv

    @classmethod
    def decrypt_file(cls, input_path: str, output_path: str,
                     master_key: bytes, mode: str = 'cbc',
                     aad: bytes = b"") -> None:
        """
        Decrypt a file with authentication verification.

        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted file
            master_key: Master key
            mode: Encryption mode
            aad: Associated Authenticated Data

        Raises:
            AuthenticationError: If MAC verification fails
            IOError: If file operations fail
        """
        # Read input file
        with open(input_path, 'rb') as f:
            data = f.read()

        # Decrypt
        plaintext = cls.decrypt_from_bytes(data, master_key, mode, aad)

        # Write output file
        with open(output_path, 'wb') as f:
            f.write(plaintext)


# Export for convenience
def new_etm(master_key: bytes, mode: str = 'cbc') -> EncryptThenMAC:
    return EncryptThenMAC(master_key, mode)


def encrypt_etm(plaintext: bytes, master_key: bytes, mode: str = 'cbc',
                aad: bytes = b"", iv: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    etm = EncryptThenMAC(master_key, mode)
    return etm.encrypt(plaintext, iv, aad)


def decrypt_etm(ciphertext: bytes, tag: bytes, iv: bytes,
                master_key: bytes, mode: str = 'cbc', aad: bytes = b"") -> bytes:
    etm = EncryptThenMAC(master_key, mode)
    return etm.decrypt(ciphertext, tag, iv, aad)