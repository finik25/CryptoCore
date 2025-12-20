import struct
from typing import Union

# Import our HMAC implementation
try:
    from ..mac.hmac import HMAC
except ImportError:
    # Try absolute import
    try:
        from cryptocore.mac.hmac import HMAC
    except ImportError:
        from src.cryptocore.mac.hmac import HMAC


def pbkdf2_hmac_sha256(
        password: Union[str, bytes],
        salt: Union[str, bytes],
        iterations: int,
        dklen: int
) -> bytes:

    # Convert inputs to bytes
    if isinstance(password, str):
        password = password.encode('utf-8')

    if isinstance(salt, str):
        # Try to interpret as hex, otherwise as raw string
        try:
            # Remove any 0x prefix or spaces
            clean_salt = salt.lower().replace('0x', '').replace(' ', '')
            if all(c in '0123456789abcdef' for c in clean_salt):
                salt = bytes.fromhex(clean_salt)
            else:
                salt = salt.encode('utf-8')
        except ValueError:
            salt = salt.encode('utf-8')

    # Validate parameters
    if iterations <= 0:
        raise ValueError("Iterations must be positive")

    if dklen <= 0:
        raise ValueError("Derived key length must be positive")

    # Calculate number of blocks needed (SHA-256 produces 32-byte output)
    blocks_needed = (dklen + 31) // 32
    derived_key = bytearray()

    for i in range(1, blocks_needed + 1):
        # U1 = HMAC(password, salt || INT_32_BE(i))
        block_salt = salt + struct.pack('>I', i)
        u_prev = HMAC.compute_hmac(password, block_salt)
        block = bytearray(u_prev)

        # Compute U2 through Uc
        for _ in range(2, iterations + 1):
            u_curr = HMAC.compute_hmac(password, u_prev)
            # XOR u_curr into block
            block = bytearray(a ^ b for a, b in zip(block, u_curr))
            u_prev = u_curr

        derived_key.extend(block)

    # Return exactly dklen bytes
    return bytes(derived_key[:dklen])


# Convenience functions
def derive_from_password(password: str, salt_hex: str = None,
                         iterations: int = 100000, keylen: int = 32) -> tuple[bytes, bytes]:
    """
    Derive key from password with optional salt generation.

    Returns:
        Tuple of (derived_key, salt_used)
    """
    import os

    if salt_hex is None:
        # Generate random 16-byte salt
        salt = os.urandom(16)
    else:
        salt = bytes.fromhex(salt_hex.replace('0x', ''))

    derived_key = pbkdf2_hmac_sha256(password, salt, iterations, keylen)
    return derived_key, salt