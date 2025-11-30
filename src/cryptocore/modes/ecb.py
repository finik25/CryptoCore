from Crypto.Cipher import AES
from src.cryptocore.utils.padding import apply_padding, remove_padding


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")

    # Apply PKCS#7 padding
    padded_plaintext = apply_padding(plaintext)

    # Create AES cipher for single block operations
    cipher = AES.new(key, AES.MODE_ECB)

    # Manual ECB implementation - process each block separately
    block_size = 16
    ciphertext = b''

    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i:i + block_size]
        encrypted_block = cipher.encrypt(block)
        ciphertext += encrypted_block

    return ciphertext


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")

    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of block size (16 bytes)")

    # Create AES cipher for single block operations
    cipher = AES.new(key, AES.MODE_ECB)

    # Manual ECB implementation - process each block separately
    block_size = 16
    padded_plaintext = b''

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        decrypted_block = cipher.decrypt(block)
        padded_plaintext += decrypted_block

    # Remove padding
    plaintext = remove_padding(padded_plaintext)

    return plaintext