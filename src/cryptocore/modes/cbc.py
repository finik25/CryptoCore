import sys
import os
from Crypto.Cipher import AES

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from cryptocore.utils.padding import apply_padding, remove_padding
except ImportError:
    # Альтернативный путь для прямого запуска
    from src.cryptocore.utils.padding import apply_padding, remove_padding


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    # Apply PKCS#7 padding
    padded_plaintext = apply_padding(plaintext)

    # Create AES cipher for single block operations
    cipher = AES.new(key, AES.MODE_ECB)

    block_size = 16
    ciphertext = b''
    previous_block = iv  # First block uses IV

    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i:i + block_size]

        # CBC encryption: block XOR previous_ciphertext, then AES encrypt
        # For first block: previous_ciphertext = IV
        xor_block = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block = cipher.encrypt(xor_block)

        ciphertext += encrypted_block
        previous_block = encrypted_block  # For next iteration

    return ciphertext


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of block size (16 bytes)")

    # Create AES cipher for single block operations
    cipher = AES.new(key, AES.MODE_ECB)

    block_size = 16
    padded_plaintext = b''
    previous_block = iv  # First block uses IV

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]

        # CBC decryption: AES decrypt, then XOR with previous ciphertext
        # For first block: previous_ciphertext = IV
        decrypted_block = cipher.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))

        padded_plaintext += plain_block
        previous_block = block  # For next iteration

    # Remove padding
    plaintext = remove_padding(padded_plaintext)

    return plaintext
