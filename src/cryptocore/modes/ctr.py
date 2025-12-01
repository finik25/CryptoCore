from Crypto.Cipher import AES
import struct

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def encrypt_ctr(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    # Create AES cipher for single block operations
    cipher = AES.new(key, AES.MODE_ECB)

    block_size = 16
    ciphertext = b''

    # Convert IV to integer for counter arithmetic
    # We'll use the last 8 bytes as counter, first 8 as nonce
    nonce = iv[:8]
    initial_counter = struct.unpack('>Q', iv[8:])[0]  # Big-endian 64-bit integer

    # Process plaintext in blocks
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]

        # Create counter block: nonce + counter
        counter_block = nonce + struct.pack('>Q', initial_counter)

        # Encrypt counter to generate keystream
        keystream = cipher.encrypt(counter_block)

        # XOR plaintext with keystream
        cipher_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))

        ciphertext += cipher_block

        # Increment counter
        initial_counter += 1

    return ciphertext


def decrypt_ctr(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # CTR decryption is identical to encryption
    return encrypt_ctr(ciphertext, key, iv)