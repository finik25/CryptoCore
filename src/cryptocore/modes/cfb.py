from Crypto.Cipher import AES

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def encrypt_cfb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    # Create AES cipher for single block operations
    cipher = AES.new(key, AES.MODE_ECB)

    block_size = 16
    ciphertext = b''
    feedback = iv  # Start with IV

    # Process plaintext in blocks
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]

        # CFB encryption: encrypt feedback, then XOR with plaintext
        encrypted_feedback = cipher.encrypt(feedback)

        # XOR with plaintext block (truncate if last block is shorter)
        cipher_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback[:len(block)]))

        ciphertext += cipher_block

        # Update feedback: for full block CFB, feedback = cipher_block
        # For partial last block, pad cipher_block to full block
        if len(cipher_block) == block_size:
            feedback = cipher_block
        else:
            # Pad with zeros for partial block (CFB standard)
            feedback = cipher_block + bytes(block_size - len(cipher_block))

    return ciphertext


def decrypt_cfb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    # Create AES cipher for single block operations
    cipher = AES.new(key, AES.MODE_ECB)

    block_size = 16
    plaintext = b''
    feedback = iv  # Start with IV

    # Process ciphertext in blocks
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]

        # CFB decryption: encrypt feedback, then XOR with ciphertext
        encrypted_feedback = cipher.encrypt(feedback)

        # XOR with ciphertext block (truncate if last block is shorter)
        plain_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback[:len(block)]))

        plaintext += plain_block

        # Update feedback: ciphertext block (not plaintext!)
        if len(block) == block_size:
            feedback = block
        else:
            # Pad with zeros for partial block
            feedback = block + bytes(block_size - len(block))

    return plaintext