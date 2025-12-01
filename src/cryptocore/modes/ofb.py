from Crypto.Cipher import AES
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def encrypt_ofb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
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

        # OFB: encrypt feedback to generate keystream
        keystream = cipher.encrypt(feedback)

        # XOR plaintext with keystream
        cipher_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))

        ciphertext += cipher_block

        # Update feedback: keystream (not ciphertext!)
        feedback = keystream

    return ciphertext


def decrypt_ofb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # OFB decryption is identical to encryption
    return encrypt_ofb(ciphertext, key, iv)