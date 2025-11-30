def apply_padding(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def remove_padding(padded_data: bytes, block_size: int = 16) -> bytes:
    if not padded_data:
        raise ValueError("Empty data")

    padding_length = padded_data[-1]

    # Check that padding is valid
    if padding_length == 0 or padding_length > block_size:
        raise ValueError("Invalid padding length")

    # Check that all padding bytes are correct
    if padded_data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")

    return padded_data[:-padding_length]
