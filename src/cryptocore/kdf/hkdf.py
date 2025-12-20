import struct
from typing import Union

try:
    from ..mac.hmac import HMAC
except ImportError:
    try:
        from cryptocore.mac.hmac import HMAC
    except ImportError:
        from src.cryptocore.mac.hmac import HMAC


def derive_key(master_key: bytes, context: Union[str, bytes], length: int = 32) -> bytes:
    if isinstance(context, str):
        context = context.encode('utf-8')

    if len(master_key) < 16:
        raise ValueError("Master key should be at least 16 bytes")

    derived = bytearray()
    counter = 1

    while len(derived) < length:
        # T_i = HMAC(master_key, context || counter)
        block_data = context + struct.pack('>I', counter)
        block = HMAC.compute_hmac(master_key, block_data)
        derived.extend(block)
        counter += 1

    return bytes(derived[:length])


def derive_key_hierarchy(master_key: bytes,
                         contexts: list[str],
                         key_length: int = 32) -> dict[str, bytes]:
    result = {}
    for context in contexts:
        result[context] = derive_key(master_key, context, key_length)
    return result