import os
from typing import Tuple, Optional


def read_file(file_path: str) -> bytes:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file not found: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except PermissionError:
        raise PermissionError(f"No permission to read file: {file_path}")
    except IOError as e:
        raise IOError(f"Error reading file {file_path}: {str(e)}")


def read_file_with_iv(file_path: str) -> Tuple[bytes, bytes]:
    data = read_file(file_path)

    if len(data) < 16:
        raise ValueError(f"File too short to contain IV: {len(data)} bytes, need at least 16 bytes")

    iv = data[:16]
    remaining_data = data[16:]

    return iv, remaining_data


def write_file(file_path: str, data: bytes, overwrite: bool = False) -> None:
    if os.path.exists(file_path) and not overwrite:
        raise FileExistsError(f"Output file already exists: {file_path}. Use --force to overwrite.")

    # Create directory if it doesn't exist
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except PermissionError:
            raise PermissionError(f"No permission to create directory: {directory}")

    try:
        with open(file_path, 'wb') as file:
            file.write(data)
    except PermissionError:
        raise PermissionError(f"No permission to write file: {file_path}")
    except IOError as e:
        raise IOError(f"Error writing file {file_path}: {str(e)}")


def write_file_with_iv(file_path: str, iv: bytes, data: bytes, overwrite: bool = False) -> None:
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)} bytes")

    combined_data = iv + data
    write_file(file_path, combined_data, overwrite)


def derive_output_filename(input_path: str, operation: str, algorithm: str, mode: str) -> str:
    base_name = os.path.basename(input_path)

    if operation == 'encrypt':
        # file.txt -> file.txt.enc
        return f"{base_name}.enc"
    elif operation == 'decrypt':
        # file.txt.enc -> file.dec.txt
        name, ext = os.path.splitext(base_name)
        if ext == '.enc':
            original_name, original_ext = os.path.splitext(name)
            if original_ext:
                return f"{original_name}.dec{original_ext}"
            else:
                return f"{name}.dec"
        else:
            return f"{base_name}.dec"
    else:
        return f"{base_name}.{operation}"


def derive_output_filename(input_path: str, operation: str, algorithm: str, mode: str) -> str:
    base_name = os.path.basename(input_path)

    if operation == 'encrypt':
        if mode == 'gcm':
            # For GCM: file.txt -> file.txt.gcm
            return f"{base_name}.gcm"
        else:
            # For other modes: file.txt -> file.txt.enc
            return f"{base_name}.enc"
    elif operation == 'decrypt':
        if mode == 'gcm':
            # For GCM: file.txt.gcm -> file.dec.txt
            name, ext = os.path.splitext(base_name)
            if ext == '.gcm':
                original_name, original_ext = os.path.splitext(name)
                if original_ext:
                    return f"{original_name}.dec{original_ext}"
                else:
                    return f"{name}.dec"
            else:
                return f"{base_name}.dec"
        else:
            # For other modes: file.txt.enc -> file.dec.txt
            name, ext = os.path.splitext(base_name)
            if ext == '.enc':
                original_name, original_ext = os.path.splitext(name)
                if original_ext:
                    return f"{original_name}.dec{original_ext}"
                else:
                    return f"{name}.dec"
            else:
                return f"{base_name}.dec"
    else:
        return f"{base_name}.{operation}"


def read_gcm_file(file_path: str) -> tuple[bytes, bytes, bytes]:
    data = read_file(file_path)

    if len(data) < 28:  # nonce(12) + tag(16)
        raise ValueError(f"GCM file too short: {len(data)} bytes, need at least 28")

    nonce = data[:12]
    tag = data[-16:]
    ciphertext = data[12:-16]

    return nonce, ciphertext, tag


def write_gcm_file(file_path: str, nonce: bytes, ciphertext: bytes, tag: bytes,
                   overwrite: bool = False) -> None:
    # Write GCM file with proper format: nonce(12 bytes) | ciphertext | tag(16 bytes)

    if len(nonce) != 12:
        raise ValueError(f"Nonce must be 12 bytes, got {len(nonce)}")

    if len(tag) != 16:
        raise ValueError(f"Tag must be 16 bytes, got {len(tag)}")

    combined_data = nonce + ciphertext + tag
    write_file(file_path, combined_data, overwrite)