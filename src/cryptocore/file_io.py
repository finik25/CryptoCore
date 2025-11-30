import os
from typing import Optional


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
