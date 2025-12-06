import os
from typing import Optional, Union
from src.cryptocore.hash import SHA256, SHA3_256


class HashCalculator:
    # Utility class for calculating hashes of files and data

    _ALGORITHMS = {
        'sha256': SHA256,
        'sha3-256': SHA3_256,
    }

    @classmethod
    def get_algorithm(cls, algorithm: str):
        # Get hash algorithm class by name

        if algorithm not in cls._ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}. "
                             f"Supported: {', '.join(cls._ALGORITHMS.keys())}")
        return cls._ALGORITHMS[algorithm]

    @classmethod
    def hash_data(cls, data: bytes, algorithm: str = 'sha256') -> bytes:
        # Hash data in memory
        algo_class = cls.get_algorithm(algorithm)
        return algo_class.hash(data)

    @classmethod
    def hash_data_hex(cls, data: bytes, algorithm: str = 'sha256') -> str:
        # Hash data in memory, return hex string
        algo_class = cls.get_algorithm(algorithm)
        return algo_class.hash_hex(data)

    @classmethod
    def hash_file(cls, file_path: str, algorithm: str = 'sha256',
                  chunk_size: int = 8192) -> bytes:
        # Hash a file using streaming to handle large files
        algo_class = cls.get_algorithm(algorithm)
        hasher = algo_class()

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            return hasher.digest()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied: {file_path}")
        except Exception as e:
            raise IOError(f"Error reading file {file_path}: {str(e)}")

    @classmethod
    def hash_file_hex(cls, file_path: str, algorithm: str = 'sha256',
                      chunk_size: int = 8192) -> str:
        # Hash a file, return hex string
        return cls.hash_file(file_path, algorithm, chunk_size).hex()

    @classmethod
    def verify_file_hash(cls, file_path: str, expected_hash: Union[str, bytes],
                         algorithm: str = 'sha256') -> bool:
        # Verify file hash against expected value

        actual_hash = cls.hash_file_hex(file_path, algorithm)

        if isinstance(expected_hash, bytes):
            expected_hex = expected_hash.hex()
        else:
            expected_hex = expected_hash.lower()

        return actual_hash == expected_hex