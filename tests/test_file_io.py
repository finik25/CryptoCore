import unittest
import os
import tempfile
from src.cryptocore.file_io import read_file, write_file, derive_output_filename


class TestFileIO(unittest.TestCase):
    def setUp(self):
        # Create temporary directory and files for testing
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_data = b"Hello, CryptoCore! This is test data."

        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)

    def tearDown(self):
        # Clean up temporary files
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_read_file(self):
        data = read_file(self.test_file)
        self.assertEqual(data, self.test_data)

    def test_read_nonexistent_file(self):
        with self.assertRaises(FileNotFoundError):
            read_file("/nonexistent/path/file.txt")

    def test_read_directory(self):
        with self.assertRaises(ValueError):
            read_file(self.temp_dir)

    def test_write_file(self):
        new_file = os.path.join(self.temp_dir, "new.txt")
        write_file(new_file, self.test_data)

        self.assertTrue(os.path.exists(new_file))
        with open(new_file, 'rb') as f:
            written_data = f.read()
        self.assertEqual(written_data, self.test_data)

    def test_write_file_overwrite(self):
        # First write
        write_file(self.test_file, b"initial data", overwrite=True)

        # Overwrite
        new_data = b"overwritten data"
        write_file(self.test_file, new_data, overwrite=True)

        with open(self.test_file, 'rb') as f:
            written_data = f.read()
        self.assertEqual(written_data, new_data)

    def test_write_file_no_overwrite(self):
        with self.assertRaises(FileExistsError):
            write_file(self.test_file, b"new data", overwrite=False)

    def test_write_file_create_directory(self):
        nested_file = os.path.join(self.temp_dir, "nested", "dir", "file.txt")
        write_file(nested_file, self.test_data, overwrite=True)

        self.assertTrue(os.path.exists(nested_file))

    def test_derive_output_filename_encrypt(self):
        result = derive_output_filename("/path/to/document.txt", "encrypt", "aes", "ecb")
        self.assertEqual(result, "document.txt.enc")

        result = derive_output_filename("/path/to/image.jpg", "encrypt", "aes", "cbc")
        self.assertEqual(result, "image.jpg.enc")

        result = derive_output_filename("/path/to/data", "encrypt", "aes", "ecb")
        self.assertEqual(result, "data.enc")

    def test_derive_output_filename_decrypt(self):
        # Decrypt: file.txt.enc -> file.dec.txt
        result = derive_output_filename("/path/to/document.txt.enc", "decrypt", "aes", "ecb")
        self.assertEqual(result, "document.dec.txt")

        result = derive_output_filename("/path/to/image.jpg.enc", "decrypt", "aes", "cbc")
        self.assertEqual(result, "image.dec.jpg")

        result = derive_output_filename("/path/to/data.enc", "decrypt", "aes", "ecb")
        self.assertEqual(result, "data.dec")

        # Files without .enc extension just get .dec appended
        result = derive_output_filename("/path/to/unknown.bin", "decrypt", "aes", "ecb")
        self.assertEqual(result, "unknown.bin.dec")

        result = derive_output_filename("/path/to/file.txt", "decrypt", "aes", "ecb")
        self.assertEqual(result, "file.txt.dec")


if __name__ == "__main__":
    unittest.main()