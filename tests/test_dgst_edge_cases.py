import unittest
import tempfile
import subprocess
import sys
import os
import time
import hashlib
import stat
import threading
import queue


class TestDgstEdgeCases(unittest.TestCase):
    def setUp(self):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(self.current_dir)

    def run_cli(self, args, input_data=None):
        cmd = [sys.executable, '-m', 'src.cryptocore.cli'] + args
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            cwd=self.project_root
        )
        return result

    def test_empty_file_size_0(self):
        """Test hashing of empty file (0 bytes)"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            # Create empty file
            temp_file = f.name

        try:
            # SHA-256 of empty file
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output = result.stdout.decode('utf-8').strip()

            expected_hash = hashlib.sha256(b'').hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(output, expected_output)
            self.assertEqual(result.returncode, 0)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_single_byte_file(self):
        """Test hashing of 1-byte file"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'X')
            temp_file = f.name

        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output = result.stdout.decode('utf-8').strip()

            expected_hash = hashlib.sha256(b'X').hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(output, expected_output)
            self.assertEqual(result.returncode, 0)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_file_exactly_block_size_sha256(self):
        """Test file exactly 64 bytes (SHA-256 block size)"""
        data = b'X' * 64
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(data)
            temp_file = f.name

        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output = result.stdout.decode('utf-8').strip()

            expected_hash = hashlib.sha256(data).hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(output, expected_output)
            self.assertEqual(result.returncode, 0)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_file_one_byte_over_block_size(self):
        """Test file of 65 bytes (1 byte over block size)"""
        data = b'X' * 65
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(data)
            temp_file = f.name

        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output = result.stdout.decode('utf-8').strip()

            expected_hash = hashlib.sha256(data).hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(output, expected_output)
            self.assertEqual(result.returncode, 0)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_file_with_spaces_in_name(self):
        """Test file with spaces in filename"""
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, 'file with spaces.txt')

        with open(temp_file, 'wb') as f:
            f.write(b'Test data with spaces in filename')

        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output = result.stdout.decode('utf-8').strip()

            expected_hash = hashlib.sha256(b'Test data with spaces in filename').hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(output, expected_output)
            self.assertEqual(result.returncode, 0)

        finally:
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_file_with_special_chars(self):
        """Test file with special characters in filename"""
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, 'file@#$%^&().txt')

        with open(temp_file, 'wb') as f:
            f.write(b'Test data with special chars')

        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output = result.stdout.decode('utf-8').strip()

            expected_hash = hashlib.sha256(b'Test data with special chars').hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(output, expected_output)
            self.assertEqual(result.returncode, 0)

        finally:
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


    def test_read_only_output_file_with_force(self):
        """Test writing to read-only file with --force flag"""
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, 'input.txt')
        out_file = os.path.join(temp_dir, 'output.hash')

        with open(temp_file, 'wb') as f:
            f.write(b'Test data')

        # Create read-only output file
        with open(out_file, 'w') as f:
            f.write('Old content\n')

        # Make file read-only
        os.chmod(out_file, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        try:
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file,
                '--output', out_file,
                '--force'
            ])

            # Should fail with permission error
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Permission denied", result.stderr.decode('utf-8'))

        finally:
            # Restore permissions for cleanup
            os.chmod(out_file, stat.S_IWUSR)
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_output_to_protected_directory(self):
        """Test writing to protected directory (e.g., /root)"""
        # Try to write to a protected location
        protected_path = "/root/hash.txt"

        # Skip if not running as root or on Windows
        if os.name == 'nt' or os.geteuid() == 0:
            self.skipTest("Skipping protected directory test")

        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'Test data')
            temp_file = f.name

        try:
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file,
                '--output', protected_path
            ])

            # Should fail with permission error
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Permission denied", result.stderr.decode('utf-8'))

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_binary_data_with_null_bytes(self):
        """Test hashing binary data containing null bytes"""
        # Create binary data with null bytes
        data = bytes([0x00, 0x01, 0x02, 0x00, 0xFF, 0x00])

        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
            f.write(data)
            temp_file = f.name

        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output = result.stdout.decode('utf-8').strip()

            expected_hash = hashlib.sha256(data).hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(output, expected_output)
            self.assertEqual(result.returncode, 0)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_stdin_binary_data(self):
        """Test hashing binary data via stdin"""
        # Binary data with null bytes and non-UTF8 sequences
        data = bytes([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD])

        result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', '-'], data)
        output = result.stdout.decode('utf-8').strip()

        expected_hash = hashlib.sha256(data).hexdigest()
        expected_output = f"{expected_hash} -"

        self.assertEqual(output, expected_output)
        self.assertEqual(result.returncode, 0)

    def test_concurrent_file_access(self):
        """Test hashing while another process is writing to the file"""
        import threading
        import time

        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, 'concurrent.txt')

        # Start a thread that writes to the file slowly
        def slow_writer(filename, data, chunks):
            with open(filename, 'wb') as f:
                for chunk in chunks:
                    f.write(chunk)
                    time.sleep(0.01)  # Small delay

        data = b'Test concurrent access ' * 1000
        chunk_size = 100
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        writer_thread = threading.Thread(target=slow_writer, args=(temp_file, data, chunks))
        writer_thread.start()

        # Give writer a head start
        time.sleep(0.05)

        try:
            # Try to hash while file is being written
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])

            # Hash might be inconsistent, but should not crash
            self.assertEqual(result.returncode, 0)

        finally:
            writer_thread.join()
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_output_format_consistency(self):
        """Test that output format is consistent (two spaces for files, one for stdin)"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'Test format')
            temp_file = f.name

        try:
            # Test file output format
            result_file = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output_file = result_file.stdout.decode('utf-8').strip()

            # Should have TWO spaces between hash and filename
            hash_part, filename_part = output_file.split('  ')  # Double space
            self.assertEqual(filename_part, temp_file)

            # Test stdin output format
            result_stdin = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', '-'], b'Test')
            output_stdin = result_stdin.stdout.decode('utf-8').strip()

            # Should have ONE space between hash and dash
            hash_part_stdin, dash_part = output_stdin.split(' ')  # Single space
            self.assertEqual(dash_part, '-')

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_missing_input_file(self):
        """Test error handling for non-existent input file"""
        non_existent = "/tmp/nonexistent_file_12345.txt"

        result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', non_existent])

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("File not found", result.stderr.decode('utf-8'))
        self.assertIn(non_existent, result.stderr.decode('utf-8'))

    def test_invalid_algorithm(self):
        """Test error handling for invalid algorithm (though argparse should catch it)"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'Test')
            temp_file = f.name

        try:
            # Note: argparse should prevent this, but test for robustness
            result = self.run_cli(['dgst', '--algorithm', 'invalid', '--input', temp_file])

            # Should fail
            self.assertNotEqual(result.returncode, 0)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_very_slow_stdin(self):
        """Test hashing data from very slow stdin (simulated)"""
        import subprocess
        import threading

        # Create a Python script that outputs data slowly
        slow_producer = """
import time
import sys
data = b"X" * 1000000  # 1MB
chunk_size = 1000
for i in range(0, len(data), chunk_size):
    sys.stdout.buffer.write(data[i:i+chunk_size])
    sys.stdout.buffer.flush()
    time.sleep(0.001)  # 1ms delay
"""

        # Run the producer and pipe to our CLI
        producer_cmd = [sys.executable, '-c', slow_producer]
        cli_cmd = [sys.executable, '-m', 'src.cryptocore.cli', 'dgst', '--algorithm', 'sha256', '--input', '-']

        producer = subprocess.Popen(producer_cmd, stdout=subprocess.PIPE, cwd=self.project_root)
        cli = subprocess.Popen(cli_cmd, stdin=producer.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               cwd=self.project_root)

        producer.stdout.close()
        stdout, stderr = cli.communicate()

        self.assertEqual(cli.returncode, 0)

        # Verify hash
        expected_hash = hashlib.sha256(b'X' * 1000000).hexdigest()
        output = stdout.decode('utf-8').strip()
        self.assertIn(expected_hash, output)

    def test_cross_platform_line_endings(self):
        """Test files with different line endings (Windows vs Unix)"""
        test_cases = [
            (b'Line1\nLine2\nLine3', 'Unix line endings'),
            (b'Line1\r\nLine2\r\nLine3', 'Windows line endings'),
            (b'Line1\rLine2\rLine3', 'Old Mac line endings'),
        ]

        for data, description in test_cases:
            with self.subTest(description):
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
                    f.write(data)
                    temp_file = f.name

                try:
                    result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
                    output = result.stdout.decode('utf-8').strip()

                    expected_hash = hashlib.sha256(data).hexdigest()
                    expected_output = f"{expected_hash}  {temp_file}"

                    self.assertEqual(output, expected_output)
                    self.assertEqual(result.returncode, 0)

                finally:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()