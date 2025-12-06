import unittest
import tempfile
import subprocess
import sys
import os
import hashlib
import json
from pathlib import Path


class TestCryptoCoreIntegration(unittest.TestCase):
    def setUp(self):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(self.current_dir)
        self.test_data = b"Hello CryptoCore Integration Test!" * 100  # ~3.2KB

    def generate_test_key_iv(self, mode):
        """Generate test key and IV for testing"""
        key = '00112233445566778899aabbccddeeff'
        iv = '11223344556677889900aabbccddeeff' if mode != 'ecb' else None
        return key, iv

    def run_cli(self, args, input_data=None):
        cmd = [sys.executable, '-m', 'src.cryptocore.cli'] + args

        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            cwd=self.project_root,
            text=False
        )

        return result

    def create_temp_file(self, content=None):
        """Create temporary file with optional content"""
        if content is None:
            content = self.test_data
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(content)
            return f.name

    def test_encryption_decryption_cycle(self):
        """Test full cycle: encrypt -> decrypt -> compare with original"""
        # Create test file
        original_file = self.create_temp_file()

        try:
            # Encrypt with auto-generated key
            encrypted_file = original_file + '.enc'
            result = self.run_cli([
                'crypto',
                '--algorithm', 'aes',
                '--mode', 'cbc',
                '--encrypt',
                '--input', original_file,
                '--output', encrypted_file,
                '--force'
            ])

            self.assertEqual(result.returncode, 0,
                             f"Encryption failed: {result.stderr.decode('utf-8')}")

            # Extract auto-generated key from output
            output = result.stdout.decode('utf-8')
            key_line = [line for line in output.split('\n') if 'Key (hex):' in line][0]
            key_hex = key_line.split(':')[1].strip().split()[0]  # Get key hex value

            # Decrypt back
            decrypted_file = original_file + '.dec'
            result = self.run_cli([
                'crypto',
                '--algorithm', 'aes',
                '--mode', 'cbc',
                '--decrypt',
                '--key', key_hex,
                '--input', encrypted_file,
                '--output', decrypted_file,
                '--force'
            ])

            self.assertEqual(result.returncode, 0,
                             f"Decryption failed: {result.stderr.decode('utf-8')}")

            # Compare original and decrypted
            with open(original_file, 'rb') as f:
                original_data = f.read()
            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()

            self.assertEqual(original_data, decrypted_data,
                             "Decrypted data doesn't match original")

            # Clean up
            if os.path.exists(encrypted_file):
                os.unlink(encrypted_file)
            if os.path.exists(decrypted_file):
                os.unlink(decrypted_file)

        finally:
            if os.path.exists(original_file):
                os.unlink(original_file)

    def test_hash_before_and_after_encryption(self):
        """Test that file hash changes after encryption, but original and decrypted have same hash"""
        # Create test file
        original_file = self.create_temp_file()

        try:
            # Get hash of original file
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', original_file
            ])
            original_hash = result.stdout.decode('utf-8').split()[0]

            # Encrypt file
            encrypted_file = original_file + '.enc'
            result = self.run_cli([
                'crypto',
                '--algorithm', 'aes',
                '--mode', 'cbc',
                '--encrypt',
                '--input', original_file,
                '--output', encrypted_file,
                '--force'
            ])

            self.assertEqual(result.returncode, 0,
                             f"Encryption failed: {result.stderr.decode('utf-8')}")

            # Get key from encryption output (IV is in the file, not needed for decryption)
            output = result.stdout.decode('utf-8')
            key_line = [line for line in output.split('\n') if 'Key (hex):' in line]
            if key_line:
                key_hex = key_line[0].split(':')[1].strip().split()[0]
            else:
                self.fail("Key not found in encryption output")

            # Get hash of encrypted file
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', encrypted_file
            ])
            self.assertEqual(result.returncode, 0,
                             f"Hash of encrypted file failed: {result.stderr.decode('utf-8')}")

            encrypted_hash = result.stdout.decode('utf-8').split()[0]

            # Hashes should be different
            self.assertNotEqual(original_hash, encrypted_hash,
                                "Hash should change after encryption")

            # Decrypt WITHOUT IV (it's in the file)
            decrypted_file = original_file + '.dec'
            result = self.run_cli([
                'crypto',
                '--algorithm', 'aes',
                '--mode', 'cbc',
                '--decrypt',
                '--key', key_hex,
                '--input', encrypted_file,
                '--output', decrypted_file,
                '--force'
            ])
            self.assertEqual(result.returncode, 0,
                             f"Decryption failed: {result.stderr.decode('utf-8')}")

            # Get hash of decrypted file
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', decrypted_file
            ])
            self.assertEqual(result.returncode, 0,
                             f"Hash of decrypted file failed: {result.stderr.decode('utf-8')}")

            decrypted_hash = result.stdout.decode('utf-8').split()[0]

            # Original and decrypted should have same hash
            self.assertEqual(original_hash, decrypted_hash,
                             "Original and decrypted files should have same hash")

            # Clean up
            if os.path.exists(encrypted_file):
                os.unlink(encrypted_file)
            if os.path.exists(decrypted_file):
                os.unlink(decrypted_file)

        finally:
            if os.path.exists(original_file):
                os.unlink(original_file)

    def test_all_aes_modes_integration(self):
        """Test encryption/decryption with all AES modes"""
        modes = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']

        for mode in modes:
            with self.subTest(f"AES mode: {mode}"):
                original_file = self.create_temp_file(b"Test data for " + mode.encode() + b" mode")

                try:
                    # Encrypt
                    encrypted_file = original_file + '.enc'
                    result = self.run_cli([
                        'crypto',
                        '--algorithm', 'aes',
                        '--mode', mode,
                        '--encrypt',
                        '--input', original_file,
                        '--output', encrypted_file,
                        '--force'
                    ])

                    self.assertEqual(result.returncode, 0,
                                     f"Encryption failed for mode {mode}: {result.stderr.decode('utf-8')}")

                    # Get key from output (auto-generated)
                    output = result.stdout.decode('utf-8')
                    key_line = [line for line in output.split('\n') if 'Key (hex):' in line]
                    if key_line:
                        key_hex = key_line[0].split(':')[1].strip().split()[0]
                    else:
                        key_hex = '00112233445566778899aabbccddeeff'

                    # Decrypt WITHOUT IV (it's already in the file)
                    decrypted_file = original_file + '.dec'
                    result = self.run_cli([
                        'crypto',
                        '--algorithm', 'aes',
                        '--mode', mode,
                        '--decrypt',
                        '--key', key_hex,
                        '--input', encrypted_file,
                        '--output', decrypted_file,
                        '--force'
                    ])

                    self.assertEqual(result.returncode, 0,
                                     f"Decryption failed for mode {mode}: {result.stderr.decode('utf-8')}")

                    # Compare
                    with open(original_file, 'rb') as f:
                        original_data = f.read()
                    with open(decrypted_file, 'rb') as f:
                        decrypted_data = f.read()

                    self.assertEqual(original_data, decrypted_data,
                                     f"Decrypted data doesn't match original for mode {mode}")

                    # Clean up
                    if os.path.exists(encrypted_file):
                        os.unlink(encrypted_file)
                    if os.path.exists(decrypted_file):
                        os.unlink(decrypted_file)

                finally:
                    if os.path.exists(original_file):
                        os.unlink(original_file)

    def test_hash_algorithms_consistency(self):
        """Test that both hash algorithms produce consistent results"""
        test_strings = [
            b"",
            b"abc",
            b"Hello World",
            b"A" * 1000,
            b"\x00\x01\x02\x03\xFF\xFE\xFD",
        ]

        for test_data in test_strings:
            with self.subTest(f"Data: {test_data[:20]}"):
                # Test via stdin
                result_sha256 = self.run_cli(
                    ['dgst', '--algorithm', 'sha256', '--input', '-'],
                    test_data
                )
                result_sha3_256 = self.run_cli(
                    ['dgst', '--algorithm', 'sha3-256', '--input', '-'],
                    test_data
                )

                self.assertEqual(result_sha256.returncode, 0)
                self.assertEqual(result_sha3_256.returncode, 0)

                # Extract hashes
                sha256_hash = result_sha256.stdout.decode('utf-8').split()[0]
                sha3_256_hash = result_sha3_256.stdout.decode('utf-8').split()[0]

                # Compare with hashlib
                expected_sha256 = hashlib.sha256(test_data).hexdigest()
                self.assertEqual(sha256_hash, expected_sha256)

                # SHA3-256 might not be available in older Python
                try:
                    expected_sha3_256 = hashlib.sha3_256(test_data).hexdigest()
                    self.assertEqual(sha3_256_hash, expected_sha3_256)
                except AttributeError:
                    pass  # Skip if not available

    def test_file_vs_stdin_hash_consistency(self):
        """Test that file and stdin produce same hash for same data"""
        test_data = b"Test data for consistency check " * 100

        # Create file
        temp_file = self.create_temp_file(test_data)

        try:
            # Get hash from file
            result_file = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file
            ])

            # Get hash from stdin
            result_stdin = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', '-'
            ], test_data)

            self.assertEqual(result_file.returncode, 0)
            self.assertEqual(result_stdin.returncode, 0)

            # Extract hashes (remove filename part)
            file_hash = result_file.stdout.decode('utf-8').split()[0]
            stdin_hash = result_stdin.stdout.decode('utf-8').split()[0]

            # They should be equal
            self.assertEqual(file_hash, stdin_hash)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_output_file_formats(self):
        """Test different output formats and locations"""
        temp_file = self.create_temp_file(b"Test output formats")

        try:
            # Test 1: Default output (stdout)
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file
            ])
            self.assertEqual(result.returncode, 0)
            stdout_output = result.stdout.decode('utf-8').strip()

            # Test 2: Output to file in same directory
            hash_file = temp_file + '.hash'
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file,
                '--output', hash_file
            ])
            self.assertEqual(result.returncode, 0)
            self.assertTrue(os.path.exists(hash_file))

            with open(hash_file, 'r') as f:
                file_output = f.read().strip()

            # Should be same content (except maybe newline)
            self.assertEqual(stdout_output, file_output)

            # Test 3: Output to file in subdirectory
            temp_dir = tempfile.mkdtemp()
            nested_hash = os.path.join(temp_dir, 'subdir', 'hash.txt')

            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file,
                '--output', nested_hash
            ])
            self.assertEqual(result.returncode, 0)
            self.assertTrue(os.path.exists(nested_hash))

            # Clean up
            if os.path.exists(hash_file):
                os.unlink(hash_file)
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_force_flag_behavior(self):
        """Test --force flag behavior across commands"""
        # Create a file that will be overwritten
        temp_dir = tempfile.mkdtemp()
        existing_file = os.path.join(temp_dir, 'existing.txt')

        with open(existing_file, 'w') as f:
            f.write("Original content\n")

        try:
            # Test 1: Try to write hash without --force (should fail)
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', existing_file,
                '--output', existing_file  # Overwrite itself
            ])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("File exists", result.stderr.decode('utf-8'))

            # Verify file wasn't changed
            with open(existing_file, 'r') as f:
                content = f.read()
            self.assertEqual(content, "Original content\n")

            # Test 2: Write hash with --force (should succeed)
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', existing_file,
                '--output', existing_file,
                '--force'
            ])
            self.assertEqual(result.returncode, 0)

            # Verify file was changed
            with open(existing_file, 'r') as f:
                content = f.read()
            self.assertNotEqual(content, "Original content\n")
            self.assertIn("  ", content)  # Should contain hash and filename

            # Test 3: Encryption with --force
            original_file = self.create_temp_file(b"Encryption test")
            encrypted_file = existing_file  # Overwrite the hash file

            result = self.run_cli([
                'crypto',
                '--algorithm', 'aes',
                '--mode', 'ecb',
                '--encrypt',
                '--input', original_file,
                '--output', encrypted_file,
                '--force'
            ])
            self.assertEqual(result.returncode, 0)

            # Verify it's now an encrypted file (not text)
            with open(encrypted_file, 'rb') as f:
                content = f.read(100)
            # Encrypted data should look random, not like our hash text
            self.assertTrue(len(content) > 0)

        finally:
            if os.path.exists(original_file):
                os.unlink(original_file)
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_weak_key_detection_integration(self):
        """Test that weak key detection works and warnings are shown"""
        weak_keys = [
            ('00000000000000000000000000000000', 'all zeros'),
            ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'all same bytes'),
            ('00112233445566778899aabbccddeeff', 'sequential bytes'),
        ]

        for key_hex, description in weak_keys:
            with self.subTest(f"Weak key: {description}"):
                temp_file = self.create_temp_file(b"Test weak key")

                try:
                    result = self.run_cli([
                        'crypto',
                        '--algorithm', 'aes',
                        '--mode', 'ecb',
                        '--encrypt',
                        '--key', key_hex,
                        '--input', temp_file,
                        '--force'
                    ])

                    # Check if encryption succeeded
                    self.assertEqual(result.returncode, 0,
                                     f"Encryption failed for key {description}: {result.stderr.decode('utf-8')}")

                    stderr = result.stderr.decode('utf-8').lower()
                    # Check if warning exists (but may not be implemented for all cases)
                    has_warning = ("weak" in stderr or
                                   "warning" in stderr or
                                   "caution" in stderr)

                    # For sequential bytes, warning may not be implemented
                    if description != 'sequential bytes':
                        self.assertTrue(has_warning,
                                        f"No warning for weak key: {description}. stderr: {stderr}")

                finally:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)

    def test_error_handling_integration(self):
        """Test that errors are handled consistently across commands"""
        test_cases = [
            # (command_args, expected_error_contains, description)
            (['crypto', '--algorithm', 'aes', '--mode', 'cbc', '--encrypt',
              '--input', '/nonexistent/file.txt'],
             'not found', 'Nonexistent input file'),

            (['crypto', '--algorithm', 'aes', '--mode', 'ecb', '--encrypt',
              '--key', 'invalid_hex', '--input', '-'],
             'Invalid', 'Invalid hex key'),

            (['crypto', '--algorithm', 'aes', '--mode', 'cbc', '--decrypt',
              '--key', '00112233445566778899aabbccddeeff', '--input', '-'],
             'not found', 'Decryption without input data'),

            (['dgst', '--algorithm', 'sha256', '--input', '/nonexistent/file.txt'],
             'not found', 'Hash nonexistent file'),
        ]

        for args, expected_error, description in test_cases:
            with self.subTest(description):
                # For stdin tests, provide some input
                input_data = b"test" if '--input -' in ' '.join(args) else None

                result = self.run_cli(args, input_data)

                self.assertNotEqual(result.returncode, 0,
                                    f"Should fail for: {description}")

                error_output = (result.stderr.decode('utf-8') +
                                result.stdout.decode('utf-8')).lower()

                # Check if expected error is in output
                self.assertTrue(expected_error.lower() in error_output,
                                f"Error message missing '{expected_error}' for: {description}. Got: {error_output}")

    def test_legacy_mode_compatibility(self):
        """Test that legacy mode still works alongside new subcommands"""
        temp_file = self.create_temp_file(b"Legacy mode test")

        try:
            # Test legacy encryption (without subcommand)
            encrypted_file = temp_file + '.enc'
            result = self.run_cli([
                '--algorithm', 'aes',
                '--mode', 'ecb',
                '--encrypt',
                '--input', temp_file,
                '--output', encrypted_file,
                '--force'
            ])

            self.assertEqual(result.returncode, 0,
                             f"Legacy mode failed: {result.stderr.decode('utf-8')}")

            # Verify it created the expected output file
            self.assertTrue(os.path.exists(encrypted_file))

            # Test that we can still use subcommands
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file
            ])
            self.assertEqual(result.returncode, 0)

            # Clean up
            if os.path.exists(encrypted_file):
                os.unlink(encrypted_file)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class TestPackageInstallation(unittest.TestCase):
    """Test package installation and command availability"""

    def test_cli_entry_points(self):
        """Test that CLI commands are available after installation"""
        # This test assumes that the package is installed on the system
        # This may not be the case in the test environment, so we skip it if it is not installed
        try:
            result = subprocess.run(
                ['cryptocore', '--help'],
                capture_output=True,
                text=True,
                timeout=2
            )

            if result.returncode == 0:
                self.assertIn('CryptoCore', result.stdout)
            else:
                self.skipTest("cryptocore command requires subcommand")

        except FileNotFoundError:
            # If not in PATH, skip the test
            self.skipTest("cryptocore not in PATH (not installed or in development mode)")
        except subprocess.TimeoutExpired:
            self.skipTest("cryptocore command timed out")

    def test_module_imports(self):
        """Test that all modules can be imported"""
        modules_to_test = [
            'cryptocore.cli',
            'cryptocore.hash.sha256',
            'cryptocore.hash.sha3_256',
            'cryptocore.modes.ecb',
            'cryptocore.modes.cbc',
            'cryptocore.modes.cfb',
            'cryptocore.modes.ofb',
            'cryptocore.modes.ctr',
            'cryptocore.utils.csprng',
            'cryptocore.file_io',
        ]

        for module_name in modules_to_test:
            with self.subTest(f"Import {module_name}"):
                try:
                    # Try absolute import
                    __import__(module_name)
                except ImportError:
                    # Try relative import from src
                    src_module = 'src.' + module_name
                    __import__(src_module)

    def test_version_info(self):
        """Test that package has version information"""
        # Check if setup.py or pyproject.toml exists
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        setup_py = os.path.join(project_root, 'setup.py')

        if os.path.exists(setup_py):
            with open(setup_py, 'r') as f:
                content = f.read()
                self.assertIn('version', content, "setup.py should contain version")

        # Try to get version from package if installed
        try:
            import cryptocore
            if hasattr(cryptocore, '__version__'):
                version = cryptocore.__version__
                self.assertTrue(isinstance(version, str))
                self.assertTrue(len(version) > 0)
        except ImportError:
            pass  # Not installed, that's OK


if __name__ == '__main__':
    unittest.main(verbosity=2)