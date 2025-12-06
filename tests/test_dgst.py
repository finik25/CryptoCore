import unittest
import tempfile
import subprocess
import sys
import os
import time
import hashlib


class TestDgstCommand(unittest.TestCase):
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

    def test_sha256_empty(self):
        result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', '-'], b'')
        output = result.stdout.decode('utf-8')
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", output)

    def test_sha3_256_empty(self):
        result = self.run_cli(['dgst', '--algorithm', 'sha3-256', '--input', '-'], b'')
        output = result.stdout.decode('utf-8')
        self.assertIn("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", output)

    def test_sha256_nist_test_vectors(self):
        test_vectors = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            (b"a" * 1000, "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"),
        ]

        for i, (data, expected) in enumerate(test_vectors):
            with self.subTest(f"Test vector {i + 1}"):
                result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', '-'], data)
                output = result.stdout.decode('utf-8')
                self.assertIn(expected, output)

    def test_sha3_256_nist_test_vectors(self):
        test_vectors = [
            (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
            (b"a" * 1000, "8f3934e6f7a15698fe0f396b95d8c4440929a8fa6eae140171c068b4549fbf81"),
        ]

        for i, (data, expected) in enumerate(test_vectors):
            with self.subTest(f"Test vector {i + 1}"):
                result = self.run_cli(['dgst', '--algorithm', 'sha3-256', '--input', '-'], data)
                output = result.stdout.decode('utf-8')
                self.assertIn(expected, output)

    def test_sha256_known_vector(self):
        result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', '-'], b'abc')
        output = result.stdout.decode('utf-8')
        expected_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertIn(expected_hash, output)

    def test_sha3_256_known_vector(self):
        result = self.run_cli(['dgst', '--algorithm', 'sha3-256', '--input', '-'], b'abc')
        output = result.stdout.decode('utf-8')
        expected_hash = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        self.assertIn(expected_hash, output)

    def test_sha256_file(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'Hello, world!')
            temp_file = f.name
        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            output = result.stdout.decode('utf-8')
            expected_hash = hashlib.sha256(b'Hello, world!').hexdigest()
            self.assertIn(expected_hash, output)
        finally:
            os.unlink(temp_file)

    def test_sha3_256_file(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'Hello, world!')
            temp_file = f.name
        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha3-256', '--input', temp_file])
            output = result.stdout.decode('utf-8')
            try:
                hasher = hashlib.sha3_256()
                hasher.update(b'Hello, world!')
                expected_hash = hasher.hexdigest()
            except AttributeError:
                expected_hash = "f345a219da005ebe9c1a1eaad97bbf38a10c8473e41d0af7fb617caa0c6aa722"
            self.assertIn(expected_hash, output)
        finally:
            os.unlink(temp_file)

    def test_interoperability_sha256(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'Interoperability test data')
            temp_file = f.name
        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            our_hash = result.stdout.decode('utf-8').split()[0]
            try:
                result_system = subprocess.run(['sha256sum', temp_file], capture_output=True, text=True)
                system_hash = result_system.stdout.split()[0]
                self.assertEqual(our_hash, system_hash)
            except FileNotFoundError:
                self.skipTest("sha256sum not available")
        finally:
            os.unlink(temp_file)

    def test_interoperability_sha3_256(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'Interoperability test data for SHA3')
            temp_file = f.name
        try:
            result = self.run_cli(['dgst', '--algorithm', 'sha3-256', '--input', temp_file])
            our_hash = result.stdout.decode('utf-8').split()[0]
            try:
                result_system = subprocess.run(['sha3sum', '-a', '256', temp_file], capture_output=True, text=True)
                system_hash = result_system.stdout.split()[0]
                self.assertEqual(our_hash, system_hash)
            except FileNotFoundError:
                self.skipTest("sha3sum not available")
        finally:
            os.unlink(temp_file)

    def test_large_file_sha256(self):
        chunk_size = 1024 * 1024  # 1MB
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(os.urandom(chunk_size))
            temp_file = f.name
        try:
            start = time.time()
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            elapsed = time.time() - start
            self.assertEqual(result.returncode, 0)
            with open(temp_file, 'rb') as f:
                expected_hash = hashlib.sha256(f.read()).hexdigest()
            our_hash = result.stdout.decode('utf-8').split()[0]
            self.assertEqual(our_hash, expected_hash)
            print(f"\nLarge file (1MB) SHA-256 hashed in {elapsed:.2f} seconds")
        finally:
            os.unlink(temp_file)

    def test_avalanche_effect_sha256(self):
        from src.cryptocore.hash.sha256 import SHA256
        data1 = b"Hello, world!"
        data2 = b"Hello, world?"
        hasher = SHA256()
        hash1 = hasher.hash(data1)
        hasher.reset()
        hash2 = hasher.hash(data2)
        int1 = int.from_bytes(hash1, byteorder='big')
        int2 = int.from_bytes(hash2, byteorder='big')
        bits1 = bin(int1)[2:].zfill(256)
        bits2 = bin(int2)[2:].zfill(256)
        diff_bits = sum(1 for a, b in zip(bits1, bits2) if a != b)
        self.assertGreater(diff_bits, 100, f"Only {diff_bits} bits changed, expected >100")
        self.assertLess(diff_bits, 156, f"Too many bits changed: {diff_bits}, expected <156")
        print(f"Avalanche effect: {diff_bits}/256 bits changed ({diff_bits / 256 * 100:.1f}%)")

    def test_avalanche_effect_sha3_256(self):
        from src.cryptocore.hash.sha3_256 import SHA3_256
        data1 = b"Hello, world!"
        data2 = b"Hello, world?"
        hasher = SHA3_256()
        hash1 = hasher.hash(data1)
        hasher.reset()
        hash2 = hasher.hash(data2)
        int1 = int.from_bytes(hash1, byteorder='big')
        int2 = int.from_bytes(hash2, byteorder='big')
        bits1 = bin(int1)[2:].zfill(256)
        bits2 = bin(int2)[2:].zfill(256)
        diff_bits = sum(1 for a, b in zip(bits1, bits2) if a != b)
        self.assertGreater(diff_bits, 100, f"Only {diff_bits} bits changed, expected >100")
        self.assertLess(diff_bits, 156, f"Too many bits changed: {diff_bits}, expected <156")
        print(f"SHA3-256 Avalanche effect: {diff_bits}/256 bits changed ({diff_bits / 256 * 100:.1f}%)")

    def test_output_to_file(self):
        # Создаем входной файл
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'Test output to file')
            temp_file = f.name

        # Создаем временную директорию для выходного файла
        temp_dir = tempfile.mkdtemp()
        out_file = os.path.join(temp_dir, 'hash.txt')

        try:
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file,
                '--output', out_file
            ])

            print(f"Return code: {result.returncode}")
            print(f"stdout: {result.stdout.decode('utf-8')}")
            print(f"stderr: {result.stderr.decode('utf-8')}")

            self.assertEqual(result.returncode, 0,
                             f"CLI failed with stderr: {result.stderr.decode('utf-8')}")

            # Проверяем что файл создан
            self.assertTrue(os.path.exists(out_file), f"Output file {out_file} not created")

            # Проверяем содержимое файла
            with open(out_file, 'r') as f:
                saved_output = f.read().strip()

            expected_hash = hashlib.sha256(b'Test output to file').hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(saved_output, expected_output)

        finally:
            # Очистка
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_output_to_file_sha3_256(self):
        # Создаем входной файл
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'Test SHA3-256 output to file')
            temp_file = f.name

        # Создаем временную директорию для выходного файла
        temp_dir = tempfile.mkdtemp()
        out_file = os.path.join(temp_dir, 'hash.txt')

        try:
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha3-256',
                '--input', temp_file,
                '--output', out_file
            ])

            self.assertEqual(result.returncode, 0,
                             f"CLI failed with stderr: {result.stderr.decode('utf-8')}")

            # Проверяем что файл создан
            self.assertTrue(os.path.exists(out_file), f"Output file {out_file} not created")

            # Проверяем содержимое файла
            with open(out_file, 'r') as f:
                saved_output = f.read().strip()

            try:
                hasher = hashlib.sha3_256()
                hasher.update(b'Test SHA3-256 output to file')
                expected_hash = hasher.hexdigest()
            except AttributeError:
                # Fallback для Python без поддержки SHA3-256
                expected_hash = "2f5c5f3a0f0d3f3e8a9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5"

            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(saved_output, expected_output)

        finally:
            # Очистка
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_output_file_exists_without_force(self):
        # Создаем входной файл
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'Test file exists')
            temp_file = f.name

        # Создаем выходной файл заранее
        temp_dir = tempfile.mkdtemp()
        out_file = os.path.join(temp_dir, 'hash.txt')

        # Создаем файл с содержимым
        with open(out_file, 'w') as f:
            f.write('Existing content\n')

        try:
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file,
                '--output', out_file
            ])

            print(f"Return code: {result.returncode}")
            print(f"stderr: {result.stderr.decode('utf-8')}")

            # Должен завершиться с ошибкой, так как файл уже существует
            self.assertNotEqual(result.returncode, 0,
                                "Should fail when output file exists without --force")
            self.assertIn("File exists", result.stderr.decode('utf-8'))
            self.assertIn("--force", result.stderr.decode('utf-8'))

            # Проверяем что оригинальное содержимое не перезаписано
            with open(out_file, 'r') as f:
                content = f.read()
            self.assertEqual(content, 'Existing content\n')

        finally:
            # Очистка
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_output_file_exists_with_force(self):
        # Создаем входной файл
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'Test force overwrite')
            temp_file = f.name

        # Создаем выходной файл заранее
        temp_dir = tempfile.mkdtemp()
        out_file = os.path.join(temp_dir, 'hash.txt')

        # Создаем файл с содержимым
        with open(out_file, 'w') as f:
            f.write('Old content that should be overwritten\n')

        try:
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file,
                '--output', out_file,
                '--force'
            ])

            print(f"Return code: {result.returncode}")
            print(f"stdout: {result.stdout.decode('utf-8')}")

            # Должен успешно выполниться с флагом --force
            self.assertEqual(result.returncode, 0,
                             "Should succeed with --force when output file exists")
            self.assertIn("Hash written to:", result.stdout.decode('utf-8'))

            # Проверяем что содержимое перезаписано
            with open(out_file, 'r') as f:
                content = f.read().strip()

            expected_hash = hashlib.sha256(b'Test force overwrite').hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(content, expected_output)

        finally:
            # Очистка
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_force_with_stdin(self):
        # Создаем временную директорию для выходного файла
        temp_dir = tempfile.mkdtemp()
        out_file = os.path.join(temp_dir, 'hash.txt')

        # Создаем файл с содержимым
        with open(out_file, 'w') as f:
            f.write('Old content\n')

        try:
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', '-',
                '--output', out_file,
                '--force'
            ], b'Test stdin with force')

            print(f"Return code: {result.returncode}")

            # Должен успешно выполниться
            self.assertEqual(result.returncode, 0,
                             "Should succeed with --force and stdin")
            self.assertIn("Hash written to:", result.stdout.decode('utf-8'))

            # Проверяем что содержимое перезаписано
            with open(out_file, 'r') as f:
                content = f.read().strip()

            expected_hash = hashlib.sha256(b'Test stdin with force').hexdigest()
            expected_output = f"{expected_hash} -"

            self.assertEqual(content, expected_output)

        finally:
            # Очистка
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_output_directory_creation(self):
        # Создаем входной файл
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'Test directory creation')
            temp_file = f.name

        # Создаем временную директорию для тестирования
        temp_dir = tempfile.mkdtemp()
        nested_output = os.path.join(temp_dir, 'nested', 'dir', 'hash.txt')

        try:
            result = self.run_cli([
                'dgst',
                '--algorithm', 'sha256',
                '--input', temp_file,
                '--output', nested_output
            ])

            print(f"Return code: {result.returncode}")
            print(f"stderr: {result.stderr.decode('utf-8')}")

            # Должен успешно выполниться
            self.assertEqual(result.returncode, 0,
                             "Should succeed creating nested directories")
            self.assertTrue(os.path.exists(nested_output),
                            f"Output file not created at {nested_output}")

            # Проверяем содержимое
            with open(nested_output, 'r') as f:
                content = f.read().strip()

            expected_hash = hashlib.sha256(b'Test directory creation').hexdigest()
            expected_output = f"{expected_hash}  {temp_file}"

            self.assertEqual(content, expected_output)

        finally:
            # Очистка
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_interoperability_with_hashlib(self):
        test_data = b"Test data for hashlib comparison"

        # SHA-256
        result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', '-'], test_data)
        our_hash_sha256 = result.stdout.decode('utf-8').split()[0]
        expected_hash_sha256 = hashlib.sha256(test_data).hexdigest()
        self.assertEqual(our_hash_sha256, expected_hash_sha256)

        # SHA3-256
        result = self.run_cli(['dgst', '--algorithm', 'sha3-256', '--input', '-'], test_data)
        our_hash_sha3_256 = result.stdout.decode('utf-8').split()[0]
        try:
            hasher = hashlib.sha3_256()
            hasher.update(test_data)
            expected_hash_sha3_256 = hasher.hexdigest()
        except AttributeError:
            self.skipTest("hashlib doesn't support sha3_256")
        self.assertEqual(our_hash_sha3_256, expected_hash_sha3_256)

    def test_performance_comparison(self):
        import time

        data_size = 1024 * 1024  # 1MB
        test_data = os.urandom(data_size)

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(test_data)
            temp_file = f.name

        try:
            start = time.time()
            result = self.run_cli(['dgst', '--algorithm', 'sha256', '--input', temp_file])
            our_time = time.time() - start

            # hashlib
            start = time.time()
            with open(temp_file, 'rb') as f:
                hashlib.sha256(f.read()).hexdigest()
            lib_time = time.time() - start

            self.assertEqual(result.returncode, 0)

            print(f"\nPerformance test (1MB file):")
            print(f"  Our implementation: {our_time:.3f}s")
            print(f"  Hashlib: {lib_time:.3f}s")
            if lib_time > 0:
                print(f"  Ratio: {our_time / lib_time:.2f}x")

            our_hash = result.stdout.decode('utf-8').split()[0]
            expected_hash = hashlib.sha256(test_data).hexdigest()
            self.assertEqual(our_hash, expected_hash, "Hash mismatch")

        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()