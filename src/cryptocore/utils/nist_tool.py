import argparse
import os
import sys

# Handle imports for both module and direct execution
try:
    # When running as module: python -m cryptocore.utils.nist_tool
    from .csprng import generate_random_bytes
except ImportError:
    # When running directly: python src/cryptocore/utils/nist_tool.py
    # Add parent directory to path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(current_dir, '..', '..')
    sys.path.insert(0, src_dir)
    from cryptocore.utils.csprng import generate_random_bytes


def generate_nist_test_file(output_path: str, size_mb: float = 10.0):
    if size_mb <= 0:
        raise ValueError("Size must be positive")

    total_bytes = int(size_mb * 1024 * 1024)
    total_bits = total_bytes * 8  # NIST STS expects bits, not bytes!
    chunk_size = 65536  # 64 KB chunks

    print(f"Generating NIST STS test file...")
    print(f"  Size: {size_mb} MB ({total_bytes:,} bytes, {total_bits:,} bits)")
    print(f"  Output: {output_path}")

    try:
        with open(output_path, 'wb') as f:
            bytes_written = 0
            chunk_count = 0

            while bytes_written < total_bytes:
                current_chunk = min(chunk_size, total_bytes - bytes_written)
                chunk = generate_random_bytes(current_chunk)
                f.write(chunk)
                bytes_written += current_chunk
                chunk_count += 1

                # Show progress every 100 chunks (~6.5 MB)
                if chunk_count % 100 == 0:
                    percent = (bytes_written / total_bytes) * 100
                    mb_written = bytes_written / (1024 * 1024)
                    print(f"  Progress: {percent:.1f}% ({mb_written:.1f} / {size_mb:.1f} MB)")

        print(f"\n✓ Successfully generated {bytes_written:,} bytes ({total_bits:,} bits)")
        print(f"\nNext steps for NIST STS testing:")
        print(
            f"1. Download NIST STS from: https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software")
        print(f"2. Extract and compile: `make` (requires C compiler)")
        print(f"3. Run NIST STS: `./assess {total_bits}`  # Note: {total_bits:,} BITS, not bytes!")
        print(f"4. Follow interactive prompts and select this file")
        print(f"\nExpected results: Most tests should pass (p-value ≥ 0.01)")
        print(f"   - 1-2 failures are statistically expected for truly random data")
        print(f"   - Widespread failures indicate flawed random number generation")

    except Exception as e:
        print(f"Error: Failed to generate test file: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Generate random data file for NIST Statistical Test Suite"
    )

    parser.add_argument(
        "output",
        help="Output file path"
    )

    parser.add_argument(
        "--size",
        type=float,
        default=10.0,
        help="Size in megabytes (default: 10 MB)"
    )

    args = parser.parse_args()
    generate_nist_test_file(args.output, args.size)


if __name__ == "__main__":
    main()