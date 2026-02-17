#!/usr/bin/env python3

import sys
import secrets

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <number_of_bits>")
        sys.exit(1)

    try:
        bits = int(sys.argv[1])
        if bits <= 0:
            raise ValueError
    except ValueError:
        print("Error: number_of_bits must be a positive integer")
        sys.exit(1)

    # Generate random integer with exactly `bits` bits
    rand_int = secrets.randbits(bits)

    # Convert to hex (without '0x' prefix)
    hex_str = format(rand_int, 'x')

    # Zero-pad to full bit length (rounded up to full hex digits)
    hex_length = (bits + 3) // 4  # 4 bits per hex digit
    hex_str = hex_str.zfill(hex_length)

    print(hex_str)

if __name__ == "__main__":
    main()

