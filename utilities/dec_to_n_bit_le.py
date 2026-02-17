#!/usr/bin/env python3

import sys
import math

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <bits> <decimal_number>")
        sys.exit(1)

    try:
        bits = int(sys.argv[1])
        number = int(sys.argv[2])
        if bits <= 0:
            raise ValueError
    except ValueError:
        print("Error: <bits> must be a positive integer and <decimal_number> must be an integer")
        sys.exit(1)

    # Check fit within bit width
    if number < 0 or number >= (1 << bits):
        print(f"Error: number does not fit in {bits} bits")
        sys.exit(1)

    # Number of bytes needed (rounded up)
    byte_length = math.ceil(bits / 8)

    # Convert to little-endian bytes (automatically zero-padded)
    little_endian_bytes = number.to_bytes(byte_length, byteorder='little')

    # Mask off unused high bits in final byte (if bits not multiple of 8)
    if bits % 8 != 0:
        mask = (1 << (bits % 8)) - 1
        last_byte = little_endian_bytes[-1] & mask
        little_endian_bytes = little_endian_bytes[:-1] + bytes([last_byte])

    # Output hex
    print(little_endian_bytes.hex())


if __name__ == "__main__":
    main()

