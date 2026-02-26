#!/usr/bin/env python3
"""
dmg2hashcat.py — Extract hashcat-compatible hashes from Apple DMG files.

Based on dmg2john.py from openwall/john (Dhiru Kholia).

Supported hashcat modes:
    6211 - Apple DMG (with appropriate settings)

Apple DMG files use AES-128 or AES-256 with PBKDF2.
The encryption header is stored in a koly block at the end of the file.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file,
)

HASHCAT_MODES = {
    6211: "Apple DMG (AES)",
}

# DMG magic signatures
KOLY_MAGIC = b'koly'
ENCRCDSA_MAGIC = b'encrcdsa'
V1_HEADER_SIZE = 40
V2_HEADER_SIZE = 100


def _find_encryption_header(data):
    """
    Find the encryption header in a DMG file.

    The encrypted DMG has an 'encrcdsa' or 'cdsaencr' header
    near the end of the file.
    """
    # Search for encrcdsa magic — typically near end
    pos = data.rfind(ENCRCDSA_MAGIC)
    if pos != -1:
        return pos, 2  # Version 2

    # Try reverse endian
    pos = data.rfind(b'cdsaencr')
    if pos != -1:
        return pos, 2

    return -1, 0


def process_dmg(filename):
    """
    Extract hashcat-compatible hash from an encrypted Apple DMG file.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, 'rb') as f:
            # Read last 512KB to find headers
            f.seek(0, 2)
            fsize = f.tell()
            read_size = min(fsize, 512 * 1024)
            f.seek(fsize - read_size)
            tail = f.read(read_size)

            # Also read the beginning for v1 headers
            f.seek(0)
            head = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return

    # Look for encryption header at start
    enc_pos = -1

    # Check for V1 encryption at start of file
    if len(head) >= V1_HEADER_SIZE:
        # V1: 8-byte signature at offset 0
        if head[:8] == ENCRCDSA_MAGIC or head[:8] == b'cdsaencr':
            enc_pos = 0
            enc_data = head

    # Check for V2 encryption in tail
    if enc_pos == -1:
        pos, ver = _find_encryption_header(tail)
        if pos != -1:
            enc_pos = pos
            enc_data = tail[pos:]

    if enc_pos == -1:
        error("No encryption header found (not encrypted?)", filename)
        return

    if len(enc_data) < 48:
        error("Encryption header too small", filename)
        return

    # Parse the encryption header
    # Layout varies by version, but generally:
    # magic(8) + version(4) + enc_iv_size(4) + various fields

    try:
        magic = enc_data[:8]
        version = struct.unpack('>I', enc_data[8:12])[0]

        if version == 1:
            # V1 header
            if len(enc_data) < 64:
                error("V1 header too small", filename)
                return
            iv_size = struct.unpack('>I', enc_data[12:16])[0]
            iv = enc_data[16:16 + iv_size]
            enc_key_size = struct.unpack('>I', enc_data[16 + iv_size:20 + iv_size])[0]
            enc_key = enc_data[20 + iv_size:20 + iv_size + enc_key_size]
            kdf_salt_size = struct.unpack('>I', enc_data[20 + iv_size + enc_key_size:24 + iv_size + enc_key_size])[0]
            offset = 24 + iv_size + enc_key_size
            kdf_salt = enc_data[offset:offset + kdf_salt_size]
            offset += kdf_salt_size
            kdf_iterations = struct.unpack('>I', enc_data[offset:offset + 4])[0]

            hashline = "$dmg$1*%d*%s*%d*%s*%d*%s*%d" % (
                iv_size, bytes_to_hex(iv),
                enc_key_size, bytes_to_hex(enc_key),
                kdf_salt_size, bytes_to_hex(kdf_salt),
                kdf_iterations,
            )
            output_hash(hashline)
            return

        elif version == 2:
            # V2 header (more structured)
            if len(enc_data) < V2_HEADER_SIZE:
                error("V2 header too small", filename)
                return

            enc_iv_size = struct.unpack('>I', enc_data[12:16])[0]
            # Read dynamic-length fields
            offset = 16
            enc_iv = enc_data[offset:offset + enc_iv_size]
            offset += enc_iv_size

            if offset + 4 > len(enc_data):
                error("Truncated V2 header", filename)
                return

            enc_bits = struct.unpack('>I', enc_data[offset:offset + 4])[0]
            offset += 4

            # Encrypted key blob
            blob_size = struct.unpack('>I', enc_data[offset:offset + 4])[0]
            offset += 4
            blob = enc_data[offset:offset + blob_size]
            offset += blob_size

            # KDF parameters
            if offset + 8 > len(enc_data):
                error("Missing KDF parameters", filename)
                return

            kdf_algo = struct.unpack('>I', enc_data[offset:offset + 4])[0]
            offset += 4
            kdf_salt_size = struct.unpack('>I', enc_data[offset:offset + 4])[0]
            offset += 4
            kdf_salt = enc_data[offset:offset + kdf_salt_size]
            offset += kdf_salt_size

            kdf_iterations = struct.unpack('>I', enc_data[offset:offset + 4])[0] if offset + 4 <= len(enc_data) else 1000

            hashline = "$dmg$2*%d*%s*%d*%d*%s*%d*%s*%d" % (
                enc_iv_size, bytes_to_hex(enc_iv),
                enc_bits,
                blob_size, bytes_to_hex(blob),
                kdf_salt_size, bytes_to_hex(kdf_salt),
                kdf_iterations,
            )
            output_hash(hashline)
            return

    except (struct.error, IndexError) as e:
        error("Failed to parse DMG header: %s" % str(e), filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from encrypted Apple DMG files.",
        file_help="Encrypted Apple DMG file(s)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_dmg(f)


if __name__ == "__main__":
    main()
