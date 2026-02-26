#!/usr/bin/env python3
"""
telegram2hashcat.py — Extract hashcat-compatible hashes from Telegram local data.

Based on telegram2john.py from openwall/john.

Supported hashcat modes:
    24500 - Telegram Desktop
    24600 - SQLCipher
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
    24500: "Telegram Desktop",
    24600: "SQLCipher",
}


def process_telegram(filename):
    """
    Extract hashcat hash from Telegram Desktop local storage.

    Telegram Desktop stores encrypted data in tdata/ directory.
    The key data file contains salt and encrypted key material.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    if len(data) < 40:
        error("File too small for Telegram data", filename)
        return

    # Telegram Desktop key_data format:
    # salt (32 bytes) + encrypted_data (remaining)
    # PBKDF2-SHA512 with salt, 100000 iterations
    # AES-256-IGE encryption

    # For map file variant:
    if len(data) >= 4:
        salt_size = struct.unpack('<I', data[0:4])[0]
        if salt_size == 32 and len(data) >= 4 + 32 + 16:
            salt = data[4:36]
            # Key iteration data follows
            key_size = struct.unpack('<I', data[36:40])[0] if len(data) >= 40 else 0
            if key_size > 0 and 40 + key_size <= len(data):
                enc_key = data[40:40 + key_size]
                hashline = "$telegram$1*100000*%s*%s" % (
                    bytes_to_hex(salt), bytes_to_hex(enc_key[:min(256, len(enc_key))])
                )
                output_hash(hashline)
                return

    # Try alternate format: raw salt + data
    salt = data[:32]
    enc_data = data[32:]
    if len(enc_data) >= 16:
        hashline = "$telegram$1*100000*%s*%s" % (
            bytes_to_hex(salt), bytes_to_hex(enc_data[:min(256, len(enc_data))])
        )
        output_hash(hashline)
        return

    error("Could not parse Telegram data format", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Telegram Desktop local data.\n"
        "Process the key_data or map* files from tdata/ directory.",
        file_help="Telegram data file(s) (key_data, map*, etc.)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_telegram(f)


if __name__ == "__main__":
    main()
