#!/usr/bin/env python3
"""
sevenz2hashcat.py — 7-Zip archive hash extractor for hashcat mode 11600.

Parses password-protected 7z archives and extracts AES-256-SHA-256
encryption parameters for hashcat cracking.

Inspired by: 7z2john.pl (openwall/john)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    11600: "7-Zip (AES-256 + SHA-256)",
}

SEVENZ_MAGIC = b'7z\xbc\xaf\x27\x1c'
# 7z AES codec ID bytes
AES_CODEC_IDS = [b'\x06\xf1\x07\x01', b'\x06\xF1\x07']


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    if len(data) < 32 or data[0:6] != SEVENZ_MAGIC:
        error("Not a valid 7-Zip file", filename)
        return

    # Parse start header
    start_header_crc = struct.unpack('<I', data[8:12])[0]
    next_header_offset = struct.unpack('<Q', data[12:20])[0]
    next_header_size = struct.unpack('<Q', data[20:28])[0]
    next_header_crc = struct.unpack('<I', data[28:32])[0]

    enc_offset = 32 + next_header_offset
    if enc_offset >= len(data):
        error("7z header points beyond file end", filename)
        return

    actual_size = min(next_header_size, len(data) - enc_offset)
    enc_data = data[int(enc_offset):int(enc_offset + min(actual_size, 32))]
    header_data = data[int(enc_offset):int(enc_offset + min(actual_size, 1024))]

    # Scan for AES-256-SHA-256 codec ID
    for marker in AES_CODEC_IDS:
        pos = header_data.find(marker)
        if pos == -1:
            continue

        prop_start = pos + len(marker)
        if prop_start + 2 > len(header_data):
            continue

        first_byte = header_data[prop_start]
        num_cycles_power = first_byte & 0x3F
        has_salt = (first_byte & 0x80) != 0
        has_iv = (first_byte & 0x40) != 0

        salt_size = 0
        iv_size = 0
        prop_pos = prop_start + 1

        if has_salt or has_iv:
            if prop_pos >= len(header_data):
                continue
            second_byte = header_data[prop_pos]
            salt_size = (second_byte >> 4) + 1 if has_salt else 0
            iv_size = (second_byte & 0x0F) + 1 if has_iv else 0
            prop_pos += 1

        salt = header_data[prop_pos:prop_pos + salt_size] if salt_size else b''
        prop_pos += salt_size
        iv = header_data[prop_pos:prop_pos + iv_size] if iv_size else b''

        data_len = min(32, len(enc_data))
        output_hash("$7z$0$%d$%d$%s$%d$%s$%d$%d$%s" % (
            num_cycles_power,
            salt_size, bytes_to_hex(salt) if salt else "0",
            iv_size, bytes_to_hex(iv) if iv else "0",
            next_header_crc, data_len, bytes_to_hex(enc_data[:data_len])
        ))
        return

    error("No AES encryption detected — archive may not be password-protected", filename)


def main():
    parser = create_parser("7-Zip archive hash extractor for hashcat", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
