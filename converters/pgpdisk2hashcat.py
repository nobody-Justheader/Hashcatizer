#!/usr/bin/env python3
"""
pgpdisk2hashcat.py — PGP Virtual Disk hash extractor.

Parses PGP disk image headers to extract user passphraseKeyInfo records
containing salt, encrypted key, check bytes, and hash iteration count.

Inspired by: pgpdisk2john.py (openwall/john)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    17010: "PGP Disk (AES-256, SHA-1)",
    17020: "PGP Disk (AES-256, SHA-256)",
    17030: "PGP Disk (AES-256, SHA-512)",
    17040: "PGP Disk (Twofish, SHA-1)",
}

PGPDISK_MAGIC = 0x50475064       # 'dPGP' little-endian
PGPDISK_MAIN_TYPE = 0x4E49414D   # 'NIAM'
PGPDISK_USER_TYPE = 0x52455355   # 'USER'


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    if len(data) < 512:
        error("File too small for PGP disk image", filename)
        return

    found = False
    salt = None
    algorithm = 0
    i = 0

    while i < len(data) - 32:
        try:
            magic = struct.unpack('<I', data[i:i + 4])[0]
        except struct.error:
            i += 1
            continue

        if magic != PGPDISK_MAGIC:
            i += 1
            continue

        header_type = struct.unpack('<I', data[i + 4:i + 8])[0]
        header_size = struct.unpack('<I', data[i + 8:i + 12])[0]

        if header_type == PGPDISK_MAIN_TYPE and 0 < header_size < 65536:
            # OnDiskHeaderInfo(28) + version(4) + sizes(24) + algorithm(4) + salt(16)
            algo_offset = i + 56
            salt_offset = i + 60
            if salt_offset + 16 <= len(data):
                algorithm = struct.unpack('<I', data[algo_offset:algo_offset + 4])[0]
                salt = data[salt_offset:salt_offset + 16]

        elif header_type == PGPDISK_USER_TYPE and 0 < header_size < 65536:
            # User record header: OnDiskHeaderInfo(28) + OnDiskUserInfo(32)
            user_data_start = i + 60
            if user_data_start + 128 + 148 <= len(data):
                username_raw = data[user_data_start:user_data_start + 128]
                username = username_raw.split(b'\x00')[0].decode('ascii', errors='ignore')

                pki = user_data_start + 128
                enc_key = data[pki:pki + 128]
                check_bytes = data[pki + 128:pki + 144]
                hash_reps = struct.unpack('<H', data[pki + 144:pki + 146])[0]

                salt_hex = bytes_to_hex(salt) if salt else "0" * 32
                output_hash("%s:$pgpdisk$0*%d*%d*%s*%s*%s" % (
                    username or "user", algorithm, hash_reps,
                    salt_hex, bytes_to_hex(enc_key), bytes_to_hex(check_bytes)
                ))
                found = True

        i += max(header_size, 1) if header_size > 0 and header_size < 65536 else 1

    if not found:
        error("No PGP disk user records found", filename)


def main():
    parser = create_parser("PGP Virtual Disk hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
