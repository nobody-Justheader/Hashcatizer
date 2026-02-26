#!/usr/bin/env python3
"""
pgpwde2hashcat.py — PGP Whole Disk Encryption hash extractor.

Parses WDE boot sector data to find symmetric user records containing
S2K salt, iteration count, and encrypted session key (ESK).

Inspired by: pgpwde2john.py (openwall/john)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    17010: "PGP WDE (AES-256, SHA-1)",
    17020: "PGP WDE (AES-256, SHA-256)",
}

USER_MAGIC = b'RESU'
SYM_TYPE = b'MMYS'
PGP_WDE_RECORD_SALT_SIZE = 16


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
        error("File too small for PGP WDE", filename)
        return

    found = False
    i = 0
    while i < len(data) - 304:
        if data[i:i + 4] != USER_MAGIC or data[i + 4:i + 8] != SYM_TYPE:
            i += 1
            continue

        # OnDiskUserInfo: magic(4)+type(4)+size(4)+flags(4)+reserved(16) = 32 bytes
        offset = i + 32  # skip OnDiskUserInfo
        if offset + 160 > len(data):
            i += 1
            continue

        # pgpDiskOnDiskUserWithSym: size(2)+symmAlg(1)+totalESKsize(2)+reserved(3)
        size = struct.unpack('<H', data[offset:offset + 2])[0]
        symm_alg = data[offset + 2]
        total_esk_size = struct.unpack('<H', data[offset + 3:offset + 5])[0]
        offset += 8  # past size+alg+esksize+reserved

        # userName (128 bytes)
        username = data[offset:offset + 128].split(b'\x00')[0].decode('ascii', errors='ignore')
        offset += 128

        # s2ktype(1) + hashIterations(4) + reserved(3) + salt(16)
        s2k_type = data[offset]
        hash_iters = struct.unpack('<I', data[offset + 1:offset + 5])[0]
        offset += 8
        salt = data[offset:offset + PGP_WDE_RECORD_SALT_SIZE]
        offset += PGP_WDE_RECORD_SALT_SIZE

        # ESK data
        esk_len = min(total_esk_size // 2 if total_esk_size else 128, 256)
        esk = data[offset:offset + esk_len] if offset + esk_len <= len(data) else data[offset:]

        output_hash("%s:$pgpwde$%d*%d*%d*%s*%s" % (
            username or "user", symm_alg, s2k_type, hash_iters,
            bytes_to_hex(salt), bytes_to_hex(esk)
        ))
        found = True
        i += max(size + 32, 304) if size > 0 else 304

    if not found:
        error("No PGP WDE user records found", filename)


def main():
    parser = create_parser("PGP Whole Disk Encryption hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
