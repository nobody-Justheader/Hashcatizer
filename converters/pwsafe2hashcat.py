#!/usr/bin/env python3
"""
pwsafe2hashcat.py — Extract hashcat-compatible hashes from Password Safe v3 files.

Based on pwsafe2john.py from openwall/john.

Supported hashcat modes:
    5200 - Password Safe v3

Output format:
    $pwsafe$*3*<salt_hex>*<iterations>*<hash_hex>

Password Safe v3 file format:
    TAG: "PWS3" (4 bytes)
    SALT: 32 bytes
    ITER: 4 bytes (LE uint32)
    H(P'): 32 bytes (SHA-256 hash of stretched key)
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
    5200: "Password Safe v3",
}

PWSAFE_TAG = b'PWS3'


def process_pwsafe(filename):
    if not validate_file(filename):
        return
    try:
        data = open(filename, 'rb').read()
    except IOError as e:
        error(str(e), filename)
        return

    if len(data) < 72:
        error("File too small for Password Safe v3", filename)
        return

    if data[:4] != PWSAFE_TAG:
        error("Not a Password Safe v3 file (missing PWS3 tag)", filename)
        return

    salt = data[4:36]       # 32 bytes
    iterations = struct.unpack('<I', data[36:40])[0]
    hp = data[40:72]        # SHA-256 hash of stretched key (32 bytes)

    hashline = "$pwsafe$*3*%s*%d*%s" % (
        bytes_to_hex(salt), iterations, bytes_to_hex(hp)
    )
    output_hash(hashline)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Password Safe v3 files.",
        file_help="Password Safe v3 (.psafe3) file(s)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_pwsafe(f)


if __name__ == "__main__":
    main()
