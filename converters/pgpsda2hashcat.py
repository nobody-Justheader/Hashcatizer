#!/usr/bin/env python3
"""
pgpsda2hashcat.py — PGP Self-Decrypting Archive hash extractor.

Parses PGPSDA magic from PGP SDA files and extracts salt, iteration count,
and check bytes for hashcat cracking.

Inspired by: pgpsda2john.py (openwall/john)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    10900: "PGP SDA (PBKDF2-SHA1)",
}

SDAHEADER_FMT = '<6sIQQ8sH8s'
SDAHEADER_SIZE = struct.calcsize(SDAHEADER_FMT)


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    found = False
    for i in range(0, len(data) - SDAHEADER_SIZE + 1):
        chunk = data[i:SDAHEADER_SIZE + i]
        try:
            fields = struct.unpack(SDAHEADER_FMT, chunk)
        except struct.error:
            continue

        magic, offset, comp_len, num_files, salt, hash_reps, check_bytes = fields
        if magic == b'PGPSDA' and offset < len(data):
            salt_hex = bytes_to_hex(salt)
            check_hex = bytes_to_hex(check_bytes)
            sys.stderr.write("SDA: compressed_len=%d, num_files=%d, iterations=%d\n" %
                             (comp_len, num_files, hash_reps))
            output_hash("%s:$pgpsda$0*%d*%s*%s" % (
                os.path.basename(filename), hash_reps, salt_hex, check_hex))
            found = True

    if not found:
        error("No PGP SDA header found", filename)


def main():
    parser = create_parser("PGP Self-Decrypting Archive hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
