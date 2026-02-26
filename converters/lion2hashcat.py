#!/usr/bin/env python3
"""
lion2hashcat.py — macOS Lion (10.7) SALTED-SHA512 hash extractor.

Parses Lion shadow files containing 68-byte SALTED-SHA512 hashes
(4 bytes salt + 64 bytes SHA-512 digest).

Inspired by: lion2john.pl, lion2john-alt.pl (openwall/john)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    1722: "macOS v10.7 SALTED-SHA512",
}


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            user, hashdata = line.split(':', 1)
            hashdata = hashdata.strip()
        else:
            user = os.path.basename(filename)
            hashdata = line
        hashdata = hashdata.replace(' ', '')
        if len(hashdata) >= 136:
            output_hash("%s:$ml$0$%s$%s" % (user, hashdata[:8], hashdata[8:136]))
        elif len(hashdata) >= 128:
            output_hash("%s:%s" % (user, hashdata))


def main():
    parser = create_parser("macOS Lion SALTED-SHA512 hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
