#!/usr/bin/env python3
"""
atmail2hashcat.py — Atmail web client hash extractor.

Parses Atmail database dumps for MD5, bcrypt, and MD5-crypt hashes.

Inspired by: atmail2john.pl (openwall/john)
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    0: "MD5",
    500: "md5crypt ($1$)",
    3200: "bcrypt ($2*$)",
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
            parts = line.split(':', 1)
            user = parts[0]
            hashval = parts[1].strip()
        else:
            # SQL dump pattern: INSERT ... VALUES ('user', 'hash', ...)
            m = re.search(r"VALUES\s*\(\s*'([^']+)'\s*,\s*'([^']+)'", line, re.I)
            if m:
                user = m.group(1)
                hashval = m.group(2)
            else:
                continue

        if len(hashval) == 32 and re.match(r'^[0-9a-fA-F]+$', hashval):
            output_hash("%s:%s" % (user, hashval))
        elif hashval.startswith('$2'):
            output_hash("%s:%s" % (user, hashval))
        elif hashval.startswith('$1'):
            output_hash("%s:%s" % (user, hashval))


def main():
    parser = create_parser("Atmail web client hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
