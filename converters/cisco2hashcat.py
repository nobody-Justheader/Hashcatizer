#!/usr/bin/env python3
"""
cisco2hashcat.py — Cisco config hash extractor.

Extracts Type 4/5/8/9 hashes from Cisco IOS/ASA configuration files.
Also decodes (weak) Type 7 passwords.

Inspired by: cisco2john.pl (openwall/john)
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    500: "Cisco-IOS Type 5 ($1$ MD5crypt)",
    5700: "Cisco-IOS Type 4 (SHA-256)",
    9200: "Cisco-IOS Type 8 (PBKDF2-SHA256)",
    9300: "Cisco-IOS Type 9 (scrypt)",
}

# Cisco Type 7 Vigenère table
TYPE7_XLAT = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
    0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
    0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
    0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76,
    0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b,
    0x3b, 0x66, 0x67, 0x38, 0x37,
]


def _decode_type7(enc):
    """Decode Cisco Type 7 password (weak reversible encoding)."""
    try:
        seed = int(enc[:2])
        return ''.join(chr(int(enc[i:i + 2], 16) ^ TYPE7_XLAT[(seed + i // 2 - 1) % len(TYPE7_XLAT)])
                       for i in range(2, len(enc), 2))
    except Exception:
        return None


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
        if not line or line.startswith('!'):
            continue

        # Type 5: $1$salt$hash
        m = re.search(r'(?:password|secret)\s+5\s+(\$1\$[^\s]+)', line, re.I)
        if m:
            output_hash(m.group(1))
            continue

        # Type 8: $8$salt$hash
        m = re.search(r'(?:password|secret)\s+8\s+(\$8\$[^\s]+)', line, re.I)
        if m:
            output_hash(m.group(1))
            continue

        # Type 9: $9$salt$hash
        m = re.search(r'(?:password|secret)\s+9\s+(\$9\$[^\s]+)', line, re.I)
        if m:
            output_hash(m.group(1))
            continue

        # Type 4: SHA-256
        m = re.search(r'(?:password|secret)\s+4\s+([A-Za-z0-9./]{43})', line, re.I)
        if m:
            output_hash(m.group(1))
            continue

        # Type 7: reversible
        m = re.search(r'(?:password|secret)\s+7\s+([0-9A-Fa-f]+)', line, re.I)
        if m:
            cleartext = _decode_type7(m.group(1))
            if cleartext:
                sys.stderr.write("[Type 7 decoded] %s\n" % cleartext)
            continue

        # enable secret (untyped, usually Type 5)
        m = re.search(r'enable\s+secret\s+(\$[^\s]+)', line, re.I)
        if m:
            output_hash(m.group(1))
            continue

        # username lines
        m = re.search(r'username\s+(\S+)\s+.*(?:password|secret)\s+\d+\s+(\$[^\s]+)', line, re.I)
        if m:
            output_hash("%s:%s" % (m.group(1), m.group(2)))


def main():
    parser = create_parser("Cisco config hash extractor (Type 4/5/7/8/9)", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
