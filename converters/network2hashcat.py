#!/usr/bin/env python3
"""
network2hashcat.py — Generic network protocol hash extractor.

Handles text-based hash dumps from Wireshark/tshark exports, SNMP
community strings, SIP digests, and other protocol hashes.

Inspired by: network2john.lua (openwall/john)
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    5500: "NetNTLMv1",
    5600: "NetNTLMv2",
    11100: "PostgreSQL CRAM (MD5)",
    11200: "MySQL CRAM (SHA1)",
    11400: "SIP digest authentication (MD5)",
    16100: "TACACS+",
    16500: "JWT (JSON Web Token)",
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

        # SIP digest: $sip$*...
        if '$sip$' in line:
            output_hash(line)
            continue

        # TACACS+: $tacacs-plus$...
        if '$tacacs-plus$' in line:
            output_hash(line)
            continue

        # JWT
        if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', line):
            parts = line.split('.')
            if len(parts) == 3:
                output_hash(line)
                continue

        # PostgreSQL MD5: md5<32hex>
        if line.startswith('md5') and len(line) == 35:
            output_hash(line)
            continue

        # Generic hash:value or user:hash passthrough
        if ':' in line or '$' in line:
            output_hash(line)


def main():
    parser = create_parser("Network protocol hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
