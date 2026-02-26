#!/usr/bin/env python3
"""
sap2hashcat.py — SAP CODVN B/F/G/H hash extractor.

Parses SAP exported user tables for BCODE and PASSCODE hashes.

Inspired by: sap2john.pl (openwall/john)
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    7700: "SAP CODVN B (BCODE)",
    7701: "SAP CODVN B (BCODE, dialog)",
    7800: "SAP CODVN F/G (PASSCODE)",
    10300: "SAP CODVN H (PWDSALTEDHASH) iSSHA-1",
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

        # Tab-separated: username  BCODE  PASSCODE
        parts = line.split('\t')
        if len(parts) >= 3:
            user = parts[0].strip()
            bcode = parts[1].strip()
            passcode = parts[2].strip() if len(parts) > 2 else ''
            if bcode and len(bcode) == 16:
                output_hash("%s:%s" % (user.upper(), bcode.upper()))
            if passcode and len(passcode) == 40:
                output_hash("%s:%s" % (user.upper(), passcode.upper()))
            continue

        # Comma or colon separated
        if ':' in line:
            parts = line.split(':')
            if len(parts) >= 2:
                output_hash(line)
        elif ',' in line:
            parts = line.split(',')
            if len(parts) >= 3:
                user = parts[0].strip()
                bcode = parts[1].strip()
                passcode = parts[2].strip() if len(parts) > 2 else ''
                if bcode and len(bcode) == 16:
                    output_hash("%s:%s" % (user.upper(), bcode.upper()))
                if passcode and len(passcode) == 40:
                    output_hash("%s:%s" % (user.upper(), passcode.upper()))

        # {x-issha, 1024}... format
        m = re.search(r'\{x-issha,\s*(\d+)\}(.+)', line, re.I)
        if m:
            output_hash(line)


def main():
    parser = create_parser("SAP CODVN B/F/G/H hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
