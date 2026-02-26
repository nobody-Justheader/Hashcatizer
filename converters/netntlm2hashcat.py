#!/usr/bin/env python3
"""
netntlm2hashcat.py — NetNTLM hash extractor.

Parses NTLM challenge/response text dumps into hashcat-compatible format.

Inspired by: netntlm.pl (openwall/john)
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    5500: "NetNTLMv1 / NetNTLMv1+ESS",
    5600: "NetNTLMv2",
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
        # user::domain:challenge:NTResponse:blob (standard NetNTLM format)
        if '::' in line:
            output_hash(line)
        elif line.startswith('$NETNTLMv') or line.startswith('$NETLM'):
            output_hash(line)


def main():
    parser = create_parser("NetNTLM hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
