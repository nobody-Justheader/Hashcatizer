#!/usr/bin/env python3
"""
ldif2hashcat.py — LDAP LDIF hash extractor.

Parses LDIF files and extracts userPassword attributes in various hash
schemes: {SSHA}, {SHA}, {MD5}, {CRYPT}, {SSHA256}, {SSHA512}, etc.

Inspired by: ldif2john.pl (openwall/john)
"""

import base64
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    111: "nsldaps {SSHA} SHA-1 Base64 salted",
    101: "nsldap {SHA} SHA-1 Base64",
    1711: "{SSHA512} SHA-512 Base64 salted",
}


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    current_uid = ""
    continuation = ""

    for raw_line in data.split('\n'):
        # Handle LDIF line continuations (lines starting with single space)
        if raw_line.startswith(' ') and continuation:
            continuation += raw_line[1:]
            continue
        elif continuation:
            _process_ldif_line(continuation, current_uid)
            continuation = ""

        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue

        if line.lower().startswith('dn:'):
            m = re.search(r'(?:uid|cn)=([^,]+)', line, re.I)
            if m:
                current_uid = m.group(1)
        elif line.lower().startswith('uid:'):
            current_uid = line[4:].strip()
        elif line.lower().startswith('userpassword:') or line.lower().startswith('userpassword::'):
            continuation = line

    if continuation:
        _process_ldif_line(continuation, current_uid)


def _process_ldif_line(line, uid):
    """Process a single userPassword line."""
    user = uid or "user"
    if line.lower().startswith('userpassword::'):
        # Double colon = base64 encoded value
        b64 = line[14:].strip()
        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            output_hash("%s:%s" % (user, decoded))
        except Exception:
            output_hash("%s:%s" % (user, b64))
    elif line.lower().startswith('userpassword:'):
        pw = line[13:].strip()
        if pw.startswith('{'):
            output_hash("%s:%s" % (user, pw))
        elif pw.startswith(':'):
            b64 = pw[1:].strip()
            try:
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                output_hash("%s:%s" % (user, decoded))
            except Exception:
                output_hash("%s:%s" % (user, b64))
        else:
            output_hash("%s:%s" % (user, pw))


def main():
    parser = create_parser("LDIF (LDAP) hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
