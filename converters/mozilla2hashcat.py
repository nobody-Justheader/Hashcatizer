#!/usr/bin/env python3
"""
mozilla2hashcat.py — Extract hashcat-compatible hashes from Mozilla/Firefox/Thunderbird profiles.

Based on mozilla2john.py from openwall/john.

Supported hashcat modes:
    26100 - Mozilla key3.db / key4.db
"""

import base64
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file,
)

HASHCAT_MODES = {
    26100: "Mozilla key3.db / key4.db",
}


def _process_key4db(filename):
    """Parse key4.db (SQLite, Firefox 58+)."""
    try:
        import sqlite3
        conn = sqlite3.connect(filename)
        cursor = conn.cursor()
        cursor.execute("SELECT item1, item2, a11 FROM metadata WHERE id = 'password'")
        row = cursor.fetchone()
        if row is None:
            cursor.execute("SELECT item1, item2 FROM metadata")
            row = cursor.fetchone()
        conn.close()

        if row is None:
            return None

        global_salt = row[0] if isinstance(row[0], bytes) else bytes(row[0])
        item2 = row[1] if isinstance(row[1], bytes) else bytes(row[1])

        # Parse ASN.1 DER to extract salt, iterations, encrypted data
        # item2 is DER-encoded PKCS#5 PBES2 parameters
        salt, iterations, enc_data = _parse_der_pbes2(item2)
        if salt is None:
            return None

        hashline = "$mozilla$*%s*%s*%d*%s" % (
            bytes_to_hex(global_salt),
            bytes_to_hex(salt),
            iterations,
            bytes_to_hex(enc_data),
        )
        return hashline

    except Exception:
        return None


def _parse_der_pbes2(data):
    """
    Simple ASN.1 DER parser for PBES2 parameters.
    Extract salt, iteration count, and encrypted data.
    """
    salt = None
    iterations = 0
    enc_data = None

    try:
        # Walk through DER structure to find OctetString (salt) and Integer (iter)
        i = 0
        found_salts = []
        found_ints = []
        found_octets = []

        while i < len(data):
            tag = data[i]
            i += 1
            if i >= len(data):
                break

            # Length
            length = data[i]
            i += 1
            if length & 0x80:
                num_bytes = length & 0x7F
                length = int.from_bytes(data[i:i + num_bytes], 'big')
                i += num_bytes

            if tag == 0x04:  # OCTET STRING
                found_octets.append(data[i:i + length])
            elif tag == 0x02:  # INTEGER
                val = int.from_bytes(data[i:i + length], 'big')
                found_ints.append(val)
            elif tag in (0x30, 0x31, 0xa0, 0xa1):  # SEQUENCE, SET, CONTEXT
                continue  # Descend into constructed types
            else:
                pass

            i += length

        # Heuristic: first small octet string is salt, larger ones are encrypted data
        for o in found_octets:
            if len(o) <= 32 and salt is None:
                salt = o
            elif len(o) > 16:
                enc_data = o

        if found_ints:
            iterations = found_ints[0]

        return salt, iterations, enc_data

    except Exception:
        return None, 0, None


def _process_key3db(filename):
    """Parse key3.db (Berkeley DB, older Firefox)."""
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError:
        return None

    # Key3.db is a Berkeley DB file
    # Look for the password check entry
    # Magic: "\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    # or "password-check"
    pc_marker = b'password-check'
    pc_pos = data.find(pc_marker)
    if pc_pos == -1:
        return None

    # Global salt is typically at fixed offset in BDB
    # For key3.db, global salt is the first entry's value (16 bytes)
    # This is simplified — full BDB parsing would be more robust
    global_salt = data[3:3 + 16] if len(data) > 19 else None
    if global_salt is None:
        return None

    # Password check is 24 bytes after the marker
    check_offset = pc_pos + len(pc_marker)
    if check_offset + 24 > len(data):
        return None

    password_check = data[check_offset:check_offset + 24]

    hashline = "$mozilla$*%s*%s" % (
        bytes_to_hex(global_salt),
        bytes_to_hex(password_check),
    )
    return hashline


def process_mozilla(filename):
    if not validate_file(filename):
        return

    basename = os.path.basename(filename)

    result = None
    if basename == 'key4.db' or filename.endswith('.sqlite'):
        result = _process_key4db(filename)
    elif basename == 'key3.db':
        result = _process_key3db(filename)
    else:
        # Try key4 first, then key3
        result = _process_key4db(filename)
        if result is None:
            result = _process_key3db(filename)

    if result:
        output_hash(result)
    else:
        error("Could not parse Mozilla key database", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Mozilla/Firefox/Thunderbird profiles.\n"
        "Process key3.db or key4.db from the profile directory.",
        file_help="Mozilla key database file(s) (key3.db, key4.db)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_mozilla(f)


if __name__ == "__main__":
    main()
