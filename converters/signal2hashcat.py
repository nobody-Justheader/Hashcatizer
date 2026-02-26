#!/usr/bin/env python3
"""
signal2hashcat.py — Extract hashcat-compatible hashes from Signal Desktop backups.

Based on signal2john.py from openwall/john.

Supported hashcat modes:
    28200 - Signal Desktop passphrase

Signal Desktop backup files use PBKDF2-SHA512 or Argon2 for key derivation.
"""

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
    28200: "Signal Desktop",
}


def process_signal(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    # Signal backup format: protobuf header
    # First field: header frame
    if len(data) < 35:
        error("File too small for Signal backup", filename)
        return

    # try JSON config (Signal Desktop config.json with encrypted key)
    text = data.decode('utf-8', errors='ignore').strip()
    try:
        config = json.loads(text)
        if 'encryptedKey' in config:
            enc_key = config['encryptedKey']
            salt = config.get('salt', '')
            hashline = "$signal$1*%s*%s" % (salt, enc_key)
            output_hash(hashline)
            return
    except json.JSONDecodeError:
        pass

    # Signal Android backup: protobuf format with BackupFrame
    # Magic: first byte is frame length varint
    offset = 0
    if data[0:1] == b'\x0a':  # Field 1, wire type 2 (length-delimited)
        # Parse protobuf header
        # Skip to find salt and IV
        try:
            # Simple protobuf parser for header frame
            frame_end = min(len(data), 200)
            header_data = data[:frame_end]

            salt = None
            iv = None

            i = 0
            while i < len(header_data):
                if i >= len(header_data):
                    break
                tag = header_data[i]
                field_number = tag >> 3
                wire_type = tag & 0x07
                i += 1

                if wire_type == 0:  # varint
                    while i < len(header_data) and header_data[i] & 0x80:
                        i += 1
                    i += 1
                elif wire_type == 2:  # length-delimited
                    if i >= len(header_data):
                        break
                    length = header_data[i]
                    i += 1
                    field_data = header_data[i:i + length]
                    i += length
                    if field_number == 2:  # salt
                        salt = field_data
                    elif field_number == 1 and len(field_data) == 16:
                        iv = field_data
                else:
                    break

            if salt and iv:
                hashline = "$signal$2*%s*%s*%s" % (
                    bytes_to_hex(salt),
                    bytes_to_hex(iv),
                    bytes_to_hex(data[frame_end:frame_end + 48])
                )
                output_hash(hashline)
                return
        except Exception:
            pass

    error("Could not parse Signal backup format", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Signal Desktop/Android backups.",
        file_help="Signal backup/config file(s)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_signal(f)


if __name__ == "__main__":
    main()
