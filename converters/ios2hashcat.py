#!/usr/bin/env python3
"""
ios2hashcat.py — iOS backup hash extractor.

Parses Manifest.plist from encrypted iOS backups (iOS 7+) to extract
PBKDF2 keybag parameters for hashcat cracking.

Inspired by: ios7tojohn.pl, itunes_backup2john.pl (openwall/john)
"""

import os
import plistlib
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file, warn

HASHCAT_MODES = {
    14700: "iTunes backup < 10.0",
    14800: "iTunes backup >= 10.0",
}


def _parse_keybag(keybag):
    """Parse TLV keybag to extract DPSL, DPIC, and other values."""
    result = {}
    i = 0
    while i < len(keybag) - 8:
        tag = keybag[i:i + 4]
        length = struct.unpack('>I', keybag[i + 4:i + 8])[0]
        if i + 8 + length > len(keybag):
            break
        value = keybag[i + 8:i + 8 + length]
        tag_str = tag.decode('ascii', errors='ignore')
        if tag == b'DPSL':
            result['dpsl'] = value
        elif tag == b'DPIC':
            result['dpic'] = struct.unpack('>I', value)[0] if length == 4 else int.from_bytes(value, 'big')
        elif tag == b'ITER':
            result['iter'] = struct.unpack('>I', value)[0] if length == 4 else int.from_bytes(value, 'big')
        elif tag == b'SALT':
            result['salt'] = value
        elif tag == b'DPIV':
            result['dpiv'] = value
        elif tag == b'UUID':
            result['uuid'] = value
        elif tag == b'WRAP':
            result['wrap'] = value
        elif tag == b'TKMT':
            result['tkmt'] = value
        i += 8 + length
    return result


def process_file(filename):
    if not validate_file(filename):
        return

    # Detect if file is Manifest.plist or a directory containing it
    actual_file = filename
    if os.path.isdir(filename):
        manifest = os.path.join(filename, 'Manifest.plist')
        if os.path.exists(manifest):
            actual_file = manifest
        else:
            error("No Manifest.plist found in directory", filename)
            return

    try:
        with open(actual_file, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), actual_file)
        return

    try:
        pl = plistlib.loads(data)
    except Exception as e:
        error("Failed to parse plist: %s" % str(e), actual_file)
        return

    is_encrypted = pl.get('IsEncrypted', False)
    if not is_encrypted:
        warn("Backup is not encrypted", actual_file)
        return

    keybag_raw = pl.get('BackupKeyBag', b'')
    if not keybag_raw:
        error("No BackupKeyBag found", actual_file)
        return

    kb = _parse_keybag(keybag_raw)
    dpsl = kb.get('dpsl', b'')
    dpic = kb.get('dpic', 0)
    salt = kb.get('salt', b'')
    iterations = kb.get('iter', 0)

    if dpsl and dpic:
        # iOS 10.2+ (mode 14800)
        output_hash("$itunes_backup$*10*%s*%d*%s*%d*%s" % (
            bytes_to_hex(keybag_raw[:40]),
            dpic, bytes_to_hex(dpsl),
            len(keybag_raw),
            bytes_to_hex(keybag_raw[:min(256, len(keybag_raw))])
        ))
    else:
        # iOS < 10.0 (mode 14700)
        output_hash("$itunes_backup$*9*%s*%d*%s*%d*%s" % (
            bytes_to_hex(salt) if salt else bytes_to_hex(keybag_raw[:20]),
            iterations or 10000,
            bytes_to_hex(dpsl) if dpsl else "0",
            len(keybag_raw),
            bytes_to_hex(keybag_raw[:min(256, len(keybag_raw))])
        ))


def main():
    parser = create_parser("iOS / iTunes backup hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
