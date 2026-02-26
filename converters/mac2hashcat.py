#!/usr/bin/env python3
"""
mac2hashcat.py — macOS password hash extractor.

Supports macOS 10.4-10.13+ by parsing plist ShadowHashData for
SALTED-SHA512-PBKDF2, SALTED-SHA512, and SALTED-SHA1.

Inspired by: mac2john.py, mac2john-alt.py (openwall/john)
"""

import os
import plistlib
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file, warn

HASHCAT_MODES = {
    7100: "macOS v10.8+ PBKDF2-SHA512",
    1722: "macOS v10.7 SALTED-SHA512",
}


def _process_inner(pl):
    """Process inner ShadowHashData plist."""
    if not isinstance(pl, dict):
        return
    pbkdf2 = pl.get('SALTED-SHA512-PBKDF2', {})
    if isinstance(pbkdf2, dict) and pbkdf2:
        entropy = pbkdf2.get('entropy', b'')
        salt = pbkdf2.get('salt', b'')
        iterations = pbkdf2.get('iterations', 0)
        if entropy and salt:
            output_hash("$ml$%d$%s$%s" % (
                iterations,
                bytes_to_hex(salt) if isinstance(salt, bytes) else salt,
                bytes_to_hex(entropy) if isinstance(entropy, bytes) else entropy))
            return
    sha512 = pl.get('SALTED-SHA512', b'')
    if sha512 and isinstance(sha512, bytes) and len(sha512) >= 68:
        output_hash("$ml$0$%s$%s" % (bytes_to_hex(sha512[:4]), bytes_to_hex(sha512[4:68])))


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    # Binary or XML plist
    try:
        pl = plistlib.loads(data)
    except Exception:
        # Fall back to text hash format
        text = data.decode('utf-8', errors='ignore')
        for line in text.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                parts = line.split(':', 1)
                output_hash(line)
        return

    if not isinstance(pl, dict):
        error("Unexpected plist structure", filename)
        return

    # Direct ShadowHashData
    shd = pl.get('ShadowHashData')
    if shd:
        raw = shd[0] if isinstance(shd, list) and shd else shd
        if isinstance(raw, bytes):
            try:
                inner = plistlib.loads(raw)
                _process_inner(inner)
                return
            except Exception:
                pass

    # Look for user records
    for key, val in pl.items():
        if isinstance(val, dict):
            shd = val.get('ShadowHashData')
            if shd:
                raw = shd[0] if isinstance(shd, list) else shd
                if isinstance(raw, bytes):
                    try:
                        inner = plistlib.loads(raw)
                        _process_inner(inner)
                    except Exception:
                        pass


def main():
    parser = create_parser("macOS password hash extractor (10.4-13+)", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
