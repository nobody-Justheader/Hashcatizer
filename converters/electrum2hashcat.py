#!/usr/bin/env python3
"""
electrum2hashcat.py — Extract hashcat-compatible hashes from Electrum wallet files.

Based on electrum2john.py from openwall/john (Dhiru Kholia).

Supported hashcat modes:
    16600 - Electrum Wallet (Salt-Type 1-5)
    21700 - Electrum Wallet (Salt-Type 4)
    21800 - Electrum Wallet (Salt-Type 5)
"""

import base64
import binascii
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file,
)

HASHCAT_MODES = {
    16600: "Electrum Wallet (Salt-Type 1-5)",
    21700: "Electrum Wallet (Salt-Type 4)",
    21800: "Electrum Wallet (Salt-Type 5)",
}


def process_electrum(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            raw = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    text = raw.decode('utf-8', errors='ignore').strip()

    # Try JSON format (Electrum 2.x+)
    try:
        data = json.loads(text)

        # Electrum 2.8+ with encrypted xprv
        if 'xprv' in data:
            xprv = data['xprv']
            try:
                ct = base64.b64decode(xprv)
                if len(ct) >= 32:
                    # Salt type 3: xprv encrypted with AES-256-CBC
                    hashline = "$electrum$3*%s" % bytes_to_hex(ct)
                    output_hash(hashline)
                    return
            except Exception:
                pass

        # Electrum with wallet_type and seed
        if 'keystore' in data:
            ks = data['keystore']
            if 'xprv' in ks:
                try:
                    ct = base64.b64decode(ks['xprv'])
                    if len(ct) >= 32:
                        hashline = "$electrum$3*%s" % bytes_to_hex(ct)
                        output_hash(hashline)
                        return
                except Exception:
                    pass

        # Electrum 2.x format with encrypted seed
        if 'seed_version' in data and 'use_encryption' in data:
            if data.get('use_encryption', False):
                # Encrypted wallet
                for key in ('seed', 'master_private_keys', 'keypairs'):
                    if key in data:
                        val = data[key]
                        if isinstance(val, str):
                            try:
                                ct = base64.b64decode(val)
                                if len(ct) >= 32:
                                    hashline = "$electrum$4*%s" % bytes_to_hex(ct)
                                    output_hash(hashline)
                                    return
                            except Exception:
                                pass
                        elif isinstance(val, dict):
                            for k, v in val.items():
                                try:
                                    ct = base64.b64decode(v)
                                    if len(ct) >= 32:
                                        hashline = "$electrum$4*%s" % bytes_to_hex(ct)
                                        output_hash(hashline)
                                        return
                                except Exception:
                                    pass

        error("Electrum wallet does not appear encrypted", filename)
        return

    except json.JSONDecodeError:
        pass

    # Electrum 1.x format (non-JSON, base64 or raw)
    # V1 wallets store encrypted seed as hex
    try:
        # Check for hex string (Electrum 1.x seed)
        if len(text) >= 64 and all(c in '0123456789abcdef' for c in text[:64]):
            seed_hex = text[:64]
            hashline = "$electrum$1*%s" % seed_hex
            output_hash(hashline)
            return

        # Try base64 decoding
        ct = base64.b64decode(text)
        if len(ct) >= 32:
            hashline = "$electrum$5*%s" % bytes_to_hex(ct)
            output_hash(hashline)
            return
    except Exception:
        pass

    error("Could not parse Electrum wallet format", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Electrum wallet files.\n"
        "Supports Electrum 1.x, 2.x, and 3.x+ formats.",
        file_help="Electrum wallet file(s)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_electrum(f)


if __name__ == "__main__":
    main()
