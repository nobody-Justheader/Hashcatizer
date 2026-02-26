#!/usr/bin/env python3
"""
blockchain2hashcat.py — Extract hashcat-compatible hashes from Blockchain.com wallet files.

Based on blockchain2john.py from openwall/john.

Supported hashcat modes:
    12700 - Blockchain, My Wallet
    15200 - Blockchain, My Wallet, V2

Output format:
    $blockchain$<version>$<len>$<data_b64>

Blockchain.com wallets use PBKDF2-SHA1 with AES-256-CBC.
"""

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    create_parser, error, output_hash,
    print_mode_info, validate_file,
)

HASHCAT_MODES = {
    12700: "Blockchain, My Wallet",
    15200: "Blockchain, My Wallet, V2",
}


def process_blockchain(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            data = f.read().strip()
    except IOError as e:
        error(str(e), filename)
        return

    # Try JSON format first
    try:
        jdata = json.loads(data)
        if 'payload' in jdata:
            payload = jdata['payload']
            version = jdata.get('version', 2)
            pbkdf2_iterations = jdata.get('pbkdf2_iterations', 5000)
            try:
                raw = base64.b64decode(payload)
            except Exception:
                raw = payload.encode()
            b64_data = base64.b64encode(raw).decode()
            hashline = "$blockchain$v2$%d$%s$%s" % (pbkdf2_iterations, len(raw), b64_data)
            output_hash(hashline)
            return
    except (json.JSONDecodeError, TypeError):
        pass

    # Try raw base64 format (V1)
    try:
        raw = base64.b64decode(data)
        if len(raw) >= 32:
            b64_data = base64.b64encode(raw[:32]).decode()
            hashline = "$blockchain$%d$%s" % (len(raw), b64_data)
            output_hash(hashline)
            return
    except Exception:
        pass

    error("Could not parse Blockchain wallet data", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Blockchain.com wallet files.",
        file_help="Blockchain wallet file(s) (JSON or raw)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_blockchain(f)


if __name__ == "__main__":
    main()
