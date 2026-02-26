#!/usr/bin/env python3
"""
mongodb2hashcat.py — MongoDB SCRAM-SHA hash extractor.

Parses MongoDB user exports (JSON/BSON) to extract SCRAM-SHA-1 and
SCRAM-SHA-256 credentials for hashcat cracking.

Inspired by: mongodb2john.js (openwall/john)
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import create_parser, error, output_hash, validate_file

HASHCAT_MODES = {
    24100: "MongoDB SCRAM-SHA-1",
    24200: "MongoDB SCRAM-SHA-256",
}


def _extract_record(record):
    """Extract hash from a single MongoDB user record dict."""
    if not isinstance(record, dict):
        return
    user = record.get('user', record.get('_id', ''))
    credentials = record.get('credentials', {})
    if not credentials:
        return

    scram1 = credentials.get('SCRAM-SHA-1', {})
    if isinstance(scram1, dict) and scram1:
        iters = scram1.get('iterationCount', 10000)
        salt = scram1.get('salt', '')
        stored_key = scram1.get('storedKey', '')
        server_key = scram1.get('serverKey', '')
        if salt and stored_key:
            output_hash("$mongodb-scram$SCRAM-SHA-1*%s*%d*%s*%s*%s" % (
                user, iters, salt, stored_key, server_key))

    scram256 = credentials.get('SCRAM-SHA-256', {})
    if isinstance(scram256, dict) and scram256:
        iters = scram256.get('iterationCount', 15000)
        salt = scram256.get('salt', '')
        stored_key = scram256.get('storedKey', '')
        server_key = scram256.get('serverKey', '')
        if salt and stored_key:
            output_hash("$mongodb-scram$SCRAM-SHA-256*%s*%d*%s*%s*%s" % (
                user, iters, salt, stored_key, server_key))


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    # Try full JSON (array or object)
    try:
        parsed = json.loads(data)
        if isinstance(parsed, list):
            for record in parsed:
                _extract_record(record)
        elif isinstance(parsed, dict):
            _extract_record(parsed)
        return
    except json.JSONDecodeError:
        pass

    # Try line-delimited JSON (mongoexport)
    for line in data.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            _extract_record(record)
        except json.JSONDecodeError:
            # Try regex extraction from mongo shell output
            m_user = re.search(r'"user"\s*:\s*"([^"]+)"', line)
            m_stored = re.search(r'"storedKey"\s*:\s*"([^"]+)"', line)
            m_salt = re.search(r'"salt"\s*:\s*"([^"]+)"', line)
            m_iter = re.search(r'"iterationCount"\s*:\s*(\d+)', line)
            if m_user and m_stored and m_salt and m_iter:
                output_hash("$mongodb-scram$*%s*%s*%s*%s" % (
                    m_user.group(1), m_iter.group(1),
                    m_salt.group(1), m_stored.group(1)))


def main():
    parser = create_parser("MongoDB SCRAM-SHA hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
