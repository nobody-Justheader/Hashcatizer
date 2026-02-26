#!/usr/bin/env python3
"""
lastpass2hashcat.py — Extract hashcat-compatible hashes from LastPass local data.

Based on lastpass2john.py from openwall/john.

Supported hashcat modes:
    6800 - LastPass + LastPass sniffed

Output format:
    $lastpass$<iterations>$<email_hex>$<hash_hex>

LastPass stores a PBKDF2-SHA256 derived key locally.
The local vault is encrypted using PBKDF2(SHA256, masterPassword, email, iterations).
"""

import base64
import binascii
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file, warn,
)

HASHCAT_MODES = {
    6800: "LastPass + LastPass sniffed",
}


def _try_sqlite(filename):
    """Try extracting from Chrome/Opera SQLite databases."""
    try:
        import sqlite3
        conn = sqlite3.connect(filename)
        cursor = conn.cursor()
        # LastPass extension stores data in localStorage
        cursor.execute("SELECT key, value FROM ItemTable WHERE key LIKE '%lastpass%' OR key LIKE '%lp%'")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return None


def _extract_from_lpall(filename):
    """
    Parse Firefox lpall.slps or similar files.

    These files contain base64-encoded LastPass data.
    The second line typically contains the encrypted vault.
    """
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except IOError:
        return None

    if len(lines) < 2:
        return None

    # First line: iterations
    try:
        iterations = int(lines[0].strip())
    except ValueError:
        iterations = 5000  # default

    # Second line: base64 encoded data
    try:
        data = base64.b64decode(lines[1].strip())
    except Exception:
        return None

    return iterations, data


def _extract_from_iterations_file(iterations_file):
    """Read iterations from key.itr file."""
    try:
        with open(iterations_file, 'r') as f:
            return int(f.read().strip())
    except Exception:
        return 5000


def process_lastpass(filename):
    """
    Extract hashcat-compatible hash from LastPass local data.

    Supports:
    - Firefox lpall.slps files
    - Chrome/Opera SQLite databases
    - Direct iteration count + hash data

    Args:
        filename: Path to LastPass data file.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, 'rb') as f:
            raw = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    # Try to detect file type and extract hash
    text = raw.decode('utf-8', errors='ignore')

    # Look for email:hash or similar patterns
    # LastPass local vault often has format: email + encrypted data

    # Pattern 1: lpall files (iterations on first line, base64 on second)
    lines = text.strip().split('\n')
    if len(lines) >= 2:
        try:
            iterations = int(lines[0].strip())
            b64_data = lines[1].strip()
            data = base64.b64decode(b64_data)
            if len(data) >= 32:
                # Extract hash — first 32 bytes
                hash_hex = bytes_to_hex(data[:32])
                # Look for email in remaining data or filename
                email = ""
                for line in lines[2:]:
                    if '@' in line:
                        email = line.strip()
                        break

                if not email:
                    email = os.path.basename(filename)

                hashline = "$lastpass$%d$%s$%s" % (
                    iterations, binascii.hexlify(email.encode()).decode(),
                    hash_hex
                )
                output_hash(hashline)
                return
        except (ValueError, base64.binascii.Error):
            pass

    # Pattern 2: Direct hash format  email:iterations:hash
    m = re.search(r'([^:@\s]+@[^:@\s]+):(\d+):([0-9a-fA-F]{64})', text)
    if m:
        email = m.group(1)
        iterations = int(m.group(2))
        hash_hex = m.group(3)
        hashline = "$lastpass$%d$%s$%s" % (
            iterations, binascii.hexlify(email.encode()).decode(), hash_hex
        )
        output_hash(hashline)
        return

    # Pattern 3: SQLite database
    rows = _try_sqlite(filename)
    if rows:
        for key, value in rows:
            if 'iterations' in str(key).lower():
                try:
                    iterations = int(value)
                except ValueError:
                    continue
        warn("SQLite parsing needs manual review for email/hash extraction", filename)
        return

    error("Could not parse LastPass data format", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from LastPass local data.\n"
        "Supports Firefox, Chrome/Opera, and direct data files.",
        file_help="LastPass data file(s)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_lastpass(f)


if __name__ == "__main__":
    main()
