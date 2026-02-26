#!/usr/bin/env python3
"""
bitcoin2hashcat.py — Extract hashcat-compatible hashes from Bitcoin/Litecoin wallet.dat files.

Based on bitcoin2john.py from openwall/john (Dhiru Kholia, Gavin Andresen).

Supported hashcat modes:
    11300 - Bitcoin/Litecoin wallet.dat

Output format:
    $bitcoin$<mkey_len>$<mkey_hex>$<salt_len>$<salt_hex>$<rounds>$2$00$2$00

Supports:
    - BDB (Berkeley DB) wallet.dat files
    - SQLite-based wallet.dat files (newer Bitcoin Core)
"""

import binascii
import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    create_parser, error, output_hash, print_mode_info, validate_file, warn,
)

HASHCAT_MODES = {
    11300: "Bitcoin/Litecoin wallet.dat",
}


def _hexstr(bytestr):
    """Convert bytes to hex string."""
    return binascii.hexlify(bytestr).decode("ascii")


class BCDataStream:
    """Bitcoin data stream parser for reading serialized wallet data."""

    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, data):
        if self.input is None:
            self.input = data
        else:
            self.input += data

    def read_string(self):
        """Read a variable-length string (compact size prefix)."""
        if self.input is None:
            raise ValueError("Call write(bytes) before deserializing")
        length = self.read_compact_size()
        return self.read_bytes(length).decode("ascii")

    def read_bytes(self, length):
        """Read exactly `length` bytes."""
        result = self.input[self.read_cursor:self.read_cursor + length]
        self.read_cursor += length
        return result

    def read_uint32(self):
        """Read a little-endian uint32."""
        return self._read_num("<I")

    def read_compact_size(self):
        """Read a Bitcoin compact size integer."""
        size = self.input[self.read_cursor]
        if isinstance(size, str):
            size = ord(size)
        self.read_cursor += 1
        if size == 253:
            size = self._read_num("<H")
        elif size == 254:
            size = self._read_num("<I")
        elif size == 255:
            size = self._read_num("<Q")
        return size

    def _read_num(self, fmt):
        (i,) = struct.unpack_from(fmt, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(fmt)
        return i


def _try_sqlite3(walletfile):
    """
    Try to open wallet.dat as SQLite3 database (newer Bitcoin Core format).

    Returns:
        List of (key, value) tuples, or None if not SQLite.
    """
    try:
        import sqlite3
        cx = sqlite3.connect(walletfile)
        cx.execute("PRAGMA quick_check")
        items = list(cx.execute("SELECT key, value FROM main"))
        cx.close()
        return items
    except Exception:
        return None


def _try_bsddb(walletfile):
    """
    Try to open wallet.dat as Berkeley DB (classic format).

    Returns:
        List of (key, value) tuples, or None if BDB is not available or file is invalid.
    """
    try:
        import bsddb3.db as bsddb_db
    except ImportError:
        try:
            import bsddb.db as bsddb_db
        except ImportError:
            return None

    try:
        db = bsddb_db.DB()
        flags = bsddb_db.DB_THREAD | bsddb_db.DB_RDONLY
        db.open(walletfile, "main", bsddb_db.DB_BTREE, flags)
        items = list(db.items())
        db.close()
        return items
    except Exception:
        return None


def _parse_wallet(items):
    """
    Parse wallet key-value pairs to extract master key encryption data.

    Returns:
        dict with 'encrypted_key', 'salt', 'nDerivationMethod', 'nDerivationIterations'
        or None if no master key found.
    """
    kds = BCDataStream()
    vds = BCDataStream()
    mkey = {}

    for key, value in items:
        kds.clear()
        kds.write(key)
        vds.clear()
        vds.write(value)

        try:
            entry_type = kds.read_string()
        except Exception:
            continue

        if entry_type == "mkey":
            try:
                vds.read_uint32()  # nID
                mkey["encrypted_key"] = vds.read_bytes(vds.read_compact_size())
                mkey["salt"] = vds.read_bytes(vds.read_compact_size())
                mkey["nDerivationMethod"] = vds.read_uint32()
                mkey["nDerivationIterations"] = vds.read_uint32()
            except Exception:
                continue

    return mkey if "salt" in mkey else None


def process_bitcoin_wallet(filename):
    """
    Extract hashcat-compatible hash from a Bitcoin/Litecoin wallet.dat file.

    The wallet.dat file contains a master key entry (mkey) with:
    - encrypted_key: AES-encrypted master key
    - salt: derivation salt
    - nDerivationMethod: key derivation method (0 = SHA-512)
    - nDerivationIterations: number of iterations

    Args:
        filename: Path to wallet.dat file.
    """
    if not validate_file(filename):
        return

    # Try SQLite first (newer), then BDB (classic)
    items = _try_sqlite3(filename)
    if items is None:
        items = _try_bsddb(filename)
    if items is None:
        # Fallback: try raw binary scan for mkey pattern
        items = _raw_scan_for_mkey(filename)
        if items is None:
            error(
                "Cannot open wallet.dat. Install bsddb3 for BDB support: "
                "pip install bsddb3",
                filename,
            )
            return

    mkey = _parse_wallet(items)
    if mkey is None:
        error("Wallet is not encrypted (no master key found)", filename)
        return

    if mkey["nDerivationMethod"] != 0:
        error("Unknown key derivation method: %d" % mkey["nDerivationMethod"], filename)
        return

    encrypted_key_hex = _hexstr(mkey["encrypted_key"])
    salt_hex = _hexstr(mkey["salt"])
    rounds = mkey["nDerivationIterations"]

    # Validate salt and key sizes
    if len(salt_hex) == 16:
        expected_mkey_len = 96  # 32 bytes padded to 3 AES blocks (48 bytes = 96 hex)
    elif len(salt_hex) == 36:
        expected_mkey_len = 160  # Nexus legacy wallet
    else:
        error("Unsupported salt size: %d" % (len(salt_hex) // 2), filename)
        return

    if len(encrypted_key_hex) != expected_mkey_len:
        warn(
            "Unexpected master key size %d (expected %d)" % (
                len(encrypted_key_hex), expected_mkey_len
            ),
            filename,
        )

    # Use last two AES blocks (64 hex chars = 32 bytes) for cracking
    cry_master = encrypted_key_hex[-64:]

    hashline = "$bitcoin$%s$%s$%s$%s$%s$2$00$2$00" % (
        len(cry_master), cry_master, len(salt_hex), salt_hex, rounds
    )
    output_hash(hashline)


def _raw_scan_for_mkey(filename):
    """
    Fallback: scan raw wallet.dat bytes for master key data if BDB is not available.

    Looks for the 'mkey' key pattern in the binary data by searching for
    the serialized key format used by Bitcoin Core.

    Returns:
        List of (key, value) tuples or None.
    """
    try:
        with open(filename, "rb") as f:
            raw = f.read()
    except IOError:
        return None

    # Search for the mkey marker pattern
    # In BDB, keys are stored as: len(4) + "mkey" + ...
    # The value contains: nID(4) + encrypted_key(compact) + salt(compact) + method(4) + iterations(4)
    marker = b"\x04mkey"
    idx = raw.find(marker)
    if idx == -1:
        return None

    # We need to find the value associated with this key
    # The value typically follows after some BDB page structure
    # Try to find a reasonable encrypted_key + salt pattern after mkey
    # Look for patterns that resemble: compact_size + data + compact_size + salt + uint32 + uint32

    results = []
    search_start = 0
    while True:
        idx = raw.find(marker, search_start)
        if idx == -1:
            break
        search_start = idx + len(marker)

        # Try to parse the region around the mkey marker
        # Skip forward to find the value data
        # The BDB structure varies, so we scan a window after the marker
        scan_region = raw[idx + len(marker):idx + len(marker) + 512]

        # Look for a plausible mkey value: starts with nID (uint32), then compact_size + encrypted_key
        for offset in range(min(16, len(scan_region))):
            try:
                vds = BCDataStream()
                vds.write(scan_region[offset:])
                nid = vds.read_uint32()
                encrypted_key = vds.read_bytes(vds.read_compact_size())
                salt = vds.read_bytes(vds.read_compact_size())
                method = vds.read_uint32()
                iterations = vds.read_uint32()

                # Sanity checks
                if 32 <= len(encrypted_key) <= 80 and 8 <= len(salt) <= 32 and method == 0 and 1 <= iterations <= 10000000:
                    kds = BCDataStream()
                    kds.write(marker)
                    key_data = marker + struct.pack("<I", nid)

                    mkey_entry = {
                        "encrypted_key": encrypted_key,
                        "salt": salt,
                        "nDerivationMethod": method,
                        "nDerivationIterations": iterations,
                    }

                    # Create synthetic items list
                    class FakeKV:
                        pass

                    kds2 = BCDataStream()
                    kds2.write(b"\x04mkey")
                    vds2 = BCDataStream()
                    vds2.write(scan_region[offset:])

                    results.append((b"\x04mkey", scan_region[offset:]))
                    return results
            except Exception:
                continue

    return results if results else None


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Bitcoin/Litecoin wallet.dat files.\n"
        "Supports both BDB (Berkeley DB) and SQLite wallet formats.",
        file_help="Bitcoin/Litecoin wallet.dat file(s)",
    )
    args = parser.parse_args()

    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return

    if not args.files:
        parser.error("No input files specified")

    for f in args.files:
        process_bitcoin_wallet(f)


if __name__ == "__main__":
    main()
