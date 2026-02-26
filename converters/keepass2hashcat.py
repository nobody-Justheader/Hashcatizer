#!/usr/bin/env python3
"""
keepass2hashcat.py — Extract hashcat-compatible hashes from KeePass database files.

Supported hashcat modes:
    13400 - KeePass 1 (AES/Twofish) and KeePass 2 (AES/ChaCha20)

Output format (KeePass 2.x KDBX):
    $keepass$*2*<rounds>*<fileversion>*<master_seed_hex>*<transform_seed_hex>*
    <enc_iv_hex>*<expected_start_hex>*<stream_start_hex>

Output format (KeePass 1.x KDB):
    $keepass$*1*<rounds>*0*<master_seed_hex>*<transform_seed_hex>*
    <enc_iv_hex>*<contents_hash_hex>
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file,
)

HASHCAT_MODES = {
    13400: "KeePass 1 (AES/Twofish) and KeePass 2 (AES/ChaCha20)",
}

# KDB (KeePass 1.x) magic signatures
KDB_SIG1 = 0x9AA2D903
KDB_SIG2 = 0xB54BFB65

# KDBX (KeePass 2.x) magic signatures
KDBX_SIG1 = 0x9AA2D903
KDBX_SIG2 = 0xB54BFB67

# KeePass 2.x header field IDs
HEADER_END = 0
HEADER_CIPHER_ID = 2
HEADER_COMPRESSION = 3
HEADER_MASTER_SEED = 4
HEADER_TRANSFORM_SEED = 5
HEADER_TRANSFORM_ROUNDS = 6
HEADER_ENCRYPTION_IV = 7
HEADER_STREAM_START_BYTES = 9
HEADER_KDF_PARAMETERS = 11


def _read_kdb(data, filename):
    """
    Parse KeePass 1.x KDB file.

    KDB header structure (124 bytes):
        0-3:   Signature 1
        4-7:   Signature 2
        8-11:  Flags
        12-15: Version
        16-31: Master seed (16 bytes)
        32-47: Encryption IV (16 bytes)
        48-51: Number of groups
        52-55: Number of entries
        56-87: Contents hash (32 bytes)
        88-119: Transform seed (32 bytes)
        120-123: Transform rounds
    """
    if len(data) < 124:
        error("KDB file too small", filename)
        return

    flags = struct.unpack('<I', data[8:12])[0]
    master_seed = data[16:32]
    enc_iv = data[32:48]
    contents_hash = data[56:88]
    transform_seed = data[88:120]
    transform_rounds = struct.unpack('<I', data[120:124])[0]

    # Check encryption algorithm from flags
    # Bit 1: Rijndael, Bit 2: Twofish
    algo_flag = flags & 0x03
    if algo_flag == 0:
        error("Unknown encryption algorithm in KDB", filename)
        return

    hashline = "$keepass$*1*%d*0*%s*%s*%s*%s" % (
        transform_rounds,
        bytes_to_hex(master_seed),
        bytes_to_hex(transform_seed),
        bytes_to_hex(enc_iv),
        bytes_to_hex(contents_hash),
    )
    output_hash(hashline)


def _read_kdbx(data, filename):
    """
    Parse KeePass 2.x KDBX file.

    KDBX has a dynamic header with TLV (type-length-value) fields after
    the 12-byte fixed header.
    """
    if len(data) < 12:
        error("KDBX file too small", filename)
        return

    # Read file version
    minor_version = struct.unpack('<H', data[8:10])[0]
    major_version = struct.unpack('<H', data[10:12])[0]
    file_version = major_version * 65536 + minor_version

    # Parse header fields
    offset = 12
    master_seed = None
    transform_seed = None
    transform_rounds = None
    enc_iv = None
    stream_start_bytes = None
    kdf_params = None

    while offset < len(data):
        if major_version >= 4:
            # KDBX 4.x uses 4-byte field size
            if offset + 5 > len(data):
                break
            field_id = data[offset]
            field_size = struct.unpack('<I', data[offset + 1:offset + 5])[0]
            field_data = data[offset + 5:offset + 5 + field_size]
            offset += 5 + field_size
        else:
            # KDBX 3.x uses 2-byte field size
            if offset + 3 > len(data):
                break
            field_id = data[offset]
            field_size = struct.unpack('<H', data[offset + 1:offset + 3])[0]
            field_data = data[offset + 3:offset + 3 + field_size]
            offset += 3 + field_size

        if field_id == HEADER_END:
            break
        elif field_id == HEADER_MASTER_SEED:
            master_seed = field_data
        elif field_id == HEADER_TRANSFORM_SEED:
            transform_seed = field_data
        elif field_id == HEADER_TRANSFORM_ROUNDS:
            if len(field_data) == 8:
                transform_rounds = struct.unpack('<Q', field_data)[0]
            else:
                transform_rounds = struct.unpack('<I', field_data)[0]
        elif field_id == HEADER_ENCRYPTION_IV:
            enc_iv = field_data
        elif field_id == HEADER_STREAM_START_BYTES:
            stream_start_bytes = field_data
        elif field_id == HEADER_KDF_PARAMETERS and major_version >= 4:
            kdf_params = field_data

    if master_seed is None or enc_iv is None:
        error("Missing required KDBX header fields", filename)
        return

    if major_version >= 4 and kdf_params is not None:
        # KDBX 4.x — KDF parameters are in a variant dictionary
        # Parse the variant map to extract transform seed and rounds
        ts, tr = _parse_kdf_params(kdf_params)
        if ts is not None:
            transform_seed = ts
        if tr is not None:
            transform_rounds = tr

    if transform_seed is None:
        error("Missing transform seed", filename)
        return

    if transform_rounds is None:
        transform_rounds = 6000  # Default

    if major_version >= 4:
        # KDBX 4.x: use SHA-256 of header as expected bytes
        import hashlib
        # The header includes everything up to and including the end-of-header field
        header_data = data[:offset]
        expected_bytes = hashlib.sha256(header_data).digest()
        stream_start_hex = bytes_to_hex(expected_bytes)
    else:
        if stream_start_bytes is None:
            error("Missing stream start bytes", filename)
            return
        stream_start_hex = bytes_to_hex(stream_start_bytes)

    hashline = "$keepass$*2*%d*%d*%s*%s*%s*%s*%s" % (
        transform_rounds,
        file_version,
        bytes_to_hex(master_seed),
        bytes_to_hex(transform_seed),
        bytes_to_hex(enc_iv),
        stream_start_hex,
        bytes_to_hex(data[offset:offset + 32]),  # First 32 bytes of encrypted data
    )
    output_hash(hashline)


def _parse_kdf_params(kdf_data):
    """
    Parse KDBX 4.x KDF parameters (variant dictionary format).

    Returns:
        (transform_seed, transform_rounds) tuple.
    """
    transform_seed = None
    transform_rounds = None

    # Variant dictionary format:
    # Version (2 bytes LE) + entries
    # Each entry: type(1) + name_len(4 LE) + name + value_len(4 LE) + value
    offset = 2  # Skip version
    while offset < len(kdf_data):
        if offset + 1 > len(kdf_data):
            break
        vtype = kdf_data[offset]
        offset += 1
        if vtype == 0:  # End
            break

        if offset + 4 > len(kdf_data):
            break
        name_len = struct.unpack('<I', kdf_data[offset:offset + 4])[0]
        offset += 4
        name = kdf_data[offset:offset + name_len].decode('utf-8', errors='ignore')
        offset += name_len

        if offset + 4 > len(kdf_data):
            break
        val_len = struct.unpack('<I', kdf_data[offset:offset + 4])[0]
        offset += 4
        value = kdf_data[offset:offset + val_len]
        offset += val_len

        if name == 'S':
            transform_seed = value
        elif name == 'R':
            if len(value) == 8:
                transform_rounds = struct.unpack('<Q', value)[0]
            elif len(value) == 4:
                transform_rounds = struct.unpack('<I', value)[0]

    return transform_seed, transform_rounds


def process_keepass(filename):
    """
    Extract hashcat-compatible hash from a KeePass database file.

    Args:
        filename: Path to .kdb or .kdbx file.
    """
    if not validate_file(filename):
        return

    try:
        data = open(filename, 'rb').read()
    except IOError as e:
        error(str(e), filename)
        return

    if len(data) < 8:
        error("File too small to be a KeePass database", filename)
        return

    sig1 = struct.unpack('<I', data[0:4])[0]
    sig2 = struct.unpack('<I', data[4:8])[0]

    if sig1 == KDB_SIG1 and sig2 == KDB_SIG2:
        _read_kdb(data, filename)
    elif sig1 == KDBX_SIG1 and sig2 == KDBX_SIG2:
        _read_kdbx(data, filename)
    else:
        error("Not a KeePass database (invalid signature)", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from KeePass database files.\n"
        "Supports KeePass 1.x (.kdb) and 2.x (.kdbx) formats.",
        file_help="KeePass database file(s) (.kdb, .kdbx)",
    )
    args = parser.parse_args()

    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return

    if not args.files:
        parser.error("No input files specified")

    for f in args.files:
        process_keepass(f)


if __name__ == "__main__":
    main()
