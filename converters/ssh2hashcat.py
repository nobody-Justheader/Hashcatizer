#!/usr/bin/env python3
"""
ssh2hashcat.py — Extract hashcat-compatible hashes from SSH private key files.

Based on ssh2john.py from openwall/john (Dhiru Kholia <kholia at kth.se>).

Supported hashcat modes:
    22911 - SSH Private Key ($sshng$0) — RSA/DSA with DES-EDE3-CBC
    22921 - SSH Private Key ($sshng$1) — RSA/DSA with AES-128-CBC
    22931 - SSH Private Key ($sshng$2) — OpenSSH bcrypt + AES-256-CBC
    22941 - SSH Private Key ($sshng$4) — RSA/DSA with AES-192-CBC

Output format:
    $sshng$<cipher_id>$<salt_len>$<salt_hex>$<data_len>$<data_hex>[#$<rounds>$<ct_offset>]
"""

import base64
import binascii
import os
import struct
import sys

# Add parent directory to path for library access
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file, warn,
)

# Cipher type constants
DES = -1       # DES-CBC (rare, 8-byte key)
DES3 = 0       # DES-EDE3-CBC (24-byte key)
AES_128 = 1    # AES-128-CBC (16-byte key)
AES_256 = 2    # AES-256-CBC (32-byte key) — used in OpenSSH new format
EC_AES128 = 3  # EC keys with AES-128-CBC
AES_192 = 4    # AES-192-CBC (24-byte key)
AES256_RSA = 5 # RSA/DSA/EC with AES-256-CBC (old format)
DES_OLD = 6    # DES-CBC (8-byte salt) or bcrypt + aes256-ctr

HASHCAT_MODES = {
    22911: "SSH Private Key ($sshng$0, DES-EDE3-CBC)",
    22921: "SSH Private Key ($sshng$1, AES-128-CBC)",
    22931: "SSH Private Key ($sshng$2, OpenSSH bcrypt + AES-256-CBC/CTR)",
    22941: "SSH Private Key ($sshng$4, AES-192-CBC)",
}

# Known encryption types for SSH private key files
CIPHER_TABLE = {
    "AES-128-CBC":   {"cipher_id": AES_128,    "keysize": 16, "blocksize": 16},
    "DES-EDE3-CBC":  {"cipher_id": DES3,       "keysize": 24, "blocksize": 8},
    "AES-256-CBC":   {"cipher_id": AES_256,    "keysize": 32, "blocksize": 16},
    "AES-192-CBC":   {"cipher_id": AES_192,    "keysize": 24, "blocksize": 16},
    "AES-256-CTR":   {"cipher_id": AES_256,    "keysize": 32, "blocksize": 16},
    "DES-CBC":       {"cipher_id": DES,        "keysize": 8,  "blocksize": 8},
}


def _detect_key_types(lines):
    """
    Scan PEM lines for all BEGIN ... PRIVATE KEY markers.

    Returns:
        tags: list of key type strings ("RSA", "DSA", "OPENSSH", "EC")
        ktypes: list of ktype integers (0=RSA, 1=DSA, 2=OPENSSH, 3=EC)
    """
    tags = []
    ktypes = []
    for line in lines:
        if "BEGIN RSA PRIVATE" in line:
            tags.append("RSA")
            ktypes.append(0)
        elif "BEGIN DSA PRIVATE KEY" in line:
            tags.append("DSA")
            ktypes.append(1)
        elif "BEGIN OPENSSH PRIVATE KEY" in line:
            tags.append("OPENSSH")
            ktypes.append(2)
        elif "BEGIN EC PRIVATE KEY" in line:
            tags.append("EC")
            ktypes.append(3)
    return tags, ktypes


def _parse_openssh_new_format(data, filename):
    """
    Parse OpenSSH new format private key (bcrypt pbkdf).

    The new format uses AUTH_MAGIC "openssh-key-v1\0" followed by
    ciphername, kdfname, kdfoptions (salt + rounds), pubkey(s), encrypted blob.

    Returns:
        (encryption_type, saltstr, rounds, ciphertext_begin_offset) or None on error.
    """
    AUTH_MAGIC = b"openssh-key-v1"
    SALT_LENGTH = 16  # fixed in sshkey.c

    offset = 0
    if not data.startswith(AUTH_MAGIC):
        error("Missing AUTH_MAGIC", filename)
        return None

    offset += len(AUTH_MAGIC) + 1  # skip null terminator

    # Read cipher name
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    cipher_name = data[offset:offset + length].decode("ascii")
    if cipher_name == "none":
        warn("Key has no password", filename)
        return None
    elif cipher_name == "aes256-cbc":
        encryption_type = "AES-256-CBC"
    elif cipher_name == "aes256-ctr":
        encryption_type = "AES-256-CTR"
    else:
        error("Unknown cipher: %s" % cipher_name, filename)
        return None

    offset += length

    # Read kdf name
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4 + length

    # Read kdf options (contains salt + rounds)
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    salt_offset = offset + 4 + 4  # skip kdf length field + salt length field

    # Skip past kdf options to number of keys
    offset += 4 + length

    # Skip public key blob(s)
    offset += 4  # number of keys
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4 + length

    # Skip encrypted blob length field
    offset += 4

    if offset > len(data):
        error("Internal offset calculation error", filename)
        return None

    ciphertext_begin_offset = offset
    saltstr = binascii.hexlify(data[salt_offset:salt_offset + SALT_LENGTH]).decode("ascii")

    # Rounds value appears after the salt in kdf options
    rounds_offset = salt_offset + SALT_LENGTH
    rounds = struct.unpack(">I", data[rounds_offset:rounds_offset + 4])[0]
    if rounds == 0:
        rounds = 16

    return encryption_type, saltstr, rounds, ciphertext_begin_offset


def process_ssh_key(filename):
    """
    Extract hashcat-compatible hash from an SSH private key file.

    Handles:
    - Traditional PEM format (RSA/DSA/EC with various ciphers)
    - OpenSSH new format (bcrypt pbkdf + aes-256-cbc/ctr)

    Args:
        filename: Path to the SSH private key file.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, "r") as f:
            lines = f.readlines()
    except (IOError, UnicodeDecodeError) as e:
        error(str(e), filename)
        return

    tags, ktypes = _detect_key_types(lines)
    if not tags:
        error("Not a recognized SSH private key file", filename)
        return

    start = 0
    num_processed = 0

    for tag, ktype in zip(tags, ktypes):
        # Find BEGIN marker
        while start < len(lines) and lines[start].strip() != "-----BEGIN %s PRIVATE KEY-----" % tag:
            start += 1

        if start >= len(lines):
            error("Malformed private key file", filename)
            return

        # Parse headers (Proc-Type, DEK-Info)
        headers = {}
        start += 1
        while start < len(lines):
            parts = lines[start].split(": ")
            if len(parts) == 1:
                break
            headers[parts[0].lower()] = parts[1].strip()
            start += 1

        # Find END marker
        end = start
        while end < len(lines) and lines[end].strip() != "-----END %s PRIVATE KEY-----" % tag:
            end += 1

        # Base64 decode the key data
        try:
            b64_data = "".join(lines[start:end]).encode()
            data = base64.b64decode(b64_data)
        except (base64.binascii.Error, Exception) as e:
            error("Base64 decoding error: %s" % str(e), filename)
            return

        # Handle OpenSSH new format (bcrypt)
        if ktype == 2:
            result = _parse_openssh_new_format(data, filename)
            if result is None:
                start = end + 1
                num_processed += 1
                continue
            encryption_type, saltstr, rounds, ct_offset = result
        else:
            # Traditional PEM format — must have Proc-Type header
            if "proc-type" not in headers:
                warn("Key has no password", filename)
                start = end + 1
                num_processed += 1
                continue

            try:
                encryption_type, saltstr = headers["dek-info"].split(",")
            except (KeyError, ValueError):
                error("Cannot parse DEK-info header", filename)
                return

            if encryption_type not in CIPHER_TABLE:
                error("Unsupported cipher: %s" % encryption_type, filename)
                return

        keysize = CIPHER_TABLE[encryption_type]["keysize"]
        salt = binascii.unhexlify(saltstr)
        data_hex = bytes_to_hex(data)

        # Determine sshng cipher ID based on key type + cipher
        if keysize == 24 and encryption_type == "AES-192-CBC" and ktype in (0, 1):
            # RSA/DSA with AES-192
            cipher_id = 4
            hashline = "$sshng$%d$%d$%s$%d$%s" % (
                cipher_id, len(saltstr) // 2, saltstr, len(data_hex) // 2, data_hex
            )
        elif keysize == 32 and encryption_type == "AES-256-CBC" and ktype in (0, 1, 3):
            # RSA/DSA/EC with AES-256 (old format)
            cipher_id = 5
            hashline = "$sshng$%d$%d$%s$%d$%s" % (
                cipher_id, len(saltstr) // 2, saltstr, len(data_hex) // 2, data_hex
            )
        elif keysize == 24:
            # DES-EDE3-CBC
            cipher_id = 0
            hashline = "$sshng$%d$%d$%s$%d$%s" % (
                cipher_id, len(salt), saltstr, len(data_hex) // 2, data_hex
            )
        elif keysize == 8 and len(salt) == 8:
            # DES-CBC
            cipher_id = 6
            hashline = "$sshng$%d$%d$%s$%d$%s" % (
                cipher_id, len(salt), saltstr, len(data_hex) // 2, data_hex
            )
        elif keysize == 16 and ktype in (0, 1):
            # RSA/DSA with AES-128
            cipher_id = 1
            hashline = "$sshng$%d$%d$%s$%d$%s" % (
                cipher_id, len(saltstr) // 2, saltstr, len(data_hex) // 2, data_hex
            )
        elif keysize == 16 and ktype == 3:
            # EC with AES-128
            cipher_id = 3
            hashline = "$sshng$%d$%d$%s$%d$%s" % (
                cipher_id, len(saltstr) // 2, saltstr, len(data_hex) // 2, data_hex
            )
        elif keysize == 32 and encryption_type == "AES-256-CBC" and ktype == 2:
            # OpenSSH bcrypt + AES-256-CBC
            cipher_id = 2
            hashline = "$sshng$%d$%d$%s$%d$%s$%d$%d" % (
                cipher_id, len(saltstr) // 2, saltstr,
                len(data_hex) // 2, data_hex, rounds, ct_offset
            )
        elif keysize == 32 and encryption_type == "AES-256-CTR" and ktype == 2:
            # OpenSSH bcrypt + AES-256-CTR
            cipher_id = 6
            hashline = "$sshng$%d$%d$%s$%d$%s$%d$%d" % (
                cipher_id, len(saltstr) // 2, saltstr,
                len(data_hex) // 2, data_hex, rounds, ct_offset
            )
        else:
            error("Unsupported cipher/key combination", filename)
            return

        output_hash(hashline)
        start = end + 1
        num_processed += 1

    if num_processed != len(tags):
        warn("Some keys could not be processed", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from SSH private key files.\n"
        "Supports RSA, DSA, EC, and OpenSSH (bcrypt) key formats.",
        file_help="SSH private key file(s)",
    )
    args = parser.parse_args()

    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return

    if not args.files:
        parser.error("No input files specified")

    for f in args.files:
        process_ssh_key(f)


if __name__ == "__main__":
    main()
