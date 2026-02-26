#!/usr/bin/env python3
"""
ansible2hashcat.py — Extract hashcat-compatible hashes from Ansible Vault files.

Based on ansible2john.py from openwall/john (Dhiru Kholia <kholia at kth.se>).

Supported hashcat modes:
    16900 - Ansible Vault

Output format:
    $ansible$0*0*<salt_hex>*<ct_hex>*<checksum_hex>
"""

import os
import sys
from binascii import unhexlify

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    create_parser, error, output_hash, print_mode_info, validate_file, warn,
)

HASHCAT_MODES = {
    16900: "Ansible Vault",
}

HEADER = b"$ANSIBLE_VAULT"


def process_ansible_vault(filename):
    """
    Parse an Ansible Vault file and extract the hash for hashcat.

    Ansible Vault format:
        Line 1: $ANSIBLE_VAULT;1.1;AES256
        Rest: hex-encoded data containing: salt, checksum, ciphertext (newline-separated)

    Args:
        filename: Path to Ansible Vault file.
    """
    if not validate_file(filename):
        return

    try:
        data = open(filename, "rb").read()
    except IOError as e:
        error(str(e), filename)
        return

    if not data.startswith(HEADER):
        error("File doesn't start with %s header" % HEADER.decode(), filename)
        return

    lines = data.splitlines()
    header_parts = lines[0].strip().split(b";")

    if len(header_parts) < 3:
        error("Malformed vault header", filename)
        return

    # header_parts[1] = version (e.g. "1.1")
    cipher_name = header_parts[2].strip().decode("ascii")

    if cipher_name != "AES256":
        error("Unsupported cipher '%s' (only AES256 is supported)" % cipher_name, filename)
        return

    # The vault body is hex-encoded, containing salt, checksum, and ciphertext
    # separated by newlines
    vault_body = b"".join(lines[1:])

    try:
        decoded = unhexlify(vault_body)
    except Exception as e:
        error("Failed to decode vault body: %s" % str(e), filename)
        return

    parts = decoded.split(b"\n")
    if len(parts) < 3:
        error("Malformed vault body (expected salt, checksum, ciphertext)", filename)
        return

    salt = parts[0].decode("ascii")
    checksum = parts[1].decode("ascii")
    ciphertext = parts[2].decode("ascii")

    # Ansible Vault version 0, cipher 0 (AES256)
    version = 0
    cipher = 0

    hashline = "$ansible$%d*%d*%s*%s*%s" % (version, cipher, salt, ciphertext, checksum)
    output_hash(hashline)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Ansible Vault files.",
        file_help="Ansible Vault .yml file(s)",
    )
    args = parser.parse_args()

    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return

    if not args.files:
        parser.error("No input files specified")

    for f in args.files:
        process_ansible_vault(f)


if __name__ == "__main__":
    main()
