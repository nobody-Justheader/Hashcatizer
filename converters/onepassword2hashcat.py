#!/usr/bin/env python3
"""
1password2hashcat.py — Extract hashcat-compatible hashes from 1Password vaults.

Based on 1password2john.py from openwall/john (Dhiru Kholia).

Supported hashcat modes:
    8200 - 1Password, cloudkeychain
    6600 - 1Password, agilekeychain
"""

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file, warn,
)

HASHCAT_MODES = {
    8200: "1Password, cloudkeychain",
    6600: "1Password, agilekeychain",
}


def _process_cloudkeychain(vault_path):
    """
    Process 1Password cloudkeychain vault.

    The vault is a directory containing profile.js and other files.
    profile.js contains the master password verification data.
    """
    profile_path = os.path.join(vault_path, 'default', 'profile.js')
    if not os.path.exists(profile_path):
        profile_path = os.path.join(vault_path, 'profile.js')
        if not os.path.exists(profile_path):
            return None

    try:
        with open(profile_path, 'r') as f:
            data = f.read()
    except IOError:
        return None

    # Remove JavaScript variable assignment if present
    data = data.strip()
    if data.startswith('var profile='):
        data = data[len('var profile='):]
    if data.endswith(';'):
        data = data[:-1]

    try:
        profile = json.loads(data)
    except json.JSONDecodeError:
        return None

    iterations = profile.get('iterations', 0)
    salt = base64.b64decode(profile.get('salt', ''))
    master_key = base64.b64decode(profile.get('masterKey', ''))

    if not salt or not master_key or iterations == 0:
        return None

    # OPVault format has slightly different structure
    # masterKey is the encrypted key; first 16 bytes = IV
    if len(master_key) < 48:
        return None

    hashline = "$cloudkeychain$%d$%s$%d$%s$%d$%s" % (
        16, bytes_to_hex(salt),
        iterations,
        len(master_key), bytes_to_hex(master_key),
        0, ""
    )
    return hashline


def _process_agilekeychain(vault_path):
    """
    Process 1Password agilekeychain vault.

    The vault has data/default/encryptionKeys.js containing the
    encrypted master key.
    """
    ek_path = os.path.join(vault_path, 'data', 'default', 'encryptionKeys.js')
    if not os.path.exists(ek_path):
        return None

    try:
        with open(ek_path, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError):
        return None

    keys = data.get('list', [])
    for key in keys:
        if key.get('level', '') == 'SL5':
            iterations = key.get('iterations', 1000)
            enc_data = base64.b64decode(key.get('data', ''))
            validation = base64.b64decode(key.get('validation', ''))

            if len(enc_data) < 48 or len(validation) < 48:
                continue

            # Salt is first 8 bytes of data (after "Salted__")
            if enc_data[:8] == b'Salted__':
                salt = enc_data[8:16]
                ct = enc_data[16:]
            else:
                salt = enc_data[:8]
                ct = enc_data[8:]

            hashline = "$agilekeychain$%d*%s*%d*%s*%d*%s" % (
                len(salt), bytes_to_hex(salt),
                iterations,
                len(ct), bytes_to_hex(ct),
                len(validation), bytes_to_hex(validation),
            )
            return hashline

    return None


def _process_opvault(vault_path):
    """
    Process 1Password OPVault format.

    OPVault stores profile data in profile.js containing
    iterations, salt, and masterKey.
    """
    profile_path = os.path.join(vault_path, 'default', 'profile.js')
    if not os.path.exists(profile_path):
        return None

    try:
        with open(profile_path, 'r') as f:
            data = f.read().strip()
    except IOError:
        return None

    # Remove JS wrapper
    if data.startswith('var profile='):
        data = data[len('var profile='):]
    if data.endswith(';'):
        data = data[:-1]

    try:
        profile = json.loads(data)
    except json.JSONDecodeError:
        return None

    iterations = profile.get('iterations', 100000)
    salt = base64.b64decode(profile.get('salt', ''))
    master_key = base64.b64decode(profile.get('masterKey', ''))
    overview_key = base64.b64decode(profile.get('overviewKey', ''))

    if not salt or not master_key:
        return None

    hashline = "$cloudkeychain$%d$%s$%d$%d$%s$%d$%s" % (
        len(salt), bytes_to_hex(salt),
        iterations,
        len(master_key), bytes_to_hex(master_key),
        len(overview_key), bytes_to_hex(overview_key),
    )
    return hashline


def process_1password(path):
    """
    Extract hashcat-compatible hash from a 1Password vault.

    Supports:
    - cloudkeychain vaults
    - agilekeychain vaults
    - OPVault format
    """
    if os.path.isfile(path):
        # Might be a profile.js or encryptionKeys.js directly
        directory = os.path.dirname(path)
        # Walk up to find vault root
        while directory and not (
            directory.endswith('.agilekeychain') or
            directory.endswith('.cloudkeychain') or
            directory.endswith('.opvault')
        ):
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
        path = directory

    if not os.path.isdir(path):
        error("Not a directory or vault path", path)
        return

    result = None

    # Try cloudkeychain
    if path.endswith('.cloudkeychain') or os.path.exists(os.path.join(path, 'profile.js')):
        result = _process_cloudkeychain(path)

    # Try OPVault
    if result is None and (path.endswith('.opvault') or os.path.exists(os.path.join(path, 'default', 'profile.js'))):
        result = _process_opvault(path)

    # Try agilekeychain
    if result is None and (path.endswith('.agilekeychain') or os.path.exists(os.path.join(path, 'data'))):
        result = _process_agilekeychain(path)

    if result:
        output_hash(result)
    else:
        error("Could not parse 1Password vault format", path)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from 1Password vaults.\n"
        "Supports agilekeychain, cloudkeychain, and OPVault formats.",
        file_help="1Password vault directory(s)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input vault paths specified")
    for f in args.files:
        process_1password(f)


if __name__ == "__main__":
    main()
