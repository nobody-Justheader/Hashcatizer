#!/usr/bin/env python3
"""
bitlocker2hashcat.py — Extract hashcat-compatible hashes from BitLocker volumes.

Based on bitlocker2john.py from openwall/john (elena).

Supported hashcat modes:
    22100 - BitLocker

BitLocker uses a FVE (Full Volume Encryption) metadata block containing
the encrypted volume master key (VMK) protected by a user password.

Output format:
    $bitlocker$<version>*<iterations>*<salt_len>*<salt_hex>*
    <mac_len>*<mac_hex>*<data_len>*<data_hex>
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
    22100: "BitLocker",
}

# BitLocker signature "-FVE-FS-"
BITLOCKER_SIGNATURE = b'-FVE-FS-'

# FVE metadata block identifiers
FVE_ENTRY_TYPE_VMK = 0x0002
FVE_VALUE_TYPE_AES_CCM = 0x0005
FVE_VALUE_TYPE_STRETCH = 0x0003

# Protection types
PROTECTION_PASSWORD = 0x2000
PROTECTION_RECOVERY = 0x0800


def _find_fve_metadata(data):
    """
    Find FVE metadata block offsets in a BitLocker volume.

    The FVE metadata is at one of three locations stored in the
    volume header (offsets 176, 184, 192 for NTFS).
    Returns list of FVE block offsets.
    """
    offsets = []

    # Check for BitLocker signature at offset 3
    if data[3:11] == BITLOCKER_SIGNATURE:
        # NTFS-based BitLocker (Windows Vista/7/8/10)
        for i in range(3):
            if 176 + i * 8 + 8 <= len(data):
                fve_offset = struct.unpack('<Q', data[176 + i * 8:184 + i * 8])[0]
                if fve_offset > 0 and fve_offset < len(data):
                    offsets.append(fve_offset)
    else:
        # Try scanning for -FVE-FS- signature
        pos = 0
        while pos < len(data):
            idx = data.find(BITLOCKER_SIGNATURE, pos)
            if idx == -1:
                break
            offsets.append(max(0, idx - 3))
            pos = idx + 8

    return offsets


def _parse_fve_block(data, offset):
    """
    Parse an FVE metadata block and extract VMK entries.

    FVE metadata block structure:
        0-7: signature
        8-11: size
        12-15: version
        ...

    Returns list of (salt, mac, encrypted_key) tuples for password-protected VMKs.
    """
    results = []

    if offset + 64 > len(data):
        return results

    # Validate signature
    block_sig = data[offset:offset + 8]
    if block_sig != b'-FVE-FS-':
        return results

    block_size = struct.unpack('<I', data[offset + 8:offset + 12])[0]
    if block_size == 0 or offset + block_size > len(data):
        return results

    # Parse entries within the block
    # Entries start after the header (48 bytes typical)
    entry_offset = offset + 48
    end_offset = offset + block_size

    while entry_offset + 8 < end_offset:
        entry_size = struct.unpack('<H', data[entry_offset:entry_offset + 2])[0]
        entry_type = struct.unpack('<H', data[entry_offset + 2:entry_offset + 4])[0]
        value_type = struct.unpack('<H', data[entry_offset + 4:entry_offset + 6])[0]

        if entry_size == 0:
            break

        if entry_type == FVE_ENTRY_TYPE_VMK:
            # VMK entry — check protection type
            if entry_offset + 28 <= end_offset:
                protection = struct.unpack('<H', data[entry_offset + 26:entry_offset + 28])[0]

                if protection == PROTECTION_PASSWORD:
                    # Password-protected VMK
                    vmk_data = data[entry_offset:entry_offset + entry_size]
                    result = _extract_password_vmk(vmk_data)
                    if result:
                        results.append(result)

        entry_offset += entry_size

    return results


def _extract_password_vmk(vmk_data):
    """
    Extract salt, nonce, MAC, and encrypted data from a password-protected VMK.

    The VMK entry contains nested sub-entries:
    1. Stretch Key entry (salt + iterations)
    2. AES-CCM encrypted VMK entry (nonce + MAC + data)
    """
    salt = None
    nonce = None
    mac = None
    enc_data = None

    offset = 36  # Skip VMK header
    while offset + 6 < len(vmk_data):
        sub_size = struct.unpack('<H', vmk_data[offset:offset + 2])[0]
        sub_type = struct.unpack('<H', vmk_data[offset + 2:offset + 4])[0]
        sub_value_type = struct.unpack('<H', vmk_data[offset + 4:offset + 6])[0]

        if sub_size == 0:
            break

        if sub_value_type == FVE_VALUE_TYPE_STRETCH:
            # Stretch key: salt (16 bytes) at offset 8
            if offset + 8 + 16 <= len(vmk_data):
                salt = vmk_data[offset + 8:offset + 8 + 16]

        elif sub_value_type == FVE_VALUE_TYPE_AES_CCM:
            # AES-CCM encrypted data
            # nonce (12 bytes) at offset 8, MAC (16 bytes), followed by encrypted data
            if offset + 8 + 12 <= len(vmk_data):
                nonce = vmk_data[offset + 8:offset + 8 + 12]
                mac_offset = offset + 20
                if mac_offset + 16 <= len(vmk_data):
                    mac = vmk_data[mac_offset:mac_offset + 16]
                    data_offset = mac_offset + 16
                    data_end = offset + sub_size
                    if data_end <= len(vmk_data):
                        enc_data = vmk_data[data_offset:data_end]

        offset += sub_size

    if salt and nonce and mac and enc_data:
        return (salt, nonce, mac, enc_data)
    return None


def process_bitlocker(filename):
    """
    Extract hashcat-compatible hash from a BitLocker volume.

    Reads the FVE metadata and extracts password-protected VMK entries.

    Args:
        filename: Path to BitLocker volume/partition image.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, 'rb') as f:
            data = f.read(4 * 1024 * 1024)  # Read first 4MB
    except IOError as e:
        error(str(e), filename)
        return

    fve_offsets = _find_fve_metadata(data)
    if not fve_offsets:
        error("No BitLocker FVE metadata found", filename)
        return

    found = False
    for fve_offset in fve_offsets:
        results = _parse_fve_block(data, fve_offset)
        for salt, nonce, mac, enc_data in results:
            # Hashcat format: $bitlocker$<version>*<iterations>*<salt>*<nonce>*<enc_data>
            # However, hashcat expects the raw data in a specific layout
            # For mode 22100, the format is the combined header data
            full_data = nonce + mac + enc_data
            hashline = "$bitlocker$1*16*%s*%d*%s*%d*%s" % (
                bytes_to_hex(salt),
                len(nonce), bytes_to_hex(nonce),
                len(mac) + len(enc_data),
                bytes_to_hex(full_data),
            )
            output_hash(hashline)
            found = True
        if found:
            break

    if not found:
        error("No password-protected VMK found in BitLocker volume", filename)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from BitLocker encrypted volumes.\n"
        "Reads FVE metadata and extracts password-protected VMK entries.",
        file_help="BitLocker volume/partition image file(s)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_bitlocker(f)


if __name__ == "__main__":
    main()
