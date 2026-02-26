#!/usr/bin/env python3
"""
vdi2hashcat.py — VirtualBox VDI encrypted disk image hash extractor.

Parses VDI file headers for encryption metadata including PBKDF2-SHA256
parameters used in VirtualBox disk encryption.

Inspired by: vdi2john.pl (openwall/john)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file

# VDI uses AES-XTS with PBKDF2 key derivation
HASHCAT_MODES = {
    27000: "VirtualBox (PBKDF2-HMAC-SHA256 + AES-XTS)",
}

VDI_SIGNATURE = b'\x7f\x10\xda\xbe'
VDI_MARKER = b'<<< '


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(8192)
    except IOError as e:
        error(str(e), filename)
        return

    if len(data) < 512:
        error("File too small for VDI", filename)
        return

    # Detect VDI header
    has_text_header = data[:4] == VDI_MARKER
    sig_pos = data.find(VDI_SIGNATURE)
    if sig_pos == -1 and not has_text_header:
        error("Not a valid VDI file", filename)
        return

    # VDI pre-header: 64-byte text + 4-byte signature + version(4) + header_size(4)
    # Encryption data stored in the VDCRYPTO extension area
    crypto_marker = b'CRYPT'
    crypto_pos = data.find(crypto_marker)

    if crypto_pos != -1 and crypto_pos + 80 <= len(data):
        offset = crypto_pos + len(crypto_marker)
        # Typical layout: cipher(4) + keylen(4) + iterations(4) + salt(32) + enc_verification(32)
        if offset + 72 <= len(data):
            cipher_id = struct.unpack('<I', data[offset:offset + 4])[0]
            key_len = struct.unpack('<I', data[offset + 4:offset + 8])[0]
            iterations = struct.unpack('<I', data[offset + 8:offset + 12])[0]
            salt = data[offset + 12:offset + 44]
            enc_data = data[offset + 44:offset + 76]
            output_hash("$vbox$%d$%d$%d$%s$%s" % (
                cipher_id, key_len, iterations,
                bytes_to_hex(salt), bytes_to_hex(enc_data)))
            return

    # Alternative: scan for PBKDF2 parameters in raw header area
    # VirtualBox stores DEK info in specific header offsets
    if sig_pos >= 0 and sig_pos + 4 <= len(data):
        ver_major = struct.unpack('<H', data[sig_pos + 4:sig_pos + 6])[0] if sig_pos + 6 <= len(data) else 0
        ver_minor = struct.unpack('<H', data[sig_pos + 6:sig_pos + 8])[0] if sig_pos + 8 <= len(data) else 0
        header_size = struct.unpack('<I', data[sig_pos + 8:sig_pos + 12])[0] if sig_pos + 12 <= len(data) else 0

        if header_size > 0:
            header_end = sig_pos + 12 + header_size
            if header_end + 128 <= len(data):
                # Look for DEK (Disk Encryption Key) info after main header
                dek_region = data[header_end:header_end + 256]
                if dek_region != b'\x00' * len(dek_region):
                    output_hash("$vbox$0$0$0$%s$%s" % (
                        bytes_to_hex(dek_region[:32]),
                        bytes_to_hex(dek_region[32:64])))
                    return

    error("VDI file does not appear to be encrypted (no crypto metadata found)", filename)


def main():
    parser = create_parser("VirtualBox VDI encrypted disk hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
