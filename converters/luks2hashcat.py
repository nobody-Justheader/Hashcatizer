#!/usr/bin/env python3
"""
luks2hashcat.py — Extract hashcat-compatible data from LUKS encrypted volumes.

Based on luks2john.py from openwall/john.

Supported hashcat modes:
    14600 - LUKS

LUKS volumes contain a cleartext header with key slots that store
the encrypted master key. Hashcat processes the LUKS header directly.

The header contains: salt, iteration count, AF-split key material.
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
    14600: "LUKS",
}

LUKS_MAGIC = b'LUKS\xba\xbe'
LUKS_HEADER_SIZE = 592
LUKS_KEY_SLOT_SIZE = 48
LUKS_NUM_KEYS = 8

# Key slot states
KEY_SLOT_ACTIVE = 0x00AC71F3
KEY_SLOT_INACTIVE = 0x0000DEAD


def _parse_luks_header(data):
    """
    Parse LUKS v1 header structure.

    Returns dict with header fields or None on error.
    """
    if len(data) < LUKS_HEADER_SIZE:
        return None

    magic = data[0:6]
    if magic != LUKS_MAGIC:
        return None

    version = struct.unpack('>H', data[6:8])[0]
    cipher_name = data[8:40].rstrip(b'\x00').decode('ascii', errors='ignore')
    cipher_mode = data[40:72].rstrip(b'\x00').decode('ascii', errors='ignore')
    hash_spec = data[72:104].rstrip(b'\x00').decode('ascii', errors='ignore')
    payload_offset = struct.unpack('>I', data[104:108])[0]
    mk_digest_length = struct.unpack('>I', data[108:112])[0]
    master_key_salt = data[112:144]  # 32 bytes
    mk_digest_iterations = struct.unpack('>I', data[144:148])[0]
    uuid = data[148:188].rstrip(b'\x00').decode('ascii', errors='ignore')
    mk_digest = data[108:108 + 20]  # PBKDF2 digest (20 bytes for SHA1)

    # Actually, mk_digest is at offset 168
    mk_digest = data[168:168 + 20]  # Master key digest

    header = {
        'version': version,
        'cipher': cipher_name,
        'mode': cipher_mode,
        'hash': hash_spec,
        'payload_offset': payload_offset,
        'mk_salt': master_key_salt,
        'mk_iterations': mk_digest_iterations,
        'mk_digest': mk_digest,
        'uuid': uuid,
        'key_slots': [],
    }

    # Parse key slots (8 slots, each 48 bytes, starting at offset 208)
    slot_offset = 208
    for i in range(LUKS_NUM_KEYS):
        if slot_offset + LUKS_KEY_SLOT_SIZE > len(data):
            break

        state = struct.unpack('>I', data[slot_offset:slot_offset + 4])[0]
        iterations = struct.unpack('>I', data[slot_offset + 4:slot_offset + 8])[0]
        salt = data[slot_offset + 8:slot_offset + 40]  # 32 bytes
        key_material_offset = struct.unpack('>I', data[slot_offset + 40:slot_offset + 44])[0]
        stripes = struct.unpack('>I', data[slot_offset + 44:slot_offset + 48])[0]

        if state == KEY_SLOT_ACTIVE:
            header['key_slots'].append({
                'index': i,
                'iterations': iterations,
                'salt': salt,
                'key_offset': key_material_offset,
                'stripes': stripes,
            })

        slot_offset += LUKS_KEY_SLOT_SIZE

    return header


def process_luks(filename, output_file=None):
    """
    Extract hashcat-compatible data from a LUKS volume.

    Hashcat mode 14600 expects the raw LUKS header data.
    We extract the header and key material for the first active slot.

    Args:
        filename: Path to LUKS volume.
        output_file: Optional output filename for binary header.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, 'rb') as f:
            data = f.read(4 * 1024 * 1024)  # Read first 4MB to capture key material
    except IOError as e:
        error(str(e), filename)
        return

    header = _parse_luks_header(data)
    if header is None:
        error("Not a valid LUKS volume", filename)
        return

    if not header['key_slots']:
        error("No active key slots found", filename)
        return

    # For hashcat, we need to write the raw header + key material
    # Hashcat processes the LUKS file directly
    # We need at least the header + first key slot material

    first_slot = header['key_slots'][0]
    # Key material is at sector offset * 512
    km_start = first_slot['key_offset'] * 512
    # AF-split uses stripes * key_bytes
    # Typical: 4000 stripes * 32 bytes = 128000 bytes
    km_size = first_slot['stripes'] * 32  # Estimate, may need MK length

    needed = km_start + km_size
    if needed > len(data):
        # Re-read with sufficient data
        try:
            with open(filename, 'rb') as f:
                data = f.read(needed + 512)
        except IOError:
            pass

    if output_file:
        # Write sufficient data for hashcat
        with open(output_file, 'wb') as out:
            out.write(data[:needed])
        sys.stderr.write("Wrote LUKS header + key material to %s\n" % output_file)
        sys.stderr.write("Use: hashcat -m 14600 %s wordlist.txt\n" % output_file)
    else:
        # Print slot info for reference
        slot = first_slot
        sys.stderr.write("LUKS v%d: %s-%s, hash=%s\n" % (
            header['version'], header['cipher'], header['mode'], header['hash']
        ))
        sys.stderr.write("Key slot %d: %d iterations, %d stripes\n" % (
            slot['index'], slot['iterations'], slot['stripes']
        ))
        sys.stderr.write("Note: hashcat -m 14600 reads LUKS volumes directly.\n")
        sys.stderr.write("Use: hashcat -m 14600 %s wordlist.txt\n" % filename)
        # Still output a text representation
        output_hash("$luks$1*%d*%s*%d*%s*%s" % (
            slot['iterations'],
            bytes_to_hex(slot['salt']),
            first_slot['stripes'],
            bytes_to_hex(header['mk_digest']),
            bytes_to_hex(header['mk_salt']),
        ))


def main():
    parser = create_parser(
        "Extract LUKS volume info for hashcat.\n\n"
        "hashcat -m 14600 reads LUKS volumes directly.\n"
        "Use --output to extract header + key material for processing.",
        file_help="LUKS volume file(s)",
    )
    parser.add_argument('--output', '-o', help="Write binary header to file")
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_luks(f, args.output)


if __name__ == "__main__":
    main()
