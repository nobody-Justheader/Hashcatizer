#!/usr/bin/env python3
"""
zed2hashcat.py — ZED/AxCrypt container hash extractor.

Decrypts ZED control file global properties with a static AES key,
then extracts per-user PBA salt, iterations, hash function, and check data.

Inspired by: zed2john.py (openwall/john)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file

CTLFILE_DELIMITER = b'\x07\x65\x92\x1A\x2A\x07\x74\x53\x47\x52\x07\x33\x61\x71\x93\x00'
STATIC_KEY = b'\x37\xF1\x3C\xF8\x1C\x78\x0A\xF2\x6B\x6A\x52\x65\x4F\x79\x4A\xEF'
PBA_SALT = b'\x80\x7a\x05\x00'
PBA_ITER = b'\x80\x7b\x02\x00'
HASH_FUNC = b'\x80\x78\x02\x00'
PBA_CHK = b'\x80\x79\x05\x00'
USERNAME_TAG = b'\x80\x71\x04\x00'


def _parse_tlv(data, tag, start):
    """Find tag in data and return its value."""
    i = start
    while i < len(data) - len(tag) - 4:
        if data[i:i + len(tag)] == tag:
            vlen = int.from_bytes(data[i + len(tag):i + len(tag) + 4], byteorder='big')
            vstart = i + len(tag) + 4
            if vstart + vlen <= len(data):
                return data[vstart:vstart + vlen]
            return b''
        i += 1
    return b''


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    # Find control file delimiter
    delim_pos = data.find(CTLFILE_DELIMITER)
    if delim_pos == -1:
        error("No ZED control data found", filename)
        return

    offset = delim_pos + len(CTLFILE_DELIMITER)
    if offset + 18 > len(data):
        error("ZED data truncated", filename)
        return

    ver = '1' if data[offset:offset + 2] == b'\x01\x00' else \
          '2' if data[offset:offset + 2] == b'\x02\x00' else '0'
    global_iv = data[offset + 2:offset + 18]

    # Find next delimiter for ciphertext boundary
    next_delim = data.find(CTLFILE_DELIMITER, offset + 18)
    ct_end = next_delim - 4 if next_delim > offset + 22 else min(offset + 4096, len(data))
    ciphertext = bytearray(data[offset + 18:ct_end])

    # Pad to AES block size
    pad_needed = 16 - (len(ciphertext) % 16)
    if pad_needed < 16:
        ciphertext.extend(bytes([pad_needed]) * pad_needed)

    try:
        from Crypto.Cipher import AES
        cipher = AES.new(STATIC_KEY, AES.MODE_CBC, global_iv)
        plaintext = cipher.decrypt(bytes(ciphertext))
    except ImportError:
        # Fallback without PyCryptodome
        output_hash("$zed$%s$raw$%s$%s" % (
            ver, bytes_to_hex(global_iv), bytes_to_hex(bytes(ciphertext[:256]))))
        return

    # Parse user records from decrypted data
    users = []
    names = []
    idx = 0
    while idx < len(plaintext) - len(USERNAME_TAG) - 4:
        if plaintext[idx:idx + len(USERNAME_TAG)] == USERNAME_TAG:
            vlen = int.from_bytes(plaintext[idx + len(USERNAME_TAG):idx + len(USERNAME_TAG) + 4], byteorder='big')
            vstart = idx + len(USERNAME_TAG) + 4
            if vstart + vlen <= len(plaintext):
                try:
                    name = plaintext[vstart:vstart + vlen].decode('utf-16', errors='ignore')
                except Exception:
                    name = "user"
                names.append(name)
                users.append(idx)
            idx = vstart + vlen
        else:
            idx += 1

    for ui, user_off in enumerate(users):
        pba_chk = bytes_to_hex(_parse_tlv(plaintext, PBA_CHK, user_off))
        hash_func = bytes_to_hex(_parse_tlv(plaintext, HASH_FUNC, user_off))
        pba_iter = bytes_to_hex(_parse_tlv(plaintext, PBA_ITER, user_off))
        pba_salt = bytes_to_hex(_parse_tlv(plaintext, PBA_SALT, user_off))
        if pba_chk and pba_salt:
            hf = int(hash_func, 16) if hash_func else 0
            pi = int(pba_iter, 16) if pba_iter else 0
            uname = names[ui] if ui < len(names) else "user"
            output_hash("%s:$zed$%s$%d$%d$%s$%s:::%s" % (
                uname, ver, hf, pi, pba_salt, pba_chk, os.path.basename(filename)))


def main():
    parser = create_parser("ZED/AxCrypt container hash extractor", {})
    args = parser.parse_args()
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
