#!/usr/bin/env python3
"""
pcap2hashcat.py — PCAP/PCAPNG network capture hash extractor.

Extracts authentication hashes from packet captures:
- NTLMSSP Type 3 messages (NTLMv1/v2)
- WPA/WPA2 EAPOL handshakes (directs to hcxpcapngtool)

Inspired by: pcap2john.py (openwall/john)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import bytes_to_hex, create_parser, error, output_hash, validate_file, warn

HASHCAT_MODES = {
    5500: "NetNTLMv1 / NetNTLMv1+ESS",
    5600: "NetNTLMv2",
    22000: "WPA-PBKDF2-PMKID+EAPOL",
}

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAPNG_MAGIC = b'\x0A\x0D\x0D\x0A'
NTLMSSP_MAGIC = b'NTLMSSP\x00'
EAPOL_ETYPE = b'\x88\x8e'


def process_file(filename):
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return

    if len(data) < 24:
        error("File too small for PCAP", filename)
        return

    magic = struct.unpack('<I', data[0:4])[0]
    is_pcap = magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE)
    is_pcapng = data[0:4] == PCAPNG_MAGIC
    if not is_pcap and not is_pcapng:
        error("Not a valid PCAP/PCAPNG file", filename)
        return

    found_any = False

    # Scan for EAPOL (WPA handshake)
    if data.find(EAPOL_ETYPE) != -1:
        sys.stderr.write("[*] WPA handshake data detected in %s\n" % filename)
        sys.stderr.write("    Use hcxpcapngtool: hcxpcapngtool -o hash.22000 %s\n" % filename)
        sys.stderr.write("    Then: hashcat -m 22000 hash.22000 wordlist.txt\n")
        found_any = True

    # Scan for NTLMSSP Type 3 (Authentication) messages
    pos = 0
    while pos < len(data) - 88:
        idx = data.find(NTLMSSP_MAGIC, pos)
        if idx == -1:
            break
        if idx + 88 > len(data):
            break

        msg_type = struct.unpack('<I', data[idx + 8:idx + 12])[0]
        if msg_type != 3:  # Only Type 3 (AUTH)
            pos = idx + 1
            continue

        # Parse NTLMSSP Type 3 fields
        lm_len = struct.unpack('<H', data[idx + 12:idx + 14])[0]
        lm_off = struct.unpack('<I', data[idx + 16:idx + 20])[0]
        nt_len = struct.unpack('<H', data[idx + 20:idx + 22])[0]
        nt_off = struct.unpack('<I', data[idx + 24:idx + 28])[0]
        dom_len = struct.unpack('<H', data[idx + 28:idx + 30])[0]
        dom_off = struct.unpack('<I', data[idx + 32:idx + 36])[0]
        usr_len = struct.unpack('<H', data[idx + 36:idx + 38])[0]
        usr_off = struct.unpack('<I', data[idx + 40:idx + 44])[0]

        if idx + nt_off + nt_len > len(data) or nt_len == 0:
            pos = idx + 1
            continue

        nt_resp = data[idx + nt_off:idx + nt_off + nt_len]
        domain = data[idx + dom_off:idx + dom_off + dom_len].decode('utf-16-le', errors='ignore') \
            if idx + dom_off + dom_len <= len(data) else ""
        user = data[idx + usr_off:idx + usr_off + usr_len].decode('utf-16-le', errors='ignore') \
            if idx + usr_off + usr_len <= len(data) else ""

        if nt_len > 24:
            # NTLMv2 (mode 5600)
            nt_hash = bytes_to_hex(nt_resp[:16])
            nt_blob = bytes_to_hex(nt_resp[16:])
            output_hash("%s::%s:challenge:%s:%s" % (user, domain, nt_hash, nt_blob))
        else:
            # NTLMv1 (mode 5500)
            lm_resp = data[idx + lm_off:idx + lm_off + lm_len] if idx + lm_off + lm_len <= len(data) else b''
            output_hash("%s::%s:%s:%s:challenge" % (
                user, domain, bytes_to_hex(lm_resp), bytes_to_hex(nt_resp)))

        found_any = True
        pos = idx + 1

    if not found_any:
        warn("No extractable hashes found. For WPA, use hcxpcapngtool.", filename)


def main():
    parser = create_parser("PCAP/PCAPNG network capture hash extractor", HASHCAT_MODES)
    args = parser.parse_args()
    if hasattr(args, 'mode_info') and args.mode_info:
        from lib.common import print_mode_info
        print_mode_info(HASHCAT_MODES)
        return
    for f in args.files:
        process_file(f)


if __name__ == "__main__":
    main()
