#!/usr/bin/env python3
"""
encfs2hashcat.py — Extract hashcat-compatible hashes from EncFS volumes.

Based on encfs2john.py from openwall/john (Dhiru Kholia).

Supported hashcat modes:
    26401 - EncFS

Output format:
    $encfs$<key_size>*<iterations>*<iv_len>*<salt_hex>*<data_len>*<data_hex>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file,
)

HASHCAT_MODES = {
    26401: "EncFS",
}


def _parse_encfs_xml(content):
    """
    Parse .encfs6.xml configuration file.

    Returns dict with: keySize, kdfIterations, salt (base64), encodedKeyData (base64)
    """
    import base64
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        return None

    result = {}

    # Find elements — EncFS config can have different structures
    for elem in root.iter():
        tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
        if tag == 'keySize':
            result['keySize'] = int(elem.text)
        elif tag == 'kdfIterations':
            result['kdfIterations'] = int(elem.text)
        elif tag == 'saltLen':
            result['saltLen'] = int(elem.text)
        elif tag == 'saltData':
            result['salt'] = base64.b64decode(elem.text)
        elif tag == 'encodedKeySize':
            result['encodedKeySize'] = int(elem.text)
        elif tag == 'encodedKeyData':
            result['encodedKeyData'] = base64.b64decode(elem.text)
        elif tag == 'uniqueIV':
            result['uniqueIV'] = int(elem.text) if elem.text else 0
        elif tag == 'chainedNameIV':
            result['chainedNameIV'] = int(elem.text) if elem.text else 0

    return result if 'keySize' in result else None


def process_encfs(filename):
    """
    Extract hashcat-compatible hash from an EncFS configuration file.

    The .encfs6.xml file contains all the encryption parameters needed
    to construct the hashcat hash.

    Args:
        filename: Path to .encfs6.xml file or directory containing it.
    """
    # If directory, look for .encfs6.xml inside
    if os.path.isdir(filename):
        xml_path = os.path.join(filename, '.encfs6.xml')
        if not os.path.isfile(xml_path):
            error("No .encfs6.xml found in directory", filename)
            return
        filename = xml_path

    if not validate_file(filename):
        return

    try:
        content = open(filename, 'r', encoding='utf-8').read()
    except (IOError, UnicodeDecodeError) as e:
        error(str(e), filename)
        return

    config = _parse_encfs_xml(content)
    if config is None:
        error("Failed to parse EncFS config", filename)
        return

    key_size = config.get('keySize', 256)
    iterations = config.get('kdfIterations', 0)
    salt = config.get('salt', b'')
    encoded_key = config.get('encodedKeyData', b'')

    if not salt or not encoded_key:
        error("Missing salt or encoded key data", filename)
        return

    salt_hex = bytes_to_hex(salt)
    data_hex = bytes_to_hex(encoded_key)

    hashline = "$encfs$%d*%d*%d*%s*%d*%s" % (
        key_size, iterations, len(salt),
        salt_hex, len(encoded_key), data_hex
    )
    output_hash(hashline)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from EncFS volumes.\n"
        "Reads the .encfs6.xml configuration file.",
        file_help="EncFS .encfs6.xml file(s) or encfs directory",
    )
    args = parser.parse_args()

    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return

    if not args.files:
        parser.error("No input files specified")

    for f in args.files:
        process_encfs(f)


if __name__ == "__main__":
    main()
