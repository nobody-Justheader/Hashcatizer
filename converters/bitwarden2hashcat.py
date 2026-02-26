#!/usr/bin/env python3
"""
bitwarden2hashcat.py — Extract hashcat-compatible hashes from Bitwarden local data.

Based on bitwarden2john.py from openwall/john (Dhiru Kholia <dhiru at openwall.com>).

Supported hashcat modes:
    31700 - Bitwarden

Output format:
    $bitwarden$0*<iterations>*<email>*<iv_hex>*<blob_hex>

Supports extraction from:
    - Firefox storage.js
    - Chrome/Edge LevelDB (requires plyvel)
    - Android preferences XML
    - Generic JSON data files
"""

import base64
import binascii
import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    create_parser, error, output_hash, print_mode_info, validate_file, warn,
)

HASHCAT_MODES = {
    31700: "Bitwarden",
}


def _process_xml_file(filename):
    """
    Parse Android Bitwarden preferences XML file.

    These are stored at:
    /data/data/com.x8bit.bitwarden/shared_prefs/com.x8bit.bitwarden_preferences.xml

    Returns:
        (email, enc_key) tuple or (None, None) on failure.
    """
    import xml.etree.ElementTree as ET

    try:
        tree = ET.parse(filename)
        root = tree.getroot()
    except ET.ParseError as e:
        error("XML parsing failed: %s" % str(e), filename)
        return None, None

    email = None
    enc_key = None

    for item in root:
        if item.tag == "string":
            name = item.attrib.get("name", "")
            if name == "encKey":
                enc_key = item.text
            elif name == "email":
                email = item.text

    return email, enc_key


def _process_leveldb(path):
    """
    Extract Bitwarden data from Chrome/Edge LevelDB storage.

    Requires the plyvel module for LevelDB access.

    Returns:
        (email, enc_key) tuple or (None, None) on failure.
    """
    try:
        import plyvel
    except ImportError:
        error("LevelDB support requires plyvel: pip install plyvel", path)
        return None, None

    try:
        db = plyvel.DB(path, create_if_missing=False)
        email = db.get(b"userEmail")
        if email:
            email = email.decode("utf-8").strip('"')
        enc_key = db.get(b"encKey")
        if enc_key:
            enc_key = enc_key.decode("ascii")
        db.close()
        return email, enc_key
    except Exception as e:
        error("LevelDB read failed: %s" % str(e), path)
        return None, None


def _process_json_file(filename, data):
    """
    Parse Bitwarden storage.js or generic JSON data file.

    Returns:
        (email, enc_key) tuple or (None, None) on failure.
    """
    try:
        parsed = json.loads(data)
        email = parsed.get("userEmail")
        enc_key = parsed.get("encKey")
        return email, enc_key
    except (json.JSONDecodeError, KeyError) as e:
        error("JSON parsing failed: %s" % str(e), filename)
        return None, None


def process_bitwarden(filename):
    """
    Extract hashcat-compatible hash from Bitwarden local data.

    Bitwarden stores the encrypted encryption key (encKey) protected by the
    master password. The encKey is formatted as "0.<base64_iv>|<base64_blob>".

    The hash for hashcat mode 31700 is:
        $bitwarden$0*<iterations>*<email>*<iv_hex>*<blob_hex>

    Default iterations: 5000 (fixed in older Bitwarden design).

    Args:
        filename: Path to Bitwarden data file or Chrome LevelDB directory.
    """
    if os.path.isdir(filename):
        email, enc_key = _process_leveldb(filename)
    elif not validate_file(filename):
        return
    else:
        try:
            with open(filename, "rb") as f:
                data = f.read()
        except IOError as e:
            error(str(e), filename)
            return

        if filename.endswith(".xml") or data.startswith(b"<?xml"):
            email, enc_key = _process_xml_file(filename)
        else:
            email, enc_key = _process_json_file(filename, data)

    if not email or not enc_key:
        error("Could not extract email and/or encKey", filename)
        return

    iterations = 5000  # Fixed in older Bitwarden design
    email = email.lower()

    try:
        # encKey format: "0.<base64_iv>|<base64_blob>"
        iv_mix, blob_b64 = enc_key.split("|")
        iv_b64 = iv_mix[2:]  # Skip "0."
        iv_hex = binascii.hexlify(base64.b64decode(iv_b64)).decode("ascii")
        blob_hex = binascii.hexlify(base64.b64decode(blob_b64)).decode("ascii")
    except (ValueError, binascii.Error) as e:
        error("Failed to parse encKey: %s" % str(e), filename)
        return

    hashline = "$bitwarden$0*%s*%s*%s*%s" % (iterations, email, iv_hex, blob_hex)
    output_hash(hashline)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Bitwarden local data.\n"
        "Supports Firefox storage.js, Chrome LevelDB, Android XML, and JSON formats.",
        file_help="Bitwarden data file(s) or LevelDB directory",
    )
    args = parser.parse_args()

    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return

    if not args.files:
        parser.error("No input files specified")

    for f in args.files:
        process_bitwarden(f)


if __name__ == "__main__":
    main()
