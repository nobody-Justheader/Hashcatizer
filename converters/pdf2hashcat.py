#!/usr/bin/env python3
"""
pdf2hashcat.py — Extract hashcat-compatible hashes from encrypted PDF files.

Based on pdf2john.py from openwall/john.

Supported hashcat modes:
    10400 - PDF 1.1-1.3 (Acrobat 2-4), 40-bit RC4
    10500 - PDF 1.4-1.6 (Acrobat 5-8), 128-bit RC4
    10600 - PDF 1.7 Level 3 (Acrobat 9), 128-bit AES
    10700 - PDF 1.7 Level 8 (Acrobat X+), 256-bit AES

Output format:
    $pdf$<V>*<R>*<key_length>*<P>*<encrypt_meta>*<id_len>*<id_hex>*[password fields]
"""

import os
import re
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file, warn,
)

HASHCAT_MODES = {
    10400: "PDF 1.1-1.3 (Acrobat 2-4), 40-bit RC4",
    10500: "PDF 1.4-1.6 (Acrobat 5-8), 128-bit RC4",
    10600: "PDF 1.7 Level 3 (Acrobat 9), 128-bit AES",
    10700: "PDF 1.7 Level 8 (Acrobat X+), 256-bit AES",
}

# Standard Security Handler revisions and expected /O, /U lengths
REVISION_KEY_LENGTHS = {
    2: 32,   # RC4 Basic
    3: 32,   # RC4 Extended
    4: 32,   # RC4 or AES-128
    5: 48,   # AES R5 256
    6: 48,   # AES 256
}


def _find_object(data, name, default=None):
    """
    Extract a PDF dictionary value by key name.
    Handles integer, hex string, and boolean values.
    """
    # Try integer
    m = re.search(rb'/' + name.encode() + rb'\s+(-?\d+)', data)
    if m:
        return int(m.group(1))
    # Try hex string <...>
    m = re.search(rb'/' + name.encode() + rb'\s*<([0-9a-fA-F]+)>', data)
    if m:
        return m.group(1).decode('ascii').lower()
    # Try boolean
    m = re.search(rb'/' + name.encode() + rb'\s+(true|false)', data, re.IGNORECASE)
    if m:
        return m.group(1).decode('ascii').lower() == 'true'
    return default


def _find_string_object(data, name):
    """Extract a PDF string value in (...) or <...> format."""
    # Hex string
    m = re.search(rb'/' + name.encode() + rb'\s*<([0-9a-fA-F]*)>', data)
    if m:
        return bytes.fromhex(m.group(1).decode('ascii'))
    # Literal string — simplified parser
    m = re.search(rb'/' + name.encode() + rb'\s*\(', data)
    if m:
        start = m.end()
        depth = 1
        i = start
        while i < len(data) and depth > 0:
            if data[i:i+1] == b'(' and data[i-1:i] != b'\\':
                depth += 1
            elif data[i:i+1] == b')' and data[i-1:i] != b'\\':
                depth -= 1
            i += 1
        return data[start:i-1]
    return None


def _extract_encrypt_dict(raw_data):
    """
    Find and extract the Encrypt dictionary from a PDF file.

    This is a simplified parser that handles the common cases.
    For complex PDFs, the pyhanko library would be more robust.
    """
    # Find /Encrypt reference in trailer or cross-ref
    encrypt_ref = re.search(rb'/Encrypt\s+(\d+)\s+(\d+)\s+R', raw_data)
    if not encrypt_ref:
        return None

    obj_num = int(encrypt_ref.group(1))

    # Find the object definition
    obj_pattern = re.compile(
        rb'%d\s+\d+\s+obj\s*(.*?)\s*endobj' % obj_num,
        re.DOTALL
    )
    obj_match = obj_pattern.search(raw_data)
    if obj_match:
        return obj_match.group(1)

    return None


def _extract_document_id(raw_data):
    """Extract the document ID from the PDF trailer."""
    # /ID [<hex1><hex2>]
    m = re.search(rb'/ID\s*\[\s*<([0-9a-fA-F]+)>', raw_data)
    if m:
        return bytes.fromhex(m.group(1).decode('ascii'))
    # /ID [(...)(...)
    m = re.search(rb'/ID\s*\[\s*\((.+?)\)', raw_data, re.DOTALL)
    if m:
        return m.group(1)
    return None


def process_pdf(filename):
    """
    Extract hashcat-compatible hash from an encrypted PDF file.

    Args:
        filename: Path to the PDF file.
    """
    if not validate_file(filename):
        return

    try:
        raw_data = open(filename, 'rb').read()
    except IOError as e:
        error(str(e), filename)
        return

    if not raw_data.startswith(b'%PDF'):
        error("Not a PDF file", filename)
        return

    # Try using pyhanko first (more robust)
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.pdf_utils.misc import PdfReadError

        with open(filename, 'rb') as f:
            pdf = PdfFileReader(f, strict=False)
            encrypt_dict = pdf.encrypt_dict

            if not encrypt_dict:
                error("File is not encrypted", filename)
                return

            V = encrypt_dict.get('/V', 0)
            R = encrypt_dict.get('/R', 0)
            key_length = encrypt_dict.get('/Length', 40)
            P = encrypt_dict['/P']
            encrypt_metadata = "1"
            try:
                encrypt_metadata = str(int(pdf.security_handler.encrypt_metadata))
            except Exception:
                pass

            doc_id = pdf.document_id[0]
            doc_id_hex = doc_id.hex()

            # Build password fields
            passwords = []
            max_key_len = REVISION_KEY_LENGTHS.get(R, 48)
            for attr_name in ('udata', 'odata', 'oeseed', 'ueseed'):
                data = getattr(pdf.security_handler, attr_name, None)
                if data:
                    data = data[:max_key_len]
                    passwords.append(str(len(data)))
                    passwords.append(data.hex())

            pw_str = '*'.join(passwords)
            hashline = "$pdf$%s*%s*%s*%s*%s*%s*%s*%s" % (
                V, R, key_length, P, encrypt_metadata,
                len(doc_id), doc_id_hex, pw_str
            )
            output_hash(hashline)
            return

    except ImportError:
        pass  # Fall through to manual parser
    except Exception as e:
        warn("pyhanko failed (%s), trying manual parser" % str(e), filename)

    # Manual parser fallback
    encrypt_dict = _extract_encrypt_dict(raw_data)
    if encrypt_dict is None:
        error("Could not find /Encrypt dictionary (not encrypted?)", filename)
        return

    V = _find_object(encrypt_dict, 'V', 0)
    R = _find_object(encrypt_dict, 'R', 0)
    key_length = _find_object(encrypt_dict, 'Length', 40)
    P = _find_object(encrypt_dict, 'P', 0)
    encrypt_metadata_val = _find_object(encrypt_dict, 'EncryptMetadata', True)
    encrypt_metadata = "1" if encrypt_metadata_val else "0"

    doc_id = _extract_document_id(raw_data)
    if doc_id is None:
        error("Could not find document ID", filename)
        return

    doc_id_hex = bytes_to_hex(doc_id) if isinstance(doc_id, bytes) else doc_id

    # Get /U and /O values
    u_hex = _find_object(encrypt_dict, 'U')
    o_hex = _find_object(encrypt_dict, 'O')
    ue_hex = _find_object(encrypt_dict, 'UE')
    oe_hex = _find_object(encrypt_dict, 'OE')

    if u_hex is None:
        u_data = _find_string_object(encrypt_dict, 'U')
        if u_data:
            u_hex = bytes_to_hex(u_data)
    if o_hex is None:
        o_data = _find_string_object(encrypt_dict, 'O')
        if o_data:
            o_hex = bytes_to_hex(o_data)
    if ue_hex is None:
        ue_data = _find_string_object(encrypt_dict, 'UE')
        if ue_data:
            ue_hex = bytes_to_hex(ue_data)
    if oe_hex is None:
        oe_data = _find_string_object(encrypt_dict, 'OE')
        if oe_data:
            oe_hex = bytes_to_hex(oe_data)

    if u_hex is None or o_hex is None:
        error("Could not extract /U and /O values", filename)
        return

    max_key_len = REVISION_KEY_LENGTHS.get(R, 48)

    # Truncate to expected length
    u_bytes_len = min(len(u_hex) // 2, max_key_len)
    o_bytes_len = min(len(o_hex) // 2, max_key_len)
    u_hex = u_hex[:u_bytes_len * 2]
    o_hex = o_hex[:o_bytes_len * 2]

    passwords = [str(u_bytes_len), u_hex, str(o_bytes_len), o_hex]

    if oe_hex:
        oe_bytes_len = min(len(oe_hex) // 2, 32)
        passwords.extend([str(oe_bytes_len), oe_hex[:oe_bytes_len * 2]])
    if ue_hex:
        ue_bytes_len = min(len(ue_hex) // 2, 32)
        passwords.extend([str(ue_bytes_len), ue_hex[:ue_bytes_len * 2]])

    pw_str = '*'.join(passwords)
    hashline = "$pdf$%s*%s*%s*%s*%s*%s*%s*%s" % (
        V, R, key_length, P, encrypt_metadata,
        len(doc_id) if isinstance(doc_id, bytes) else len(doc_id) // 2,
        doc_id_hex, pw_str
    )
    output_hash(hashline)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from encrypted PDF files.\n"
        "Supports PDF 1.1 through 2.0 (Acrobat 2 through X+).",
        file_help="Encrypted PDF file(s)",
    )
    args = parser.parse_args()

    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return

    if not args.files:
        parser.error("No input files specified")

    for f in args.files:
        process_pdf(f)


if __name__ == "__main__":
    main()
