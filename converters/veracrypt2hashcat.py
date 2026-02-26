#!/usr/bin/env python3
"""
veracrypt2hashcat.py — Extract VeraCrypt volume headers for hashcat.

Supported hashcat modes:
    13711-13713 - VeraCrypt RIPEMD160 + XTS
    13721-13723 - VeraCrypt SHA512 + XTS
    13731-13733 - VeraCrypt Whirlpool + XTS
    13751-13753 - VeraCrypt SHA256 + XTS
    13771-13773 - VeraCrypt Streebog-512 + XTS
    13781-13783 - VeraCrypt Streebog-512 + XTS (boot)

VeraCrypt uses the first 512 bytes of the volume as the header.
Hashcat reads this directly as a binary file.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file,
)

HASHCAT_MODES = {
    13711: "VeraCrypt RIPEMD160 + XTS 512 bit",
    13712: "VeraCrypt RIPEMD160 + XTS 1024 bit",
    13713: "VeraCrypt RIPEMD160 + XTS 1536 bit",
    13721: "VeraCrypt SHA512 + XTS 512 bit",
    13722: "VeraCrypt SHA512 + XTS 1024 bit",
    13723: "VeraCrypt SHA512 + XTS 1536 bit",
    13731: "VeraCrypt Whirlpool + XTS 512 bit",
    13732: "VeraCrypt Whirlpool + XTS 1024 bit",
    13733: "VeraCrypt Whirlpool + XTS 1536 bit",
    13751: "VeraCrypt SHA256 + XTS 512 bit",
    13752: "VeraCrypt SHA256 + XTS 1024 bit",
    13753: "VeraCrypt SHA256 + XTS 1536 bit",
    13771: "VeraCrypt Streebog-512 + XTS 512 bit",
    13772: "VeraCrypt Streebog-512 + XTS 1024 bit",
    13773: "VeraCrypt Streebog-512 + XTS 1536 bit",
}

VC_HEADER_SIZE = 512


def process_veracrypt(filename, output_file=None):
    """
    Extract VeraCrypt volume header for hashcat.

    VeraCrypt stores the volume header in the first 512 bytes.
    For hidden volumes, the header is at offset 65536 (64KB).

    Args:
        filename: Path to VeraCrypt volume.
        output_file: Optional output filename for binary header.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, 'rb') as f:
            header = f.read(VC_HEADER_SIZE)
    except IOError as e:
        error(str(e), filename)
        return

    if len(header) < VC_HEADER_SIZE:
        error("File too small for VeraCrypt volume", filename)
        return

    if output_file:
        with open(output_file, 'wb') as out:
            out.write(header)
        sys.stderr.write("Wrote VeraCrypt header to %s\n" % output_file)
        sys.stderr.write("Use: hashcat -m 13721 %s wordlist.txt\n" % output_file)
    else:
        output_hash(bytes_to_hex(header))

    # Also try hidden volume header
    try:
        with open(filename, 'rb') as f:
            f.seek(65536)
            hidden = f.read(VC_HEADER_SIZE)
            if len(hidden) == VC_HEADER_SIZE and output_file:
                with open(output_file + '.hidden', 'wb') as out:
                    out.write(hidden)
                sys.stderr.write("Wrote hidden volume header to %s.hidden\n" % output_file)
    except IOError:
        pass


def main():
    parser = create_parser(
        "Extract VeraCrypt volume headers for hashcat.\n\n"
        "VeraCrypt modes (13711-13773) expect binary header files.\n"
        "Use --output to write binary header, or pipe hex output.",
        file_help="VeraCrypt volume file(s)",
    )
    parser.add_argument('--output', '-o', help="Write binary header to file")
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_veracrypt(f, args.output)


if __name__ == "__main__":
    main()
