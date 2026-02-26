#!/usr/bin/env python3
"""
truecrypt2hashcat.py — Extract TrueCrypt volume headers for hashcat.

Based on truecrypt2john.py from openwall/john.

Supported hashcat modes:
    6211 - TrueCrypt RIPEMD160 + XTS 512 bit (AES)
    6212 - TrueCrypt RIPEMD160 + XTS 1024 bit (AES-Twofish)
    6213 - TrueCrypt RIPEMD160 + XTS 1536 bit (AES-Twofish-Serpent)
    6221 - TrueCrypt SHA512 + XTS 512 bit
    6222 - TrueCrypt SHA512 + XTS 1024 bit
    6223 - TrueCrypt SHA512 + XTS 1536 bit
    6231 - TrueCrypt Whirlpool + XTS 512 bit
    6232 - TrueCrypt Whirlpool + XTS 1024 bit
    6233 - TrueCrypt Whirlpool + XTS 1536 bit

TrueCrypt uses the first 512 bytes of the volume as the header.
Hashcat reads this directly as a binary file.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file, warn,
)

HASHCAT_MODES = {
    6211: "TrueCrypt RIPEMD160 + XTS 512 bit (AES)",
    6212: "TrueCrypt RIPEMD160 + XTS 1024 bit (AES-Twofish)",
    6213: "TrueCrypt RIPEMD160 + XTS 1536 bit (AES-Twofish-Serpent)",
    6221: "TrueCrypt SHA512 + XTS 512 bit",
    6222: "TrueCrypt SHA512 + XTS 1024 bit",
    6223: "TrueCrypt SHA512 + XTS 1536 bit",
    6231: "TrueCrypt Whirlpool + XTS 512 bit",
    6232: "TrueCrypt Whirlpool + XTS 1024 bit",
    6233: "TrueCrypt Whirlpool + XTS 1536 bit",
}

TC_HEADER_SIZE = 512


def process_truecrypt(filename, output_file=None):
    """
    Extract TrueCrypt volume header for hashcat.

    TrueCrypt stores the volume header in the first 512 bytes.
    For hidden volumes, the header is at offset 65536 (64KB).

    Hashcat reads TrueCrypt headers as binary files, so we extract
    the 512-byte header and write it out.

    Args:
        filename: Path to TrueCrypt volume.
        output_file: Optional output filename for binary header.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, 'rb') as f:
            header = f.read(TC_HEADER_SIZE)
    except IOError as e:
        error(str(e), filename)
        return

    if len(header) < TC_HEADER_SIZE:
        error("File too small for TrueCrypt volume", filename)
        return

    if output_file:
        # Write binary header to file (hashcat reads this directly)
        with open(output_file, 'wb') as out:
            out.write(header)
        sys.stderr.write("Wrote TrueCrypt header to %s\n" % output_file)
        sys.stderr.write("Use: hashcat -m 6211 %s wordlist.txt\n" % output_file)
    else:
        # Output as hex for text-based processing
        header_hex = bytes_to_hex(header)
        output_hash(header_hex)

    # Also try hidden volume header at offset 65536
    try:
        with open(filename, 'rb') as f:
            f.seek(65536)
            hidden_header = f.read(TC_HEADER_SIZE)
            if len(hidden_header) == TC_HEADER_SIZE:
                if output_file:
                    hidden_output = output_file + '.hidden'
                    with open(hidden_output, 'wb') as out:
                        out.write(hidden_header)
                    sys.stderr.write("Wrote hidden volume header to %s\n" % hidden_output)
    except IOError:
        pass


def main():
    parser = create_parser(
        "Extract TrueCrypt volume headers for hashcat.\n\n"
        "TrueCrypt modes (6211-6233) expect binary header files.\n"
        "Use --output to write binary header, or pipe hex output.",
        file_help="TrueCrypt volume file(s)",
    )
    parser.add_argument(
        '--output', '-o',
        help="Write binary header to file (for direct hashcat use)",
    )
    args = parser.parse_args()
    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return
    if not args.files:
        parser.error("No input files specified")
    for f in args.files:
        process_truecrypt(f, args.output)


if __name__ == "__main__":
    main()
