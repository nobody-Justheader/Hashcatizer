"""
Hashcatizer Common Library
==========================

Shared utilities for all converter scripts. Provides:
- File I/O helpers
- Hex encoding/decoding
- Argument parsing
- Output formatting
"""

import argparse
import binascii
import os
import struct
import sys


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to lowercase hex string."""
    return binascii.hexlify(data).decode("ascii")


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes."""
    return binascii.unhexlify(hex_string)


def read_file_bytes(path: str, offset: int = 0, length: int = None) -> bytes:
    """
    Read binary data from a file.

    Args:
        path: File path to read.
        offset: Starting byte offset.
        length: Number of bytes to read (None = read to end).

    Returns:
        Bytes read from the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If the file cannot be read.
    """
    with open(path, "rb") as f:
        if offset:
            f.seek(offset)
        if length is not None:
            return f.read(length)
        return f.read()


def read_file_text(path: str, encoding: str = "utf-8") -> str:
    """
    Read text from a file.

    Args:
        path: File path to read.
        encoding: Text encoding (default: utf-8).

    Returns:
        File contents as string.
    """
    with open(path, "r", encoding=encoding) as f:
        return f.read()


def unpack_uint32_be(data: bytes, offset: int = 0) -> int:
    """Unpack a big-endian uint32 from data at given offset."""
    return struct.unpack(">I", data[offset:offset + 4])[0]


def unpack_uint32_le(data: bytes, offset: int = 0) -> int:
    """Unpack a little-endian uint32 from data at given offset."""
    return struct.unpack("<I", data[offset:offset + 4])[0]


def unpack_uint16_le(data: bytes, offset: int = 0) -> int:
    """Unpack a little-endian uint16 from data at given offset."""
    return struct.unpack("<H", data[offset:offset + 2])[0]


def unpack_uint64_le(data: bytes, offset: int = 0) -> int:
    """Unpack a little-endian uint64 from data at given offset."""
    return struct.unpack("<Q", data[offset:offset + 8])[0]


def output_hash(hash_string: str, filename: str = None, file=None):
    """
    Output a hash line to stdout (or specified file object).

    Hashcat format: just the hash string (no filename prefix).

    Args:
        hash_string: The hashcat-compatible hash string.
        filename: Optional, not included in output (for logging only).
        file: Output file object (default: sys.stdout).
    """
    out = file or sys.stdout
    out.write("%s\n" % hash_string)
    out.flush()


def error(message: str, filename: str = None):
    """Write an error message to stderr."""
    if filename:
        sys.stderr.write("[%s] %s\n" % (os.path.basename(filename), message))
    else:
        sys.stderr.write("ERROR: %s\n" % message)


def warn(message: str, filename: str = None):
    """Write a warning message to stderr."""
    if filename:
        sys.stderr.write("[WARNING] [%s] %s\n" % (os.path.basename(filename), message))
    else:
        sys.stderr.write("[WARNING] %s\n" % message)


def create_parser(description: str, file_help: str = "Input file(s)") -> argparse.ArgumentParser:
    """
    Create a common argument parser for converter scripts.

    Args:
        description: Script description for --help.
        file_help: Help text for the positional file argument.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files",
        nargs="*",
        help=file_help,
    )
    parser.add_argument(
        "--mode-info",
        action="store_true",
        help="Print supported hashcat mode numbers and exit",
    )
    return parser


def validate_file(path: str) -> bool:
    """
    Validate that a file exists and is readable.

    Args:
        path: File path to validate.

    Returns:
        True if the file exists and is readable, False otherwise.
    """
    if not os.path.isfile(path):
        error("File not found: %s" % path)
        return False
    if not os.access(path, os.R_OK):
        error("File not readable: %s" % path)
        return False
    return True


def print_mode_info(modes: dict):
    """
    Print hashcat mode information.

    Args:
        modes: Dictionary mapping mode number to description.
              e.g. {22931: "SSH Private Key (OpenSSH, bcrypt)"}
    """
    print("Supported hashcat modes:")
    for mode_id, desc in sorted(modes.items()):
        print("  -m %d  %s" % (mode_id, desc))
