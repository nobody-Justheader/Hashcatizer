#!/usr/bin/env python3
"""
ethereum2hashcat.py — Extract hashcat-compatible hashes from Ethereum wallet files.

Based on ethereum2john.py from openwall/john (Dhiru Kholia <dhiru.kholia at gmail.com>).
Special thanks to @Chick3nman for the output hash format.

Supported hashcat modes:
    15600 - Ethereum Wallet, PBKDF2-HMAC-SHA256
    15700 - Ethereum Wallet, SCRYPT

Output format (scrypt):
    $ethereum$s*<n>*<r>*<p>*<salt>*<ciphertext>*<mac>

Output format (pbkdf2):
    $ethereum$p*<iterations>*<salt>*<ciphertext>*<mac>

Supports:
    - Geth/Mist JSON keystore files (V3)
    - MyEtherWallet JSON keystore files
    - Presale wallets (V1)

References:
    - https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
"""

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    create_parser, error, output_hash, print_mode_info, validate_file, warn,
)

HASHCAT_MODES = {
    15600: "Ethereum Wallet, PBKDF2-HMAC-SHA256",
    15700: "Ethereum Wallet, SCRYPT",
}


def _process_presale_wallet(filename, data):
    """
    Handle Ethereum presale wallet format (V1).

    Presale wallets contain:
        - encseed: encrypted seed
        - ethaddr: ethereum address
        - bkp: backup key
    """
    try:
        bkp = data["bkp"]
    except KeyError:
        error("Presale wallet missing 'bkp' field", filename)
        return

    try:
        encseed = data["encseed"]
        ethaddr = data["ethaddr"]
    except KeyError:
        error("Presale wallet missing required fields", filename)
        return

    # Use first 16 bytes (32 hex chars) of bkp
    hashline = "$ethereum$w*%s*%s*%s" % (encseed, ethaddr, bkp[:32])
    output_hash(hashline)


def process_ethereum_wallet(filename):
    """
    Parse an Ethereum wallet JSON keystore file and extract the hash for hashcat.

    The keystore format (V3) contains:
        - crypto.cipher: encryption algorithm (aes-128-ctr)
        - crypto.kdf: key derivation function (scrypt or pbkdf2)
        - crypto.kdfparams: KDF parameters (n, r, p, salt for scrypt; c, salt for pbkdf2)
        - crypto.ciphertext: encrypted private key
        - crypto.mac: message authentication code

    Args:
        filename: Path to Ethereum wallet JSON file.
    """
    if not validate_file(filename):
        return

    try:
        with open(filename, "rb") as f:
            data = f.read().decode("utf-8")
    except (IOError, UnicodeDecodeError) as e:
        error(str(e), filename)
        return

    warn(
        "Upon successful recovery, this format may expose your PRIVATE KEY. "
        "Do not share extracted hashes with untrusted parties!",
        filename,
    )

    try:
        data = json.loads(data)

        # V3 format: "crypto" or "Crypto" key
        crypto = None
        try:
            crypto = data["crypto"]
        except KeyError:
            try:
                crypto = data["Crypto"]
            except KeyError:
                # Might be a presale wallet (V1)
                _process_presale_wallet(filename, data)
                return

        cipher = crypto["cipher"]
        if cipher != "aes-128-ctr":
            error("Unexpected cipher '%s' (expected aes-128-ctr)" % cipher, filename)
            return

        kdf = crypto["kdf"]
        ciphertext = crypto["ciphertext"]
        mac = crypto["mac"]

        if kdf == "scrypt":
            kdfparams = crypto["kdfparams"]
            n = kdfparams["n"]
            r = kdfparams["r"]
            p = kdfparams["p"]
            salt = kdfparams["salt"]
            hashline = "$ethereum$s*%s*%s*%s*%s*%s*%s" % (n, r, p, salt, ciphertext, mac)
            output_hash(hashline)

        elif kdf == "pbkdf2":
            kdfparams = crypto["kdfparams"]
            iterations = kdfparams["c"]
            prf = kdfparams.get("prf", "hmac-sha256")
            if prf != "hmac-sha256":
                error("Unexpected PRF '%s' (expected hmac-sha256)" % prf, filename)
                return
            salt = kdfparams["salt"]
            hashline = "$ethereum$p*%s*%s*%s*%s" % (iterations, salt, ciphertext, mac)
            output_hash(hashline)

        else:
            error("Unsupported KDF '%s' (expected scrypt or pbkdf2)" % kdf, filename)

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        error("Failed to parse JSON keystore: %s" % str(e), filename)
        traceback.print_exc(file=sys.stderr)


def main():
    parser = create_parser(
        "Extract hashcat-compatible hashes from Ethereum wallet files.\n"
        "Supports Geth/Mist/MyEtherWallet JSON keystores and presale wallets.",
        file_help="Ethereum wallet JSON file(s)",
    )
    args = parser.parse_args()

    if args.mode_info:
        print_mode_info(HASHCAT_MODES)
        return

    if not args.files:
        parser.error("No input files specified")

    for f in args.files:
        process_ethereum_wallet(f)


if __name__ == "__main__":
    main()
