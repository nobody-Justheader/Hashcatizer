# Hashcatizer 🔓

**File-to-Hashcat Converter Suite** — Extract hashes from encrypted files and output them in [hashcat](https://hashcat.net/hashcat/)-compatible format.

Inspired by the [`*2john` scripts](https://github.com/openwall/john/tree/bleeding-jumbo/run) from [John the Ripper](https://github.com/openwall/john) (openwall/john). Full credits in [CREDITS.md](CREDITS.md).

> **Built with [Claude Opus 4.6](https://www.anthropic.com/)** — All converter scripts in this repository were authored using the Claude Opus 4.6 model by Anthropic. Contributors are encouraged to use the same model for maintaining consistency and quality when adding new converters or extending existing ones.

---

## Supported Formats

| Converter | Hashcat Mode(s) | Description |
|---|---|---|
| `ssh2hashcat` | 22911, 22921, 22931 | SSH Private Keys (RSA/DSA/EC/OpenSSH) |
| `pdf2hashcat` | 10400, 10500, 10600, 10700 | PDF 1.1-2.0 |
| `office2hashcat` | 9400, 9500, 9600, 9700, 9800 | MS Office 97-2013+ |
| `keepass2hashcat` | 13400 | KeePass 1.x/2.x Databases |
| `bitlocker2hashcat` | 22100 | BitLocker Volumes |
| `truecrypt2hashcat` | 6211-6233 | TrueCrypt Volumes |
| `veracrypt2hashcat` | 13711-13773 | VeraCrypt Volumes |
| `luks2hashcat` | 14600 | LUKS Encrypted Volumes |
| `ethereum2hashcat` | 15600, 15700 | Ethereum Wallets (scrypt/pbkdf2) |
| `bitcoin2hashcat` | 11300 | Bitcoin/Litecoin wallet.dat |
| `electrum2hashcat` | 16600, 21700, 21800 | Electrum Wallets |
| `blockchain2hashcat` | 12700, 15200 | Blockchain.com Wallets |
| `ansible2hashcat` | 16900 | Ansible Vault |
| `bitwarden2hashcat` | 31700 | Bitwarden |
| `lastpass2hashcat` | 6800 | LastPass |
| `1password2hashcat` | 6600, 8200 | 1Password Vaults |
| `pwsafe2hashcat` | 5200 | Password Safe v3 |
| `encfs2hashcat` | 26401 | EncFS |
| `dmg2hashcat` | — | Apple DMG Encrypted Images |
| `mozilla2hashcat` | 26100 | Mozilla/Firefox key3/key4.db |
| `telegram2hashcat` | 24500 | Telegram Desktop |
| `signal2hashcat` | 28200 | Signal Desktop/Android |
| `batch_converters` | Various | 28+ additional formats (monero, dashlane, tezos, axcrypt, keychain, keyring, enpass, diskcryptor, ...) |

## Installation

```bash
git clone https://github.com/yourusername/hashcatizer.git
cd hashcatizer
pip install -e .
```

## Usage

### Unified CLI

```bash
# List all available converters
python hashcatizer.py --list

# Convert a file
python hashcatizer.py ssh <id_rsa>
python hashcatizer.py pdf <document.pdf>
python hashcatizer.py ansible <vault.yml>
python hashcatizer.py ethereum <keystore.json>

# Show mode info for a converter
python hashcatizer.py ssh --mode-info
```

### Standalone Scripts

Each converter can also be run directly:

```bash
python converters/ssh2hashcat.py id_rsa
python converters/pdf2hashcat.py document.pdf
python converters/ansible2hashcat.py vault.yml
python converters/ethereum2hashcat.py keystore.json
python converters/bitcoin2hashcat.py wallet.dat

# Batch converter (multiple formats in one module)
python converters/batch_converters.py --type monero wallet.bin
python converters/batch_converters.py --type keychain login.keychain
```

### Output

Output is printed to stdout, one hash per line, ready to pipe into hashcat:

```bash
python converters/ssh2hashcat.py id_rsa | hashcat -m 22931 -a 0 wordlist.txt
python converters/pdf2hashcat.py doc.pdf | hashcat -m 10500 -a 0 wordlist.txt
```

## Testing

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Contributing

This project is built with **Claude Opus 4.6**. Contributors are encouraged to use the same model for consistency when:
- Adding new converters for additional file formats
- Improving existing parsing logic
- Writing tests and documentation

## License

MIT License — see [LICENSE](LICENSE).

## Credits

This project is directly inspired by the `*2john` scripts from [openwall/john](https://github.com/openwall/john).
See [CREDITS.md](CREDITS.md) for full attribution.
