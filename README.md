# Hashcatizer 🔓

[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/nobody-Justheader/Hashcatizer?utm_source=oss&utm_medium=github&utm_campaign=nobody-Justheader%2FHashcatizer&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)](https://coderabbit.ai)

**File-to-Hashcat Converter Suite** — Extract hashes from encrypted files and output them in [hashcat](https://hashcat.net/hashcat/)-compatible format.

Inspired by the [`*2john` scripts](https://github.com/openwall/john/tree/bleeding-jumbo/run) from [John the Ripper](https://github.com/openwall/john) (openwall/john). Full credits in [CREDITS.md](CREDITS.md).

> **Built with [Claude Opus 4.6](https://www.anthropic.com/)** — All converter scripts in this repository were authored using the Claude Opus 4.6 model by Anthropic. Contributors are encouraged to use the same model for maintaining consistency and quality when adding new converters or extending existing ones.

---

## Supported Formats (111 Converters)

| Converter | Hashcat Mode(s) | Description |
|---|---|---|
| `ssh` | 22911, 22921, 22931 | SSH Private Keys (RSA/DSA/EC/OpenSSH) |
| `pdf` | 10400-10700 | PDF 1.1-2.0 |
| `office` | 9400-9800 | MS Office 97-2013+ |
| `keepass` | 13400 | KeePass 1.x/2.x Databases |
| `bitlocker` | 22100 | BitLocker Volumes |
| `truecrypt` | 6211-6233 | TrueCrypt Volumes |
| `veracrypt` | 13711-13773 | VeraCrypt Volumes |
| `luks` | 14600 | LUKS Encrypted Volumes |
| `ethereum` | 15600, 15700 | Ethereum Wallets (scrypt/pbkdf2) |
| `bitcoin` | 11300 | Bitcoin/Litecoin wallet.dat |
| `electrum` | 16600, 21700, 21800 | Electrum Wallets |
| `blockchain` | 12700, 15200 | Blockchain.com Wallets |
| `ansible` | 16900 | Ansible Vault |
| `bitwarden` | 31700 | Bitwarden |
| `lastpass` | 6800 | LastPass |
| `1password` | 6600, 8200 | 1Password Vaults |
| `pwsafe` | 5200 | Password Safe v3 |
| `encfs` | 26401 | EncFS |
| `dmg` | — | Apple DMG Encrypted Images |
| `mozilla` | 26100 | Mozilla/Firefox key3/key4.db |
| `telegram` | 24500 | Telegram Desktop |
| `signal` | 28200 | Signal Desktop/Android |
| `7z` | 11600 | 7-Zip Archives (AES-256-SHA-256) |
| `pgpsda` | — | PGP Self-Decrypting Archives |
| `pgpdisk` | 17010-17040 | PGP Virtual Disk Images |
| `pgpwde` | 17010-17020 | PGP Whole Disk Encryption |
| `zed` | — | ZED/AxCrypt Containers |
| `mac` | 7100, 1722 | macOS Password Hashes (10.4-13+) |
| `lion` | 1722 | macOS Lion SALTED-SHA512 |
| `pcap` | 5500, 5600, 22000 | PCAP/PCAPNG (NTLM, WPA) |
| `netntlm` | 5500, 5600 | NetNTLMv1/v2 Challenge-Response |
| `cisco` | 500, 5700, 9200, 9300 | Cisco Config (Type 4/5/7/8/9) |
| `sap` | 7700, 7800, 10300 | SAP CODVN B/F/G/H |
| `ldif` | 111, 101, 1711 | LDAP LDIF Password Hashes |
| `atmail` | 0, 500, 3200 | Atmail Web Client |
| `mongodb` | 24100, 24200 | MongoDB SCRAM-SHA-1/256 |
| `network` | Various | Network Protocol Hashes (SIP, TACACS+, JWT) |
| `ios` | 14700, 14800 | iOS / iTunes Backup Encryption |
| `vdi` | 27000 | VirtualBox VDI Encryption |
| *batch* | Various | 28 more formats (monero, dashlane, tezos, axcrypt, keychain, ...) |
| *extended* | Various | 44 more formats (Kerberos, RADIUS, DPAPI, Oracle, ...) |


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

This project is directly inspired by the `*2john` scripts from [openwall/john](https://github.com/openwall/john),
and built to complement [hashcat](https://github.com/hashcat/hashcat) — the world's fastest password recovery tool by **Jens "atom" Steube**.
See [CREDITS.md](CREDITS.md) for full attribution.
