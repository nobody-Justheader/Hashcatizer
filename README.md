# Hashcatizer 🔓

[![CI](https://github.com/nobody-Justheader/Hashcatizer/actions/workflows/ci.yml/badge.svg)](https://github.com/nobody-Justheader/Hashcatizer/actions/workflows/ci.yml)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/nobody-Justheader/Hashcatizer?utm_source=oss&utm_medium=github&utm_campaign=nobody-Justheader%2FHashcatizer&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![License](https://img.shields.io/github/license/nobody-Justheader/Hashcatizer)](LICENSE)

**File-to-Hashcat Converter Suite** — Extract hashes from encrypted files and output them in [hashcat](https://hashcat.net/hashcat/)-compatible format. Written in Rust for maximum speed.

Inspired by the [`*2john` scripts](https://github.com/openwall/john/tree/bleeding-jumbo/run) from [John the Ripper](https://github.com/openwall/john). Full credits in [CREDITS.md](CREDITS.md).

> **Built with [GitHub Copilot](https://github.com/features/copilot) (Claude Sonnet 4.6)** — All Rust source in this repository was authored using GitHub Copilot powered by Claude Sonnet 4.6. Contributors are encouraged to use the same model for consistency when adding converters or fixing parsing logic.

---

## Features

- **Single static binary** — no runtime dependencies, no interpreter required
- **89 converters** covering wallets, password managers, disk encryption, archives, SSH keys, and more
- **Auto-detection** — pass any file and Hashcatizer identifies the format automatically
- **Hash identification** — pass a raw hash string to identify its type and hashcat mode
- **Hashcat hints** — every result includes the exact `hashcat -m <mode>` command to use

---

## Installation

### Pre-built binaries

Download the latest release for your platform from the [Releases page](../../releases).

```bash
# Linux (musl static binary)
curl -Lo hashcatizer-linux-x86_64.tar.gz https://github.com/nobody-Justheader/Hashcatizer/releases/latest/download/hashcatizer-linux-x86_64.tar.gz
tar -xzf hashcatizer-linux-x86_64.tar.gz
chmod +x hashcatizer
sudo mv hashcatizer /usr/local/bin/
```

### Build from source

Requires [Rust](https://rustup.rs/) 1.75+.

```bash
git clone https://github.com/nobody-Justheader/Hashcatizer.git
cd Hashcatizer
cargo build --release
# Binary: target/release/hashcatizer
```

---

## Usage

```bash
# Auto-detect format and extract hash
hashcatizer <file>

# Use explicit converter
hashcatizer <converter> <file>

# Identify a raw hash string
hashcatizer '<hash_string>'

# List all converters with hashcat mode info
hashcatizer --list
```

### Examples

```bash
# SSH private key → hash + crack command
hashcatizer id_rsa

# Explicit converter
hashcatizer keepass vault.kdbx
hashcatizer pdf document.pdf
hashcatizer ethereum keystore.json
hashcatizer ansible vault.yml

# Pipe straight into hashcat
hashcatizer id_rsa | hashcat -m 22931 -a 0 rockyou.txt
hashcatizer vault.kdbx | hashcat -m 13400 -a 0 rockyou.txt

# Identify a hash you already have
hashcatizer '$2a$12$LlMILsdbh1gAdLhWBXWzXu...'
# → bcrypt (hashcat -m 3200)
```

---

## Supported Formats (89 Converters)

| Converter | Hashcat Mode(s) | Description |
|---|---|---|
| `ssh` | 22911–22941 | SSH private keys (RSA/DSA/EC/OpenSSH) |
| `pdf` | 10400–10700 | PDF 1.1–2.0 |
| `office` | 9400–9800 | MS Office 97–2013+ |
| `keepass` | 13400 | KeePass 1.x / 2.x |
| `bitlocker` | 22100 | BitLocker volumes |
| `truecrypt` | 6211–6243 | TrueCrypt volumes |
| `veracrypt` | 13711–13743 | VeraCrypt volumes |
| `luks` | 14600 | LUKS encrypted volumes |
| `ethereum` | 15600, 15700 | Ethereum wallets (scrypt / pbkdf2) |
| `bitcoin` | 11300 | Bitcoin / Litecoin wallet.dat |
| `electrum` | 16600 | Electrum wallets |
| `blockchain` | 15200 | Blockchain.com wallets |
| `ansible` | 16900 | Ansible Vault |
| `bitwarden` | 26400 | Bitwarden |
| `lastpass` | 6800 | LastPass |
| `1password` | 8200 | 1Password vaults |
| `pwsafe` | 5200 | Password Safe v3 |
| `encfs` | 6211–6221 | EncFS |
| `dmg` | 12700 | Apple DMG encrypted images |
| `mozilla` | 16600 | Firefox / Thunderbird key3/key4.db |
| `telegram` | 22301 | Telegram Desktop |
| `signal` | 25300 | Signal Desktop / Android |
| `7z` | 11600 | 7-Zip archives |
| `pgpdisk` | 22600 | PGP Virtual Disk |
| `pgpsda` | 22600 | PGP Self-Decrypting Archives |
| `pgpwde` | 22600 | PGP Whole Disk Encryption |
| `zed` | 13711 | ZED / AxCrypt containers |
| `mac` | 7100 | macOS password hashes |
| `lion` | 7100 | macOS Lion SHA-512 |
| `pcap` | 5500, 5600 | PCAP / PCAPNG (NTLM, WPA) |
| `netntlm` | 5500, 5600 | NetNTLMv1/v2 |
| `cisco` | 500, 9200, 9300 | Cisco IOS configs |
| `sap` | 7700, 7800 | SAP CODVN B/F/G |
| `ldif` | various | LDAP LDIF hashes |
| `mongodb` | 24100, 24200 | MongoDB SCRAM-SHA-1/256 |
| `ios` | 14800 | iOS / iTunes backup encryption |
| `vdi` | 13711–13733 | VirtualBox VDI encryption |
| `androidbackup` | 18900 | Android ADB backup |
| `androidfde` | 12900 | Android Full-Disk Encryption |
| `axcrypt` | 13200 | AxCrypt |
| `bestcrypt` | 23400 | BestCrypt containers |
| `cardano` | 28500 | Cardano wallets |
| `coinomi` | — | Coinomi wallets |
| `dashlane` | — | Dashlane vaults |
| `deepsound` | 24310 | DeepSound audio steganography |
| `diskcryptor` | 22500 | DiskCryptor volumes |
| `dpapimk` | 15300, 15900 | Windows DPAPI Master Keys |
| `ecryptfs` | 12200 | eCryptfs |
| `enpass` | 24600 | Enpass |
| `fvde` | 16700 | FileVault 2 / Core Storage |
| `geli` | 16800 | FreeBSD GELI |
| `htdigest` | — | Apache htdigest |
| `hccapx` | 22000 | WPA2 HCCAPX |
| `iwork` | 9600 | Apple iWork (Pages/Numbers/Keynote) |
| `keychain` | 23100 | macOS Keychain |
| `keyring` | — | GNOME Keyring |
| `known_hosts` | — | SSH known_hosts (hashed) |
| `libreoffice` | 18400 | LibreOffice / ODF documents |
| `monero` | 26620 | Monero wallets |
| `multibit` | 22200 | MultiBit wallets |
| `openbsd_softraid` | — | OpenBSD softraid crypto |
| `openssl` | 500 | OpenSSL `enc` (Salted__) |
| `pem` | — | Encrypted PEM private keys |
| `pfx` | 24410 | PKCS#12 / PFX |
| `restic` | 24410 | Restic repos |
| `staroffice` | 18400 | StarOffice / OOo documents |
| `strip` | 24420 | Strip password manager |
| `tezos` | 28510 | Tezos wallets |
| `vmx` | 17300 | VMware VMX encryption |
| `aix` | — | AIX password hashes |
| `andotp` | — | andOTP backups |
| `applenotes` | — | Apple Notes (encrypted) |
| `bks` | — | Bouncy Castle BKS keystore |
| `ccache` | — | Kerberos ccache |
| `ejabberd` | — | ejabberd SCRAM hashes |
| `gitea` | — | Gitea password hashes |
| `ikescan` | — | ike-scan IKE PSK hashes |
| `kdcdump` | — | KDC key dump |
| `keystore` | — | Java KeyStore (JKS) |
| `keplr` | — | Keplr wallet |
| `kirbi` | — | Kerberos tickets (kirbi) |
| `krb` | — | Kerberos hashes |
| `kwallet` | — | KDE KWallet |
| `lotus` | — | Lotus Notes ID files |
| `prosody` | — | Prosody XMPP SCRAM hashes |
| `radius` | — | RADIUS hashes |
| `sipdump` | — | SIP digest auth |

---

## License

MIT — see [LICENSE](LICENSE).

## Credits

Inspired by the `*2john` scripts from [openwall/john](https://github.com/openwall/john), built to complement [hashcat](https://github.com/hashcat/hashcat) by **Jens "atom" Steube**. See [CREDITS.md](CREDITS.md) for full attribution.

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
