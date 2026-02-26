#!/usr/bin/env python3
"""
lib/detect.py — File type auto-detection engine.

Uses magic bytes, file extensions, and content pattern matching to identify
encrypted file types and route them to the correct hashcatizer converter.
"""

import json
import os
import re
import struct

# ============================================================================
# Magic byte signatures: (offset, bytes, converter_name)
# ============================================================================
MAGIC_SIGNATURES = [
    # Archives / Containers
    (0, b'7z\xbc\xaf\x27\x1c',       '7z'),
    (0, b'PK\x03\x04',                None),  # ZIP — needs further inspection
    # PDF
    (0, b'%PDF',                       'pdf'),
    # Office (OLE2 Compound Binary)
    (0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'office'),
    # KeePass
    (0, b'\x03\xd9\xa2\x9a',          'keepass'),    # KDBX magic
    (0, b'\x03\xd9\xa2\x9a\x67\xFB\x4b\xb5', 'keepass'),  # KeePass 2.x
    # BitLocker (BDE)
    (3, b'-FVE-FS-',                   'bitlocker'),
    # LUKS
    (0, b'LUKS\xba\xbe',              'luks'),
    # Password Safe v3
    (0, b'PWS3',                       'pwsafe'),
    # Apple DMG (koly trailer at EOF, checked separately)
    # EncFS — XML-based .encfs6.xml
    # Network captures
    (0, b'\xa1\xb2\xc3\xd4',          'pcap'),       # PCAP LE
    (0, b'\xd4\xc3\xb2\xa1',          'pcap'),       # PCAP BE
    (0, b'\x0a\x0d\x0d\x0a',          'pcap'),       # PCAPNG
    # PGP SDA
    # (scanned inline; 'PGPSDA' magic can appear at variable offset)
    # VDI
    (0, b'<<< ',                       'vdi'),
    # SQLite (Mozilla key4.db, etc.)
    (0, b'SQLite format 3\x00',       None),  # needs further inspection
    # macOS binary plist
    (0, b'bplist00',                   'mac'),
    # TrueCrypt/VeraCrypt — no magic, need special handling
]

# ============================================================================
# Extension-based detection
# ============================================================================
EXTENSION_MAP = {
    # Documents
    '.pdf':      'pdf',
    '.doc':      'office',
    '.docx':     'office',
    '.xls':      'office',
    '.xlsx':     'office',
    '.ppt':      'office',
    '.pptx':     'office',
    # Archives
    '.7z':       '7z',
    # Crypto wallets
    '.json':     None,  # needs content inspection
    # SSH keys
    '.pem':      None,  # could be SSH or PEM cert
    '.key':      None,  # could be SSH or other
    # KeePass
    '.kdbx':     'keepass',
    '.kdb':      'keepass',
    # Password Safe
    '.psafe3':   'pwsafe',
    # Disk encryption
    '.tc':       'truecrypt',
    '.hc':       'veracrypt',
    '.dmg':      'dmg',
    '.vdi':      'vdi',
    '.vmx':      'vmx',
    # Network
    '.pcap':     'pcap',
    '.pcapng':   'pcap',
    '.cap':      'pcap',
    '.hccapx':   'hccapx',
    # macOS
    '.plist':    'mac',
    '.keychain': 'keychain',
    '.keychain-db': 'keychain',
    # Configs
    '.cfg':      None,  # need content inspection
    '.conf':     None,
    '.config':   None,
    # Databases
    '.db':       None,  # could be SQLite/Mozilla
    '.sqlite':   None,
    # PGP
    '.pgd':      'pgpdisk',
    '.pgp':      None,  # could be SDA/WDE/Disk
    '.sda':      'pgpsda',
    # Signal
    '.sqlite-signal': 'signal',
    # Electrum
    '.electrum':  'electrum',
    # AxCrypt/ZED
    '.axx':      'zed',
    '.zed':      'zed',
    # LDIF
    '.ldif':     'ldif',
    '.ldf':      'ldif',
    # Kerberos
    '.kirbi':    'kirbi',
    '.ccache':   'ccache',
    # Java keystore
    '.jks':      'keystore',
    '.bks':      'bks',
    # KWallet
    '.kwl':      'kwallet',
    # EncFS
    '.encfs6.xml': 'encfs',
    # iOS backup
    '.plist':    'mac',   # Manifest.plist handled by ios detection
    # Password managers
    '.1pif':     '1password',
    '.opvault':  '1password',
    '.agilekeychain': '1password',
    '.bitwarden': 'bitwarden',
    # Linux encryption
    '.ecryptfs': 'ecryptfs',
    # iWork
    '.pages':    'iwork',
    '.numbers':  'iwork',
    '.key':      None,
}

# ============================================================================
# Content-pattern detection (for text/JSON files)
# ============================================================================


def _detect_by_content(data, text, filename):
    """Detect file type from content patterns."""
    basename = os.path.basename(filename).lower()

    # SSH private key
    if b'-----BEGIN' in data[:512] and b'PRIVATE KEY-----' in data[:512]:
        return 'ssh'
    if b'-----BEGIN OPENSSH PRIVATE KEY-----' in data[:64]:
        return 'ssh'
    if b'-----BEGIN ENCRYPTED PRIVATE KEY-----' in data[:64]:
        return 'ssh'
    if b'-----BEGIN RSA PRIVATE KEY-----' in data[:64]:
        return 'ssh'

    # PEM certificate (not SSH)
    if b'-----BEGIN CERTIFICATE-----' in data[:64]:
        return 'pem'

    # Ansible Vault
    if data[:14] == b'$ANSIBLE_VAULT':
        return 'ansible'

    # EncFS config
    if b'<boost_serialization' in data[:256] and b'encfs' in data[:512].lower():
        return 'encfs'
    if basename == '.encfs6.xml' or basename == 'encfs6.xml':
        return 'encfs'

    # Cisco config
    if text:
        for pattern in ['enable secret', 'password 5 $', 'password 7 ', 'password 8 $', 'password 9 $']:
            if pattern in text[:4096]:
                return 'cisco'

    # LDIF
    if text and text.lstrip().startswith('dn:'):
        return 'ldif'
    if text and 'userPassword' in text[:4096]:
        return 'ldif'

    # Manifest.plist (iOS backup)
    if basename == 'manifest.plist':
        return 'ios'
    if b'BackupKeyBag' in data[:8192]:
        return 'ios'

    # Mozilla key4.db / key3.db
    if basename in ('key4.db', 'key3.db', 'cert9.db'):
        return 'mozilla'
    if data[:16] == b'SQLite format 3\x00':
        # Could be Mozilla, Signal, etc.
        if basename.startswith('key') and basename.endswith('.db'):
            return 'mozilla'
        if 'signal' in basename:
            return 'signal'

    # Ethereum keystore (JSON with "crypto" key)
    if data[:1] in (b'{', b'['):
        try:
            j = json.loads(data)
            if isinstance(j, dict):
                if 'crypto' in j or 'Crypto' in j:
                    return 'ethereum'
                if 'keystore' in j:
                    return 'ethereum'
                # Electrum wallet
                if 'wallet_type' in j:
                    return 'electrum'
                # 1Password
                if 'SL5' in j or 'keysets' in j:
                    return '1password'
                # Bitwarden
                if 'encrypted' in j and 'passwordHash' in str(j)[:4096]:
                    return 'bitwarden'
                # Blockchain.com wallet
                if 'payload' in j and 'pbkdf2_iterations' in j:
                    return 'blockchain'
                # MongoDB user
                if 'credentials' in j:
                    creds = j.get('credentials', {})
                    if 'SCRAM-SHA-1' in creds or 'SCRAM-SHA-256' in creds:
                        return 'mongodb'
                # LastPass export
                if 'iterations' in j and 'username' in j:
                    return 'lastpass'
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Bitcoin wallet.dat (Berkeley DB)
    if b'\x00\x06\x15\x61' in data[:16] or b'bitcoin' in data[:4096].lower():
        if basename == 'wallet.dat' or b'\x62\x31\x05\x00\x09\x00' in data[:64]:
            return 'bitcoin'

    # SAP export (tab-separated with BCODE)
    if text and '\t' in text[:512]:
        lines = text[:1024].split('\n')
        if any(len(l.split('\t')) >= 3 and len(l.split('\t')[1].strip()) == 16 for l in lines if l.strip()):
            return 'sap'

    # Atmail (email:hash format with MD5-length hashes)
    if text and '@' in text[:512] and ':' in text[:512]:
        lines = text[:1024].split('\n')
        for l in lines:
            if '@' in l and ':' in l:
                parts = l.split(':')
                if len(parts) >= 2 and len(parts[1].strip()) == 32:
                    return 'atmail'

    # NetNTLM
    if text and '::' in text[:512]:
        if re.search(r'\w+::\w+:', text[:1024]):
            return 'netntlm'

    # PGP SDA (scan for magic)
    if b'PGPSDA' in data:
        return 'pgpsda'

    # ZED container
    if b'\x07\x65\x92\x1A\x2A\x07\x74\x53' in data[:4096]:
        return 'zed'

    # PGP disk magic ('PGPd' = 0x50475064 LE)
    if b'PGPd' in data[:512] or b'dPGP' in data[:512]:
        return 'pgpdisk'

    # PGP WDE (RESU+MMYS)
    if b'RESU' in data[:8192] and b'MMYS' in data[:8192]:
        return 'pgpwde'

    # DMG (koly trailer)
    if len(data) > 512 and data[-512:-508] == b'koly':
        return 'dmg'

    # TrueCrypt/VeraCrypt (no magic — 512 byte header, all look random)
    # These need explicit selection; can't auto-detect safely

    return None


def detect_file_type(filename):
    """Auto-detect the converter type for a given file.

    Returns: converter name string, or None if unable to detect.
    """
    if not os.path.isfile(filename):
        # Directory — check for known structures
        if os.path.isdir(filename):
            manifest = os.path.join(filename, 'Manifest.plist')
            if os.path.exists(manifest):
                return 'ios'
            # 1Password vault
            if filename.endswith('.agilekeychain') or filename.endswith('.opvault'):
                return '1password'
        return None

    # Read first 8KB for analysis
    try:
        with open(filename, 'rb') as f:
            data = f.read(8192)
    except IOError:
        return None

    if not data:
        return None

    # 1. Check magic bytes
    for offset, magic, converter in MAGIC_SIGNATURES:
        if converter and offset + len(magic) <= len(data):
            if data[offset:offset + len(magic)] == magic:
                return converter

    # 2. Check file extension
    basename = os.path.basename(filename).lower()
    _, ext = os.path.splitext(basename)
    if ext in EXTENSION_MAP and EXTENSION_MAP[ext] is not None:
        return EXTENSION_MAP[ext]

    # Handle compound extensions
    if basename.endswith('.encfs6.xml'):
        return 'encfs'

    # 3. Content-based detection
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        text = None

    return _detect_by_content(data, text, filename)


# ============================================================================
# Hash string identification — recognizes hashes already in hashcat format
# ============================================================================

# (regex_pattern, hash_name, hashcat_mode)
HASH_PATTERNS = [
    # MD5 variants
    (r'^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$', 'md5crypt', 500),
    (r'^[a-fA-F0-9]{32}$', 'MD5 (or NTLM — use -m 0 or -m 1000)', 0),
    (r'^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$', 'Apache APR1', 1600),
    (r'^\{MD5\}[A-Za-z0-9+/=]+$', 'LDAP MD5 Base64', 0),
    (r'^\{SMD5\}[A-Za-z0-9+/=]+$', 'LDAP SSHA (MD5 salted)', 6300),

    # SHA variants
    (r'^[a-fA-F0-9]{40}$', 'SHA-1', 100),
    (r'^[a-fA-F0-9]{64}$', 'SHA-256', 1400),
    (r'^[a-fA-F0-9]{128}$', 'SHA-512', 1700),
    (r'^\{SHA\}[A-Za-z0-9+/=]+$', 'LDAP SHA Base64', 101),
    (r'^\{SSHA\}[A-Za-z0-9+/=]+$', 'LDAP SSHA Base64', 111),
    (r'^\{SSHA256\}[A-Za-z0-9+/=]+$', 'LDAP SSHA256 Base64', 1411),
    (r'^\{SSHA512\}[A-Za-z0-9+/=]+$', 'LDAP SSHA512 Base64', 1711),

    # SHA-crypt (Linux shadow)
    (r'^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$', 'sha256crypt', 7400),
    (r'^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$', 'sha512crypt', 1800),

    # bcrypt
    (r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$', 'bcrypt', 3200),

    # NTLM / LM
    (r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$', 'LM:NTLM', 1000),

    # NetNTLM
    (r'^[^:]+::\S+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+$', 'NetNTLMv2', 5600),
    (r'^[^:]+::\S+:[a-fA-F0-9]+:[a-fA-F0-9]{48}:[a-fA-F0-9]+$', 'NetNTLMv1', 5500),

    # Kerberos
    (r'^\$krb5pa\$', 'Kerberos 5 Pre-Auth (etype 23)', 7500),
    (r'^\$krb5tgs\$', 'Kerberos 5 TGS-REP (etype 23)', 13100),
    (r'^\$krb5asrep\$', 'Kerberos 5 AS-REP (etype 23)', 18200),

    # Cisco
    (r'^\$8\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$', 'Cisco Type 8 (PBKDF2-SHA256)', 9200),
    (r'^\$9\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$', 'Cisco Type 9 (scrypt)', 9300),

    # MS Office
    (r'^\$office\$\*2013\*', 'MS Office 2013+', 9600),
    (r'^\$office\$\*2010\*', 'MS Office 2010', 9500),
    (r'^\$office\$\*2007\*', 'MS Office 2007', 9400),

    # PDF
    (r'^\$pdf\$', 'PDF', 10400),

    # 7-Zip
    (r'^\$7z\$', '7-Zip', 11600),

    # KeePass
    (r'^\$keepass\$', 'KeePass', 13400),

    # SSH
    (r'^\$sshng\$', 'SSH (RSA/DSA/EC/Ed25519)', 22911),

    # Ethereum
    (r'^\$ethereum\$', 'Ethereum Wallet', 15600),

    # BitLocker
    (r'^\$bitlocker\$', 'BitLocker', 22100),

    # LUKS
    (r'^\$luks\$', 'LUKS', 14600),

    # Ansible Vault
    (r'^\$ansible\$', 'Ansible Vault', 16900),

    # PBKDF2 generic
    (r'^\$pbkdf2-sha256\$', 'PBKDF2-HMAC-SHA256', 10900),
    (r'^\$pbkdf2-sha512\$', 'PBKDF2-HMAC-SHA512', 12100),
    (r'^\$pbkdf2-sha1\$', 'PBKDF2-HMAC-SHA1', 12001),

    # scrypt
    (r'^\$scrypt\$', 'scrypt', 8900),

    # Argon2
    (r'^\$argon2id?\$', 'Argon2', 0),

    # macOS
    (r'^\$ml\$', 'macOS PBKDF2-SHA512 / SALTED-SHA512', 7100),

    # Bitcoin / blockchain
    (r'^\$bitcoin\$', 'Bitcoin/Litecoin wallet', 11300),
    (r'^\$blockchain\$', 'Blockchain.com wallet', 12700),
    (r'^\$electrum\$', 'Electrum wallet', 16600),

    # WPA
    (r'^WPA\*', 'WPA-PBKDF2-PMKID+EAPOL', 22000),

    # Django
    (r'^pbkdf2_sha256\$', 'Django PBKDF2-SHA256', 10000),

    # WordPress
    (r'^\$P\$[A-Za-z0-9./]{31}$', 'WordPress (phpass)', 400),

    # Drupal
    (r'^\$S\$[A-Za-z0-9./]{52}$', 'Drupal 7+', 7900),

    # MySQL
    (r'^\*[a-fA-F0-9]{40}$', 'MySQL 4.1+', 300),

    # PostgreSQL
    (r'^md5[a-fA-F0-9]{32}$', 'PostgreSQL MD5', 12),

    # Oracle
    (r'^S:[a-fA-F0-9]{60}$', 'Oracle 11g+', 112),

    # MSSQL
    (r'^0x0100[a-fA-F0-9]{88}$', 'MSSQL 2005', 132),
    (r'^0x0200[a-fA-F0-9]{136}$', 'MSSQL 2012+', 1731),

    # Telegram
    (r'^\$telegram\$', 'Telegram Desktop', 24500),

    # Signal
    (r'^\$signal\$', 'Signal', 28200),

    # iTunes backup
    (r'^\$itunes_backup\$', 'iTunes Backup', 14700),

    # TrueCrypt
    (r'^\$truecrypt\$', 'TrueCrypt', 6211),

    # VeraCrypt
    (r'^\$veracrypt\$', 'VeraCrypt', 13711),

    # SAP
    (r'^[A-Z0-9]+:[A-F0-9]{16}$', 'SAP CODVN B (BCODE)', 7700),

    # MongoDB SCRAM
    (r'^\$mongodb-scram\$', 'MongoDB SCRAM', 24100),

    # DES crypt
    (r'^[./A-Za-z0-9]{13}$', 'DES crypt (traditional)', 1500),

    # Bitwarden
    (r'^\$bitwarden\$', 'Bitwarden', 31700),
]


def identify_hash(hash_string):
    """Identify a hash string and return its type and hashcat mode.

    Args:
        hash_string: The hash string to identify.

    Returns:
        List of (hash_name, hashcat_mode) tuples for all matching patterns.
        Empty list if no match found.
    """
    hash_string = hash_string.strip()
    if not hash_string:
        return []

    matches = []
    for pattern, name, mode in HASH_PATTERNS:
        try:
            if re.match(pattern, hash_string):
                matches.append((name, mode))
        except re.error:
            continue

    return matches


def is_hash_string(arg):
    """Check if the argument looks like a hash string rather than a filename.

    Returns True if it's likely a hash, False if likely a file path.
    """
    # If it exists as a file/directory, it's a file
    if os.path.exists(arg):
        return False
    # Hash prefixes
    hash_prefixes = ('$', '{', '0x', 'md5', 'pbkdf2_', 'WPA*')
    if any(arg.startswith(p) for p in hash_prefixes):
        return True
    # Hex-only strings of known hash lengths
    if re.match(r'^[a-fA-F0-9]+$', arg) and len(arg) in (32, 40, 64, 128):
        return True
    # Contains :: (NetNTLM format)
    if '::' in arg and ':' in arg:
        return True
    # Contains $ with no path separator
    if '$' in arg and os.sep not in arg:
        return True
    return False
