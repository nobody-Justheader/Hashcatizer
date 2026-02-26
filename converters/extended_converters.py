#!/usr/bin/env python3
"""
Additional converters — network, Kerberos, application-specific formats.

This module covers:
- Network captures (pcap, radius, SIP, SNMP)
- Kerberos (kirbi, ccache, krb)
- Application-specific (Apple Notes, Prosody, GitLab/Gitea, etc.)
- Miscellaneous (GPG, 7z-like, FileMaker, Oracle, SAP, etc.)
"""

import base64
import binascii
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file, warn,
)

# ============================================================================
# Kerberos / Authentication Converters
# ============================================================================


def kirbi2hashcat(filename):
    """Kerberos .kirbi ticket hash extractor (mode 13100, 18200)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # .kirbi files are ASN.1 DER-encoded Kerberos tickets
    if data[0] != 0x76 and data[0] != 0x30:
        error("Not a valid .kirbi file", filename)
        return
    # extract ticket data for hashcat
    output_hash("$krb5tgs$%s" % bytes_to_hex(data[:min(4096, len(data))]))


def ccache2hashcat(filename):
    """Kerberos ccache hash extractor (mode 13100)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # ccache magic: 0x0504 (version 4)
    if len(data) < 4:
        error("File too small for ccache", filename)
        return
    version = struct.unpack('>H', data[0:2])[0]
    if version not in (0x0504, 0x0503, 0x0502, 0x0501):
        error("Not a valid ccache file (version %04x)" % version, filename)
        return
    output_hash("$krb5cc$%s" % bytes_to_hex(data[:min(4096, len(data))]))


def krb2hashcat(filename):
    """Kerberos packet hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read().strip()
    except IOError as e:
        error(str(e), filename)
        return
    # Parse Kerberos AS-REP or TGS-REP data
    lines = data.strip().split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith('$krb5') or line.startswith('$krb'):
            output_hash(line)
        elif ':' in line and '$' in line:
            # user:hash format
            parts = line.split(':', 1)
            if len(parts) == 2 and parts[1].startswith('$krb'):
                output_hash(line)


def kdcdump2hashcat(filename):
    """KDC dump hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Format: principal:kvno:enctype:key
        parts = line.split(':')
        if len(parts) >= 4:
            principal = parts[0]
            kvno = parts[1]
            enctype = parts[2]
            key = parts[3]
            output_hash("$krb5kdc$%s*%s*%s*%s" % (enctype, kvno, principal, key))


# ============================================================================
# Network / Capture Converters
# ============================================================================


def sipdump2hashcat(filename):
    """SIP digest hash extractor (mode 11400)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # SIP dump format: user"IP"sip_URI"nonce"date"method"response"...
        parts = line.split('"')
        if len(parts) >= 7:
            output_hash("$sip$*%s" % '*'.join(parts))


def ikescan2hashcat(filename):
    """IKE-scan hash extractor (mode 5300, 5400)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read().strip()
    except IOError as e:
        error(str(e), filename)
        return
    # PSK hash format from ike-scan
    lines = data.split('\n')
    for line in lines:
        if ':' in line and len(line) > 50:
            output_hash(line.strip())


def hccapx2hashcat(filename):
    """hccapx (WPA) hash extractor (mode 22000, 22001)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # hccapx magic: 0x58504348 ("HCPX")
    if len(data) < 393:
        error("File too small for hccapx", filename)
        return
    magic = struct.unpack('<I', data[0:4])[0]
    if magic != 0x58504348:
        warn("Non-standard hccapx header", filename)
    # hashcat can process hccapx directly
    sys.stderr.write("Note: hashcat processes hccapx files directly.\n")
    sys.stderr.write("Use: hashcat -m 22000 %s wordlist.txt\n" % filename)
    output_hash(bytes_to_hex(data[:393]))


def radius2hashcat(filename):
    """RADIUS hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Try as pcap first, then raw
    text = data.decode('utf-8', errors='ignore')
    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if line and ':' in line:
            output_hash(line)


# ============================================================================
# Application-Specific Converters
# ============================================================================


def applenotes2hashcat(filename):
    """Apple Notes hash extractor."""
    if not validate_file(filename):
        return
    try:
        import sqlite3
        conn = sqlite3.connect(filename)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ZCRYPTOITERATIONCOUNT, ZCRYPTOSALT, ZCRYPTOWRAPPEDKEY, ZCRYPTOINITIALIZATIONVECTOR
            FROM ZICCLOUDSYNCINGOBJECT
            WHERE ZCRYPTOITERATIONCOUNT IS NOT NULL
        """)
        rows = cursor.fetchall()
        conn.close()
        for row in rows:
            iterations, salt, wrapped_key, iv = row
            if salt and wrapped_key:
                salt_hex = bytes_to_hex(salt) if isinstance(salt, bytes) else salt
                wk_hex = bytes_to_hex(wrapped_key) if isinstance(wrapped_key, bytes) else wrapped_key
                iv_hex = bytes_to_hex(iv) if isinstance(iv, bytes) and iv else "0"
                output_hash("$ANP$%d*%s*%s*%s" % (iterations, salt_hex, wk_hex, iv_hex))
    except Exception as e:
        error("Failed to parse Apple Notes database: %s" % str(e), filename)


def gitea2hashcat(filename):
    """Gitea hash extractor (mode 28500)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read().strip()
    except IOError as e:
        error(str(e), filename)
        return
    # Try JSON
    try:
        users = json.loads(data)
        if isinstance(users, list):
            for user in users:
                _process_gitea_user(user)
        elif isinstance(users, dict):
            _process_gitea_user(users)
        return
    except json.JSONDecodeError:
        pass
    # Try CSV/line format
    lines = data.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Format: user:algo$hash or similar
        if '$' in line:
            output_hash(line)


def _process_gitea_user(user):
    if not isinstance(user, dict):
        return
    passwd = user.get('passwd', '') or user.get('password', '')
    salt = user.get('salt', '')
    algo = user.get('passwd_hash_algo', 'pbkdf2')
    name = user.get('name', user.get('login_name', ''))
    if passwd:
        if algo == 'pbkdf2':
            output_hash("%s:$pbkdf2-sha256$10000$%s$%s" % (name, salt, passwd))
        elif algo == 'bcrypt':
            output_hash("%s:%s" % (name, passwd))
        elif algo == 'scrypt':
            output_hash("%s:$scrypt$%s$%s" % (name, salt, passwd))
        else:
            output_hash("%s:%s" % (name, passwd))


def prosody2hashcat(filename):
    """Prosody XMPP hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Prosody stores SCRAM-SHA-1 data
    # Format: stored_key|server_key|salt|iteration_count
    # Or Lua table format
    m = re.findall(r'"iteration_count"\s*=\s*(\d+)', data)
    s = re.findall(r'"salt"\s*=\s*"([^"]+)"', data)
    sk = re.findall(r'"stored_key"\s*=\s*"([^"]+)"', data)
    if m and s and sk:
        for i in range(min(len(m), len(s), len(sk))):
            output_hash("$scram$%s$%s$%s" % (m[i], s[i], sk[i]))
        return
    error("Could not parse Prosody data", filename)


def ejabberd2hashcat(filename):
    """ejabberd hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # ejabberd SCRAM data in Erlang term format or SQL dump
    # Pattern: {scram, StoredKey, ServerKey, Salt, IterationCount}
    scram_pattern = re.findall(
        r'\{scram,\s*<<"([^"]+)">>,\s*<<"([^"]+)">>,\s*<<"([^"]+)">>,\s*(\d+)\}',
        data
    )
    for stored_key, server_key, salt, iters in scram_pattern:
        output_hash("$scram$%s$%s$%s$%s" % (iters, salt, stored_key, server_key))
    if not scram_pattern:
        # Try SQL format
        for line in data.split('\n'):
            if 'scram' in line.lower() and '=' in line:
                output_hash(line.strip())


def mosquitto2hashcat(filename):
    """Mosquitto MQTT broker hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Format: user:$6$salt$hash or user:$7$...
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2 and parts[1].startswith('$'):
                output_hash(line)


def lotus2hashcat(filename):
    """Lotus Notes hash extractor (mode 8600, 9100)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Look for Lotus Notes ID file signature
    if len(data) < 48:
        error("File too small for Lotus Notes ID", filename)
        return
    output_hash("$lotus$%s" % bytes_to_hex(data[:min(256, len(data))]))


def oracle2hashcat(filename):
    """Oracle hash extractor (mode 112, 12300)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # user:hash format
        if ':' in line:
            output_hash(line)


def aix2hashcat(filename):
    """AIX hash extractor (mode 6300, 6400, 6500, 6700)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # AIX /etc/security/passwd format: user:attributes:hash
        if ':' in line:
            parts = line.split(':')
            for part in parts:
                part = part.strip()
                if part.startswith('{'):
                    # {ssha256}, {ssha512}, {smd5}, {ssha1}
                    output_hash(part)


def cracf2hashcat(filename):
    """IBM RACF hash extractor (mode 8500)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            output_hash(line)


def sense2hashcat(filename):
    """pfSense/OPNsense hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # config.xml contains bcrypt hashes
    password_matches = re.findall(r'<password>([^<]+)</password>', data)
    for pw in password_matches:
        pw = pw.strip()
        if pw.startswith('$2') or pw.startswith('$1') or pw.startswith('$6'):
            output_hash(pw)


def mcafee_epo2hashcat(filename):
    """McAfee ePO hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Look for SHA1 or MD5 hashes in ePO format
    lines = data.strip().split('\n')
    for line in lines:
        line = line.strip()
        if ':' in line and len(line) > 32:
            output_hash(line)


def apex2hashcat(filename):
    """Salesforce APEX hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # user:{SSHA}base64hash
        m = re.match(r'(\S+):(\{[^}]+\}\S+)', line)
        if m:
            output_hash(line)


def aruba2hashcat(filename):
    """Aruba Networks hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if 'mgmt-user' in line or 'hash' in line.lower():
            # Extract hash from config line
            m = re.search(r'([0-9a-fA-F]{64,})', line)
            if m:
                output_hash(m.group(1))


def ibmiscanner2hashcat(filename):
    """IBM iSeries scanner hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            output_hash(line)


def andotp2hashcat(filename):
    """andOTP backup hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 32:
        error("File too small for andOTP backup", filename)
        return
    # Encrypted andOTP backups use AES-GCM
    # First 12 bytes: IV, then encrypted data
    iv = data[:12]
    enc = data[12:min(256, len(data))]
    output_hash("$andotp$%s*%s" % (bytes_to_hex(iv), bytes_to_hex(enc)))


def authenticator2hashcat(filename):
    """Authenticator app hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 32:
        error("File too small", filename)
        return
    output_hash("$authenticator$%s" % bytes_to_hex(data[:min(256, len(data))]))


def money2hashcat(filename):
    """Microsoft Money hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 64:
        error("File too small for MS Money file", filename)
        return
    # MS Money uses JET database encryption
    output_hash("$money$%s" % bytes_to_hex(data[:64]))


def neo2hashcat(filename):
    """NEO wallet hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        error(str(e), filename)
        return
    # NEO wallet JSON
    accounts = data.get('accounts', [])
    for acc in accounts:
        key = acc.get('key', '')
        if key:  # NEP-2 encrypted key
            output_hash("$neo$%s" % key)


def oubliette2hashcat(filename):
    """Oubliette hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(256)
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 48:
        error("File too small", filename)
        return
    output_hash("$oubliette$%s" % bytes_to_hex(data[:48]))


def padlock2hashcat(filename):
    """Padlock hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 32:
        error("File too small", filename)
        return
    output_hash("$padlock$%s" % bytes_to_hex(data[:min(256, len(data))]))


def ps_token2hashcat(filename):
    """PeopleSoft token hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read().strip()
    except IOError as e:
        error(str(e), filename)
        return
    # PS token is base64 encoded
    try:
        decoded = base64.b64decode(data)
        if len(decoded) >= 32:
            output_hash("$ps_token$%s" % bytes_to_hex(decoded))
    except Exception:
        output_hash("$ps_token$%s" % data)


def pse2hashcat(filename):
    """SAP PSE hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 48:
        error("File too small for SAP PSE", filename)
        return
    output_hash("$pse$%s" % bytes_to_hex(data[:min(512, len(data))]))


def strip2hashcat(filename):
    """STRIP hash extractor (mode 15000)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 32:
        error("File too small for STRIP database", filename)
        return
    # STRIP uses SQLCipher
    salt = data[:16]
    enc_page = data[16:48]
    output_hash("$strip$*%s*%s" % (bytes_to_hex(salt), bytes_to_hex(enc_page)))


def apop2hashcat(filename):
    """APOP hash extractor (mode 4800)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Format: user:challenge:response
        if ':' in line:
            output_hash(line)


def filezilla2hashcat(filename):
    """FileZilla Server hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Parse FileZilla Server XML
    try:
        root = ET.fromstring(data)
        for user in root.findall('.//User') or root.findall('.//user'):
            name = user.get('Name', user.get('name', ''))
            for opt in user.findall('.//Option') or user.findall('.//option'):
                opt_name = opt.get('Name', opt.get('name', ''))
                if opt_name and 'pass' in opt_name.lower():
                    pw = opt.text
                    if pw:
                        output_hash("%s:%s" % (name, pw))
    except Exception:
        # Fallback: regex
        users = re.findall(r'Name="([^"]+)"', data)
        passwords = re.findall(r'>([0-9a-fA-F]{32,})<', data)
        for u, p in zip(users, passwords):
            output_hash("%s:%s" % (u, p))


def deepsound2hashcat(filename):
    """DeepSound hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    # DeepSound embeds encrypted data in audio files
    # Look for DeepSound magic
    magic = b'DSCF'
    pos = data.find(magic)
    if pos == -1:
        error("No DeepSound data found", filename)
        return
    header = data[pos:pos + 256]
    output_hash("$deepsound$%s" % bytes_to_hex(header))


def bitshares2hashcat(filename):
    """BitShares wallet hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        error(str(e), filename)
        return
    cipher_keys = data.get('cipher_keys', '')
    if cipher_keys:
        output_hash("$bitshares$%s" % cipher_keys)
    else:
        error("No cipher_keys found in BitShares wallet", filename)


def bks2hashcat(filename):
    """Bouncy Castle Keystore (BKS) hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # BKS format: version(4) + salt_len(4) + salt + iter(4) + entries
    if len(data) < 16:
        error("File too small for BKS", filename)
        return
    version = struct.unpack('>I', data[0:4])[0]
    if version not in (1, 2):
        error("Unsupported BKS version %d" % version, filename)
        return
    salt_len = struct.unpack('>I', data[4:8])[0]
    if salt_len > 128 or 8 + salt_len + 4 > len(data):
        error("Invalid salt length", filename)
        return
    salt = data[8:8 + salt_len]
    iterations = struct.unpack('>I', data[8 + salt_len:12 + salt_len])[0]
    # HMAC is last 20 bytes
    hmac = data[-20:]
    output_hash("$bks$%d*%d*%s*%d*%s*%s" % (
        version, salt_len, bytes_to_hex(salt),
        iterations, bytes_to_hex(hmac),
        bytes_to_hex(data[12 + salt_len:12 + salt_len + 48])
    ))


def keystore2hashcat(filename):
    """Java Keystore (JKS) hash extractor (mode 15500)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # JKS magic: 0xFEEDFEED
    if len(data) < 12:
        error("File too small for JKS", filename)
        return
    magic = struct.unpack('>I', data[0:4])[0]
    if magic != 0xFEEDFEED:
        error("Not a valid Java KeyStore file", filename)
        return
    # SHA1 hash of keystore password is embedded
    # The last 20 bytes are SHA1(password + "Mighty Aphrodite" + data)
    sha1_hash = data[-20:]
    output_hash("$keystore$0*%s*%s" % (
        bytes_to_hex(sha1_hash),
        bytes_to_hex(data[:-20][-32:])
    ))


def kwallet2hashcat(filename):
    """KDE KWallet hash extractor (mode 13000)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # KWallet magic: "KWALLET"
    magic = b'KWALLET'
    if data[:7] != magic:
        error("Not a KWallet file", filename)
        return
    # Parse KWallet header
    if len(data) < 48:
        error("KWallet file too small", filename)
        return
    # Hash at offset 8 (SHA1 of password, 20 bytes)
    enc_data = data[8:56]
    output_hash("$kwallet$%s" % bytes_to_hex(enc_data))


def keplr2hashcat(filename):
    """Keplr wallet hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        error(str(e), filename)
        return
    # Keplr extension data
    if 'crypto' in data:
        crypto = data['crypto']
        cipher = crypto.get('cipher', '')
        ct = crypto.get('ciphertext', '')
        kdf = crypto.get('kdf', '')
        kdf_params = crypto.get('kdfparams', {})
        salt = kdf_params.get('salt', '')
        n = kdf_params.get('n', 0) or kdf_params.get('N', 0)
        r = kdf_params.get('r', 0)
        p = kdf_params.get('p', 0)
        if kdf == 'scrypt':
            output_hash("$keplr$scrypt*%d*%d*%d*%s*%s" % (n, r, p, salt, ct))
        elif kdf == 'pbkdf2':
            iterations = kdf_params.get('c', 0)
            output_hash("$keplr$pbkdf2*%d*%s*%s" % (iterations, salt, ct))
    else:
        error("No crypto data found in Keplr wallet", filename)


def adxcsouf2hashcat(filename):
    """SAP CODVN B/F/H hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            output_hash(line)


def aem2hashcat(filename):
    """Adobe Experience Manager hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        error(str(e), filename)
        return
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # AEM stores {SHA-256}hash format
        if ':' in line and ('{' in line or '$' in line):
            output_hash(line)


def DPAPImk2hashcat(filename):
    """DPAPI masterkey hash extractor (mode 15300, 15900)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # DPAPI master key files
    if len(data) < 100:
        error("File too small for DPAPI masterkey", filename)
        return
    # Version, SID, hash algorithm, cipher algorithm, etc.
    output_hash("$DPAPImk$%s" % bytes_to_hex(data[:min(512, len(data))]))


def encdatavault2hashcat(filename):
    """ENCDataVault hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 32:
        error("File too small", filename)
        return
    output_hash("$encdv$%s" % bytes_to_hex(data[:min(256, len(data))]))


def sspr2hashcat(filename):
    """NetIQ SSPR hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Try JSON or XML format
    try:
        j = json.loads(data)
        if 'StoredConfiguration' in j:
            config = j['StoredConfiguration']
            for key, val in config.items():
                if 'password' in key.lower():
                    output_hash("$sspr$%s" % val)
    except json.JSONDecodeError:
        pass
    # XML format
    pw_matches = re.findall(r'<value><![CDATA\[([^\]]+)\]\]></value>', data)
    for pw in pw_matches:
        if len(pw) > 20:
            output_hash("$sspr$%s" % pw)


# Registry of all converters
CONVERTERS = {
    'kirbi': kirbi2hashcat,
    'ccache': ccache2hashcat,
    'krb': krb2hashcat,
    'kdcdump': kdcdump2hashcat,
    'sipdump': sipdump2hashcat,
    'ikescan': ikescan2hashcat,
    'hccapx': hccapx2hashcat,
    'radius': radius2hashcat,
    'applenotes': applenotes2hashcat,
    'gitea': gitea2hashcat,
    'prosody': prosody2hashcat,
    'ejabberd': ejabberd2hashcat,
    'mosquitto': mosquitto2hashcat,
    'lotus': lotus2hashcat,
    'oracle': oracle2hashcat,
    'aix': aix2hashcat,
    'cracf': cracf2hashcat,
    'sense': sense2hashcat,
    'mcafee_epo': mcafee_epo2hashcat,
    'apex': apex2hashcat,
    'aruba': aruba2hashcat,
    'ibmiscanner': ibmiscanner2hashcat,
    'andotp': andotp2hashcat,
    'authenticator': authenticator2hashcat,
    'money': money2hashcat,
    'neo': neo2hashcat,
    'oubliette': oubliette2hashcat,
    'padlock': padlock2hashcat,
    'ps_token': ps_token2hashcat,
    'pse': pse2hashcat,
    'strip': strip2hashcat,
    'apop': apop2hashcat,
    'filezilla': filezilla2hashcat,
    'deepsound': deepsound2hashcat,
    'bitshares': bitshares2hashcat,
    'bks': bks2hashcat,
    'keystore': keystore2hashcat,
    'kwallet': kwallet2hashcat,
    'keplr': keplr2hashcat,
    'adxcsouf': adxcsouf2hashcat,
    'aem': aem2hashcat,
    'DPAPImk': DPAPImk2hashcat,
    'encdatavault': encdatavault2hashcat,
    'sspr': sspr2hashcat,
}


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Hashcatizer extended converter module.\n"
                    "Use --type to select a converter.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--type', '-t', required=True, choices=sorted(CONVERTERS.keys()),
                        help="Converter type to use")
    parser.add_argument('files', nargs='+', help="Input file(s)")
    args = parser.parse_args()
    converter = CONVERTERS[args.type]
    for f in args.files:
        converter(f)


if __name__ == "__main__":
    main()
