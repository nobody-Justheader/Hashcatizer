#!/usr/bin/env python3
"""
Batch converter collection — smaller converters in one module.

This module contains simpler converters that share common patterns:
- Read file → extract specific fields → output hashcat format.

Each converter is a standalone function that can also be used individually.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.common import (
    bytes_to_hex, create_parser, error, output_hash,
    print_mode_info, validate_file, warn,
)

# ============================================================================
# Individual converter implementations
# ============================================================================


def monero2hashcat(filename):
    """Monero wallet hash extractor (mode 28300)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Monero wallet files start with specific header
    if len(data) < 48:
        error("File too small for Monero wallet", filename)
        return
    # Extract first 48 bytes as crypto data
    output_hash("$monero$0*%s" % bytes_to_hex(data[:48]))


def dashlane2hashcat(filename):
    """Dashlane vault hash extractor (mode 28000)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    text = data.decode('utf-8', errors='ignore')
    # Dashlane uses AES-256-CBC with PBKDF2
    # The file starts with salt (32 bytes) + encrypted data
    if len(data) >= 48:
        salt = data[:32]
        enc = data[32:64]
        output_hash("$dashlane$1*%s*%s" % (bytes_to_hex(salt), bytes_to_hex(enc)))
        return
    # Try JSON
    try:
        j = json.loads(text)
        if 'salt' in j and 'content' in j:
            output_hash("$dashlane$1*%s*%s" % (j['salt'], j['content'][:64]))
            return
    except Exception:
        pass
    error("Could not parse Dashlane vault data", filename)


def tezos2hashcat(filename):
    """Tezos wallet hash extractor (mode 25900)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        error(str(e), filename)
        return
    # Tezos encrypted key format
    if isinstance(data, list):
        for entry in data:
            _process_tezos_entry(entry)
    elif isinstance(data, dict):
        _process_tezos_entry(data)


def _process_tezos_entry(entry):
    if not isinstance(entry, dict):
        return
    # Look for encrypted secret key
    for key in ('encrypted_secret_key', 'secret_key', 'sk'):
        if key in entry:
            val = entry[key]
            if val.startswith('encrypted:') or val.startswith('p2esk') or val.startswith('spesk') or val.startswith('edesk'):
                try:
                    # Base58check decode would give us the raw data
                    # For simplicity, output in JtR-compatible format
                    output_hash("$tezos$%s" % val)
                except Exception:
                    pass


def coinomi2hashcat(filename):
    """Coinomi wallet hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Coinomi uses protobuf format
    if len(data) >= 48:
        output_hash("$coinomi$%s" % bytes_to_hex(data[:min(256, len(data))]))


def cardano2hashcat(filename):
    """Cardano wallet hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        error(str(e), filename)
        return
    if 'data' in data:
        output_hash("$cardano$%s" % data['data'])


def androidbackup2hashcat(filename):
    """Android backup hash extractor (mode 18900)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            header = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    text = header.decode('utf-8', errors='ignore')
    lines = text.split('\n')
    if len(lines) < 5 or lines[0] != 'ANDROID BACKUP':
        error("Not an Android backup file", filename)
        return
    version = int(lines[1]) if lines[1].isdigit() else 0
    compress = int(lines[2]) if lines[2].isdigit() else 0
    encryption = lines[3].strip()
    if encryption == 'none':
        error("Backup is not encrypted", filename)
        return
    # Remaining lines: user password salt, master key checksum salt,
    # rounds, user IV, master key blob
    if len(lines) >= 9:
        user_salt = lines[4].strip()
        ck_salt = lines[5].strip()
        rounds = lines[6].strip()
        user_iv = lines[7].strip()
        mk_blob = lines[8].strip()
        hashline = "$ab$%s*%s*%s*%s*%s*%s" % (
            version, rounds, user_salt, ck_salt, user_iv, mk_blob
        )
        output_hash(hashline)
    else:
        error("Incomplete Android backup header", filename)


def androidfde2hashcat(filename):
    """Android FDE hash extractor (mode 8800)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(16384)
    except IOError as e:
        error(str(e), filename)
        return
    # Look for Android FDE footer magic
    magic = b'\xd0\xb5\xb1\xc4'
    pos = data.find(magic)
    if pos == -1:
        # Try reading from end of file
        try:
            with open(filename, 'rb') as f:
                f.seek(-16384, 2)
                data = f.read()
        except IOError:
            pass
        pos = data.find(magic)
    if pos == -1:
        error("No Android FDE footer found", filename)
        return
    footer = data[pos:]
    if len(footer) < 104:
        error("FDE footer too small", filename)
        return
    # Parse crypto footer
    ftr_magic = struct.unpack('<I', footer[0:4])[0]
    major = struct.unpack('<H', footer[4:6])[0]
    minor = struct.unpack('<H', footer[6:8])[0]
    ftr_size = struct.unpack('<I', footer[8:12])[0]
    flags = struct.unpack('<I', footer[12:16])[0]
    keysize = struct.unpack('<I', footer[16:20])[0]
    failed_decrypt = struct.unpack('<I', footer[20:24])[0]
    crypto_type = footer[24:56].rstrip(b'\x00').decode('ascii', errors='ignore')
    master_key = footer[56:56 + keysize] if keysize <= 48 else footer[56:104]
    salt = footer[104:104 + 16] if len(footer) > 120 else b''
    # N_factor, r_factor, p_factor for scrypt
    if len(footer) > 140:
        n_factor = struct.unpack('<I', footer[120:124])[0]
        r_factor = struct.unpack('<I', footer[124:128])[0]
        p_factor = struct.unpack('<I', footer[128:132])[0]
        hashline = "$fde$%d$%s$%d$%s$%d$%d$%d" % (
            keysize, bytes_to_hex(master_key[:keysize]),
            len(salt), bytes_to_hex(salt),
            n_factor, r_factor, p_factor
        )
        output_hash(hashline)
    else:
        hashline = "$fde$%d$%s$%d$%s" % (
            keysize, bytes_to_hex(master_key[:keysize]),
            len(salt), bytes_to_hex(salt),
        )
        output_hash(hashline)


def axcrypt2hashcat(filename):
    """AxCrypt hash extractor (mode 13200)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    # AxCrypt magic: c0 b9 07 2e
    if data[:4] != b'\xc0\xb9\x07\x2e':
        error("Not an AxCrypt file", filename)
        return
    # Parse AxCrypt header sections
    offset = 4
    salt = None
    key_wrap_iterations = 0
    wrapped_key = None
    while offset + 4 < len(data):
        header_type = struct.unpack('<I', data[offset:offset + 4])[0]
        header_len = struct.unpack('<I', data[offset + 4:offset + 8])[0] if offset + 8 <= len(data) else 0
        if header_len == 0 or offset + 8 + header_len > len(data):
            break
        section_data = data[offset + 8:offset + 8 + header_len]
        if header_type == 4:  # Key wrap iterations
            key_wrap_iterations = struct.unpack('<I', section_data[:4])[0] if len(section_data) >= 4 else 0
        elif header_type == 5:  # Salt
            salt = section_data
        elif header_type == 24:  # Wrapped key
            wrapped_key = section_data
        offset += 8 + header_len
    if salt and wrapped_key:
        hashline = "$axcrypt$*1*%d*%s*%s" % (
            key_wrap_iterations, bytes_to_hex(salt), bytes_to_hex(wrapped_key)
        )
        output_hash(hashline)
    else:
        error("Could not extract AxCrypt key data", filename)


def iwork2hashcat(filename):
    """Apple iWork hash extractor (mode 23400)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # iWork encrypted files use protobuf
    # Look for EncryptionInfo within the zip
    try:
        import zipfile
        if zipfile.is_zipfile(filename):
            zf = zipfile.ZipFile(filename)
            for name in zf.namelist():
                if 'EncryptedDocument' in name or 'encryption' in name.lower():
                    enc_data = zf.read(name)
                    output_hash("$iwork$%s" % bytes_to_hex(enc_data[:min(256, len(enc_data))]))
                    return
    except Exception:
        pass
    error("Could not parse iWork document", filename)


def libreoffice2hashcat(filename):
    """LibreOffice/StarOffice hash extractor (mode 18400)."""
    if not validate_file(filename):
        return
    try:
        import zipfile
        if not zipfile.is_zipfile(filename):
            error("Not a zip file (LibreOffice format)", filename)
            return
        zf = zipfile.ZipFile(filename)
        if 'META-INF/manifest.xml' not in zf.namelist():
            error("No manifest.xml found", filename)
            return
        manifest = zf.read('META-INF/manifest.xml').decode('utf-8', errors='ignore')
        root = ET.fromstring(manifest)
        ns = {'m': 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'}
        for entry in root.findall('.//m:file-entry', ns):
            enc_data_elem = entry.find('.//m:encryption-data', ns)
            if enc_data_elem is not None:
                algo = enc_data_elem.find('.//m:algorithm', ns)
                kd = enc_data_elem.find('.//m:key-derivation', ns)
                start = enc_data_elem.find('.//m:start-key-generation', ns)
                if algo is not None and kd is not None:
                    iv = algo.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}initialisation-vector', '')
                    salt_b64 = kd.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}salt', '')
                    iter_count = kd.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}iteration-count', '')
                    key_size = kd.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}key-size', '16')
                    checksum = enc_data_elem.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}checksum', '')
                    # Get some encrypted content
                    path = entry.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}full-path', '')
                    enc_content = b''
                    if path and path in zf.namelist():
                        enc_content = zf.read(path)[:1024]
                    salt = base64.b64decode(salt_b64) if salt_b64 else b''
                    iv_bytes = base64.b64decode(iv) if iv else b''
                    checksum_bytes = base64.b64decode(checksum) if checksum else b''
                    hashline = "$odf$*0*0*%s*%s*%s*%d*%s*%s" % (
                        iter_count, key_size,
                        bytes_to_hex(checksum_bytes),
                        len(salt), bytes_to_hex(salt),
                        bytes_to_hex(iv_bytes),
                    )
                    output_hash(hashline)
                    return
    except Exception as e:
        error("Failed to parse LibreOffice file: %s" % str(e), filename)


def keychain2hashcat(filename):
    """macOS Keychain hash extractor (mode 23100)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # macOS keychain magic: kych
    magic = b'kych'
    if data[:4] != magic:
        # Try finding it
        pos = data.find(magic)
        if pos == -1:
            error("Not a macOS keychain file", filename)
            return
        data = data[pos:]
    # Extract salt and wrapped key
    if len(data) >= 84:
        salt = data[44:64]  # 20-byte salt at offset 44
        iv = data[64:72]
        wrapped = data[72:96]
        output_hash("$keychain$*%s*%s*%s" % (
            bytes_to_hex(salt), bytes_to_hex(iv), bytes_to_hex(wrapped)
        ))
    else:
        error("Keychain file too small", filename)


def keyring2hashcat(filename):
    """GNOME Keyring hash extractor (mode 23200)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    # GNOME Keyring magic
    magic = b'GnomeKeyring\n\r\0\n'
    if data[:len(magic)] != magic:
        error("Not a GNOME keyring file", filename)
        return
    offset = len(magic)
    if offset + 8 > len(data):
        error("Keyring file too small", filename)
        return
    # Read crypto type, hash iterations, salt
    major = data[offset]
    minor = data[offset + 1]
    crypto = data[offset + 2]
    hash_algo = data[offset + 3]
    offset += 4
    # Name length + name
    name_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4 + name_len
    # Creation/modification times
    offset += 16
    # Flags
    offset += 4
    # Lock timeout
    offset += 8
    # Hash iterations
    if offset + 4 > len(data):
        return
    iterations = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    # Salt (8 bytes)
    salt = data[offset:offset + 8]
    offset += 8
    # Reserved
    offset += 16
    # Number of items
    if offset + 4 > len(data):
        return
    num_items = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    # Encrypted data starts after item definitions
    # Skip item definitions
    for _ in range(num_items):
        if offset + 8 > len(data):
            break
        item_id = struct.unpack('>I', data[offset:offset + 4])[0]
        item_type = struct.unpack('>I', data[offset + 4:offset + 8])[0]
        offset += 8
        # Attributes
        attr_count = struct.unpack('>I', data[offset:offset + 4])[0] if offset + 4 <= len(data) else 0
        offset += 4
        for _ in range(attr_count):
            if offset + 4 > len(data):
                break
            attr_name_len = struct.unpack('>I', data[offset:offset + 4])[0]
            offset += 4 + attr_name_len
            attr_type = struct.unpack('>I', data[offset:offset + 4])[0] if offset + 4 <= len(data) else 0
            offset += 4
            if attr_type == 0:  # string
                val_len = struct.unpack('>I', data[offset:offset + 4])[0] if offset + 4 <= len(data) else 0
                offset += 4 + val_len
            elif attr_type == 1:  # uint32
                offset += 4

    # Encrypted data
    enc_data = data[offset:offset + 48] if offset + 48 <= len(data) else data[offset:]
    hashline = "$keyring$%d*%s*%d*%s" % (
        iterations, bytes_to_hex(salt), crypto, bytes_to_hex(enc_data)
    )
    output_hash(hashline)


def enpass2hashcat(filename):
    """Enpass vault hash extractor (mode 25900)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    # Enpass uses SQLCipher (SQLite extension with encryption)
    # SQLCipher magic: first 16 bytes are the salt
    if len(data) < 32:
        error("File too small for Enpass vault", filename)
        return
    # Check if it's an SQLite file (starts with "SQLite format 3\000")
    if data[:16] == b'SQLite format 3\x00':
        error("Database is not encrypted", filename)
        return
    salt = data[:16]
    enc_page = data[16:16 + 48]  # First encrypted page data
    output_hash("$enpass$0*24000*%s*%s" % (bytes_to_hex(salt), bytes_to_hex(enc_page)))


def diskcryptor2hashcat(filename):
    """DiskCryptor hash extractor (mode 20011)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(2048)
    except IOError as e:
        error(str(e), filename)
        return
    # DiskCryptor header: first 2048 bytes
    if len(data) < 2048:
        error("File too small for DiskCryptor volume", filename)
        return
    # The entire 2048-byte header is needed by hashcat
    output_hash("$diskcryptor$0*%s" % bytes_to_hex(data[:2048]))


def bestcrypt2hashcat(filename):
    """BestCrypt hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(4096)
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 512:
        error("File too small for BestCrypt volume", filename)
        return
    output_hash("$bestcrypt$0*%s" % bytes_to_hex(data[:512]))


def openssl2hashcat(filename):
    """OpenSSL encrypted file hash extractor (mode 15400)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(48)
    except IOError as e:
        error(str(e), filename)
        return
    # OpenSSL "Salted__" magic + 8-byte salt + encrypted data
    if data[:8] != b'Salted__':
        # May be in PEM/b64 format
        try:
            text = open(filename, 'r').read()
            lines = text.strip().split('\n')
            # Skip PEM headers
            b64_data = ''.join(l for l in lines if not l.startswith('-----'))
            decoded = base64.b64decode(b64_data)
            if decoded[:8] == b'Salted__':
                data = decoded
            else:
                error("Not an OpenSSL encrypted file", filename)
                return
        except Exception:
            error("Not an OpenSSL encrypted file", filename)
            return
    salt = data[8:16]
    ct = data[16:48]
    output_hash("$openssl$0*%s*%s" % (bytes_to_hex(salt), bytes_to_hex(ct)))


def ecryptfs2hashcat(filename):
    """eCryptfs hash extractor (mode 12200)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # eCryptfs wrapped-passphrase file or sig file
    if len(data) >= 58:
        # wrapped-passphrase format: salt(8) + wrapped(48)
        salt = data[:8]
        wrapped = data[8:56]
        output_hash("$ecryptfs$0$1$%s$%s" % (bytes_to_hex(salt), bytes_to_hex(wrapped)))


def fvde2hashcat(filename):
    """FileVault 2 hash extractor (mode 16700)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(65536)
    except IOError as e:
        error(str(e), filename)
        return
    # FileVault 2 uses CoreStorage with PBKDF2-SHA256
    # Look for EncryptedRoot.plist.wipekey
    # The volume header contains encrypted metadata
    if len(data) < 512:
        error("File too small for FileVault 2 volume", filename)
        return
    # Output raw header for hashcat
    output_hash("$fvde$1*%s" % bytes_to_hex(data[:min(4096, len(data))]))


def vmx2hashcat(filename):
    """VMware VMX hash extractor (mode 27400)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            text = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # Look for encryption keySafe and related fields
    ks_match = re.search(r'encryption\.keySafe\s*=\s*"([^"]+)"', text)
    if not ks_match:
        error("No encryption keySafe found", filename)
        return
    key_safe = ks_match.group(1)

    # Parse the keySafe blob
    # Format: vmware:key/list/(...)
    output_hash("$vmx$%s" % key_safe)


def restic2hashcat(filename):
    """Restic backup repository hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        error(str(e), filename)
        return
    # Restic key file contains N, r, p, salt, data
    n = data.get('N', 0)
    r = data.get('r', 0)
    p = data.get('p', 0)
    salt = data.get('salt', '')
    key_data = data.get('data', '')
    if not salt or not key_data:
        error("Missing salt or data in Restic key", filename)
        return
    output_hash("$restic$%d*%d*%d*%s*%s" % (n, r, p, salt, key_data))


def staroffice2hashcat(filename):
    """StarOffice hash extractor (mode 18600)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # StarOffice uses Blowfish-CFB with SHA1
    # Look for encrypted content stream in OLE
    try:
        import olefile
        if not olefile.isOleFile(filename):
            error("Not an OLE file", filename)
            return
        ole = olefile.OleFileIO(filename)
        if not ole.exists('EncryptedPackage') and not ole.exists('Content'):
            error("No encrypted content found", filename)
            return
        # Get encryption data
        if ole.exists('EncryptionInfo'):
            enc_info = ole.openstream('EncryptionInfo').read()
            output_hash("$staroffice$%s" % bytes_to_hex(enc_info[:min(256, len(enc_info))]))
        elif ole.exists('Content'):
            content = ole.openstream('Content').read()[:64]
            output_hash("$staroffice$%s" % bytes_to_hex(content))
        ole.close()
    except ImportError:
        error("olefile library required", filename)


def multibit2hashcat(filename):
    """MultiBit wallet hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # MultiBit Classic (.key files contain salt + encrypted key)
    if filename.endswith('.key') or filename.endswith('.key.backup'):
        text = data.decode('utf-8', errors='ignore').strip()
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if len(line) >= 48 and all(c in '0123456789abcdefABCDEF' for c in line):
                salt_hex = line[:16]
                enc_hex = line[16:]
                output_hash("$multibit$1*%s*%s" % (salt_hex, enc_hex))
                return
    # MultiBit HD (.wallet)
    if len(data) >= 16:
        # Protobuf format
        output_hash("$multibit$2*%s" % bytes_to_hex(data[:min(256, len(data))]))


def known_hosts2hashcat(filename):
    """SSH known_hosts hash extractor (mode 160)."""
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
        if line.startswith('|1|'):
            parts = line.split(' ')
            if len(parts) >= 2:
                hash_field = parts[0]
                # |1|base64salt|base64hash
                fields = hash_field.split('|')
                if len(fields) >= 4:
                    salt_b64 = fields[2]
                    hash_b64 = fields[3]
                    try:
                        salt = base64.b64decode(salt_b64)
                        h = base64.b64decode(hash_b64)
                        output_hash("$sshng$%s$%s" % (
                            bytes_to_hex(salt), bytes_to_hex(h)
                        ))
                    except Exception:
                        pass


def htdigest2hashcat(filename):
    """Apache htdigest hash extractor (mode 1600)."""
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
        if ':' in line:
            parts = line.split(':')
            if len(parts) == 3:
                user = parts[0]
                realm = parts[1]
                h = parts[2]
                output_hash("%s:$htdigest$%s$%s$%s" % (user, user, realm, h))


def pem2hashcat(filename):
    """PEM encrypted key hash extractor (mode 22911)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'r') as f:
            text = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    if 'ENCRYPTED' not in text:
        error("PEM file is not encrypted", filename)
        return
    # Parse DEK-Info header
    dek_match = re.search(r'DEK-Info:\s*(\S+),([0-9a-fA-F]+)', text)
    if not dek_match:
        error("No DEK-Info found in PEM", filename)
        return
    cipher = dek_match.group(1)
    iv_hex = dek_match.group(2)
    # Get base64 data
    lines = text.split('\n')
    b64_lines = []
    in_data = False
    for line in lines:
        if line.startswith('-----BEGIN'):
            in_data = True
            continue
        if line.startswith('-----END'):
            break
        if in_data and ':' not in line and line.strip():
            b64_lines.append(line.strip())
    b64_data = ''.join(b64_lines)
    try:
        raw = base64.b64decode(b64_data)
    except Exception:
        error("Failed to decode PEM data", filename)
        return
    output_hash("$PEM$1*%s*%s*%d*%s" % (
        cipher.replace('-', '_'), iv_hex, len(raw), bytes_to_hex(raw[:min(256, len(raw))])
    ))


def pfx2hashcat(filename):
    """PKCS#12/PFX hash extractor (mode 23700)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(str(e), filename)
        return
    # PKCS#12 starts with ASN.1 SEQUENCE tag
    if data[0] != 0x30:
        error("Not a valid PKCS#12/PFX file", filename)
        return
    # Extract enough data for hashcat
    # Hashcat processes the raw DER data
    output_hash("$pfx$*%d*%s" % (len(data), bytes_to_hex(data[:min(4096, len(data))])))


def geli2hashcat(filename):
    """FreeBSD GELI hash extractor (mode 26500)."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(8192)
    except IOError as e:
        error(str(e), filename)
        return
    # GELI metadata is at sector 0 with a specific magic
    if len(data) < 512:
        error("File too small for GELI volume", filename)
        return
    output_hash("$geli$0*%s" % bytes_to_hex(data[:512]))


def openbsd_softraid2hashcat(filename):
    """OpenBSD Softraid hash extractor."""
    if not validate_file(filename):
        return
    try:
        with open(filename, 'rb') as f:
            data = f.read(8192)
    except IOError as e:
        error(str(e), filename)
        return
    if len(data) < 512:
        error("File too small", filename)
        return
    output_hash("$softraid$0*%s" % bytes_to_hex(data[:512]))


# Registry of all converters in this module
CONVERTERS = {
    'monero': monero2hashcat,
    'dashlane': dashlane2hashcat,
    'tezos': tezos2hashcat,
    'coinomi': coinomi2hashcat,
    'cardano': cardano2hashcat,
    'androidbackup': androidbackup2hashcat,
    'androidfde': androidfde2hashcat,
    'axcrypt': axcrypt2hashcat,
    'iwork': iwork2hashcat,
    'libreoffice': libreoffice2hashcat,
    'keychain': keychain2hashcat,
    'keyring': keyring2hashcat,
    'enpass': enpass2hashcat,
    'diskcryptor': diskcryptor2hashcat,
    'bestcrypt': bestcrypt2hashcat,
    'openssl': openssl2hashcat,
    'ecryptfs': ecryptfs2hashcat,
    'fvde': fvde2hashcat,
    'vmx': vmx2hashcat,
    'restic': restic2hashcat,
    'staroffice': staroffice2hashcat,
    'multibit': multibit2hashcat,
    'known_hosts': known_hosts2hashcat,
    'htdigest': htdigest2hashcat,
    'pem': pem2hashcat,
    'pfx': pfx2hashcat,
    'geli': geli2hashcat,
    'openbsd_softraid': openbsd_softraid2hashcat,
}


def main():
    """CLI entry point for batch converters."""
    import argparse
    parser = argparse.ArgumentParser(
        description="Hashcatizer batch converter module.\n"
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
