#!/usr/bin/env python3
"""
hashcatizer.py — Unified CLI dispatcher for all Hashcatizer converters.

Usage:
    python hashcatizer.py <file>                  # Auto-detect and convert
    python hashcatizer.py <hash_string>           # Identify hash type + mode
    python hashcatizer.py <converter> <file(s)>   # Explicit converter
    python hashcatizer.py --list                  # List all converters
    python hashcatizer.py <converter> --mode-info # Show hashcat modes

Examples:
    python hashcatizer.py id_rsa                  # Auto-detects SSH key
    python hashcatizer.py document.pdf            # Auto-detects PDF
    python hashcatizer.py '$2a$10$...'            # Identifies as bcrypt -m 3200
    python hashcatizer.py ssh id_rsa              # Explicit SSH converter
    python hashcatizer.py ethereum keystore.json  # Explicit Ethereum converter
"""

import importlib
import os
import sys

# All standalone converter modules (name -> module)
STANDALONE_CONVERTERS = {
    'ssh': 'converters.ssh2hashcat',
    'ansible': 'converters.ansible2hashcat',
    'ethereum': 'converters.ethereum2hashcat',
    'bitcoin': 'converters.bitcoin2hashcat',
    'bitwarden': 'converters.bitwarden2hashcat',
    'pdf': 'converters.pdf2hashcat',
    'keepass': 'converters.keepass2hashcat',
    'encfs': 'converters.encfs2hashcat',
    'pwsafe': 'converters.pwsafe2hashcat',
    'lastpass': 'converters.lastpass2hashcat',
    'truecrypt': 'converters.truecrypt2hashcat',
    'veracrypt': 'converters.veracrypt2hashcat',
    'office': 'converters.office2hashcat',
    'bitlocker': 'converters.bitlocker2hashcat',
    'luks': 'converters.luks2hashcat',
    'blockchain': 'converters.blockchain2hashcat',
    'dmg': 'converters.dmg2hashcat',
    '1password': 'converters.onepassword2hashcat',
    'electrum': 'converters.electrum2hashcat',
    'telegram': 'converters.telegram2hashcat',
    'signal': 'converters.signal2hashcat',
    'mozilla': 'converters.mozilla2hashcat',
    # New converters — completing 100% JtR coverage
    '7z': 'converters.sevenz2hashcat',
    'pgpsda': 'converters.pgpsda2hashcat',
    'pgpdisk': 'converters.pgpdisk2hashcat',
    'pgpwde': 'converters.pgpwde2hashcat',
    'zed': 'converters.zed2hashcat',
    'mac': 'converters.mac2hashcat',
    'lion': 'converters.lion2hashcat',
    'pcap': 'converters.pcap2hashcat',
    'netntlm': 'converters.netntlm2hashcat',
    'cisco': 'converters.cisco2hashcat',
    'sap': 'converters.sap2hashcat',
    'ldif': 'converters.ldif2hashcat',
    'atmail': 'converters.atmail2hashcat',
    'mongodb': 'converters.mongodb2hashcat',
    'network': 'converters.network2hashcat',
    'ios': 'converters.ios2hashcat',
    'vdi': 'converters.vdi2hashcat',
}

# Batch converters (name -> module.function_name)
BATCH_CONVERTERS = {}
EXTENDED_CONVERTERS = {}


def _load_batch_converters():
    """Dynamically load batch converter registries."""
    global BATCH_CONVERTERS, EXTENDED_CONVERTERS
    try:
        from converters.batch_converters import CONVERTERS as bc
        BATCH_CONVERTERS = bc
    except ImportError:
        pass
    try:
        from converters.extended_converters import CONVERTERS as ec
        EXTENDED_CONVERTERS = ec
    except ImportError:
        pass


def get_all_converters():
    """Return sorted list of all available converter names."""
    _load_batch_converters()
    all_names = set(STANDALONE_CONVERTERS.keys())
    all_names.update(BATCH_CONVERTERS.keys())
    all_names.update(EXTENDED_CONVERTERS.keys())
    return sorted(all_names)


def list_converters():
    """Print all available converters."""
    _load_batch_converters()
    print("=" * 60)
    print("Hashcatizer — Available Converters")
    print("=" * 60)

    print("\n--- Standalone Converters ---")
    for name in sorted(STANDALONE_CONVERTERS.keys()):
        print("  %-20s %s" % (name, STANDALONE_CONVERTERS[name]))

    if BATCH_CONVERTERS:
        print("\n--- Batch Converters (converters/batch_converters.py) ---")
        for name in sorted(BATCH_CONVERTERS.keys()):
            print("  %-20s batch_converters.%s" % (name, name))

    if EXTENDED_CONVERTERS:
        print("\n--- Extended Converters (converters/extended_converters.py) ---")
        for name in sorted(EXTENDED_CONVERTERS.keys()):
            print("  %-20s extended_converters.%s" % (name, name))

    total = len(STANDALONE_CONVERTERS) + len(BATCH_CONVERTERS) + len(EXTENDED_CONVERTERS)
    print("\nTotal: %d converters" % total)
    print("=" * 60)


def run_converter(name, args):
    """Run a converter by name with the given args."""
    if name in STANDALONE_CONVERTERS:
        module_name = STANDALONE_CONVERTERS[name]
        sys.argv = [name] + args
        try:
            mod = importlib.import_module(module_name)
            mod.main()
        except ImportError as e:
            sys.stderr.write("Error: Failed to import %s: %s\n" % (module_name, e))
            sys.exit(1)
    elif name in BATCH_CONVERTERS:
        func = BATCH_CONVERTERS[name]
        for filename in args:
            func(filename)
    elif name in EXTENDED_CONVERTERS:
        func = EXTENDED_CONVERTERS[name]
        for filename in args:
            func(filename)
    else:
        sys.stderr.write("Error: Unknown converter '%s'\n" % name)
        sys.exit(1)


def auto_detect_and_run(files):
    """Auto-detect file types and run appropriate converters."""
    from lib.detect import detect_file_type

    for filename in files:
        converter = detect_file_type(filename)
        if converter:
            sys.stderr.write("[*] Detected: %s → using '%s' converter\n" % (
                os.path.basename(filename), converter))
            run_converter(converter, [filename])
        else:
            sys.stderr.write("[!] Could not auto-detect type of '%s'\n" % filename)
            sys.stderr.write("    Specify converter explicitly: hashcatizer <converter> %s\n" % filename)
            sys.stderr.write("    Run 'hashcatizer --list' to see all converters.\n")


def identify_hash_mode(hash_string):
    """Identify a hash string and print its type + hashcat mode."""
    from lib.detect import identify_hash

    matches = identify_hash(hash_string)
    if matches:
        print("=" * 60)
        print("Hash Identified!")
        print("=" * 60)
        for name, mode in matches:
            if mode > 0:
                print("  %-40s hashcat -m %d" % (name, mode))
            else:
                print("  %-40s (mode varies)" % name)
        print()
        # Print recommended command
        best = matches[0]
        if best[1] > 0:
            print("Recommended:")
            print("  hashcat -m %d '%s' wordlist.txt" % (best[1], hash_string[:60] + ('...' if len(hash_string) > 60 else '')))
        print("=" * 60)
    else:
        print("[!] Hash format not recognized: %s" % hash_string[:80])
        print("    Try: https://hashcat.net/wiki/doku.php?id=example_hashes")


def main():
    # Add project root to path
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    _load_batch_converters()

    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        print("Use --list to see all available converters.")
        sys.exit(0)

    if sys.argv[1] == '--list':
        list_converters()
        sys.exit(0)

    arg1 = sys.argv[1]
    remaining_args = sys.argv[2:]
    all_names = get_all_converters()

    # --- Case 1: Explicit converter name ---
    if arg1 in all_names:
        if not remaining_args:
            sys.stderr.write("Error: No input files specified\n")
            sys.exit(1)
        run_converter(arg1, remaining_args)
        return

    # --- Case 2: Hash string identification ---
    from lib.detect import is_hash_string
    if is_hash_string(arg1):
        identify_hash_mode(arg1)
        return

    # --- Case 3: Auto-detect file(s) ---
    files = [arg1] + remaining_args
    existing_files = [f for f in files if os.path.exists(f)]
    if existing_files:
        auto_detect_and_run(existing_files)
        # Report any non-existent args
        missing = [f for f in files if not os.path.exists(f)]
        for m in missing:
            # Maybe it's a hash string mixed with files
            if is_hash_string(m):
                identify_hash_mode(m)
            else:
                sys.stderr.write("[!] File not found: %s\n" % m)
        return

    # --- Case 4: Not a file, not a known converter — try hash identification ---
    identify_hash_mode(arg1)


if __name__ == "__main__":
    main()
