#!/usr/bin/env python3
"""
hashcatizer.py — Unified CLI dispatcher for all Hashcatizer converters.

Usage:
    python hashcatizer.py <converter> [options] <file(s)>
    python hashcatizer.py --list
    python hashcatizer.py <converter> --mode-info

Examples:
    python hashcatizer.py ssh id_rsa
    python hashcatizer.py pdf document.pdf
    python hashcatizer.py ethereum keystore.json
    python hashcatizer.py office document.docx
    python hashcatizer.py bitcoin wallet.dat
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


def run_standalone(name, args):
    """Run a standalone converter module."""
    module_name = STANDALONE_CONVERTERS[name]
    # Set sys.argv for the module's argparse
    sys.argv = [name] + args
    try:
        mod = importlib.import_module(module_name)
        mod.main()
    except ImportError as e:
        sys.stderr.write("Error: Failed to import %s: %s\n" % (module_name, e))
        sys.exit(1)


def run_batch(name, args, converter_dict):
    """Run a batch converter function."""
    func = converter_dict[name]
    if not args:
        sys.stderr.write("Error: No input files specified\n")
        sys.exit(1)
    for filename in args:
        func(filename)


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

    converter_name = sys.argv[1]
    remaining_args = sys.argv[2:]

    # Try standalone first
    if converter_name in STANDALONE_CONVERTERS:
        run_standalone(converter_name, remaining_args)
        return

    # Try batch converters
    if converter_name in BATCH_CONVERTERS:
        run_batch(converter_name, remaining_args, BATCH_CONVERTERS)
        return

    # Try extended converters
    if converter_name in EXTENDED_CONVERTERS:
        run_batch(converter_name, remaining_args, EXTENDED_CONVERTERS)
        return

    # Not found
    sys.stderr.write("Error: Unknown converter '%s'\n" % converter_name)
    sys.stderr.write("Use --list to see all available converters.\n")

    # Suggest similar names
    all_names = get_all_converters()
    suggestions = [n for n in all_names if converter_name.lower() in n.lower()]
    if suggestions:
        sys.stderr.write("Did you mean: %s\n" % ', '.join(suggestions))

    sys.exit(1)


if __name__ == "__main__":
    main()
