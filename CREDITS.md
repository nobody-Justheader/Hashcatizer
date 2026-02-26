# Credits & Acknowledgments

## Inspiration

This project is directly inspired by the **`*2john` converter scripts** from the
[John the Ripper](https://github.com/openwall/john) project (bleeding-jumbo branch).

The original `*2john` scripts convert various encrypted file formats into John the Ripper's
hash format. **Hashcatizer** adapts these concepts for [hashcat](https://hashcat.net/hashcat/),
outputting hashes in hashcat-compatible format with appropriate mode numbers.

## Original Authors (openwall/john)

The following individuals authored the original JtR converter scripts that served as
reference implementations for Hashcatizer's extraction logic:

- **Dhiru Kholia** (`@kholia`) — `ssh2john.py`, `ethereum2john.py`, `bitcoin2john.py`,
  `ansible2john.py`, `bitwarden2john.py`, `bitlocker2john.py`, `keepass2john.py`,
  `encfs2john.py`, `truecrypt_volume2john.py`, and many others
- **magnumripper** — Core JtR development and hash format contributions
- **Fist0urs** — `office2john.py`, `pdf2john.py` contributions
- **philsmd** — hashcat format specifications and `itunes_backup2hashcat`
- **Chick3nman** — Ethereum hash format design
- **Gavin Andresen** — Original Bitcoin wallet parsing code

## Projects

- **[openwall/john](https://github.com/openwall/john)** — John the Ripper jumbo.
  The `run/` directory contains 80+ converter scripts under permissive licenses.
  Redistribution and use in source and binary forms, with or without modification, are permitted.

- **[hashcat/hashcat](https://github.com/hashcat/hashcat)** — World's fastest and most
  advanced password recovery utility. Hash format specifications and mode numbers are
  referenced from hashcat's documentation and example hashes.

- **[0x6470/bitwarden2hashcat](https://github.com/0x6470/bitwarden2hashcat)** — Bitwarden
  hash extraction for hashcat.

- **[philsmd/itunes_backup2hashcat](https://github.com/philsmd/itunes_backup2hashcat)** —
  iTunes backup hash extraction.

## License Compatibility

The original JtR Python scripts are released under permissive terms:
> "Redistribution and use in source and binary forms, with or without modification, are permitted."

Hashcatizer is released under the MIT License, which is compatible with this permissive licensing.
