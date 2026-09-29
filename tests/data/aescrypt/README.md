# AES Crypt fixtures

`kat.txt` holds known-answer streams for versions 0–3 (password
`kat password ✓`, fixed IVs and session key, three plaintexts each).

Every `.aes` file decrypts to `fox.txt` (`fox.*.aes`) or to nothing
(`empty.*.aes`) with the password `aescry test ✓`. The ✓ checks that
non-ASCII passwords are encoded correctly: UTF-16LE for versions 0–2 and
UTF-8 for version 3.

| Files | Written by |
|-------|-----------|
| `*.v0.aes`, `*.v1.aes`, `*.v2.aes` | [`legacy_writer.py`](legacy_writer.py), an independent Python implementation of the format (no current tool writes these versions) |
| `*.v3.aes` | aescry 0.5.0, with 1000 PBKDF2 iterations |
| `kat.txt` | [`kat_writer.py`](kat_writer.py), an independent deterministic writer for all versions; aescry must reproduce every stream octet for octet |

Each fixture and known-answer stream was also decrypted with the official AES Crypt 4.7 command-line
tool (`aescrypt -d`) before it was added. No file here was produced by
AES Crypt software.
