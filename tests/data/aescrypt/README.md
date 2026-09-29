# AES Crypt fixtures

Every `.aes` file decrypts to `fox.txt` (`fox.*.aes`) or to nothing
(`empty.*.aes`) with the password `aescry test ✓`. The ✓ checks that
non-ASCII passwords are encoded correctly: UTF-16LE for versions 0–2 and
UTF-8 for version 3.

| Files | Written by |
|-------|-----------|
| `*.v0.aes`, `*.v1.aes`, `*.v2.aes` | [`legacy_writer.py`](legacy_writer.py), an independent Python implementation of the format (no current tool writes these versions) |
| `*.v3.aes` | aescry 0.5.0, with 1000 PBKDF2 iterations |

Each fixture was also decrypted with the official AES Crypt 4.7 command-line
tool (`aescrypt -d`) before it was added. No file here was produced by
AES Crypt software.
