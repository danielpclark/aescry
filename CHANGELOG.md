# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - Unreleased

First release. The existing primitives are now a public API.

### Added
- `aes` module: the AES-128/192/256 block cipher (`Aes128`, `Aes192`,
  `Aes256`, and `Aes` for a key size chosen at runtime) behind a `BlockCipher`
  trait.
- `sha256` module: an incremental `Sha256` hasher and a one-shot `sha256()`.
- `detect` module: `from_bytes`, `from_header`, `from_reader` and `from_file`,
  plus a `Version` type covering AES Crypt stream format versions 0–3. Detection
  checks the minimum stream length when it is known.
- `Error` type.
- Tests against the NESSIE AES vectors from RustCrypto, the FIPS-197 examples
  and the Rijndael Monte Carlo tests.
- CI on Linux, macOS and Windows, plus Rust 1.63 (the minimum supported
  version).

### Changed
- `detect::get_file` accepts any `AsRef<Path>`. `AesFile::version()` returns
  a `Version` and `AesFile::path()` returns a `&Path`.
- AES tables are compile-time statics instead of being generated per use.
- Edition 2021. `byteorder` is no longer a dependency.

### Fixed
- The crate builds on stable Rust.
- The forward S-box, GF(2^8) multiply, key schedule (including AES-256) and
  decryption key schedule were incorrect.
- SHA-256 read out of bounds on short inputs and mis-padded 55-octet
  remainders.

### Removed
- The unused `AesFileData` and `Extension` placeholder types.

[0.2.0]: https://github.com/danielpclark/aescry/releases/tag/v0.2.0
