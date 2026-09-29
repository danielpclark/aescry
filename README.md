# aescry

AES encryption and decryption for Rust, with support for the
[AES Crypt](https://www.aescrypt.com/aes_stream_format.html) file format.

`aescry` implements its cryptography in pure Rust with no dependencies:

- **`aes`**: the AES-128, AES-192 and AES-256 block cipher (FIPS-197)
- **`sha256`**: SHA-256 (FIPS 180-2)
- **`detect`**: detection of AES Crypt files and streams (format versions 0–3)

## Installation

```toml
[dependencies]
aescry = "0.2"
```

`aescry` requires Rust 1.63 or newer.

## Usage

### AES block cipher

Each cipher type encrypts and decrypts single 16-octet blocks in place. Use
`Aes128`, `Aes192` or `Aes256` when the key size is known at compile time, or
`Aes` to choose it at runtime from the key's length.

```rust
use aescry::aes::{Aes, Aes256, BlockCipher};

let key = [0x42u8; 32];
let cipher = Aes256::new(&key);

let mut block = *b"exactly 16 bytes";
cipher.encrypt_block(&mut block);
assert_ne!(&block, b"exactly 16 bytes");

cipher.decrypt_block(&mut block);
assert_eq!(&block, b"exactly 16 bytes");

// Key size chosen at runtime: 16, 24 or 32 octets.
let cipher = Aes::new(&key[..16])?;
assert_eq!(cipher.key_size(), 16);
assert!(Aes::new(&key[..20]).is_err());
# Ok::<(), aescry::Error>(())
```

> **Note:** encrypting blocks one at a time with the same key (ECB mode)
> reveals which blocks are equal. The block cipher is a building block for
> modes like CBC. It is not a way to encrypt messages on its own.

### SHA-256

```rust
use aescry::sha256::{sha256, Sha256};

let digest = sha256(b"abc");

let mut hasher = Sha256::new();
hasher.update(b"a");
hasher.update(b"bc");
assert_eq!(hasher.finalize(), digest);
```

### Detecting AES Crypt files

Detection checks for the `AES` magic octets, a known format version and, when
the length is known, the minimum length of a valid stream of that version.

```rust,no_run
use aescry::detect;

// From a file on disk; returns None instead of an error.
if let Some(file) = detect::get_file("secrets.txt.aes") {
    println!("{} uses {}", file.path().display(), file.version());
}

// From a file, keeping I/O errors.
let version = detect::from_file("secrets.txt.aes")?;

// From bytes already in memory.
let data = std::fs::read("secrets.txt.aes")?;
if let Some(version) = detect::from_bytes(&data) {
    println!("version {}", version.as_u8());
}

// From any reader (reads only the 4-octet header).
let version = detect::from_reader(std::io::stdin())?;
# Ok::<(), std::io::Error>(())
```

| Version | Key derivation                | Notes                               |
|---------|-------------------------------|-------------------------------------|
| 0       | 8192 × SHA-256                | No session key                      |
| 1       | 8192 × SHA-256                | Encrypted session IV and key        |
| 2       | 8192 × SHA-256                | Adds header extensions              |
| 3       | PBKDF2-HMAC-SHA512            | Current format; PKCS#7 padding      |

## Security

- The AES implementation uses lookup tables indexed by secret data. Its
  timing can leak information about the key to an attacker who can measure it
  precisely, for example another tenant on the same machine. A hardware-backed,
  constant-time backend is planned.
- `Debug` output of cipher types never includes key material.

## Roadmap

| Version       | Feature set                                                                                       |
|---------------|---------------------------------------------------------------------------------------------------|
| 0.2           | Core primitives: AES block cipher, SHA-256, AES Crypt detection                                   |
| 0.3           | Encrypting byte buffers: CBC mode, PKCS#7 padding, secure random keys and IVs                     |
| 0.4           | Integrity and key derivation: SHA-512, HMAC, constant-time comparison, PBKDF2                     |
| 0.5           | AES Crypt file format: password-based encryption and decryption of buffers, streams and files     |
| 0.6           | Hardening: hardware AES (AES-NI) backend and wiping secrets from memory                           |
| 1.0.0-beta.1  | Security toolkit: raw-byte passwords, IVs and keys; stream inspection and verification            |

## Development

```sh
cargo test
cargo test --release   # faster run of the AES Monte Carlo tests
```

Tests cover the FIPS-197 examples, the Rijndael Monte Carlo tests and the
NESSIE AES vectors from the [RustCrypto](https://github.com/RustCrypto) project
(see [`tests/data/rustcrypto`](tests/data/rustcrypto)).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
