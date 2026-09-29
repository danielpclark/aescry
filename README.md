# aescry

AES encryption and decryption for Rust, with support for the
[AES Crypt](https://www.aescrypt.com/aes_stream_format.html) file format.

`aescry` implements its cryptography in pure Rust. Its only dependency is
[`getrandom`](https://crates.io/crates/getrandom), for the operating system's
random number generator.

- **`cbc`**: encrypt and decrypt raw byte buffers with AES in CBC mode
- **`aes`**: the AES-128, AES-192 and AES-256 block cipher (FIPS-197)
- **`padding`**: PKCS#7 padding
- **`random`**: secure random keys, IVs and bytes
- **`sha256`**, **`sha512`**: SHA-256 and SHA-512 (FIPS 180-2)
- **`hmac`**: HMAC-SHA256 and HMAC-SHA512 with constant-time verification
- **`kdf`**: PBKDF2 and the AES Crypt legacy key derivation
- **`ct`**: constant-time comparison
- **`detect`**: detection of AES Crypt files and streams (format versions 0–3)

## Installation

```toml
[dependencies]
aescry = "0.4"
```

`aescry` requires Rust 1.63 or newer.

## Usage

### Encrypting byte buffers (AES-CBC)

`cbc::encrypt` and `cbc::decrypt` take a raw key (16, 24 or 32 octets for
AES-128, AES-192 or AES-256), a raw 16-octet IV and the data, and apply PKCS#7
padding. Any bytes work as input: text, files read into memory, serialized
data, and so on.

```rust
use aescry::{cbc, random};

let key = random::bytes::<32>()?; // AES-256
let iv = random::iv()?;           // never reuse an IV with the same key

let data: &[u8] = &[0x00, 0xFF, 0x10, 0x80];
let ciphertext = cbc::encrypt(&key, &iv, data)?;
let plaintext = cbc::decrypt(&key, &iv, &ciphertext)?;
assert_eq!(plaintext, data);
# Ok::<(), aescry::Error>(())
```

To have the IV generated for you and stored in front of the ciphertext:

```rust
use aescry::{cbc, random};

let key = random::bytes::<16>()?; // AES-128
let message = cbc::encrypt_with_random_iv(&key, b"attack at dawn")?; // IV || ciphertext
assert_eq!(cbc::decrypt_with_iv_prefix(&key, &message)?, b"attack at dawn");
# Ok::<(), aescry::Error>(())
```

For data that is already a multiple of 16 octets there are
`cbc::encrypt_no_padding` and `cbc::decrypt_no_padding`. For streaming, use
`CbcEncryptor` and `CbcDecryptor`, which keep the chaining value between
calls:

```rust
use aescry::aes::Aes128;
use aescry::cbc::{CbcDecryptor, CbcEncryptor};

let cipher = Aes128::new(&[0x42; 16]);
let iv = [0x24; 16];
let mut data = [0u8; 64];

let mut encryptor = CbcEncryptor::new(&cipher, &iv);
encryptor.encrypt_in_place(&mut data[..32])?; // any whole number of blocks
encryptor.encrypt_in_place(&mut data[32..])?;

let mut decryptor = CbcDecryptor::new(&cipher, &iv);
decryptor.decrypt_in_place(&mut data)?;
assert_eq!(data, [0u8; 64]);
# Ok::<(), aescry::Error>(())
```

> **Note:** CBC keeps data confidential but does not detect tampering. If an
> attacker can change the ciphertext, authenticate it with a MAC before
> decrypting. See [Authenticating ciphertext](#authenticating-ciphertext).

### Authenticating ciphertext

Encrypt-then-MAC with HMAC-SHA256 detects any change to the IV or ciphertext.
Use separate keys for encryption and authentication, and check the tag
before decrypting.

```rust
use aescry::hmac::{hmac_sha256, HmacSha256};
use aescry::{cbc, random};

let enc_key = random::bytes::<32>()?;
let mac_key = random::bytes::<32>()?;

// Sender: encrypt, then MAC the IV and ciphertext.
let message = cbc::encrypt_with_random_iv(&enc_key, b"wire $100 to Bob")?;
let tag = hmac_sha256(&mac_key, &message);

// Receiver: verify (in constant time) before decrypting.
let mut mac = HmacSha256::new(&mac_key);
mac.update(&message);
mac.verify(&tag)?;
let plaintext = cbc::decrypt_with_iv_prefix(&enc_key, &message)?;
# assert_eq!(plaintext, b"wire $100 to Bob");
# Ok::<(), aescry::Error>(())
```

### Deriving keys from passwords

```rust
use aescry::kdf;

let salt = aescry::random::bytes::<16>()?; // store the salt with the data
let key: [u8; 32] = kdf::pbkdf2_hmac_sha512_array(b"correct horse", &salt, 600_000)?;
# Ok::<(), aescry::Error>(())
```

`kdf::aescrypt_legacy` is the iterated SHA-256 derivation of AES Crypt formats
0–2, and `kdf::utf16le` encodes a password the way those formats expect.

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

### Hashing

```rust
use aescry::sha256::{sha256, Sha256};
use aescry::sha512::sha512;

let digest = sha256(b"abc");

let mut hasher = Sha256::new();
hasher.update(b"a");
hasher.update(b"bc");
assert_eq!(hasher.finalize(), digest);

assert_eq!(sha512(b"abc").len(), 64);
```

`aescry::ct::eq` compares secret values such as tags in constant time.

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

- `cbc::decrypt` reports bad padding as an error. If callers can observe that
  error for ciphertexts they choose, they can decrypt data (a padding oracle
  attack). Verify a MAC before decrypting.
- The AES implementation uses lookup tables indexed by secret data. Its
  timing can leak information about the key to an attacker who can measure it
  precisely, for example another tenant on the same machine. A hardware-backed,
  constant-time backend is planned.
- `Debug` output of cipher, hash and MAC types never includes key material.
- `Hmac::verify` compares tags in constant time. `Hmac::verify_truncated`
  refuses tags shorter than 80 bits.

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

Tests cover:
- the FIPS-197, FIPS 180-2 and NIST SP 800-38A examples;
- the Rijndael Monte Carlo tests;
- vectors from the [RustCrypto](https://github.com/RustCrypto) project (see
  [`tests/data/rustcrypto`](tests/data/rustcrypto)): NESSIE AES, NIST CAVP
  CBC, SHA-2 known answers, HMAC from RFC 4231 and Project Wycheproof, and
  PBKDF2;
- cross-checks against OpenSSL and Python's `hashlib`.

To test with the minimum supported Rust version, first pick dependency
versions that support it:

```sh
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo generate-lockfile
cargo +1.63 test
```

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
