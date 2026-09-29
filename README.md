# aescry

AES encryption and decryption for Rust, with support for the
[AES Crypt](https://www.aescrypt.com/aes_stream_format.html) file format.

`aescry` implements its cryptography in pure Rust. Its only dependency is
[`getrandom`](https://crates.io/crates/getrandom), for the operating system's
random number generator.

- **`aescrypt`**: password-based encryption of data, streams and files in the
  AES Crypt format (reads versions 0–3, writes version 3), compatible with
  the AES Crypt 4.x tools
- **`security`**: a toolkit for security work with raw-byte passwords, IVs
  and keys; writes every format version, inspects and verifies streams, and
  decrypts with recovered keys
- **`cbc`**: encrypt and decrypt raw byte buffers with AES in CBC mode
- **`aes`**: the AES-128, AES-192 and AES-256 block cipher (FIPS-197)
- **`padding`**: PKCS#7 padding
- **`random`**: secure random keys, IVs and bytes
- **`sha256`**, **`sha512`**: SHA-256 and SHA-512 (FIPS 180-2)
- **`hmac`**: HMAC-SHA256 and HMAC-SHA512 with constant-time verification
- **`kdf`**: PBKDF2 and the AES Crypt legacy key derivation
- **`ct`**: constant-time comparison
- **`zeroize`**: wiping secrets from memory
- **`detect`**: detection of AES Crypt files and streams (format versions 0–3)

## Installation

```toml
[dependencies]
aescry = "1.0.0-beta.2"
```

`aescry` requires Rust 1.63 or newer.

## Usage

### Encrypting with a password (AES Crypt format)

`aescrypt::encrypt` and `aescrypt::decrypt` work on any bytes in memory. The
output is a complete AES Crypt stream: a `.aes` file's contents.

```rust
use aescry::aescrypt;

let data: &[u8] = b"any bytes: text, images, archives \x00\xff";

let encrypted = aescrypt::encrypt("correct horse battery staple", data)?;
let decrypted = aescrypt::decrypt("correct horse battery staple", &encrypted)?;
assert_eq!(decrypted, data);
# Ok::<(), aescry::Error>(())
```

Decryption verifies both HMACs before returning anything. A wrong password
gives `Error::InvalidPassword`, and modified or truncated data gives
`Error::AlteredMessage`.

`Encryptor` and `Decryptor` add settings, streaming and files:

```rust,no_run
use aescry::aescrypt::{Decryptor, Encryptor, Extension, Iterations};

let encryptor = Encryptor::new("correct horse battery staple")?
    .iterations(Iterations::new(1_000_000)?) // 1 to 5,000,000; default 600,000
    .extension(Extension::new("urn:example:owner", "alice")?);

encryptor.encrypt_file("report.pdf", "report.pdf.aes")?;

let decryptor = Decryptor::new("correct horse battery staple")?;
decryptor.decrypt_file("report.pdf.aes", "report-decrypted.pdf")?;

// Any Read to any Write, without holding the data in memory.
let input = std::fs::File::open("big.tar")?;
let output = std::fs::File::create("big.tar.aes")?;
encryptor.encrypt_stream(input, output)?;
# Ok::<(), aescry::Error>(())
```

- `encrypt_file` and `decrypt_file` write to a temporary file and rename it
  into place when done. A failed decryption never leaves unauthenticated
  output behind.
- `decrypt_stream` writes plaintext as it goes, so if it returns an error,
  discard what it wrote.
- `aescrypt::read_header` reads the unencrypted header: version, iteration
  count and extensions.
- Reading is bounded by `Limits`: at most 5,000,000 PBKDF2 iterations, a
  1 MiB header and 256 extensions. `Decryptor::limits` can lower these.

| Format version | Read | Write            | Key derivation     | Written by                  |
|----------------|------|------------------|--------------------|-----------------------------|
| 3              | ✓    | ✓                | PBKDF2-HMAC-SHA512 | AES Crypt 4.x               |
| 2              | ✓    | `security` only  | 8192 × SHA-256     | AES Crypt 3.x, pyAesCrypt   |
| 1              | ✓    | `security` only  | 8192 × SHA-256     | older AES Crypt             |
| 0              | ✓    | `security` only  | 8192 × SHA-256     | older AES Crypt             |

### Security toolkit: raw bytes for passwords, IVs and keys

The `security` module gives direct control over every input, for work such
as testing other AES Crypt implementations, generating test vectors,
forensics, and recovering your own data. Raw bytes are checked once, when
they become typed values, and the risky operations are separate types, so
they can't be used by accident.

```rust
use aescry::security::{
    inspect, verify, DecryptKey, EncryptKey, PublicIv, RawDecryptor, RawEncryptor, SessionIv, SessionKey,
};
use aescry::Version;

// Any octets can be the password: not necessarily UTF-8 or UTF-16.
let password: &[u8] = &[0x00, 0xFF, 0xC3, 0x28];

// Fixed IVs and session key make the output reproducible. This is a
// separate type, RawEncryptor<Deterministic>, because reusing IVs is unsafe.
let stream = RawEncryptor::new(EncryptKey::raw_password(password))
    .version(Version::V2)           // any format version, 0 to 3
    .deterministic(
        PublicIv::try_from(&[0x01; 16][..])?, // raw bytes, length-checked once
        SessionIv::from([0x02; 16]),
        SessionKey::from([0x03; 32]),
    )
    .encrypt(b"test vector")?;

// Map the stream's structure without a password.
let layout = inspect(&stream)?;
assert_eq!(layout.plaintext_len(), Some(11));

// Check both HMACs without producing plaintext.
assert!(verify(&DecryptKey::raw_password(password), &stream)?.is_authentic());

// Decrypt, and get the derived key and session key (wiped when dropped).
let opened = RawDecryptor::new(DecryptKey::raw_password(password)).decrypt(&stream)?;
assert_eq!(opened.plaintext(), b"test vector");
let report = opened.report();

// Later: skip key derivation, or bypass the password entirely.
let derived = report.derived_key().unwrap().clone_secret();
let again = RawDecryptor::new(DecryptKey::Derived(derived)).decrypt(&stream)?;
let session = DecryptKey::Session(*report.session_iv(), report.session_key().clone_secret());
let again = RawDecryptor::new(session).decrypt(&stream)?;
# let _ = again;
# Ok::<(), aescry::Error>(())
```

Decrypting a damaged or tampered stream is possible, but the result is
wrapped so it can't be used as if it were verified:

```rust,no_run
use aescry::security::{DecryptKey, RawDecryptor};

let damaged = std::fs::read("damaged.aes")?;
let result = RawDecryptor::new(DecryptKey::password("pw")?)
    .skip_verification()           // RawDecryptor<Unverified>
    .decrypt(&damaged)?;           // Unauthenticated<Decrypted>

println!("authentic: {}", result.is_authentic());
let recovered = result.assume_authentic(); // an explicit, visible choice
# let _ = recovered;
# Ok::<(), aescry::Error>(())
```

The toolkit also offers:
- `Password::encoded` and `DerivedKey::derive` show exactly what the key
  derivation receives and produces.
- `RawDecryptor::limits` can raise `Limits` above the defaults, for example
  for streams with more than 5,000,000 iterations.
- `Extension::from_bytes` writes arbitrary, even malformed, header extensions
  for testing parsers.
- `ecb_encrypt` / `ecb_decrypt` are raw block operations on an `AesKey`.

These tools make it easy to do unsafe things, like reusing IVs or trusting
unauthenticated plaintext. Use `aescrypt` for everyday encryption.

### Encrypting byte buffers with a raw key (AES-CBC)

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

// Which implementation is running: AES-NI (constant-time) or software.
println!("{:?}", cipher.backend());
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


## Security

- **Memory safety:** untrusted bytes are handled only by safe Rust. The only
  `unsafe` code is the AES-NI backend (fixed 16-octet blocks) and the
  volatile writes in `zeroize`. Raw bytes for passwords, IVs and keys are
  length-checked once, when they become typed values (`AesKey`, `PublicIv`,
  `SessionIv`, `SessionKey`, `DerivedKey`, `Iterations`, `Password`).
- **Hostile streams:** parsing is bounded by `Limits` before anything is
  allocated. Malformed input returns an error, never a panic; the test suite
  feeds thousands of random and mutated streams to every parser and
  decryptor to check this.
- On x86 and x86-64 CPUs with AES-NI (nearly all since 2010), AES uses the
  hardware instructions. They run in constant time and are much faster. The
  key schedule is also computed without secret-dependent table lookups.
  `aes::Backend::detect()` reports which backend is in use.
- Other CPUs use the portable table-based implementation. Its timing depends
  on the key and data, which can leak them to an attacker who can measure it
  precisely, such as another tenant on the same machine.
  `Backend::is_constant_time()` tells you which case applies.
- Key schedules, hash and MAC states, passwords, derived keys, session keys
  and AES Crypt buffers are wiped from memory when dropped. `secret::Secret`
  holds your own secrets the same way, with constant-time comparison and no
  `Debug` output; `zeroize::Zeroizing` wipes other values.
- `cbc::decrypt` reports bad padding as an error. If callers can observe that
  error for ciphertexts they choose, they can decrypt data (a padding oracle
  attack). Verify a MAC before decrypting.
- `Debug` output never includes key material or passwords.
- AES Crypt header extensions are neither encrypted nor authenticated. Don't
  trust their contents.
- Version 3 streams asking for more than 5,000,000 PBKDF2 iterations are
  refused, so a hostile file can't tie up the CPU for long.
  `Decryptor::limits` lowers the limit.
- `Hmac::verify` compares tags in constant time. `Hmac::verify_truncated`
  refuses tags shorter than 80 bits.

## Releases

Each release adds one feature set; see the [changelog](CHANGELOG.md).

| Version       | Feature set                                                                                       |
|---------------|---------------------------------------------------------------------------------------------------|
| 0.2           | Core primitives: AES block cipher, SHA-256, AES Crypt detection                                   |
| 0.3           | Encrypting byte buffers: CBC mode, PKCS#7 padding, secure random keys and IVs                     |
| 0.4           | Integrity and key derivation: SHA-512, HMAC, constant-time comparison, PBKDF2                     |
| 0.5           | AES Crypt file format: password-based encryption and decryption of buffers, streams and files     |
| 0.6           | Hardening: hardware AES (AES-NI) backend and wiping secrets from memory                           |
| 1.0.0-beta.1  | Security toolkit: raw-byte passwords, IVs and keys; stream inspection and verification            |
| 1.0.0-beta.2  | Type safety: validated key/IV/iteration types, `Secret<T>`, typestate toolkit, resource limits     |

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
- cross-checks against OpenSSL and Python's `hashlib`;
- AES Crypt fixtures and byte-exact known-answer streams for every format
  version (see [`tests/data/aescrypt`](tests/data/aescrypt)). They come from
  an independent Python implementation, and the official AES Crypt tool
  decrypts every one of them.

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
