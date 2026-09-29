# aescry

AES encryption and decryption for Rust, with full support for the
[AES Crypt](https://www.aescrypt.com/aes_stream_format.html) file format.

- Encrypt and decrypt **data, streams and files with a password**, compatible
  with the AES Crypt 4.x tools (reads format versions 0–3, writes version 3).
- Encrypt and decrypt **raw byte buffers with your own key** (AES-128/192/256
  in CBC mode).
- The building blocks, all usable on their own: AES, SHA-256, SHA-512, HMAC,
  PBKDF2, PKCS#7 padding, secure randomness, constant-time comparison and
  secret wiping.
- A **security toolkit** for testing, forensics and research, with raw-byte
  control over passwords, IVs and keys.

All cryptography is implemented in Rust. The only dependency is
[`getrandom`](https://crates.io/crates/getrandom), for the operating system's
random number generator. On x86/x86-64 CPUs with AES-NI, AES runs on the
hardware instructions in constant time.

## Contents

- [Installation](#installation)
- [Which API should I use?](#which-api-should-i-use)
- [Quick start](#quick-start)
- [Encrypting with a password (AES Crypt)](#encrypting-with-a-password-aes-crypt)
- [Encrypting with your own key (AES-CBC)](#encrypting-with-your-own-key-aes-cbc)
- [Authenticating ciphertext](#authenticating-ciphertext)
- [Deriving keys from passwords](#deriving-keys-from-passwords)
- [Hashing and MACs](#hashing-and-macs)
- [Building blocks](#building-blocks)
- [Keeping secrets out of memory](#keeping-secrets-out-of-memory)
- [Handling errors](#handling-errors)
- [Security toolkit](#security-toolkit)
- [Security notes](#security-notes)
- [Releases](#releases) · [Development](#development) · [License](#license)

## Installation

```toml
[dependencies]
aescry = "1.0.0-beta.2"
```

`aescry` requires Rust 1.63 or newer.

## Which API should I use?

| You want to…                                                          | Use                                     |
|-----------------------------------------------------------------------|-----------------------------------------|
| Encrypt data or files with a password                                 | [`aescrypt`](#encrypting-with-a-password-aes-crypt) |
| Open `.aes` files made by AES Crypt or pyAesCrypt                      | [`aescrypt`](#encrypting-with-a-password-aes-crypt) |
| Check whether a file is AES Crypt data                                | [`detect`](#detecting-aes-crypt-files)  |
| Encrypt with a key you manage (not a password)                        | [`cbc`](#encrypting-with-your-own-key-aes-cbc) + [`hmac`](#authenticating-ciphertext) |
| Turn a password into a key for your own format                        | [`kdf`](#deriving-keys-from-passwords)  |
| Hash data or compute a MAC                                            | [`sha256`, `sha512`, `hmac`](#hashing-and-macs) |
| Encrypt single blocks, pad, get random bytes, compare in constant time | [building blocks](#building-blocks)     |
| Test other implementations, write old formats, recover damaged files  | [`security`](#security-toolkit)         |

If you are unsure, use `aescrypt`: it handles key derivation, random IVs,
authentication and file handling for you, and its output opens in AES Crypt.

## Quick start

```rust
use aescry::aescrypt;

let secret: &[u8] = b"any bytes: text, images, archives \x00\xff";

let encrypted = aescrypt::encrypt("correct horse battery staple", secret)?;
let decrypted = aescrypt::decrypt("correct horse battery staple", &encrypted)?;
assert_eq!(decrypted, secret);

// A wrong password is detected, never silently decrypted to garbage.
assert!(aescrypt::decrypt("wrong password", &encrypted).is_err());
# Ok::<(), aescry::Error>(())
```

`encrypted` is a complete AES Crypt stream: save it as a `.aes` file and the
AES Crypt apps can open it.

## Encrypting with a password (AES Crypt)

The `aescrypt` module encrypts with the current AES Crypt format (version 3):
the password goes through PBKDF2-HMAC-SHA512 (600,000 iterations by default),
the data is encrypted with AES-256-CBC under a random session key, and two
HMAC-SHA256 tags detect a wrong password and any modification. Decryption
checks both tags before returning anything.

### Data in memory

```rust
use aescry::aescrypt;

let encrypted = aescrypt::encrypt("pw", b"hello")?;
assert_eq!(aescrypt::decrypt("pw", &encrypted)?, b"hello");
# Ok::<(), aescry::Error>(())
```

### Settings: iterations and extensions

`Encryptor` and `Decryptor` hold a password and settings, and can be reused.

```rust
use aescry::aescrypt::{Decryptor, Encryptor, Extension, Iterations};

let encryptor = Encryptor::new("pw")?
    // PBKDF2 iterations: 1 to 5,000,000 (default 600,000). More is slower
    // for attackers guessing passwords, and for you.
    .iterations(Iterations::new(1_000_000)?)
    // Unencrypted, unauthenticated metadata stored in the header.
    .extension(Extension::new("urn:example:owner", "alice")?);

let encrypted = encryptor.encrypt(b"quarterly numbers")?;

let decryptor = Decryptor::new("pw")?;
assert_eq!(decryptor.decrypt(&encrypted)?, b"quarterly numbers");
# Ok::<(), aescry::Error>(())
```

By default the header also carries a `CREATED_BY` extension and an empty
128-octet container extension, as AES Crypt recommends;
`.without_default_extensions()` leaves them out.

### Files

```rust,no_run
use aescry::aescrypt::{Decryptor, Encryptor};

Encryptor::new("pw")?.encrypt_file("report.pdf", "report.pdf.aes")?;
Decryptor::new("pw")?.decrypt_file("report.pdf.aes", "report-copy.pdf")?;
# Ok::<(), aescry::Error>(())
```

Output goes to a temporary file next to the destination and is renamed into
place only when complete. A failed decryption (wrong password, altered file)
leaves no output file behind and does not touch an existing one.

### Streams

Any `Read` can be encrypted to any `Write` without holding the data in memory:

```rust,no_run
use aescry::aescrypt::{Decryptor, Encryptor};
use std::fs::File;
use std::io::{stdin, stdout};

// stdin -> encrypted file
Encryptor::new("pw")?.encrypt_stream(stdin(), File::create("backup.tar.aes")?)?;

// encrypted file -> stdout
Decryptor::new("pw")?.decrypt_stream(File::open("backup.tar.aes")?, stdout())?;
# Ok::<(), aescry::Error>(())
```

`decrypt_stream` writes plaintext as it goes, before the final integrity
check. If it returns an error, discard what it wrote. `decrypt` and
`decrypt_file` never expose unverified data.

### Reading the header

The header is not encrypted, so it can be read without the password:

```rust
use aescry::aescrypt::{self, Encryptor, Iterations};
use aescry::Version;

let encrypted = Encryptor::new("pw")?.iterations(Iterations::new(1000)?).encrypt(b"x")?;
let header = aescrypt::read_header(&encrypted[..])?;

assert_eq!(header.version(), Version::V3);
assert_eq!(header.iterations(), Some(1000));
assert!(header.extension("CREATED_BY").is_some());
# Ok::<(), aescry::Error>(())
```

### Detecting AES Crypt files

```rust,no_run
use aescry::detect;

// A file on disk: None if it can't be read or isn't AES Crypt data.
if let Some(file) = detect::get_file("secrets.txt.aes") {
    println!("{} uses {}", file.path().display(), file.version());
}

// Bytes in memory, keeping the version.
let data = std::fs::read("secrets.txt.aes")?;
if let Some(version) = detect::from_bytes(&data) {
    println!("format version {}", version.as_u8());
}

// Any reader (only the 4-octet header is read).
let version = detect::from_reader(std::io::stdin())?;
# let _ = version;
# Ok::<(), std::io::Error>(())
```

Detection checks the `AES` magic octets, a known version and, when the length
is known, the minimum length of a valid stream of that version.

### Limits on untrusted files

Everything in a header comes from the file, so reading is bounded by
`Limits`: at most 5,000,000 PBKDF2 iterations, a 1 MiB header and 256
extensions. You can lower them for untrusted input:

```rust
use aescry::aescrypt::{Decryptor, Limits};

let strict = Decryptor::new("pw")?.limits(Limits::DEFAULT.max_iterations(1_000_000).max_extensions(8));
# let _ = strict;
# Ok::<(), aescry::Error>(())
```

### Supported format versions

| Version | Read | Write            | Key derivation     | Written by                |
|---------|------|------------------|--------------------|---------------------------|
| 3       | ✓    | ✓                | PBKDF2-HMAC-SHA512 | AES Crypt 4.x             |
| 2       | ✓    | `security` only  | 8192 × SHA-256     | AES Crypt 3.x, pyAesCrypt |
| 1       | ✓    | `security` only  | 8192 × SHA-256     | older AES Crypt           |
| 0       | ✓    | `security` only  | 8192 × SHA-256     | older AES Crypt           |

## Encrypting with your own key (AES-CBC)

Use `cbc` when you manage keys yourself instead of using passwords. Keys are
16, 24 or 32 octets (AES-128, AES-192, AES-256); IVs are 16 octets and must
never repeat for the same key.

### Keys

`AesKey` is a key whose length has been checked. It is wiped from memory when
dropped and never printed.

```rust
use aescry::aes::{AesKey, KeySize};

let key = AesKey::generate(KeySize::Aes256)?;           // random key
let from_bytes = AesKey::try_from(&[0x42u8; 16][..])?;   // raw bytes, checked once
assert!(AesKey::try_from(&[0u8; 20][..]).is_err());       // not an AES key size
# let _ = (key, from_bytes);
# Ok::<(), aescry::Error>(())
```

### Encrypting and decrypting

`cbc::encrypt` / `cbc::decrypt` take a raw key, a raw IV and any bytes, and
apply PKCS#7 padding:

```rust
use aescry::aes::{AesKey, KeySize};
use aescry::{cbc, random};

let key = AesKey::generate(KeySize::Aes256)?;
let iv = random::iv()?;

let ciphertext = cbc::encrypt(key.expose_secret(), &iv, b"attack at dawn")?;
let plaintext = cbc::decrypt(key.expose_secret(), &iv, &ciphertext)?;
assert_eq!(plaintext, b"attack at dawn");
# Ok::<(), aescry::Error>(())
```

To have the IV generated for you and stored in front of the ciphertext:

```rust
use aescry::{cbc, random};

let key = random::bytes::<32>()?;
let message = cbc::encrypt_with_random_iv(&key, b"attack at dawn")?; // IV || ciphertext
assert_eq!(cbc::decrypt_with_iv_prefix(&key, &message)?, b"attack at dawn");
# Ok::<(), aescry::Error>(())
```

For data that is already a multiple of 16 octets there are
`cbc::encrypt_no_padding` and `cbc::decrypt_no_padding`.

### Streaming

`CbcEncryptor` and `CbcDecryptor` keep the chaining value between calls, so
data can be processed in pieces of whole blocks:

```rust
use aescry::aes::Aes128;
use aescry::cbc::{CbcDecryptor, CbcEncryptor};

let cipher = Aes128::new(&[0x42; 16]);
let iv = [0x24; 16];
let mut data = [0u8; 64];

let mut encryptor = CbcEncryptor::new(&cipher, &iv);
encryptor.encrypt_in_place(&mut data[..32])?;
encryptor.encrypt_in_place(&mut data[32..])?;

let mut decryptor = CbcDecryptor::new(&cipher, &iv);
decryptor.decrypt_in_place(&mut data)?;
assert_eq!(data, [0u8; 64]);
# Ok::<(), aescry::Error>(())
```

> **CBC alone does not detect tampering.** Anyone who can change the
> ciphertext can make predictable changes to the plaintext. Add a MAC, as
> shown next, or use `aescrypt`, which does this for you.

## Authenticating ciphertext

Encrypt-then-MAC: encrypt, then compute an HMAC over the IV and ciphertext
with a separate key. The receiver checks the tag (in constant time) before
decrypting.

```rust
use aescry::hmac::{hmac_sha256, HmacSha256};
use aescry::{cbc, random};

let enc_key = random::bytes::<32>()?;
let mac_key = random::bytes::<32>()?;

// Sender
let message = cbc::encrypt_with_random_iv(&enc_key, b"wire $100 to Bob")?;
let tag = hmac_sha256(&mac_key, &message);

// Receiver
let mut mac = HmacSha256::new(&mac_key);
mac.update(&message);
mac.verify(&tag)?; // Err(Error::AuthenticationFailed) if anything changed
let plaintext = cbc::decrypt_with_iv_prefix(&enc_key, &message)?;
assert_eq!(plaintext, b"wire $100 to Bob");
# Ok::<(), aescry::Error>(())
```

## Deriving keys from passwords

PBKDF2 turns a password into a key for your own formats. Use a random salt
per password, store it with the data, and pick an iteration count that takes
a noticeable fraction of a second.

```rust
use aescry::kdf;

let salt = aescry::random::bytes::<16>()?;
let key: [u8; 32] = kdf::pbkdf2_hmac_sha512_array(b"correct horse", &salt, 600_000)?;

// Any output length, and SHA-256 as the hash:
let mut material = [0u8; 64];
kdf::pbkdf2_hmac_sha256(b"correct horse", &salt, 600_000, &mut material)?;
# let _ = key;
# Ok::<(), aescry::Error>(())
```

`kdf::aescrypt_legacy` and `kdf::utf16le` implement the older AES Crypt
derivation (formats 0–2) for compatibility.

## Hashing and MACs

```rust
use aescry::hmac::{hmac_sha512, HmacSha256};
use aescry::sha256::{sha256, Sha256};
use aescry::sha512::sha512;

// One call
let digest = sha256(b"abc");
assert_eq!(sha512(b"abc").len(), 64);

// Incrementally, for large or streamed data
let mut hasher = Sha256::new();
hasher.update(b"a");
hasher.update(b"bc");
assert_eq!(hasher.finalize(), digest);

// HMAC, one call or incremental
let tag = hmac_sha512(b"key", b"message");
let mut mac = HmacSha256::new(b"key");
mac.update(b"message");
let tag256 = mac.finalize();
# let _ = (tag, tag256);
```

`Hmac::verify` compares a tag in constant time; `Hmac::verify_truncated`
checks truncated tags of at least 80 bits. Code can be generic over the hash
with the `digest::Digest` trait:

```rust
use aescry::digest::Digest;
use aescry::sha512::Sha512;

fn fingerprint<H: Digest>(data: &[u8]) -> H::Output {
    H::digest(data)
}

let print = fingerprint::<Sha512>(b"data");
# let _ = print;
```

## Building blocks

### AES block cipher

Each cipher encrypts and decrypts single 16-octet blocks in place. Use
`Aes128`, `Aes192` or `Aes256` when the key size is fixed, or `Aes` for a key
size chosen at runtime.

```rust
use aescry::aes::{Aes, Aes256, AesKey, Backend, BlockCipher, KeySize};

let cipher = Aes256::new(&[0x42u8; 32]);
let mut block = *b"exactly 16 bytes";
cipher.encrypt_block(&mut block);
cipher.decrypt_block(&mut block);
assert_eq!(&block, b"exactly 16 bytes");

let cipher = Aes::from_key(&AesKey::generate(KeySize::Aes128)?);
assert_eq!(cipher.key_size(), 16);

// AES-NI (constant-time) where available, portable software otherwise.
println!("{:?}, constant time: {}", cipher.backend(), cipher.backend().is_constant_time());
let software = Aes::with_backend(&[0u8; 16], Backend::Software)?;
# let _ = software;
# Ok::<(), aescry::Error>(())
```

Encrypting blocks independently (ECB) reveals which blocks are equal; use the
block cipher as a building block, not to encrypt messages.

### Padding, randomness and constant-time comparison

```rust
use aescry::padding::{pkcs7_pad, pkcs7_unpad};
use aescry::{ct, random};

// PKCS#7: always adds 1 to 16 octets
let padded = pkcs7_pad(b"YELLOW SUBMARINE!");
assert_eq!(padded.len(), 32);
assert_eq!(pkcs7_unpad(&padded)?, b"YELLOW SUBMARINE!");

// Secure random values from the operating system
let key: [u8; 32] = random::bytes()?;
let iv = random::iv()?;
let key_192 = random::key(24)?;

// Compare secrets without leaking where they differ
assert!(ct::eq(b"tag", b"tag"));
# let _ = (key, iv, key_192);
# Ok::<(), aescry::Error>(())
```

## Keeping secrets out of memory

Keys, passwords, hash states and decryption buffers inside `aescry` are wiped
when dropped. Two types do the same for your own values:

```rust
use aescry::secret::Secret;
use aescry::zeroize::{Zeroize, Zeroizing};

// Secret: wiped on drop, never printed, constant-time ==, explicit access.
let api_key = Secret::new([0x5Au8; 32]);
assert_eq!(format!("{:?}", api_key), "Secret([REDACTED])");
let bytes: &[u8; 32] = api_key.expose_secret();

// Zeroizing: wiped on drop, otherwise behaves like the value.
let mut buffer = Zeroizing::new(vec![0u8; 1024]);
buffer[0] = 1;

// Wipe something right now.
let mut password = String::from("hunter2");
password.zeroize();
assert!(password.is_empty());
# let _ = bytes;
```

## Handling errors

Every fallible function returns `Result<_, aescry::Error>`. The variants say
what went wrong, so you can respond precisely:

```rust
use aescry::{aescrypt, Error, Limit};

fn open(password: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    aescrypt::decrypt(password, data).map_err(|e| match e {
        Error::InvalidPassword => "wrong password".to_string(),
        Error::AlteredMessage => "the file was modified or truncated".to_string(),
        Error::NotAesCrypt => "not an AES Crypt file".to_string(),
        Error::UnsupportedVersion(v) => format!("unsupported format version {}", v),
        Error::InvalidStream(why) => format!("corrupt file: {}", why),
        Error::LimitExceeded(Limit::Iterations { found, .. }) => {
            format!("refusing a file that asks for {} iterations", found)
        }
        other => other.to_string(),
    })
}

assert_eq!(open("pw", b"hello"), Err("not an AES Crypt file".to_string()));
```

`Error` implements `std::error::Error` and `Display`, so it also works with
`?`, `Box<dyn Error>` and error-handling crates.

## Security toolkit

The `security` module is for security work: testing other AES Crypt
implementations, generating test vectors, forensics and recovering your own
data. It gives raw-byte control over passwords, IVs and keys, writes every
format version, and exposes derived and session keys. The risky operations
are separate types, so they can't be used by accident.

```rust
use aescry::security::{
    inspect, verify, DecryptKey, EncryptKey, PublicIv, RawDecryptor, RawEncryptor, SessionIv, SessionKey,
};
use aescry::Version;

// Any octets can be the password, not just valid text.
let password: &[u8] = &[0x00, 0xFF, 0xC3, 0x28];

// Fixed IVs and session key make output reproducible. This is a separate
// type, RawEncryptor<Deterministic>, because reusing IVs is unsafe.
let stream = RawEncryptor::new(EncryptKey::raw_password(password))
    .version(Version::V2)                     // any format version, 0 to 3
    .deterministic(
        PublicIv::try_from(&[0x01; 16][..])?, // raw bytes, length-checked once
        SessionIv::from([0x02; 16]),
        SessionKey::from([0x03; 32]),
    )
    .encrypt(b"test vector")?;

// Map the structure without the password, and check the HMACs without
// producing plaintext.
assert_eq!(inspect(&stream)?.plaintext_len(), Some(11));
assert!(verify(&DecryptKey::raw_password(password), &stream)?.is_authentic());

// Decrypt and recover the keys.
let opened = RawDecryptor::new(DecryptKey::raw_password(password)).decrypt(&stream)?;
assert_eq!(opened.plaintext(), b"test vector");
let derived = opened.report().derived_key().unwrap().clone_secret();

// Reopen with the derived key alone (no password or key derivation).
let again = RawDecryptor::new(DecryptKey::Derived(derived)).decrypt(&stream)?;
# let _ = again;
# Ok::<(), aescry::Error>(())
```

Damaged or tampered files can be decrypted for recovery, but the result is
wrapped in `Unauthenticated`, so using it is an explicit choice:

```rust,no_run
use aescry::security::{DecryptKey, RawDecryptor};

let damaged = std::fs::read("damaged.aes")?;
let result = RawDecryptor::new(DecryptKey::password("pw")?)
    .skip_verification()
    .decrypt(&damaged)?;

println!("authentic: {}", result.is_authentic());
let recovered = result.assume_authentic();
# let _ = recovered;
# Ok::<(), aescry::Error>(())
```

The module also offers `Password::encoded` and `DerivedKey::derive` (what the
key derivation sees and produces), raising `Limits` beyond the defaults,
arbitrary header extensions for parser testing (`Extension::from_bytes`), and
raw ECB block operations. Use `aescrypt` for everyday encryption.

## Security notes

- **Memory safety.** Untrusted bytes are handled only by safe Rust. The only
  `unsafe` code is the AES-NI backend (fixed 16-octet blocks) and the
  volatile writes in `zeroize`. Raw bytes for keys, IVs and passwords are
  length-checked once, when they become typed values.
- **Hostile files.** Header parsing is bounded by `Limits` before anything is
  allocated, and malformed input returns an error rather than panicking. The
  test suite feeds thousands of random and mutated streams to every parser and
  decryptor to check this.
- **Timing.** With AES-NI (nearly all x86 CPUs since 2010), AES runs in
  constant time. Other CPUs use a table-based implementation whose timing
  can leak key information to an attacker who can measure it precisely, such
  as another tenant on the same machine; `Backend::is_constant_time()` says
  which applies. MAC and padding checks are constant-time.
- **Secrets** are wiped from memory when dropped and never appear in `Debug`
  output. Wiping cannot reach copies made by the operating system (swap) or
  earlier reallocations.
- **CBC padding.** `cbc::decrypt` reports bad padding as an error. If an
  attacker can submit ciphertexts and observe that error, they can decrypt
  data (a padding oracle), so verify a MAC first.
- **AES Crypt header extensions** are neither encrypted nor authenticated.
  Don't trust their contents.

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
cargo test --release   # much faster for the Monte Carlo and hostile-input tests
```

Tests cover:
- the FIPS-197, FIPS 180-2 and NIST SP 800-38A examples;
- the Rijndael Monte Carlo tests, on every AES backend;
- vectors from the [RustCrypto](https://github.com/RustCrypto) project (see
  [`tests/data/rustcrypto`](tests/data/rustcrypto)): NESSIE AES, NIST CAVP
  CBC, SHA-2 known answers, HMAC from RFC 4231 and Project Wycheproof, and
  PBKDF2;
- cross-checks against OpenSSL and Python's `hashlib`;
- AES Crypt fixtures and byte-exact known-answer streams for every format
  version (see [`tests/data/aescrypt`](tests/data/aescrypt)). They come from
  an independent Python implementation, and the official AES Crypt tool
  decrypts every one of them;
- thousands of random and mutated streams that must never cause a panic.

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
