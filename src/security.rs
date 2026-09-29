//! Security toolkit: raw-byte control over AES Crypt streams.
//!
//! The rest of the crate chooses safe defaults. This module gives security
//! work (testing other implementations, generating test vectors, forensics,
//! recovering your own data, auditing) direct control over every input:
//!
//! - **Raw-byte passwords.** [`Key::RawPassword`] feeds octets to the key
//!   derivation unchanged: no UTF-8 or UTF-16LE encoding, no validity checks.
//! - **Caller-chosen IVs and keys.** [`RawEncryptor`] takes the public IV,
//!   session IV and session key as raw bytes, so output is reproducible.
//! - **Every format version.** Streams can be written in versions 0–3.
//! - **Key-level access.** [`Key::DerivedKey`] skips key derivation, and
//!   [`Key::Session`] decrypts with a recovered session IV and key.
//! - **Inspection and verification.** [`inspect`] maps a stream's layout
//!   without a password, and [`verify`] checks both HMACs without producing
//!   plaintext.
//! - **Unverified decryption.** [`RawDecryptor::skip_verification`] decrypts
//!   damaged or tampered streams and reports which checks failed.
//!
//! These tools make it easy to do unsafe things: reuse IVs, use weak
//! iteration counts, or trust unauthenticated plaintext. Use the
//! [`aescrypt`] module for ordinary encryption.
//!
//! ```
//! use aescry::security::{Key, RawDecryptor, RawEncryptor};
//! use aescry::Version;
//!
//! // Any octets can be the password, including invalid UTF-8.
//! let password: &[u8] = &[0xFF, 0x00, 0xC3, 0x28];
//!
//! let stream = RawEncryptor::new(Key::RawPassword(password))
//!     .version(Version::V3)
//!     .iterations(1000)
//!     .public_iv(&[0x11; 16])?
//!     .session_iv(&[0x22; 16])?
//!     .session_key(&[0x33; 32])?
//!     .encrypt(b"deterministic output")?;
//!
//! let decrypted = RawDecryptor::new(Key::RawPassword(password)).decrypt(&stream)?;
//! assert_eq!(&decrypted.plaintext[..], b"deterministic output");
//! assert_eq!(decrypted.report.session_key(), &[0x33; 32]);
//! # Ok::<(), aescry::Error>(())
//! ```

use crate::aes::{Aes, Block, BlockCipher, BLOCK_SIZE};
use crate::aescrypt::{self, Credential, DecryptInfo, DecryptOptions, EncryptParams};
use crate::detect::Version;
use crate::zeroize::Zeroizing;
use crate::{kdf, random, Error};
use core::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::ops::Range;
use std::path::Path;

pub use crate::aescrypt::{Extension, Header};

/// The secret that opens or creates a stream.
#[derive(Clone, Copy)]
pub enum Key<'a> {
    /// A text password, encoded the way each version expects: UTF-16LE for
    /// versions 0–2 and UTF-8 for version 3.
    Text(&'a str),
    /// Password octets passed to the key derivation exactly as given.
    ///
    /// For a password that AES Crypt would accept, versions 0–2 expect
    /// UTF-16LE octets and version 3 expects UTF-8; see [`password_bytes`].
    RawPassword(&'a [u8]),
    /// The 32-octet key the password derives to, skipping key derivation.
    /// See [`derive_key`] and [`DecryptReport::derived_key`].
    DerivedKey(&'a [u8]),
    /// The 16-octet session IV and 32-octet session key (decryption only).
    /// Skips the password and the key block entirely; for version 0 streams
    /// these are the public IV and the derived key.
    Session {
        /// The session IV.
        iv: &'a [u8],
        /// The session key.
        key: &'a [u8],
    },
}

impl fmt::Debug for Key<'_> {
    // never print secrets
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Key::Text(_) => "Key::Text(..)",
            Key::RawPassword(_) => "Key::RawPassword(..)",
            Key::DerivedKey(_) => "Key::DerivedKey(..)",
            Key::Session { .. } => "Key::Session { .. }",
        })
    }
}

fn array<const N: usize>(bytes: &[u8], err: fn(usize) -> Error) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| err(bytes.len()))
}

/// A [`Key`] with its lengths checked, borrowing fixed-size arrays for the
/// engine.
enum CheckedKey<'a> {
    Text(&'a str),
    Raw(&'a [u8]),
    Derived([u8; 32]),
    Session([u8; 16], [u8; 32]),
}

impl Drop for CheckedKey<'_> {
    fn drop(&mut self) {
        use crate::zeroize::Zeroize;
        match self {
            CheckedKey::Derived(key) | CheckedKey::Session(_, key) => key.zeroize(),
            _ => {}
        }
    }
}

impl<'a> Key<'a> {
    fn check(self) -> Result<CheckedKey<'a>, Error> {
        Ok(match self {
            Key::Text(text) => CheckedKey::Text(text),
            Key::RawPassword(raw) => CheckedKey::Raw(raw),
            Key::DerivedKey(key) => CheckedKey::Derived(array(key, Error::InvalidKeyLength)?),
            Key::Session { iv, key } => CheckedKey::Session(
                array(iv, Error::InvalidIvLength)?,
                array(key, Error::InvalidKeyLength)?,
            ),
        })
    }
}

impl CheckedKey<'_> {
    fn credential(&self) -> Credential<'_> {
        match self {
            CheckedKey::Text(text) => Credential::Text(text),
            CheckedKey::Raw(raw) => Credential::Raw(raw),
            CheckedKey::Derived(key) => Credential::DerivedKey(key),
            CheckedKey::Session(iv, key) => Credential::Session { iv, key },
        }
    }
}

/// The octets AES Crypt feeds to key derivation for a text password:
/// UTF-16LE for versions 0–2, UTF-8 for version 3.
pub fn password_bytes(version: Version, password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(if version >= Version::V3 { password.as_bytes().to_vec() } else { kdf::utf16le(password) })
}

/// Derive the 32-octet key for a stream of `version` from raw password
/// octets and the 16-octet public IV.
///
/// Version 3 uses PBKDF2-HMAC-SHA512 with `iterations` (at least 1);
/// versions 0–2 use 8192 rounds of SHA-256 and ignore `iterations`.
pub fn derive_key(version: Version, password: &[u8], iv: &[u8], iterations: u32) -> Result<Zeroizing<[u8; 32]>, Error> {
    let iv: [u8; 16] = array(iv, Error::InvalidIvLength)?;
    Ok(Zeroizing::new(aescrypt::derive_key(version, password, &iv, iterations)?))
}

/// Writes AES Crypt streams of any version with caller-controlled inputs.
///
/// IVs and the session key are random unless set.  Nothing else is added:
/// there are no default extensions, and the iteration count may be any
/// value from 1 up, including values the [`aescrypt`]
/// module refuses.
pub struct RawEncryptor<'a> {
    key: Key<'a>,
    version: Version,
    iterations: u32,
    extensions: Vec<Extension>,
    public_iv: Option<[u8; 16]>,
    session_iv: Option<[u8; 16]>,
    session_key: Option<Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for RawEncryptor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawEncryptor")
            .field("key", &self.key)
            .field("version", &self.version)
            .field("iterations", &self.iterations)
            .field("extensions", &self.extensions)
            .field("public_iv", &self.public_iv)
            .field("session_iv", &self.session_iv)
            .finish_non_exhaustive()
    }
}

impl<'a> RawEncryptor<'a> {
    /// Start a version 3 stream with [`aescrypt::DEFAULT_ITERATIONS`].
    ///
    /// [`Key::Session`] cannot create streams.
    pub fn new(key: Key<'a>) -> Self {
        RawEncryptor {
            key,
            version: Version::V3,
            iterations: aescrypt::DEFAULT_ITERATIONS,
            extensions: Vec::new(),
            public_iv: None,
            session_iv: None,
            session_key: None,
        }
    }

    /// The stream format version to write (0–3).
    pub fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// The PBKDF2 iteration count for version 3 (any value from 1).
    pub fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Add a header extension (versions 2 and 3).  See
    /// [`Extension::from_bytes`] for arbitrary, even malformed, extensions.
    pub fn extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Use these 16 octets as the public IV (also the key derivation salt).
    pub fn public_iv(mut self, iv: &[u8]) -> Result<Self, Error> {
        self.public_iv = Some(array(iv, Error::InvalidIvLength)?);
        Ok(self)
    }

    /// Use these 16 octets as the session IV (versions 1–3).
    pub fn session_iv(mut self, iv: &[u8]) -> Result<Self, Error> {
        self.session_iv = Some(array(iv, Error::InvalidIvLength)?);
        Ok(self)
    }

    /// Use these 32 octets as the session key (versions 1–3).
    pub fn session_key(mut self, key: &[u8]) -> Result<Self, Error> {
        self.session_key = Some(Zeroizing::new(array(key, Error::InvalidKeyLength)?));
        Ok(self)
    }

    fn stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<u64, Error> {
        let key = self.key.check()?;
        if let CheckedKey::Session(..) = key {
            return Err(Error::InvalidStream("a session key cannot be used to write a stream"));
        }
        if self.version >= Version::V3 && self.iterations == 0 {
            return Err(Error::InvalidIterations(0));
        }

        let params = EncryptParams {
            version: self.version,
            credential: key.credential(),
            iterations: self.iterations,
            extensions: &self.extensions,
            public_iv: match self.public_iv {
                Some(iv) => iv,
                None => random::bytes()?,
            },
            session_iv: match self.session_iv {
                Some(iv) => iv,
                None => random::bytes()?,
            },
            session_key: match &self.session_key {
                Some(key) => **key,
                None => random::bytes()?,
            },
        };

        aescrypt::encrypt_engine(&params, reader, writer)
    }

    /// Encrypt `plaintext` and return the stream.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len() + 256);
        self.stream(plaintext, &mut out)?;
        Ok(out)
    }

    /// Encrypt everything from `reader` into `writer`; returns the number of
    /// plaintext octets.
    pub fn encrypt_stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<u64, Error> {
        self.stream(reader, writer)
    }

    /// Encrypt the file at `input` into `output` (written atomically).
    pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(&self, input: P, output: Q) -> Result<u64, Error> {
        let reader = BufReader::new(File::open(input)?);
        aescrypt::write_atomically(output.as_ref(), |file| self.stream(reader, BufWriter::new(file)))
    }
}

/// What decrypting a stream revealed.
pub struct DecryptReport {
    header: Header,
    plaintext_len: u64,
    derived_key: Option<Zeroizing<[u8; 32]>>,
    session_iv: [u8; 16],
    session_key: Zeroizing<[u8; 32]>,
    key_block_authentic: Option<bool>,
    message_authentic: bool,
}

impl From<DecryptInfo> for DecryptReport {
    fn from(info: DecryptInfo) -> Self {
        DecryptReport {
            header: info.header,
            plaintext_len: info.plaintext_len,
            derived_key: info.derived_key,
            session_iv: info.session_iv,
            session_key: info.session_key,
            key_block_authentic: info.key_hmac_ok,
            message_authentic: info.message_hmac_ok,
        }
    }
}

impl fmt::Debug for DecryptReport {
    // keys are secret; print only whether they are present
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptReport")
            .field("header", &self.header)
            .field("plaintext_len", &self.plaintext_len)
            .field("key_block_authentic", &self.key_block_authentic)
            .field("message_authentic", &self.message_authentic)
            .finish_non_exhaustive()
    }
}

impl DecryptReport {
    /// The stream header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The number of plaintext octets produced.
    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// The key derived from the password (not available when decrypting
    /// with [`Key::Session`]).  Use it with [`Key::DerivedKey`] to skip key
    /// derivation next time.
    pub fn derived_key(&self) -> Option<&[u8; 32]> {
        self.derived_key.as_deref()
    }

    /// The IV that encrypted the message (the public IV for version 0).
    pub fn session_iv(&self) -> &[u8; 16] {
        &self.session_iv
    }

    /// The key that encrypted the message (the derived key for version 0).
    pub fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }

    /// Whether the key block's HMAC matched: `None` for version 0 streams
    /// and when decrypting with [`Key::Session`].
    pub fn key_block_authentic(&self) -> Option<bool> {
        self.key_block_authentic
    }

    /// Whether the message HMAC matched.
    pub fn message_authentic(&self) -> bool {
        self.message_authentic
    }

    /// Whether every HMAC that was checked matched.
    pub fn is_authentic(&self) -> bool {
        self.message_authentic && self.key_block_authentic != Some(false)
    }
}

/// Plaintext (wiped on drop) and what decryption revealed.
#[derive(Debug)]
pub struct Decrypted {
    /// The decrypted data.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Keys, header and authentication results.
    pub report: DecryptReport,
}

/// Decrypts AES Crypt streams with raw-byte keys, reporting the keys and
/// integrity results.
#[derive(Debug)]
pub struct RawDecryptor<'a> {
    key: Key<'a>,
    max_iterations: u32,
    verify: bool,
}

impl<'a> RawDecryptor<'a> {
    /// Decrypt with `key`, verifying both HMACs.  Iteration counts up to
    /// [`aescrypt::MAX_ITERATIONS`] are accepted.
    pub fn new(key: Key<'a>) -> Self {
        RawDecryptor { key, max_iterations: aescrypt::MAX_ITERATIONS, verify: true }
    }

    /// Accept any PBKDF2 iteration count up to `max`, including more than
    /// [`aescrypt::MAX_ITERATIONS`].  Large values can take a very long time.
    pub fn max_iterations(mut self, max: u32) -> Self {
        self.max_iterations = max;
        self
    }

    /// Decrypt even if an HMAC does not match, and report the results
    /// instead of failing.
    ///
    /// **The plaintext is then unauthenticated**: it may have been modified
    /// by an attacker, or be garbage from a wrong key.  Check
    /// [`DecryptReport::is_authentic`] before trusting it.
    pub fn skip_verification(mut self) -> Self {
        self.verify = false;
        self
    }

    fn stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<DecryptReport, Error> {
        let key = self.key.check()?;
        let options = DecryptOptions { max_iterations: self.max_iterations, verify: self.verify };
        Ok(aescrypt::decrypt_engine(key.credential(), &options, reader, writer)?.into())
    }

    /// Decrypt a stream held in memory.
    pub fn decrypt(&self, data: &[u8]) -> Result<Decrypted, Error> {
        let mut plaintext = Zeroizing::new(Vec::with_capacity(data.len()));
        let report = self.stream(data, &mut *plaintext)?;
        Ok(Decrypted { plaintext, report })
    }

    /// Decrypt from `reader` to `writer`.  Plaintext is written before the
    /// final HMAC check; discard it if this fails.
    pub fn decrypt_stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<DecryptReport, Error> {
        self.stream(reader, writer)
    }

    /// Decrypt the file at `input` into `output`.  With verification on,
    /// `output` is only created if the stream is authentic.
    pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(&self, input: P, output: Q) -> Result<DecryptReport, Error> {
        let reader = BufReader::new(File::open(input)?);
        aescrypt::write_atomically(output.as_ref(), |file| self.stream(reader, BufWriter::new(file)))
    }
}

/// Integrity results for a stream, from [`verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verification {
    /// Whether the key block's HMAC matched (`None` for version 0).  A
    /// mismatch means a wrong password or a modified key block.
    pub key_block: Option<bool>,
    /// Whether the message HMAC matched.  For version 0 this also depends on
    /// the password.
    pub message: bool,
}

impl Verification {
    /// Whether every HMAC matched.
    pub fn is_authentic(&self) -> bool {
        self.message && self.key_block != Some(false)
    }
}

/// Check both HMACs of a stream without returning any plaintext.
///
/// Version 3 streams asking for more than [`aescrypt::MAX_ITERATIONS`] are
/// refused; use [`RawDecryptor::max_iterations`] with
/// [`RawDecryptor::skip_verification`] to check those.
///
/// ```
/// # use aescry::security::{verify, Key, RawEncryptor};
/// let stream = RawEncryptor::new(Key::Text("pw")).iterations(10).encrypt(b"data")?;
///
/// assert!(verify(Key::Text("pw"), &stream)?.is_authentic());
/// assert_eq!(verify(Key::Text("nope"), &stream)?.key_block, Some(false));
/// # Ok::<(), aescry::Error>(())
/// ```
pub fn verify(key: Key<'_>, data: &[u8]) -> Result<Verification, Error> {
    let report = RawDecryptor::new(key).skip_verification().decrypt_stream(data, io::sink())?;

    Ok(Verification { key_block: report.key_block_authentic, message: report.message_authentic })
}

/// The layout of an AES Crypt stream, from [`inspect`].
///
/// Offsets are positions in the stream.  Nothing here is secret: it is all
/// visible without the password.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Layout {
    /// The unencrypted header.
    pub header: Header,
    /// The position and contents of each extension (after its length).
    pub extensions: Vec<(Range<usize>, Extension)>,
    /// The encrypted session IV and key (versions 1–3).
    pub key_block: Option<(Range<usize>, [u8; 48])>,
    /// The key block's HMAC (versions 1–3).
    pub key_block_hmac: Option<(Range<usize>, [u8; 32])>,
    /// Where the ciphertext is.
    pub ciphertext: Range<usize>,
    /// The final block size field: the reserved header octet in version 0,
    /// the octet after the ciphertext in versions 1 and 2, `None` in version 3.
    pub final_block_size: Option<u8>,
    /// The message HMAC.
    pub message_hmac: (Range<usize>, [u8; 32]),
    /// The stream length in octets.
    pub total_len: usize,
}

impl Layout {
    /// The ciphertext length in octets.
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }

    /// The plaintext length this stream decrypts to, if it can be known
    /// without the key (versions 0–2).  For version 3 it is between
    /// `ciphertext_len() - 16` and `ciphertext_len() - 1`.
    pub fn plaintext_len(&self) -> Option<usize> {
        let size = self.final_block_size? & 0x0f;
        let len = self.ciphertext.len();
        Some(if len == 0 || size == 0 { len } else { len - 16 + size as usize })
    }
}

/// Map the structure of a stream without a password.
///
/// ```
/// # use aescry::security::{inspect, Key, RawEncryptor};
/// # use aescry::Version;
/// let stream = RawEncryptor::new(Key::Text("pw")).version(Version::V2).encrypt(&[0; 20])?;
/// let layout = inspect(&stream)?;
///
/// assert_eq!(layout.header.version(), Version::V2);
/// assert_eq!(layout.ciphertext_len(), 32);
/// assert_eq!(layout.plaintext_len(), Some(20));
/// # Ok::<(), aescry::Error>(())
/// ```
pub fn inspect(data: &[u8]) -> Result<Layout, Error> {
    let header = aescrypt::read_header(data)?;
    let version = header.version();

    // extension positions: after magic, version and reserved octet
    let mut extensions = Vec::new();
    if version >= Version::V2 {
        let mut pos = 5;
        for ext in header.extensions() {
            let start = pos + 2;
            let end = start + ext.as_bytes().len();
            extensions.push((start..end, ext.clone()));
            pos = end;
        }
    }

    let mut pos = header.len();
    let take = |pos: &mut usize, n: usize| -> Result<Range<usize>, Error> {
        let range = *pos..*pos + n;
        if range.end > data.len() {
            return Err(Error::InvalidStream("truncated stream"));
        }
        *pos = range.end;
        Ok(range)
    };

    let (key_block, key_block_hmac) = if version >= Version::V1 {
        let block = take(&mut pos, 48)?;
        let hmac = take(&mut pos, 32)?;
        let block_bytes = data[block.clone()].try_into().expect("48 octets");
        let hmac_bytes = data[hmac.clone()].try_into().expect("32 octets");
        (Some((block, block_bytes)), Some((hmac, hmac_bytes)))
    } else {
        (None, None)
    };

    let trailer = match version {
        Version::V1 | Version::V2 => 33,
        _ => 32,
    };
    if data.len() < pos + trailer {
        return Err(Error::InvalidStream("truncated stream"));
    }

    let ciphertext = pos..data.len() - trailer;
    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err(Error::InvalidStream("ciphertext length is not a multiple of 16"));
    }

    let final_block_size = match version {
        Version::V0 => Some(header.reserved()),
        Version::V1 | Version::V2 => Some(data[ciphertext.end]),
        _ => None,
    };

    let hmac = data.len() - 32..data.len();
    let hmac_bytes = data[hmac.clone()].try_into().expect("32 octets");

    Ok(Layout {
        header,
        extensions,
        key_block,
        key_block_hmac,
        ciphertext,
        final_block_size,
        message_hmac: (hmac, hmac_bytes),
        total_len: data.len(),
    })
}

/// Encrypt whole blocks with AES in ECB mode using a raw 16, 24 or 32 octet
/// key.  `data` must be a multiple of 16 octets.
///
/// ECB encrypts equal blocks to equal ciphertext and is only useful as a
/// primitive (for example, to reproduce a single block operation).
pub fn ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    ecb(key, data, |cipher, block| cipher.encrypt_block(block))
}

/// Decrypt whole blocks with AES in ECB mode using a raw key.
pub fn ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    ecb(key, data, |cipher, block| cipher.decrypt_block(block))
}

fn ecb(key: &[u8], data: &[u8], op: impl Fn(&Aes, &mut Block)) -> Result<Vec<u8>, Error> {
    let cipher = Aes::new(key)?;
    if data.len() % BLOCK_SIZE != 0 {
        return Err(Error::InvalidCiphertextLength(data.len()));
    }

    let mut out = data.to_vec();
    for chunk in out.chunks_exact_mut(BLOCK_SIZE) {
        let mut block: Block = (&*chunk).try_into().expect("16-octet chunk");
        op(&cipher, &mut block);
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}
