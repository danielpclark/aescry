//! Security toolkit: raw-byte control over AES Crypt streams.
//!
//! The rest of the crate chooses safe defaults. This module gives security
//! work (testing other implementations, generating test vectors, forensics,
//! recovering your own data, auditing) direct control over every input, and
//! uses the type system to keep the dangerous parts visible:
//!
//! - **Raw bytes, checked once.** Raw bytes become validated values
//!   ([`Password::from_raw_bytes`], [`PublicIv`], [`SessionIv`],
//!   [`SessionKey`], [`DerivedKey`], [`Iterations`]) at the edge of the API.
//!   Values of the same size are different types, so a session key can't be
//!   used as a derived key by mistake.
//! - **Secrets stay secret.** Keys and passwords are wiped on drop, never
//!   printed, compared in constant time, and read only through
//!   `expose_secret()`.
//! - **Deterministic encryption is a separate type.** [`RawEncryptor`] uses
//!   fresh random values; [`RawEncryptor::deterministic`] returns a
//!   `RawEncryptor<Deterministic>`, which reuses the values you give it.
//! - **Unverified plaintext is wrapped.** A decryptor that skips
//!   verification returns [`Unauthenticated`] values, which can't be used
//!   without choosing [`Unauthenticated::into_authentic`] or
//!   [`Unauthenticated::assume_authentic`].
//! - **Limits are explicit.** Reading is bounded by [`Limits`]; only this
//!   module can raise them.
//! - **Every format version** can be written, [`inspect`] maps a stream
//!   without a password, and [`verify`] checks both HMACs without producing
//!   plaintext.
//!
//! ```
//! use aescry::security::{DecryptKey, EncryptKey, Iterations, PublicIv, RawDecryptor, RawEncryptor, SessionIv, SessionKey};
//! use aescry::Version;
//!
//! // Any octets can be a password, including invalid UTF-8.
//! let password: &[u8] = &[0xFF, 0x00, 0xC3, 0x28];
//!
//! let stream = RawEncryptor::new(EncryptKey::raw_password(password))
//!     .version(Version::V3)
//!     .iterations(Iterations::new(1000)?)
//!     .deterministic(
//!         PublicIv::try_from(&[0x11; 16][..])?,
//!         SessionIv::from([0x22; 16]),
//!         SessionKey::from([0x33; 32]),
//!     )
//!     .encrypt(b"reproducible output")?;
//!
//! let opened = RawDecryptor::new(DecryptKey::raw_password(password)).decrypt(&stream)?;
//! assert_eq!(opened.plaintext(), b"reproducible output");
//! assert_eq!(opened.report().session_key().expose_secret(), &[0x33; 32]);
//! # Ok::<(), aescry::Error>(())
//! ```

use crate::aes::{Aes, AesKey, Block, BlockCipher, BLOCK_SIZE};
use crate::aescrypt::{self, DecryptInfo, DecryptOptions, EncryptParams};
use crate::detect::Version;
use crate::zeroize::Zeroizing;
use crate::{Error, StreamError};
use core::fmt;
use core::marker::PhantomData;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::ops::Range;
use std::path::Path;

pub use crate::aescrypt::{
    DerivedKey, Extension, Header, Iterations, Limits, Password, PublicIv, SessionIv, SessionKey,
};

/// What can create a stream: a password or an already derived key.
#[derive(Debug)]
pub enum EncryptKey {
    /// Derive the key from a password.
    Password(Password),
    /// Use a derived key directly, skipping key derivation.
    Derived(DerivedKey),
}

impl EncryptKey {
    /// A non-empty text password, encoded as each version expects.
    pub fn password(text: &str) -> Result<Self, Error> {
        Ok(EncryptKey::Password(Password::new(text)?))
    }

    /// Password octets used exactly as given, for every version.
    pub fn raw_password(bytes: impl Into<Vec<u8>>) -> Self {
        EncryptKey::Password(Password::from_raw_bytes(bytes))
    }

    /// A 32-octet derived key from raw bytes.
    pub fn derived(bytes: &[u8]) -> Result<Self, Error> {
        Ok(EncryptKey::Derived(DerivedKey::try_from(bytes)?))
    }

    fn as_engine_key(&self) -> aescrypt::EncryptKey<'_> {
        match self {
            EncryptKey::Password(p) => aescrypt::EncryptKey::Password(p),
            EncryptKey::Derived(k) => aescrypt::EncryptKey::Derived(k),
        }
    }
}

impl From<Password> for EncryptKey {
    fn from(password: Password) -> Self {
        EncryptKey::Password(password)
    }
}

impl From<DerivedKey> for EncryptKey {
    fn from(key: DerivedKey) -> Self {
        EncryptKey::Derived(key)
    }
}

/// What can open a stream: a password, a derived key, or the session IV
/// and key.
#[derive(Debug)]
pub enum DecryptKey {
    /// Derive the key from a password.
    Password(Password),
    /// Use a derived key directly, skipping key derivation.
    Derived(DerivedKey),
    /// Use the session IV and key, skipping the password and the key block
    /// entirely.  For version 0 streams these are the public IV and the
    /// derived key.
    Session(SessionIv, SessionKey),
}

impl DecryptKey {
    /// A non-empty text password, encoded as each version expects.
    pub fn password(text: &str) -> Result<Self, Error> {
        Ok(DecryptKey::Password(Password::new(text)?))
    }

    /// Password octets used exactly as given, for every version.
    pub fn raw_password(bytes: impl Into<Vec<u8>>) -> Self {
        DecryptKey::Password(Password::from_raw_bytes(bytes))
    }

    /// A 32-octet derived key from raw bytes.
    pub fn derived(bytes: &[u8]) -> Result<Self, Error> {
        Ok(DecryptKey::Derived(DerivedKey::try_from(bytes)?))
    }

    /// A 16-octet session IV and 32-octet session key from raw bytes.
    pub fn session(iv: &[u8], key: &[u8]) -> Result<Self, Error> {
        Ok(DecryptKey::Session(SessionIv::try_from(iv)?, SessionKey::try_from(key)?))
    }

    fn as_engine_key(&self) -> aescrypt::DecryptKey<'_> {
        match self {
            DecryptKey::Password(p) => aescrypt::DecryptKey::Password(p),
            DecryptKey::Derived(k) => aescrypt::DecryptKey::Derived(k),
            DecryptKey::Session(iv, k) => aescrypt::DecryptKey::Session(iv, k),
        }
    }
}

impl From<Password> for DecryptKey {
    fn from(password: Password) -> Self {
        DecryptKey::Password(password)
    }
}

impl From<DerivedKey> for DecryptKey {
    fn from(key: DerivedKey) -> Self {
        DecryptKey::Derived(key)
    }
}

mod sealed {
    use super::*;

    /// How a [`RawEncryptor`](super::RawEncryptor) gets its IVs and session
    /// key.
    pub trait Values {
        fn values(&self) -> Result<(PublicIv, SessionIv, SessionKey), Error>;
    }

    /// Whether a [`RawDecryptor`](super::RawDecryptor) fails on HMAC
    /// mismatches.
    pub trait Verify {
        const VERIFY: bool;
    }
}

/// How a [`RawEncryptor`] gets its IVs and session key.  Sealed.
pub trait ValueSource: sealed::Values {}

/// Fresh random IVs and session key for every stream (the default).
#[derive(Clone, Copy, Debug, Default)]
pub struct Random;

/// Fixed IVs and session key, reused for every stream.
///
/// **Reusing IVs and keys across different messages breaks the security of
/// the encryption.**  Use this only to reproduce streams: test vectors,
/// regression tests, or checking other implementations.
#[derive(Debug)]
pub struct Deterministic {
    public_iv: PublicIv,
    session_iv: SessionIv,
    session_key: SessionKey,
}

impl sealed::Values for Random {
    fn values(&self) -> Result<(PublicIv, SessionIv, SessionKey), Error> {
        Ok((PublicIv::generate()?, SessionIv::generate()?, SessionKey::generate()?))
    }
}

impl sealed::Values for Deterministic {
    fn values(&self) -> Result<(PublicIv, SessionIv, SessionKey), Error> {
        Ok((self.public_iv, self.session_iv, self.session_key.clone_secret()))
    }
}

impl ValueSource for Random {}
impl ValueSource for Deterministic {}

/// Writes AES Crypt streams of any version with caller-controlled inputs.
///
/// Nothing is added implicitly: there are no default extensions, and the
/// iteration count may be any [`Iterations`] value, including counts the
/// [`aescrypt`] module refuses to read.
#[derive(Debug)]
pub struct RawEncryptor<S: ValueSource = Random> {
    key: EncryptKey,
    version: Version,
    iterations: Iterations,
    extensions: Vec<Extension>,
    source: S,
}

impl RawEncryptor<Random> {
    /// Start a version 3 stream with [`Iterations::DEFAULT`] and random IVs
    /// and session key.
    pub fn new(key: EncryptKey) -> Self {
        RawEncryptor {
            key,
            version: Version::V3,
            iterations: Iterations::DEFAULT,
            extensions: Vec::new(),
            source: Random,
        }
    }

    /// Use fixed IVs and session key, making the output reproducible.  See
    /// [`Deterministic`] for why this is unsafe for real data.  Version 0
    /// streams use only the public IV.
    pub fn deterministic(
        self,
        public_iv: PublicIv,
        session_iv: SessionIv,
        session_key: SessionKey,
    ) -> RawEncryptor<Deterministic> {
        RawEncryptor {
            key: self.key,
            version: self.version,
            iterations: self.iterations,
            extensions: self.extensions,
            source: Deterministic { public_iv, session_iv, session_key },
        }
    }
}

impl<S: ValueSource> RawEncryptor<S> {
    /// The stream format version to write (0–3).
    pub fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// The PBKDF2 iteration count for version 3 (ignored by versions 0–2).
    pub fn iterations(mut self, iterations: Iterations) -> Self {
        self.iterations = iterations;
        self
    }

    /// Add a header extension (versions 2 and 3).  See
    /// [`Extension::from_bytes`] for arbitrary, even malformed, extensions.
    pub fn extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    fn stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<u64, Error> {
        let (public_iv, session_iv, session_key) = sealed::Values::values(&self.source)?;
        let params = EncryptParams {
            version: self.version,
            key: self.key.as_engine_key(),
            iterations: self.iterations,
            extensions: &self.extensions,
            public_iv,
            session_iv,
            session_key: &session_key,
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

/// Integrity results for a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub struct Verification {
    /// Whether the key block's HMAC matched: `None` for version 0 streams
    /// and when the key block was bypassed with [`DecryptKey::Session`].
    /// A mismatch means a wrong password or a modified key block.
    pub key_block: Option<bool>,
    /// Whether the message HMAC matched.  For version 0 this also depends on
    /// the password.
    pub message: bool,
}

impl Verification {
    /// Whether every HMAC that was checked matched.
    pub fn is_authentic(&self) -> bool {
        self.message && self.key_block != Some(false)
    }
}

/// What decrypting a stream revealed.
#[must_use]
pub struct DecryptReport {
    header: Header,
    plaintext_len: u64,
    derived_key: Option<DerivedKey>,
    session_iv: SessionIv,
    session_key: SessionKey,
    verification: Verification,
}

impl From<DecryptInfo> for DecryptReport {
    fn from(info: DecryptInfo) -> Self {
        DecryptReport {
            header: info.header,
            plaintext_len: info.plaintext_len,
            derived_key: info.derived_key,
            session_iv: info.session_iv,
            session_key: info.session_key,
            verification: Verification { key_block: info.key_hmac_ok, message: info.message_hmac_ok },
        }
    }
}

impl fmt::Debug for DecryptReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptReport")
            .field("header", &self.header)
            .field("plaintext_len", &self.plaintext_len)
            .field("derived_key", &self.derived_key)
            .field("session_iv", &self.session_iv)
            .field("session_key", &self.session_key)
            .field("verification", &self.verification)
            .finish()
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

    /// The key derived from the password (`None` when decrypting with
    /// [`DecryptKey::Session`]).  It opens the stream again as
    /// [`DecryptKey::Derived`], skipping key derivation.
    pub fn derived_key(&self) -> Option<&DerivedKey> {
        self.derived_key.as_ref()
    }

    /// The IV that encrypted the message (the public IV for version 0).
    pub fn session_iv(&self) -> &SessionIv {
        &self.session_iv
    }

    /// The key that encrypted the message (the derived key for version 0).
    pub fn session_key(&self) -> &SessionKey {
        &self.session_key
    }

    /// Which HMACs matched.
    pub fn verification(&self) -> Verification {
        self.verification
    }
}

/// Decrypted data (wiped on drop) and what decryption revealed.
#[derive(Debug)]
#[must_use]
pub struct Decrypted {
    plaintext: Zeroizing<Vec<u8>>,
    report: DecryptReport,
}

impl Decrypted {
    /// The plaintext.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Keys, header and authentication results.
    pub fn report(&self) -> &DecryptReport {
        &self.report
    }

    /// Take the plaintext (still wiped when dropped) and the report.
    pub fn into_parts(self) -> (Zeroizing<Vec<u8>>, DecryptReport) {
        (self.plaintext, self.report)
    }
}

/// A value produced without checking integrity.
///
/// It may have been modified by an attacker or be garbage from a wrong key.
/// Get at it with [`into_authentic`](Unauthenticated::into_authentic), which
/// fails unless every HMAC matched, or deliberately with
/// [`assume_authentic`](Unauthenticated::assume_authentic).
#[must_use]
pub struct Unauthenticated<T> {
    value: T,
    verification: Verification,
}

impl<T> Unauthenticated<T> {
    /// Which HMACs matched.
    pub fn verification(&self) -> Verification {
        self.verification
    }

    /// Whether every HMAC that was checked matched.
    pub fn is_authentic(&self) -> bool {
        self.verification.is_authentic()
    }

    /// The value, if every HMAC matched; otherwise
    /// [`Error::AuthenticationFailed`].
    pub fn into_authentic(self) -> Result<T, Error> {
        if self.is_authentic() {
            Ok(self.value)
        } else {
            Err(Error::AuthenticationFailed)
        }
    }

    /// The value, whether or not it is authentic.  Only use this when you
    /// have decided to handle possibly altered data, as in forensics.
    pub fn assume_authentic(self) -> T {
        self.value
    }

    /// Look at the value without claiming it is authentic.
    pub fn peek_unauthenticated(&self) -> &T {
        &self.value
    }
}

impl<T> fmt::Debug for Unauthenticated<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unauthenticated").field("verification", &self.verification).finish_non_exhaustive()
    }
}

/// [`RawDecryptor`] mode: fail if an HMAC does not match (the default).
#[derive(Clone, Copy, Debug)]
pub struct Verified;

/// [`RawDecryptor`] mode: decrypt even if an HMAC does not match, returning
/// [`Unauthenticated`] results.
#[derive(Clone, Copy, Debug)]
pub struct Unverified;

impl sealed::Verify for Verified {
    const VERIFY: bool = true;
}

impl sealed::Verify for Unverified {
    const VERIFY: bool = false;
}

/// Whether a [`RawDecryptor`] checks integrity.  Sealed.
pub trait VerifyMode: sealed::Verify {}
impl VerifyMode for Verified {}
impl VerifyMode for Unverified {}

/// Decrypts AES Crypt streams with any [`DecryptKey`], reporting the keys
/// and integrity results.
#[derive(Debug)]
pub struct RawDecryptor<V: VerifyMode = Verified> {
    key: DecryptKey,
    limits: Limits,
    mode: PhantomData<V>,
}

impl RawDecryptor<Verified> {
    /// Decrypt with `key`, verifying both HMACs, within [`Limits::DEFAULT`].
    pub fn new(key: DecryptKey) -> Self {
        RawDecryptor { key, limits: Limits::DEFAULT, mode: PhantomData }
    }

    /// Decrypt even if an HMAC does not match.  Results are wrapped in
    /// [`Unauthenticated`].
    pub fn skip_verification(self) -> RawDecryptor<Unverified> {
        RawDecryptor { key: self.key, limits: self.limits, mode: PhantomData }
    }

    /// Decrypt a stream held in memory.
    pub fn decrypt(&self, data: &[u8]) -> Result<Decrypted, Error> {
        self.decrypt_to_memory(data)
    }

    /// Decrypt from `reader` to `writer`.  Plaintext is written before the
    /// final HMAC check; discard it if this fails.
    pub fn decrypt_stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<DecryptReport, Error> {
        self.run(reader, writer)
    }

    /// Decrypt the file at `input` into `output`, which is only created if
    /// the stream is authentic.
    pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(&self, input: P, output: Q) -> Result<DecryptReport, Error> {
        self.run_file(input.as_ref(), output.as_ref())
    }
}

impl RawDecryptor<Unverified> {
    /// Decrypt a stream held in memory, even if it is not authentic.
    pub fn decrypt(&self, data: &[u8]) -> Result<Unauthenticated<Decrypted>, Error> {
        let decrypted = self.decrypt_to_memory(data)?;
        let verification = decrypted.report.verification;
        Ok(Unauthenticated { value: decrypted, verification })
    }

    /// Decrypt from `reader` to `writer`, even if the stream is not
    /// authentic.  Check the returned verification before trusting what was
    /// written.
    pub fn decrypt_stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<Unauthenticated<DecryptReport>, Error> {
        let report = self.run(reader, writer)?;
        let verification = report.verification;
        Ok(Unauthenticated { value: report, verification })
    }

    /// Decrypt the file at `input` into `output`, even if the stream is not
    /// authentic (for recovering damaged files).
    pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        input: P,
        output: Q,
    ) -> Result<Unauthenticated<DecryptReport>, Error> {
        let report = self.run_file(input.as_ref(), output.as_ref())?;
        let verification = report.verification;
        Ok(Unauthenticated { value: report, verification })
    }
}

impl<V: VerifyMode> RawDecryptor<V> {
    /// Set the resource limits, including raising them above
    /// [`Limits::DEFAULT`].  High iteration limits let a hostile stream
    /// take a very long time to open.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    fn run<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<DecryptReport, Error> {
        let options = DecryptOptions { limits: self.limits, verify: <V as sealed::Verify>::VERIFY };
        Ok(aescrypt::decrypt_engine(self.key.as_engine_key(), &options, reader, writer)?.into())
    }

    fn decrypt_to_memory(&self, data: &[u8]) -> Result<Decrypted, Error> {
        // wiped if decryption fails; large enough to never reallocate
        let mut plaintext = Zeroizing::new(Vec::with_capacity(data.len()));
        let report = self.run(data, &mut *plaintext)?;
        Ok(Decrypted { plaintext, report })
    }

    fn run_file(&self, input: &Path, output: &Path) -> Result<DecryptReport, Error> {
        let reader = BufReader::new(File::open(input)?);
        aescrypt::write_atomically(output, |file| self.run(reader, BufWriter::new(file)))
    }
}

/// Check both HMACs of a stream without returning any plaintext, within
/// [`Limits::DEFAULT`].
///
/// ```
/// # use aescry::security::{verify, DecryptKey, EncryptKey, Iterations, RawEncryptor};
/// let stream = RawEncryptor::new(EncryptKey::password("pw")?)
///     .iterations(Iterations::new(10)?)
///     .encrypt(b"data")?;
///
/// assert!(verify(&DecryptKey::password("pw")?, &stream)?.is_authentic());
/// assert_eq!(verify(&DecryptKey::password("nope")?, &stream)?.key_block, Some(false));
/// # Ok::<(), aescry::Error>(())
/// ```
pub fn verify(key: &DecryptKey, data: &[u8]) -> Result<Verification, Error> {
    let options = DecryptOptions { limits: Limits::DEFAULT, verify: false };
    let info = aescrypt::decrypt_engine(key.as_engine_key(), &options, data, io::sink())?;
    Ok(Verification { key_block: info.key_hmac_ok, message: info.message_hmac_ok })
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
        let size = (self.final_block_size? & 0x0f) as usize;
        let len = self.ciphertext.len();
        Some(match len.checked_sub(BLOCK_SIZE) {
            Some(full_blocks) if size != 0 => full_blocks + size,
            _ => len,
        })
    }
}

/// Copy `N` octets at `range`, or report a truncated stream.
fn field<const N: usize>(data: &[u8], range: &Range<usize>) -> Result<[u8; N], Error> {
    data.get(range.clone())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::InvalidStream(StreamError::Truncated))
}

/// Map the structure of a stream without a password, within
/// [`Limits::DEFAULT`].
///
/// ```
/// # use aescry::security::{inspect, EncryptKey, RawEncryptor};
/// # use aescry::Version;
/// let stream = RawEncryptor::new(EncryptKey::password("pw")?).version(Version::V2).encrypt(&[0; 20])?;
/// let layout = inspect(&stream)?;
///
/// assert_eq!(layout.header.version(), Version::V2);
/// assert_eq!(layout.ciphertext_len(), 32);
/// assert_eq!(layout.plaintext_len(), Some(20));
/// # Ok::<(), aescry::Error>(())
/// ```
pub fn inspect(data: &[u8]) -> Result<Layout, Error> {
    inspect_with_limits(data, Limits::DEFAULT)
}

/// [`inspect`] with explicit resource limits.
pub fn inspect_with_limits(data: &[u8], limits: Limits) -> Result<Layout, Error> {
    let header = aescrypt::read_header_with_limits(data, limits)?;
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
    let mut take = |n: usize| -> Range<usize> {
        let range = pos..pos + n;
        pos = range.end;
        range
    };

    let (key_block, key_block_hmac) = if version >= Version::V1 {
        let block = take(48);
        let hmac = take(32);
        let block_bytes = field(data, &block)?;
        let hmac_bytes = field(data, &hmac)?;
        (Some((block, block_bytes)), Some((hmac, hmac_bytes)))
    } else {
        (None, None)
    };

    let trailer = match version {
        Version::V1 | Version::V2 => 33,
        _ => 32,
    };
    let ciphertext_end = data
        .len()
        .checked_sub(trailer)
        .filter(|&end| end >= pos)
        .ok_or(Error::InvalidStream(StreamError::Truncated))?;

    let ciphertext = pos..ciphertext_end;
    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err(Error::InvalidStream(StreamError::UnalignedCiphertext));
    }

    let final_block_size = match version {
        Version::V0 => Some(header.reserved()),
        Version::V1 | Version::V2 => data.get(ciphertext.end).copied(),
        _ => None,
    };

    // at least `trailer` (>= 32) octets follow the ciphertext
    let hmac = data.len() - 32..data.len();
    let hmac_bytes = field(data, &hmac)?;

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

/// Encrypt whole blocks with AES in ECB mode.  `data` must be a multiple of
/// 16 octets.
///
/// ECB encrypts equal blocks to equal ciphertext and is only useful as a
/// primitive (for example, to reproduce a single block operation).
pub fn ecb_encrypt(key: &AesKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    ecb(key, data, |cipher, block| cipher.encrypt_block(block))
}

/// Decrypt whole blocks with AES in ECB mode.
pub fn ecb_decrypt(key: &AesKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    ecb(key, data, |cipher, block| cipher.decrypt_block(block))
}

fn ecb(key: &AesKey, data: &[u8], op: impl Fn(&Aes, &mut Block)) -> Result<Vec<u8>, Error> {
    if data.len() % BLOCK_SIZE != 0 {
        return Err(Error::InvalidCiphertextLength(data.len()));
    }

    let cipher = Aes::from_key(key);
    let mut out = data.to_vec();
    for chunk in out.chunks_exact_mut(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        op(&cipher, &mut block);
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}
