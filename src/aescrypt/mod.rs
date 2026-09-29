//! The [AES Crypt] file format: password-based encryption of files and data.
//!
//! Streams written here use format version 3: PBKDF2-HMAC-SHA512 key
//! derivation, AES-256-CBC with a random session key, PKCS#7 padding and
//! HMAC-SHA256 integrity checks.  Streams of versions 0–3 can be read.
//! Output is compatible with the AES Crypt 4.x tools.
//!
//! ```
//! use aescry::aescrypt::{self, Encryptor, Iterations};
//!
//! let data = b"any bytes at all \x00\xff";
//!
//! // Low iteration counts keep examples fast; use the default for real data.
//! let encrypted = Encryptor::new("correct horse")?.iterations(Iterations::new(1000)?).encrypt(data)?;
//! let decrypted = aescrypt::decrypt("correct horse", &encrypted)?;
//! assert_eq!(decrypted, data);
//!
//! assert!(matches!(aescrypt::decrypt("wrong", &encrypted), Err(aescry::Error::InvalidPassword)));
//! # Ok::<(), aescry::Error>(())
//! ```
//!
//! Versions 0–2 do not authenticate the final block size, so a modified
//! legacy file can lose up to 15 octets from its end without failing the
//! HMAC checks.  Version 3 authenticates its padding.  The
//! [`security`](crate::security) toolkit can detect most such changes (see
//! `Verification::final_block`).
//!
//! Reading a stream is bounded by [`Limits`]: at most
//! [`MAX_ITERATIONS`] of PBKDF2, a 1 MiB header and 256 extensions, so a
//! hostile stream cannot make a reader spend unbounded memory or time.
//!
//! [AES Crypt]: https://www.aescrypt.com/aes_stream_format.html

mod engine;
mod format;
mod types;

pub use self::format::{Extension, Header, DEFAULT_CONTAINER_LEN, MAX_EXTENSION_LEN};
pub use self::types::{
    DerivedKey, Iterations, Limits, Password, PublicIv, SessionIv, SessionKey, DEFAULT_ITERATIONS, MAX_ITERATIONS,
    MIN_ITERATIONS,
};

pub(crate) use self::engine::{
    decrypt as decrypt_engine, encrypt as encrypt_engine, DecryptInfo, DecryptKey, DecryptOptions, EncryptKey,
    EncryptParams,
};

use crate::detect::Version;
use crate::zeroize::Zeroizing;
use crate::{random, Error};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// Encrypt `plaintext` with `password` using the default settings.
///
/// This uses [`DEFAULT_ITERATIONS`] of PBKDF2, which intentionally takes a
/// noticeable fraction of a second.
pub fn encrypt(password: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    Encryptor::new(password)?.encrypt(plaintext)
}

/// Decrypt an AES Crypt stream (versions 0–3) held in memory.
///
/// Both HMACs are verified before any plaintext is returned.
///
/// Errors include [`Error::InvalidPassword`] for a wrong password,
/// [`Error::AlteredMessage`] if the ciphertext was modified or truncated,
/// [`Error::NotAesCrypt`], [`Error::UnsupportedVersion`],
/// [`Error::InvalidStream`] and [`Error::LimitExceeded`].
pub fn decrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    Decryptor::new(password)?.decrypt(data)
}

/// Read only the unencrypted header of a stream, within the default
/// [`Limits`].
///
/// ```
/// # use aescry::aescrypt::{self, Encryptor, Iterations};
/// let encrypted = Encryptor::new("pw")?.iterations(Iterations::new(1000)?).encrypt(b"hi")?;
/// let header = aescrypt::read_header(&encrypted[..])?;
///
/// assert_eq!(header.version(), aescry::Version::V3);
/// assert_eq!(header.iterations(), Some(1000));
/// assert!(header.extension("CREATED_BY").unwrap().starts_with(b"aescry"));
/// # Ok::<(), aescry::Error>(())
/// ```
pub fn read_header<R: Read>(reader: R) -> Result<Header, Error> {
    read_header_with_limits(reader, Limits::DEFAULT)
}

/// Read only the unencrypted header of a stream, within `limits`.
pub fn read_header_with_limits<R: Read>(mut reader: R, limits: Limits) -> Result<Header, Error> {
    format::read_header(&mut reader, true, &limits)
}

/// Encrypts data into AES Crypt format version 3.
///
/// By default the stream carries a `CREATED_BY` extension naming this crate
/// and an empty 128-octet container extension, as AES Crypt recommends.
pub struct Encryptor {
    password: Password,
    iterations: Iterations,
    extensions: Vec<Extension>,
    default_extensions: bool,
}

impl core::fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Encryptor")
            .field("password", &self.password)
            .field("iterations", &self.iterations)
            .field("extensions", &self.extensions)
            .field("default_extensions", &self.default_extensions)
            .finish()
    }
}

impl Encryptor {
    /// Create an encryptor for a non-empty text password.
    pub fn new(password: &str) -> Result<Self, Error> {
        Ok(Encryptor {
            password: Password::new(password)?,
            iterations: Iterations::DEFAULT,
            extensions: Vec::new(),
            default_extensions: true,
        })
    }

    /// Set the PBKDF2 iteration count.  Higher is slower for attackers and
    /// for you.
    pub fn iterations(mut self, iterations: Iterations) -> Self {
        self.iterations = iterations;
        self
    }

    /// Add a header extension.  Extensions are stored in plain text and are
    /// not authenticated.
    pub fn extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Do not add the `CREATED_BY` and container extensions.
    pub fn without_default_extensions(mut self) -> Self {
        self.default_extensions = false;
        self
    }

    fn all_extensions(&self) -> Result<Vec<Extension>, Error> {
        let mut extensions = Vec::with_capacity(self.extensions.len().saturating_add(2));

        if self.default_extensions {
            extensions.push(Extension::new("CREATED_BY", concat!("aescry ", env!("CARGO_PKG_VERSION")))?);
        }
        extensions.extend(self.extensions.iter().cloned());
        if self.default_extensions {
            extensions.push(Extension::container(DEFAULT_CONTAINER_LEN)?);
        }

        Ok(extensions)
    }

    fn stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<u64, Error> {
        let extensions = self.all_extensions()?;
        let session_key = SessionKey::generate()?;
        let params = EncryptParams {
            version: Version::V3,
            key: EncryptKey::Password(&self.password),
            iterations: self.iterations,
            extensions: &extensions,
            public_iv: PublicIv::generate()?,
            session_iv: SessionIv::generate()?,
            session_key: &session_key,
        };

        encrypt_engine(&params, reader, writer)
    }

    /// Encrypt `plaintext` and return the AES Crypt stream.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len().saturating_add(400));
        self.stream(plaintext, &mut out)?;
        Ok(out)
    }

    /// Encrypt everything read from `reader`, writing the stream to `writer`.
    /// Returns the number of plaintext octets read.
    pub fn encrypt_stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<u64, Error> {
        self.stream(reader, writer)
    }

    /// Encrypt the file at `input` into a new file at `output`.
    ///
    /// The output is written to a temporary file in the same directory and
    /// renamed into place once complete, replacing any existing file.
    pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(&self, input: P, output: Q) -> Result<u64, Error> {
        let reader = BufReader::new(File::open(input)?);
        write_atomically(output.as_ref(), |file| self.stream(reader, BufWriter::new(file)))
    }
}

/// Decrypts AES Crypt streams of versions 0–3.
pub struct Decryptor {
    password: Password,
    limits: Limits,
}

impl core::fmt::Debug for Decryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Decryptor").field("password", &self.password).field("limits", &self.limits).finish()
    }
}

impl Decryptor {
    /// Create a decryptor for a non-empty text password.
    pub fn new(password: &str) -> Result<Self, Error> {
        Ok(Decryptor { password: Password::new(password)?, limits: Limits::DEFAULT })
    }

    /// Use stricter resource limits.  Each limit can only be lowered from
    /// [`Limits::DEFAULT`]; the [`security`](crate::security) toolkit can
    /// raise them.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits.at_most_default();
        self
    }

    fn stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<DecryptInfo, Error> {
        let options = DecryptOptions::verified(self.limits);
        decrypt_engine(DecryptKey::Password(&self.password), &options, reader, writer)
    }

    /// Decrypt a stream held in memory.  Both HMACs are verified before
    /// any plaintext is returned.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        // wiped if decryption fails; large enough to never reallocate
        let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
        self.stream(data, &mut *out)?;
        Ok(out.take())
    }

    /// Decrypt a stream from `reader`, writing plaintext to `writer`, and
    /// return the number of plaintext octets.
    ///
    /// Plaintext is written as it is decrypted, before the final integrity
    /// check.  If this returns an error, anything already written must be
    /// discarded: it may be unauthenticated.
    pub fn decrypt_stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<u64, Error> {
        Ok(self.stream(reader, writer)?.plaintext_len)
    }

    /// Decrypt the file at `input` into a new file at `output`.
    ///
    /// Plaintext is written to a temporary file in the same directory, which
    /// is renamed into place only if the stream is authentic and deleted
    /// otherwise, so `output` never holds unauthenticated data.
    pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(&self, input: P, output: Q) -> Result<u64, Error> {
        let reader = BufReader::new(File::open(input)?);
        write_atomically(output.as_ref(), |file| Ok(self.stream(reader, BufWriter::new(file))?.plaintext_len))
    }
}

/// Write to a new temporary file next to `path`, then rename it to `path`
/// if `write` succeeds, or delete it if it fails.
pub(crate) fn write_atomically<T>(path: &Path, write: impl FnOnce(&mut File) -> Result<T, Error>) -> Result<T, Error> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path.file_name().ok_or(Error::InvalidPath)?;

    let suffix: [u8; 8] = random::bytes()?;
    let suffix: String = suffix.iter().map(|b| format!("{:02x}", b)).collect();
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".{}.aescry-tmp", suffix));
    let temp = dir.join(temp_name);

    let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)?;

    let result = write(&mut file).and_then(|value| {
        file.sync_all()?;
        Ok(value)
    });
    drop(file);

    match result {
        Ok(value) => match fs::rename(&temp, path) {
            Ok(()) => Ok(value),
            Err(e) => {
                let _ = fs::remove_file(&temp);
                Err(e.into())
            }
        },
        Err(e) => {
            let _ = fs::remove_file(&temp);
            Err(e)
        }
    }
}
