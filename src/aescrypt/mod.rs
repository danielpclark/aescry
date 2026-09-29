//! The [AES Crypt] file format: password-based encryption of files and data.
//!
//! Streams written here use format version 3: PBKDF2-HMAC-SHA512 key
//! derivation, AES-256-CBC with a random session key, PKCS#7 padding and
//! HMAC-SHA256 integrity checks.  Streams of versions 0–3 can be read.
//! Output is compatible with the AES Crypt 4.x tools.
//!
//! ```
//! use aescry::aescrypt::{self, Encryptor};
//!
//! let data = b"any bytes at all \x00\xff";
//!
//! // Low iteration counts keep examples fast; use the default for real data.
//! let encrypted = Encryptor::new("correct horse")?.iterations(1000).encrypt(data)?;
//! let decrypted = aescrypt::decrypt("correct horse", &encrypted)?;
//! assert_eq!(decrypted, data);
//!
//! assert!(matches!(aescrypt::decrypt("wrong", &encrypted), Err(aescry::Error::InvalidPassword)));
//! # Ok::<(), aescry::Error>(())
//! ```
//!
//! [AES Crypt]: https://www.aescrypt.com/aes_stream_format.html

mod engine;
mod format;

pub use self::format::{Extension, Header, DEFAULT_CONTAINER_LEN, MAX_EXTENSION_LEN};

pub(crate) use self::engine::{
    decrypt as decrypt_engine, encrypt as encrypt_engine, Credential, DecryptInfo, DecryptOptions,
    EncryptParams,
};

use crate::detect::Version;
use crate::zeroize::Zeroizing;
use crate::{random, Error};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// The PBKDF2 iteration count used by default, matching the AES Crypt 4.x
/// command-line tool.
pub const DEFAULT_ITERATIONS: u32 = 600_000;

/// The smallest accepted PBKDF2 iteration count.
pub const MIN_ITERATIONS: u32 = 1;

/// The largest accepted PBKDF2 iteration count.  Larger values in a stream
/// are refused, so a hostile file cannot make decryption take hours.
pub const MAX_ITERATIONS: u32 = engine::MAX_ITERATIONS;

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
/// [`Error::NotAesCrypt`], [`Error::UnsupportedVersion`] and
/// [`Error::InvalidStream`].
pub fn decrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    Decryptor::new(password)?.decrypt(data)
}

/// Read only the unencrypted header of a stream.
///
/// ```
/// # use aescry::aescrypt::{self, Encryptor};
/// let encrypted = Encryptor::new("pw")?.iterations(1000).encrypt(b"hi")?;
/// let header = aescrypt::read_header(&encrypted[..])?;
///
/// assert_eq!(header.version(), aescry::Version::V3);
/// assert_eq!(header.iterations(), Some(1000));
/// assert!(header.extension("CREATED_BY").unwrap().starts_with(b"aescry"));
/// # Ok::<(), aescry::Error>(())
/// ```
pub fn read_header<R: Read>(mut reader: R) -> Result<Header, Error> {
    format::read_header(&mut reader, true)
}

fn check_password(password: &str) -> Result<(), Error> {
    if password.is_empty() {
        Err(Error::EmptyPassword)
    } else {
        Ok(())
    }
}

/// Encrypts data into AES Crypt format version 3.
///
/// By default the stream carries a `CREATED_BY` extension naming this crate
/// and an empty 128-octet container extension, as AES Crypt recommends.
#[derive(Clone)]
pub struct Encryptor<'a> {
    password: &'a str,
    iterations: u32,
    extensions: Vec<Extension>,
    default_extensions: bool,
}

impl core::fmt::Debug for Encryptor<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Encryptor")
            .field("iterations", &self.iterations)
            .field("extensions", &self.extensions)
            .field("default_extensions", &self.default_extensions)
            .finish_non_exhaustive()
    }
}

impl<'a> Encryptor<'a> {
    /// Create an encryptor for a non-empty password.
    pub fn new(password: &'a str) -> Result<Self, Error> {
        check_password(password)?;

        Ok(Encryptor {
            password,
            iterations: DEFAULT_ITERATIONS,
            extensions: Vec::new(),
            default_extensions: true,
        })
    }

    /// Set the PBKDF2 iteration count ([`MIN_ITERATIONS`] to
    /// [`MAX_ITERATIONS`]).  Higher is slower for attackers and for you.
    pub fn iterations(mut self, iterations: u32) -> Self {
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
        let mut extensions = Vec::with_capacity(self.extensions.len() + 2);

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
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(Error::InvalidIterations(self.iterations));
        }

        let extensions = self.all_extensions()?;
        let params = EncryptParams {
            version: Version::V3,
            credential: Credential::Text(self.password),
            iterations: self.iterations,
            extensions: &extensions,
            public_iv: random::bytes()?,
            session_iv: random::bytes()?,
            session_key: random::bytes()?,
        };

        encrypt_engine(&params, reader, writer)
    }

    /// Encrypt `plaintext` and return the AES Crypt stream.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len() + 400);
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
#[derive(Clone)]
pub struct Decryptor<'a> {
    password: &'a str,
    max_iterations: u32,
}

impl core::fmt::Debug for Decryptor<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Decryptor").field("max_iterations", &self.max_iterations).finish_non_exhaustive()
    }
}

impl<'a> Decryptor<'a> {
    /// Create a decryptor for a non-empty password.
    pub fn new(password: &'a str) -> Result<Self, Error> {
        check_password(password)?;
        Ok(Decryptor { password, max_iterations: MAX_ITERATIONS })
    }

    /// Refuse version 3 streams that ask for more than `max` PBKDF2
    /// iterations (at most [`MAX_ITERATIONS`]).
    pub fn max_iterations(mut self, max: u32) -> Self {
        self.max_iterations = max.min(MAX_ITERATIONS);
        self
    }

    fn stream<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<DecryptInfo, Error> {
        let options = DecryptOptions { max_iterations: self.max_iterations, verify: true };
        decrypt_engine(Credential::Text(self.password), &options, reader, writer)
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
