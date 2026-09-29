use core::fmt;
use std::io;

/// Errors returned by this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A key had an unsupported length (in octets).
    InvalidKeyLength(usize),
    /// An initialization vector was not 16 octets long.
    InvalidIvLength(usize),
    /// Data to be decrypted (or encrypted without padding) was not a
    /// multiple of the 16-octet block size.
    InvalidCiphertextLength(usize),
    /// Decrypted data did not end with valid PKCS#7 padding.  Without an
    /// integrity check this usually means the key or IV was wrong.
    InvalidPadding,
    /// A MAC or other integrity check did not match.
    AuthenticationFailed,
    /// A key derivation iteration count was out of range.
    InvalidIterations(u32),
    /// An empty password was given.
    EmptyPassword,
    /// The password is incorrect, or the part of the stream protecting the
    /// key was modified.
    InvalidPassword,
    /// The encrypted message was modified or truncated.
    AlteredMessage,
    /// The data does not start with the AES Crypt header.
    NotAesCrypt,
    /// The AES Crypt stream format version is not supported.
    UnsupportedVersion(u8),
    /// The AES Crypt stream is malformed.
    InvalidStream(&'static str),
    /// A header extension is invalid.
    InvalidExtension(&'static str),
    /// A path has no file name.
    InvalidPath,
    /// The requested AES backend is not supported by this CPU.
    BackendUnavailable,
    /// The operating system's random number generator failed.
    Random(io::Error),
    /// An I/O error occurred while reading or writing.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength(n) => write!(f, "invalid key length: {} octets", n),
            Error::InvalidIvLength(n) => write!(f, "invalid IV length: {} octets (expected 16)", n),
            Error::InvalidCiphertextLength(n) => {
                write!(f, "invalid data length: {} octets is not a multiple of 16", n)
            }
            Error::InvalidPadding => f.write_str("invalid padding"),
            Error::AuthenticationFailed => f.write_str("authentication failed"),
            Error::InvalidIterations(n) => write!(f, "invalid iteration count: {}", n),
            Error::EmptyPassword => f.write_str("the password is empty"),
            Error::InvalidPassword => f.write_str("the password is incorrect or the stream was altered"),
            Error::AlteredMessage => f.write_str("the encrypted message was altered or truncated"),
            Error::NotAesCrypt => f.write_str("not an AES Crypt stream"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported AES Crypt stream version {}", v),
            Error::InvalidStream(why) => write!(f, "invalid AES Crypt stream: {}", why),
            Error::InvalidExtension(why) => write!(f, "invalid extension: {}", why),
            Error::InvalidPath => f.write_str("the path has no file name"),
            Error::BackendUnavailable => f.write_str("the AES backend is not supported by this CPU"),
            Error::Random(e) => write!(f, "random number generator failed: {}", e),
            Error::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) | Error::Random(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
