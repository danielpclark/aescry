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
