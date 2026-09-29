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
    InvalidStream(StreamError),
    /// A header extension is invalid.
    InvalidExtension(ExtensionError),
    /// A stream exceeded a resource limit (see
    /// [`Limits`](crate::aescrypt::Limits)).
    LimitExceeded(Limit),
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
            Error::LimitExceeded(limit) => write!(f, "limit exceeded: {}", limit),
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

/// How an AES Crypt stream is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StreamError {
    /// The stream ends inside the header.
    TruncatedHeader,
    /// The stream ends inside the header extensions.
    TruncatedExtensions,
    /// The stream ends inside the encrypted key block.
    TruncatedKeyBlock,
    /// The stream ends before its trailing HMAC.
    Truncated,
    /// The ciphertext is not a whole number of 16-octet blocks.
    UnalignedCiphertext,
    /// A version 3 stream has no ciphertext (it always has at least one
    /// padded block).
    MissingFinalBlock,
    /// The authenticated final block has invalid PKCS#7 padding.
    InvalidPadding,
    /// The header declares zero PBKDF2 iterations.
    ZeroIterations,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StreamError::TruncatedHeader => "truncated header",
            StreamError::TruncatedExtensions => "truncated extensions",
            StreamError::TruncatedKeyBlock => "truncated key block",
            StreamError::Truncated => "truncated stream",
            StreamError::UnalignedCiphertext => "ciphertext length is not a multiple of 16",
            StreamError::MissingFinalBlock => "missing final block",
            StreamError::InvalidPadding => "invalid padding",
            StreamError::ZeroIterations => "zero PBKDF2 iterations",
        })
    }
}

/// Why a header extension is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExtensionError {
    /// The identifier is empty.
    EmptyIdentifier,
    /// The identifier contains a NUL octet.
    NulInIdentifier,
    /// The encoded extension is empty or longer than 65535 octets.
    InvalidLength,
    /// Stream versions 0 and 1 have no extensions.
    UnsupportedVersion,
}

impl fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ExtensionError::EmptyIdentifier => "the identifier is empty",
            ExtensionError::NulInIdentifier => "the identifier contains a NUL octet",
            ExtensionError::InvalidLength => "extension length must be 1 to 65535 octets",
            ExtensionError::UnsupportedVersion => "versions 0 and 1 do not support extensions",
        })
    }
}

/// A resource limit a stream exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Limit {
    /// The header asks for more PBKDF2 iterations than allowed.
    Iterations {
        /// The count in the stream.
        found: u32,
        /// The largest count allowed.
        max: u32,
    },
    /// The header is longer than allowed.
    HeaderLength {
        /// The largest header length allowed, in octets.
        max: usize,
    },
    /// The header has more extensions than allowed.
    Extensions {
        /// The largest number of extensions allowed.
        max: usize,
    },
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Limit::Iterations { found, max } => write!(f, "{} PBKDF2 iterations (at most {} allowed)", found, max),
            Limit::HeaderLength { max } => write!(f, "header longer than {} octets", max),
            Limit::Extensions { max } => write!(f, "more than {} header extensions", max),
        }
    }
}
