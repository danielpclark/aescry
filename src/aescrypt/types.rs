//! Validated values used by the AES Crypt format.
//!
//! Raw bytes are checked once, when one of these values is created; code that
//! receives them never needs to check again.  Values of the same size are
//! distinct types, so a session key can't be passed where a derived key is
//! expected, or a session IV where the public IV belongs.

use crate::detect::Version;
use crate::secret::Secret;
use crate::zeroize::Zeroize;
use crate::{kdf, random, Error};
use core::fmt;
use core::num::NonZeroU32;

/// A password, wiped when dropped and never printed.
///
/// A text password is encoded the way each stream version expects: UTF-16LE
/// for versions 0–2 and UTF-8 for version 3.  A raw password is a sequence
/// of octets used exactly as given, for every version.
pub struct Password {
    inner: PasswordInner,
}

enum PasswordInner {
    Text(Secret<String>),
    Raw(Secret<Vec<u8>>),
}

impl Password {
    /// A text password.  Returns [`Error::EmptyPassword`] if it is empty.
    pub fn new(text: &str) -> Result<Self, Error> {
        if text.is_empty() {
            return Err(Error::EmptyPassword);
        }
        Ok(Password { inner: PasswordInner::Text(Secret::new(text.to_owned())) })
    }

    /// Password octets passed to key derivation exactly as given: no text
    /// encoding and no validity checks, so any octets (including an empty
    /// password or invalid UTF-8) are accepted.
    pub fn from_raw_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Password { inner: PasswordInner::Raw(Secret::new(bytes.into())) }
    }

    /// Whether this is a raw password (from [`Password::from_raw_bytes`]).
    pub fn is_raw(&self) -> bool {
        matches!(self.inner, PasswordInner::Raw(_))
    }

    /// The octets key derivation receives for a stream of `version`.
    pub fn encoded(&self, version: Version) -> Secret<Vec<u8>> {
        Secret::new(match &self.inner {
            PasswordInner::Text(text) if version >= Version::V3 => text.expose_secret().as_bytes().to_vec(),
            PasswordInner::Text(text) => kdf::utf16le(text.expose_secret()),
            PasswordInner::Raw(raw) => raw.expose_secret().clone(),
        })
    }

    /// Make a copy of the password.  Both copies are wiped when dropped.
    pub fn clone_secret(&self) -> Self {
        Password {
            inner: match &self.inner {
                PasswordInner::Text(t) => PasswordInner::Text(t.clone_secret()),
                PasswordInner::Raw(r) => PasswordInner::Raw(r.clone_secret()),
            },
        }
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_raw() { "Password::Raw([REDACTED])" } else { "Password::Text([REDACTED])" })
    }
}

fn to_array<const N: usize>(bytes: &[u8], err: fn(usize) -> Error) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| err(bytes.len()))
}

macro_rules! iv_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// A random value from the operating system.
            pub fn generate() -> Result<Self, Error> {
                Ok($name(random::bytes()?))
            }

            /// The 16 octets.
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl From<[u8; 16]> for $name {
            fn from(bytes: [u8; 16]) -> Self {
                $name(bytes)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = Error;

            /// Copy exactly 16 octets; any other length is
            /// [`Error::InvalidIvLength`].
            fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                Ok($name(to_array(bytes, Error::InvalidIvLength)?))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                for b in &self.0 {
                    write!(f, "{:02x}", b)?;
                }
                f.write_str(")")
            }
        }
    };
}

iv_type!(
    /// The public IV in a stream header.  It is also the key derivation
    /// salt, and is not secret.
    PublicIv
);

iv_type!(
    /// The IV that encrypts the message (versions 1–3).  It is stored
    /// encrypted in the stream.  For version 0 streams, which have no
    /// session values, reports use the public IV here.
    SessionIv
);

macro_rules! key_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name(Secret<[u8; 32]>);

        impl $name {
            /// A random key from the operating system.
            pub fn generate() -> Result<Self, Error> {
                Ok($name(Secret::new(random::bytes()?)))
            }

            /// Borrow the key octets.
            pub fn expose_secret(&self) -> &[u8; 32] {
                self.0.expose_secret()
            }

            /// Make a copy of the key.  Both copies are wiped when dropped.
            pub fn clone_secret(&self) -> Self {
                $name(self.0.clone_secret())
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(mut bytes: [u8; 32]) -> Self {
                let key = $name(Secret::new(bytes));
                bytes.zeroize();
                key
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = Error;

            /// Copy exactly 32 octets; any other length is
            /// [`Error::InvalidKeyLength`].
            fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                Ok($name(Secret::new(to_array(bytes, Error::InvalidKeyLength)?)))
            }
        }
    };
}

key_type!(
    /// The AES-256 key that encrypts the message (versions 1–3), stored
    /// encrypted in the stream.  For version 0 streams, which have no session
    /// values, reports use the derived key here.
    SessionKey
);

key_type!(
    /// The 32-octet key derived from a password and the public IV.  It
    /// protects the session key (versions 1–3) or the message (version 0).
    DerivedKey
);

impl DerivedKey {
    /// Derive the key for a stream of `version` from a password and the
    /// public IV.
    ///
    /// Version 3 uses PBKDF2-HMAC-SHA512 with `iterations`; versions 0–2
    /// use 8192 rounds of SHA-256 and ignore `iterations`.
    pub fn derive(version: Version, password: &Password, iv: &PublicIv, iterations: Iterations) -> Result<Self, Error> {
        let encoded = password.encoded(version);
        let key = if version >= Version::V3 {
            kdf::pbkdf2_hmac_sha512_array(encoded.expose_secret(), iv.as_bytes(), iterations.get())?
        } else {
            kdf::aescrypt_legacy(encoded.expose_secret(), iv.as_bytes())
        };
        Ok(DerivedKey::from(key))
    }
}

/// The PBKDF2 iteration count used by default, matching the AES Crypt 4.x
/// command-line tool.
pub const DEFAULT_ITERATIONS: u32 = 600_000;

/// The smallest accepted PBKDF2 iteration count.
pub const MIN_ITERATIONS: u32 = 1;

/// The largest PBKDF2 iteration count accepted by default, matching the
/// AES Crypt reference implementation.
pub const MAX_ITERATIONS: u32 = 5_000_000;

/// A PBKDF2 iteration count: never zero, and by default at most
/// [`MAX_ITERATIONS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Iterations(NonZeroU32);

impl Iterations {
    /// [`DEFAULT_ITERATIONS`].
    pub const DEFAULT: Iterations = match NonZeroU32::new(DEFAULT_ITERATIONS) {
        Some(n) => Iterations(n),
        None => panic!("DEFAULT_ITERATIONS is not zero"),
    };

    /// An iteration count from [`MIN_ITERATIONS`] to [`MAX_ITERATIONS`];
    /// anything else is [`Error::InvalidIterations`].
    pub fn new(iterations: u32) -> Result<Self, Error> {
        if iterations > MAX_ITERATIONS {
            return Err(Error::InvalidIterations(iterations));
        }
        Self::new_unbounded(iterations)
    }

    /// Any iteration count except zero, including counts above
    /// [`MAX_ITERATIONS`] that can take a very long time.  For security
    /// testing; ordinary streams should use [`Iterations::new`].
    pub fn new_unbounded(iterations: u32) -> Result<Self, Error> {
        NonZeroU32::new(iterations).map(Iterations).ok_or(Error::InvalidIterations(iterations))
    }

    /// The iteration count.
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl Default for Iterations {
    fn default() -> Self {
        Iterations::DEFAULT
    }
}

impl TryFrom<u32> for Iterations {
    type Error = Error;

    fn try_from(iterations: u32) -> Result<Self, Error> {
        Iterations::new(iterations)
    }
}

/// Resource limits for reading streams.
///
/// Every length and count in a stream header comes from the stream itself, so
/// these bound how much memory and CPU a hostile stream can make a reader
/// spend.  The [`aescrypt`](super) API can only lower them; the
/// [`security`](crate::security) toolkit can raise them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// The largest PBKDF2 iteration count to accept (version 3).
    pub max_iterations: u32,
    /// The largest header to read, in octets, up to and including the
    /// public IV.
    pub max_header_len: usize,
    /// The largest number of header extensions to read.
    pub max_extensions: usize,
}

impl Limits {
    /// The defaults: [`MAX_ITERATIONS`], a 1 MiB header and 256 extensions.
    pub const DEFAULT: Limits = Limits { max_iterations: MAX_ITERATIONS, max_header_len: 1 << 20, max_extensions: 256 };

    /// Set the largest iteration count.
    pub fn max_iterations(mut self, max: u32) -> Self {
        self.max_iterations = max;
        self
    }

    /// Set the largest header length in octets.
    pub fn max_header_len(mut self, max: usize) -> Self {
        self.max_header_len = max;
        self
    }

    /// Set the largest number of extensions.
    pub fn max_extensions(mut self, max: usize) -> Self {
        self.max_extensions = max;
        self
    }

    /// Each limit lowered to at most the default.
    pub(crate) fn at_most_default(self) -> Limits {
        Limits {
            max_iterations: self.max_iterations.min(Limits::DEFAULT.max_iterations),
            max_header_len: self.max_header_len.min(Limits::DEFAULT.max_header_len),
            max_extensions: self.max_extensions.min(Limits::DEFAULT.max_extensions),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_validate_lengths() {
        assert!(PublicIv::try_from(&[0u8; 16][..]).is_ok());
        assert!(matches!(PublicIv::try_from(&[0u8; 15][..]), Err(Error::InvalidIvLength(15))));
        assert!(matches!(SessionIv::try_from(&[0u8; 17][..]), Err(Error::InvalidIvLength(17))));
        assert!(matches!(SessionKey::try_from(&[0u8; 16][..]), Err(Error::InvalidKeyLength(16))));
        assert!(matches!(DerivedKey::try_from(&[0u8; 33][..]), Err(Error::InvalidKeyLength(33))));
        assert_ne!(PublicIv::generate().unwrap(), PublicIv::generate().unwrap());
    }

    #[test]
    fn iterations_bounds() {
        assert!(matches!(Iterations::new(0), Err(Error::InvalidIterations(0))));
        assert_eq!(Iterations::new(1).unwrap().get(), 1);
        assert_eq!(Iterations::new(MAX_ITERATIONS).unwrap().get(), MAX_ITERATIONS);
        assert!(Iterations::new(MAX_ITERATIONS + 1).is_err());
        assert_eq!(Iterations::new_unbounded(u32::MAX).unwrap().get(), u32::MAX);
        assert!(Iterations::new_unbounded(0).is_err());
        assert_eq!(Iterations::default().get(), DEFAULT_ITERATIONS);
    }

    #[test]
    fn passwords() {
        assert!(matches!(Password::new(""), Err(Error::EmptyPassword)));
        let text = Password::new("é").unwrap();
        assert_eq!(text.encoded(Version::V2).expose_secret(), &vec![0xE9, 0x00]);
        assert_eq!(text.encoded(Version::V3).expose_secret(), &vec![0xC3, 0xA9]);

        let raw = Password::from_raw_bytes(vec![0xFF]);
        assert!(raw.is_raw());
        assert_eq!(raw.encoded(Version::V0).expose_secret(), &vec![0xFF]);
        assert_eq!(raw.encoded(Version::V3).expose_secret(), &vec![0xFF]);

        assert_eq!(format!("{:?}", text), "Password::Text([REDACTED])");
        assert_eq!(format!("{:?}", DerivedKey::from([1u8; 32])), "DerivedKey(Secret([REDACTED]))");
    }

    #[test]
    fn limits_only_lower_by_default() {
        let raised = Limits::DEFAULT.max_iterations(u32::MAX).max_extensions(10_000);
        assert_eq!(raised.at_most_default(), Limits::DEFAULT);
        let lowered = Limits::DEFAULT.max_iterations(10);
        assert_eq!(lowered.at_most_default().max_iterations, 10);
    }
}
