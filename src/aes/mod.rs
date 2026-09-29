//! The AES (Rijndael) block cipher, FIPS-197.
//!
//! This module provides raw single-block encryption and decryption with
//! 128, 192 and 256-bit keys.  Encrypting individual blocks on their own is
//! the "ECB" mode, which leaks patterns in the data; use it as a building
//! block, not as a way to encrypt messages.
//!
//! ```
//! use aescry::aes::{Aes128, BlockCipher};
//!
//! let key = [0u8; 16];
//! let cipher = Aes128::new(&key);
//!
//! let mut block = *b"sixteen byte msg";
//! cipher.encrypt_block(&mut block);
//! cipher.decrypt_block(&mut block);
//! assert_eq!(&block, b"sixteen byte msg");
//! ```

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod ni;
mod soft;

use crate::secret::Secret;
use crate::Error;
use core::fmt;

/// An AES implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// Portable table-based implementation.  Its timing depends on the key
    /// and data, so it can leak them to an attacker who can measure it.
    Software,
    /// The x86 AES-NI instructions: constant-time and much faster.
    AesNi,
}

impl Backend {
    /// The best backend this CPU supports; [`Backend::AesNi`] where available.
    pub fn detect() -> Backend {
        if Backend::AesNi.is_available() {
            Backend::AesNi
        } else {
            Backend::Software
        }
    }

    /// Whether this backend can be used on this CPU.
    pub fn is_available(self) -> bool {
        match self {
            Backend::Software => true,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Backend::AesNi => ni::available(),
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            Backend::AesNi => false,
        }
    }

    /// Whether this backend runs in constant time.
    pub fn is_constant_time(self) -> bool {
        matches!(self, Backend::AesNi)
    }

    /// A constant-time backend for this CPU, or
    /// [`Error::BackendUnavailable`] if there is none.  Use it to refuse to
    /// run rather than fall back to the table-based software backend:
    ///
    /// ```
    /// use aescry::aes::{Aes, Backend};
    ///
    /// match Backend::constant_time() {
    ///     Ok(backend) => {
    ///         let cipher = Aes::with_backend(&[0u8; 32], backend)?;
    ///         assert!(cipher.backend().is_constant_time());
    ///     }
    ///     Err(e) => eprintln!("no constant-time AES here: {}", e),
    /// }
    /// # Ok::<(), aescry::Error>(())
    /// ```
    pub fn constant_time() -> Result<Backend, Error> {
        if Backend::AesNi.is_available() {
            Ok(Backend::AesNi)
        } else {
            Err(Error::BackendUnavailable)
        }
    }
}

/// A borrowed key whose length is one of the three AES key sizes.
#[derive(Clone, Copy)]
pub(crate) enum KeyRef<'a> {
    K128(&'a [u8; 16]),
    K192(&'a [u8; 24]),
    K256(&'a [u8; 32]),
}

impl<'a> KeyRef<'a> {
    fn from_slice(key: &'a [u8]) -> Result<Self, Error> {
        if let Ok(k) = key.try_into() {
            return Ok(KeyRef::K128(k));
        }
        if let Ok(k) = key.try_into() {
            return Ok(KeyRef::K192(k));
        }
        if let Ok(k) = key.try_into() {
            return Ok(KeyRef::K256(k));
        }
        Err(Error::InvalidKeyLength(key.len()))
    }

    pub(crate) fn as_bytes(&self) -> &'a [u8] {
        match *self {
            KeyRef::K128(k) => k,
            KeyRef::K192(k) => k,
            KeyRef::K256(k) => k,
        }
    }

    /// Key length in 32-bit words (Nk).
    pub(crate) fn words(&self) -> usize {
        match self {
            KeyRef::K128(_) => 4,
            KeyRef::K192(_) => 6,
            KeyRef::K256(_) => 8,
        }
    }

    /// Number of rounds (Nr).
    pub(crate) fn rounds(&self) -> usize {
        match self {
            KeyRef::K128(_) => 10,
            KeyRef::K192(_) => 12,
            KeyRef::K256(_) => 14,
        }
    }
}

/// An AES key of a valid size, wiped when dropped.
///
/// Converting raw bytes checks the length once; everything that takes an
/// `AesKey` can rely on it.
///
/// ```
/// use aescry::aes::{Aes, AesKey, KeySize};
///
/// let key = AesKey::try_from(&[7u8; 24][..])?;
/// assert_eq!(key.size(), KeySize::Aes192);
/// assert!(AesKey::try_from(&[7u8; 20][..]).is_err());
///
/// let cipher = Aes::from_key(&AesKey::generate(KeySize::Aes256)?);
/// assert_eq!(cipher.key_size(), 32);
/// # Ok::<(), aescry::Error>(())
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum AesKey {
    /// A 128-bit key.
    Aes128(Secret<[u8; 16]>),
    /// A 192-bit key.
    Aes192(Secret<[u8; 24]>),
    /// A 256-bit key.
    Aes256(Secret<[u8; 32]>),
}

/// The three AES key sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeySize {
    /// 16 octets.
    Aes128,
    /// 24 octets.
    Aes192,
    /// 32 octets.
    Aes256,
}

impl KeySize {
    /// The key length in octets.
    pub fn len(self) -> usize {
        match self {
            KeySize::Aes128 => 16,
            KeySize::Aes192 => 24,
            KeySize::Aes256 => 32,
        }
    }

    /// Always false: no key size is empty.
    pub fn is_empty(self) -> bool {
        false
    }
}

impl AesKey {
    /// Generate a random key from the operating system's random number
    /// generator.
    pub fn generate(size: KeySize) -> Result<Self, Error> {
        Ok(match size {
            KeySize::Aes128 => AesKey::Aes128(Secret::new(crate::random::bytes()?)),
            KeySize::Aes192 => AesKey::Aes192(Secret::new(crate::random::bytes()?)),
            KeySize::Aes256 => AesKey::Aes256(Secret::new(crate::random::bytes()?)),
        })
    }

    /// The key size.
    pub fn size(&self) -> KeySize {
        match self {
            AesKey::Aes128(_) => KeySize::Aes128,
            AesKey::Aes192(_) => KeySize::Aes192,
            AesKey::Aes256(_) => KeySize::Aes256,
        }
    }

    /// Borrow the key octets.
    pub fn expose_secret(&self) -> &[u8] {
        self.key_ref().as_bytes()
    }

    /// Make a copy of the key.  Both copies are wiped when dropped.
    pub fn clone_secret(&self) -> Self {
        match self {
            AesKey::Aes128(k) => AesKey::Aes128(k.clone_secret()),
            AesKey::Aes192(k) => AesKey::Aes192(k.clone_secret()),
            AesKey::Aes256(k) => AesKey::Aes256(k.clone_secret()),
        }
    }

    fn key_ref(&self) -> KeyRef<'_> {
        match self {
            AesKey::Aes128(k) => KeyRef::K128(k.expose_secret()),
            AesKey::Aes192(k) => KeyRef::K192(k.expose_secret()),
            AesKey::Aes256(k) => KeyRef::K256(k.expose_secret()),
        }
    }
}

impl TryFrom<&[u8]> for AesKey {
    type Error = Error;

    /// Copy a 16, 24 or 32 octet key.
    fn try_from(key: &[u8]) -> Result<Self, Error> {
        Ok(match KeyRef::from_slice(key)? {
            KeyRef::K128(k) => AesKey::Aes128(Secret::new(*k)),
            KeyRef::K192(k) => AesKey::Aes192(Secret::new(*k)),
            KeyRef::K256(k) => AesKey::Aes256(Secret::new(*k)),
        })
    }
}

/// Round keys for whichever backend is in use.
#[derive(Clone)]
enum Inner {
    Soft(soft::KeySchedule),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Ni(ni::KeySchedule),
}

impl Inner {
    /// Expand a key with the best available backend.
    fn auto(key: KeyRef<'_>) -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(ks) = ni::KeySchedule::new(key) {
            return Inner::Ni(ks);
        }
        Inner::Soft(soft::KeySchedule::new(key))
    }

    /// Expand a key with a specific backend.
    fn new(key: KeyRef<'_>, backend: Backend) -> Result<Self, Error> {
        match backend {
            Backend::Software => Ok(Inner::Soft(soft::KeySchedule::new(key))),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Backend::AesNi => ni::KeySchedule::new(key).map(Inner::Ni).ok_or(Error::BackendUnavailable),
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            Backend::AesNi => Err(Error::BackendUnavailable),
        }
    }

    fn backend(&self) -> Backend {
        match self {
            Inner::Soft(_) => Backend::Software,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Inner::Ni(_) => Backend::AesNi,
        }
    }

    fn rounds(&self) -> usize {
        match self {
            Inner::Soft(ks) => ks.nr,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Inner::Ni(ks) => ks.rounds(),
        }
    }

    #[inline]
    fn encrypt(&self, block: &mut Block) {
        match self {
            Inner::Soft(ks) => soft::encrypt(ks, block),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Inner::Ni(ks) => ks.encrypt(block),
        }
    }

    #[inline]
    fn decrypt(&self, block: &mut Block) {
        match self {
            Inner::Soft(ks) => soft::decrypt(ks, block),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Inner::Ni(ks) => ks.decrypt(block),
        }
    }
}

/// The AES block size in octets.
pub const BLOCK_SIZE: usize = 16;

/// A single 16-octet AES block.
pub type Block = [u8; BLOCK_SIZE];

/// A block cipher operating on 16-octet blocks.
pub trait BlockCipher {
    /// Encrypt a single block in place.
    fn encrypt_block(&self, block: &mut Block);

    /// Decrypt a single block in place.
    fn decrypt_block(&self, block: &mut Block);

    /// Encrypt a sequence of independent blocks in place (ECB).
    fn encrypt_blocks(&self, blocks: &mut [Block]) {
        for block in blocks {
            self.encrypt_block(block);
        }
    }

    /// Decrypt a sequence of independent blocks in place (ECB).
    fn decrypt_blocks(&self, blocks: &mut [Block]) {
        for block in blocks {
            self.decrypt_block(block);
        }
    }
}

macro_rules! fixed_key_aes {
    ($name:ident, $variant:ident, $bits:expr, $len:expr) => {
        #[doc = concat!("AES with a ", stringify!($bits), "-bit key.")]
        ///
        /// The fastest available backend is chosen automatically; see
        /// [`Backend`].  Round keys are wiped when the cipher is dropped.
        #[derive(Clone)]
        pub struct $name {
            inner: Inner,
        }

        impl $name {
            #[doc = concat!("The key size in octets (", stringify!($len), ").")]
            pub const KEY_SIZE: usize = $len;

            /// Expand the key into encryption and decryption round keys.
            pub fn new(key: &[u8; $len]) -> Self {
                $name { inner: Inner::auto(KeyRef::$variant(key)) }
            }

            /// Create a cipher from a key slice, which must be exactly
            #[doc = concat!(stringify!($len), " octets long.")]
            pub fn from_slice(key: &[u8]) -> Result<Self, Error> {
                let key: &[u8; $len] = key.try_into().map_err(|_| Error::InvalidKeyLength(key.len()))?;
                Ok(Self::new(key))
            }

            /// Create a cipher that uses a specific backend.  Returns
            /// [`Error::BackendUnavailable`] if this CPU does not support it.
            pub fn with_backend(key: &[u8; $len], backend: Backend) -> Result<Self, Error> {
                Ok($name { inner: Inner::new(KeyRef::$variant(key), backend)? })
            }

            /// The backend in use.
            pub fn backend(&self) -> Backend {
                self.inner.backend()
            }
        }

        impl BlockCipher for $name {
            fn encrypt_block(&self, block: &mut Block) {
                self.inner.encrypt(block);
            }

            fn decrypt_block(&self, block: &mut Block) {
                self.inner.decrypt(block);
            }
        }

        impl fmt::Debug for $name {
            // never print key material
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

fixed_key_aes!(Aes128, K128, 128, 16);
fixed_key_aes!(Aes192, K192, 192, 24);
fixed_key_aes!(Aes256, K256, 256, 32);

/// AES with a key size chosen at runtime (16, 24 or 32 octets).
///
/// ```
/// use aescry::aes::{Aes, BlockCipher};
///
/// let cipher = Aes::new(&[0u8; 24]).unwrap();
/// assert_eq!(cipher.key_size(), 24);
///
/// assert!(Aes::new(&[0u8; 20]).is_err());
/// ```
#[derive(Clone)]
pub struct Aes {
    inner: Inner,
}

impl Aes {
    /// Create a cipher from a 16, 24 or 32 octet key.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Aes { inner: Inner::auto(KeyRef::from_slice(key)?) })
    }

    /// Create a cipher from a validated key; this cannot fail.
    pub fn from_key(key: &AesKey) -> Self {
        Aes { inner: Inner::auto(key.key_ref()) }
    }

    /// Create a cipher that uses a specific backend.  Returns
    /// [`Error::BackendUnavailable`] if this CPU does not support it.
    pub fn with_backend(key: &[u8], backend: Backend) -> Result<Self, Error> {
        Ok(Aes { inner: Inner::new(KeyRef::from_slice(key)?, backend)? })
    }

    /// The key size in octets.
    pub fn key_size(&self) -> usize {
        match self.rounds() {
            10 => 16,
            12 => 24,
            _ => 32,
        }
    }

    /// The number of rounds (10, 12 or 14).
    pub fn rounds(&self) -> usize {
        self.inner.rounds()
    }

    /// The backend in use.
    pub fn backend(&self) -> Backend {
        self.inner.backend()
    }
}

impl BlockCipher for Aes {
    fn encrypt_block(&self, block: &mut Block) {
        self.inner.encrypt(block);
    }

    fn decrypt_block(&self, block: &mut Block) {
        self.inner.decrypt(block);
    }
}

impl fmt::Debug for Aes {
    // never print key material
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes{} {{ .. }}", self.key_size().saturating_mul(8))
    }
}

impl<T: BlockCipher + ?Sized> BlockCipher for &T {
    fn encrypt_block(&self, block: &mut Block) {
        (**self).encrypt_block(block)
    }

    fn decrypt_block(&self, block: &mut Block) {
        (**self).decrypt_block(block)
    }
}
