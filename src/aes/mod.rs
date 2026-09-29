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
}

/// Round keys for whichever backend is in use.
#[derive(Clone)]
enum Inner {
    Soft(soft::KeySchedule),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Ni(ni::KeySchedule),
}

impl Inner {
    /// Expand a 16, 24 or 32 octet key.  The caller guarantees the length.
    fn new(key: &[u8], backend: Backend) -> Result<Self, Error> {
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
    ($name:ident, $bits:expr, $len:expr) => {
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
                $name { inner: Inner::new(key, Backend::detect()).expect("detected backend is available") }
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
                Ok($name { inner: Inner::new(key, backend)? })
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

fixed_key_aes!(Aes128, 128, 16);
fixed_key_aes!(Aes192, 192, 24);
fixed_key_aes!(Aes256, 256, 32);

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
        Self::with_backend(key, Backend::detect())
    }

    /// Create a cipher that uses a specific backend.  Returns
    /// [`Error::BackendUnavailable`] if this CPU does not support it.
    pub fn with_backend(key: &[u8], backend: Backend) -> Result<Self, Error> {
        match key.len() {
            16 | 24 | 32 => Ok(Aes { inner: Inner::new(key, backend)? }),
            n => Err(Error::InvalidKeyLength(n)),
        }
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
        write!(f, "Aes{} {{ .. }}", self.key_size() * 8)
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
