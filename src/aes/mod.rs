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

mod soft;

use crate::Error;
use core::fmt;

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
        #[derive(Clone)]
        pub struct $name {
            ks: soft::KeySchedule,
        }

        impl $name {
            #[doc = concat!("The key size in octets (", stringify!($len), ").")]
            pub const KEY_SIZE: usize = $len;

            /// Expand the key into encryption and decryption round keys.
            pub fn new(key: &[u8; $len]) -> Self {
                $name { ks: soft::KeySchedule::new(key) }
            }

            /// Create a cipher from a key slice, which must be exactly
            #[doc = concat!(stringify!($len), " octets long.")]
            pub fn from_slice(key: &[u8]) -> Result<Self, Error> {
                if key.len() != $len {
                    return Err(Error::InvalidKeyLength(key.len()));
                }
                Ok($name { ks: soft::KeySchedule::new(key) })
            }
        }

        impl BlockCipher for $name {
            fn encrypt_block(&self, block: &mut Block) {
                soft::encrypt(&self.ks, block);
            }

            fn decrypt_block(&self, block: &mut Block) {
                soft::decrypt(&self.ks, block);
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
    ks: soft::KeySchedule,
}

impl Aes {
    /// Create a cipher from a 16, 24 or 32 octet key.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        match key.len() {
            16 | 24 | 32 => Ok(Aes { ks: soft::KeySchedule::new(key) }),
            n => Err(Error::InvalidKeyLength(n)),
        }
    }

    /// The key size in octets.
    pub fn key_size(&self) -> usize {
        match self.ks.nr {
            10 => 16,
            12 => 24,
            _ => 32,
        }
    }

    /// The number of rounds (10, 12 or 14).
    pub fn rounds(&self) -> usize {
        self.ks.nr
    }
}

impl BlockCipher for Aes {
    fn encrypt_block(&self, block: &mut Block) {
        soft::encrypt(&self.ks, block);
    }

    fn decrypt_block(&self, block: &mut Block) {
        soft::decrypt(&self.ks, block);
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
