//! A common interface to the hash functions in this crate.
//!
//! [`Hmac`](crate::hmac::Hmac) and [`pbkdf2`](crate::kdf::pbkdf2) are generic
//! over this trait.  It is sealed: only this crate's hashes implement it, so
//! code generic over `Digest` can rely on their sizes.

use crate::{sha256::Sha256, sha512::Sha512};

mod private {
    pub trait Sealed {}
    impl Sealed for crate::sha256::Sha256 {}
    impl Sealed for crate::sha512::Sha512 {}
}

/// An incremental cryptographic hash function.
pub trait Digest: Clone + private::Sealed {
    /// Digest size in octets.
    const OUTPUT_SIZE: usize;
    /// Internal block size in octets.
    const BLOCK_SIZE: usize;
    /// The digest, a fixed-size array of octets.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// Create a hasher in its initial state.
    fn new() -> Self;
    /// Feed more data into the hash.
    fn update(&mut self, data: &[u8]);
    /// Finish the hash and return the digest.
    fn finalize(self) -> Self::Output;

    /// Hash `data` in one call.
    fn digest(data: &[u8]) -> Self::Output {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Digest for Sha256 {
    const OUTPUT_SIZE: usize = crate::sha256::OUTPUT_SIZE;
    const BLOCK_SIZE: usize = crate::sha256::BLOCK_SIZE;
    type Output = [u8; crate::sha256::OUTPUT_SIZE];

    fn new() -> Self {
        Sha256::new()
    }

    fn update(&mut self, data: &[u8]) {
        Sha256::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        Sha256::finalize(self)
    }
}

impl Digest for Sha512 {
    const OUTPUT_SIZE: usize = crate::sha512::OUTPUT_SIZE;
    const BLOCK_SIZE: usize = crate::sha512::BLOCK_SIZE;
    type Output = [u8; crate::sha512::OUTPUT_SIZE];

    fn new() -> Self {
        Sha512::new()
    }

    fn update(&mut self, data: &[u8]) {
        Sha512::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        Sha512::finalize(self)
    }
}
