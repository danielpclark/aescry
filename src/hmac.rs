//! HMAC (RFC 2104 / FIPS 198-1) with SHA-256 or SHA-512.
//!
//! ```
//! use aescry::hmac::{hmac_sha256, HmacSha256};
//!
//! let tag = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
//!
//! let mut mac = HmacSha256::new(b"key");
//! mac.update(b"The quick brown fox ");
//! mac.update(b"jumps over the lazy dog");
//! assert!(mac.verify(&tag).is_ok());
//! ```

use crate::digest::Digest;
use crate::sha256::Sha256;
use crate::sha512::Sha512;
use crate::{ct, Error};
use core::fmt;

/// HMAC with SHA-256.
pub type HmacSha256 = Hmac<Sha256>;

/// HMAC with SHA-512.
pub type HmacSha512 = Hmac<Sha512>;

/// The largest block size of any supported hash.
const MAX_BLOCK_SIZE: usize = 128;

// Digest is sealed, so these are all the hashes Hmac can be used with.
const _: () = assert!(
    crate::sha256::BLOCK_SIZE <= MAX_BLOCK_SIZE
        && crate::sha512::BLOCK_SIZE <= MAX_BLOCK_SIZE
        && crate::sha256::OUTPUT_SIZE <= crate::sha256::BLOCK_SIZE
        && crate::sha512::OUTPUT_SIZE <= crate::sha512::BLOCK_SIZE
);

/// An incremental HMAC computation.
#[derive(Clone)]
pub struct Hmac<H: Digest> {
    inner: H,
    outer: H,
}

impl<H: Digest> fmt::Debug for Hmac<H> {
    // the keyed hash states are derived from the key; never print them
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hmac { .. }")
    }
}

impl<H: Digest> Hmac<H> {
    /// Start an HMAC with `key`, which may be any length.
    pub fn new(key: &[u8]) -> Self {
        let mut block = [0u8; MAX_BLOCK_SIZE];
        let block = &mut block[..H::BLOCK_SIZE];

        // keys longer than the block size are hashed first
        if key.len() > H::BLOCK_SIZE {
            let digest = H::digest(key);
            block[..H::OUTPUT_SIZE].copy_from_slice(digest.as_ref());
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        for b in block.iter_mut() {
            *b ^= 0x36;
        }
        let mut inner = H::new();
        inner.update(block);

        for b in block.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        let mut outer = H::new();
        outer.update(block);

        crate::zeroize::Zeroize::zeroize(block);

        Hmac { inner, outer }
    }

    /// Feed more data into the MAC.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finish and return the tag.
    pub fn finalize(self) -> H::Output {
        let mut inner = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(inner.as_ref());
        crate::zeroize::Zeroize::zeroize(inner.as_mut());
        outer.finalize()
    }

    /// Finish and compare against `tag` in constant time.
    ///
    /// Returns [`Error::AuthenticationFailed`] if the tag does not match.
    pub fn verify(self, tag: &[u8]) -> Result<(), Error> {
        if ct::eq(self.finalize().as_ref(), tag) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }

    /// Finish and compare the leftmost `tag.len()` octets of the tag against
    /// `tag` in constant time.
    ///
    /// Truncated tags weaken the MAC; this refuses tags shorter than
    /// 10 octets (80 bits, the minimum in NIST SP 800-107) or longer than
    /// the hash output.
    pub fn verify_truncated(self, tag: &[u8]) -> Result<(), Error> {
        if tag.len() < 10 || tag.len() > H::OUTPUT_SIZE {
            return Err(Error::AuthenticationFailed);
        }

        if ct::eq(&self.finalize().as_ref()[..tag.len()], tag) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

/// Compute HMAC-SHA256 of `data` in one call.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(data);
    mac.finalize()
}

/// Compute HMAC-SHA512 of `data` in one call.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new(key);
    mac.update(data);
    mac.finalize()
}
