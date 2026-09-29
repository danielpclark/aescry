//! Key derivation: turning passwords into keys.
//!
//! - [`pbkdf2`] (RFC 8018) with HMAC-SHA256 or HMAC-SHA512, used by AES Crypt
//!   stream format version 3.
//! - [`aescrypt_legacy`], the iterated SHA-256 derivation used by AES Crypt
//!   stream format versions 0, 1 and 2.
//!
//! Passwords are raw octets here.  AES Crypt versions 0–2 encode text
//! passwords as UTF-16LE (see [`utf16le`]) and version 3 as UTF-8.
//!
//! ```
//! use aescry::kdf;
//!
//! let key: [u8; 32] = kdf::pbkdf2_hmac_sha512_array(b"password", b"salt", 1000)?;
//! # Ok::<(), aescry::Error>(())
//! ```

use crate::digest::Digest;
use crate::hmac::Hmac;
use crate::sha256::Sha256;
use crate::sha512::Sha512;
use crate::zeroize::Zeroize;
use crate::Error;

/// PBKDF2 (RFC 8018, section 5.2) with HMAC over the hash `H`.
///
/// Fills `output` with derived key material.  Returns
/// [`Error::InvalidIterations`] if `iterations` is 0.
pub fn pbkdf2<H: Digest>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
) -> Result<(), Error> {
    if iterations == 0 {
        return Err(Error::InvalidIterations(0));
    }

    let prf = Hmac::<H>::new(password);

    for (i, chunk) in output.chunks_mut(H::OUTPUT_SIZE).enumerate() {
        let block_index = (i as u32).wrapping_add(1);

        // U1 = PRF(P, S || INT(i))
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = mac.finalize();
        let mut t = u;

        // Uj = PRF(P, Uj-1); T = U1 ^ U2 ^ ... ^ Uc
        for _ in 1..iterations {
            let mut mac = prf.clone();
            mac.update(u.as_ref());
            u = mac.finalize();

            for (x, y) in t.as_mut().iter_mut().zip(u.as_ref()) {
                *x ^= *y;
            }
        }

        chunk.copy_from_slice(&t.as_ref()[..chunk.len()]);

        u.as_mut().zeroize();
        t.as_mut().zeroize();
    }

    Ok(())
}

/// PBKDF2 with HMAC-SHA256.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<(), Error> {
    pbkdf2::<Sha256>(password, salt, iterations, output)
}

/// PBKDF2 with HMAC-SHA512.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<(), Error> {
    pbkdf2::<Sha512>(password, salt, iterations, output)
}

/// PBKDF2 with HMAC-SHA256, returning `N` octets.
pub fn pbkdf2_hmac_sha256_array<const N: usize>(password: &[u8], salt: &[u8], iterations: u32) -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    pbkdf2_hmac_sha256(password, salt, iterations, &mut out)?;
    Ok(out)
}

/// PBKDF2 with HMAC-SHA512, returning `N` octets.
pub fn pbkdf2_hmac_sha512_array<const N: usize>(password: &[u8], salt: &[u8], iterations: u32) -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    pbkdf2_hmac_sha512(password, salt, iterations, &mut out)?;
    Ok(out)
}

/// The number of SHA-256 iterations in the AES Crypt legacy derivation.
pub const AESCRYPT_LEGACY_ITERATIONS: usize = 8192;

/// The key derivation of AES Crypt stream format versions 0, 1 and 2.
///
/// Starting from the 16-octet IV padded with zeros to 32 octets, the digest
/// is replaced 8192 times by `SHA-256(digest || password)`.  AES Crypt passes
/// the password as UTF-16LE octets; see [`utf16le`].
pub fn aescrypt_legacy(password: &[u8], iv: &[u8; 16]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(iv);

    for _ in 0..AESCRYPT_LEGACY_ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(&digest);
        hasher.update(password);
        let next = hasher.finalize();
        digest.zeroize();
        digest = next;
    }

    digest
}

/// Encode a password as UTF-16LE octets, as AES Crypt versions 0–2 expect.
///
/// The result holds the password; wipe it with
/// [`Zeroize`] when done.
pub fn utf16le(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_iterations_is_an_error() {
        let mut out = [0u8; 32];
        assert!(matches!(pbkdf2_hmac_sha256(b"p", b"s", 0, &mut out), Err(Error::InvalidIterations(0))));
    }

    #[test]
    fn utf16le_encoding() {
        assert_eq!(utf16le("Ab"), vec![0x41, 0x00, 0x62, 0x00]);
        assert_eq!(utf16le("é"), vec![0xE9, 0x00]);
        // outside the BMP: a surrogate pair
        assert_eq!(utf16le("😀"), vec![0x3D, 0xD8, 0x00, 0xDE]);
    }
}
