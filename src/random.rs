//! Cryptographically secure random bytes from the operating system.
//!
//! ```
//! let key: [u8; 32] = aescry::random::bytes()?;
//! let iv = aescry::random::iv()?;
//! assert_ne!(key, [0u8; 32]);
//! # let _ = iv;
//! # Ok::<(), aescry::Error>(())
//! ```

use crate::aes::Block;
use crate::Error;

/// Fill `buf` with random octets from the operating system.
pub fn fill(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|e| Error::Random(e.into()))
}

/// Return `N` random octets, e.g. a 16, 24 or 32 octet AES key.
pub fn bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut buf = [0u8; N];
    fill(&mut buf)?;
    Ok(buf)
}

/// Return a random 16-octet initialization vector.
pub fn iv() -> Result<Block, Error> {
    bytes()
}

/// Return a random AES key of `key_size` octets (16, 24 or 32).
pub fn key(key_size: usize) -> Result<Vec<u8>, Error> {
    match key_size {
        16 | 24 | 32 => {
            let mut key = vec![0u8; key_size];
            fill(&mut key)?;
            Ok(key)
        }
        n => Err(Error::InvalidKeyLength(n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_values() {
        let a: [u8; 32] = bytes().unwrap();
        let b: [u8; 32] = bytes().unwrap();
        assert_ne!(a, b);
        assert_ne!(iv().unwrap(), iv().unwrap());
    }

    #[test]
    fn key_sizes() {
        for size in [16, 24, 32] {
            assert_eq!(key(size).unwrap().len(), size);
        }
        assert!(matches!(key(20), Err(Error::InvalidKeyLength(20))));
    }
}
