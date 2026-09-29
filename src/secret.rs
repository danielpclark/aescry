//! A container for secret values.
//!
//! [`Secret`] holds key material and passwords so that they are hard to leak
//! by accident:
//!
//! - the contents are wiped when the secret is dropped;
//! - `Debug` never shows the contents, and there is no `Display`;
//! - comparison with `==` takes constant time;
//! - there is no implicit `Clone`: copying needs [`Secret::clone_secret`];
//! - reading the value needs [`Secret::expose_secret`], which makes every use
//!   of key material easy to find in review.
//!
//! ```
//! use aescry::secret::Secret;
//!
//! let key = Secret::new([0x42u8; 32]);
//! assert_eq!(format!("{:?}", key), "Secret([REDACTED])");
//! assert_eq!(key.expose_secret()[0], 0x42);
//! assert!(key == Secret::new([0x42u8; 32]));
//! ```

use crate::ct;
use crate::zeroize::Zeroize;
use core::fmt;

/// A secret value, wiped on drop and never printed.
pub struct Secret<T: Zeroize> {
    value: T,
}

impl<T: Zeroize> Secret<T> {
    /// Take ownership of a secret value.
    pub fn new(value: T) -> Self {
        Secret { value }
    }

    /// Borrow the secret value.
    pub fn expose_secret(&self) -> &T {
        &self.value
    }

    /// Mutably borrow the secret value.
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Make a copy of the secret.  Both copies are wiped when dropped.
    pub fn clone_secret(&self) -> Self
    where
        T: Clone,
    {
        Secret { value: self.value.clone() }
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Secret::new(value)
    }
}

impl<const N: usize> PartialEq for Secret<[u8; N]> {
    /// Constant-time comparison.
    fn eq(&self, other: &Self) -> bool {
        ct::eq(&self.value, &other.value)
    }
}

impl<const N: usize> Eq for Secret<[u8; N]> {}

impl PartialEq for Secret<Vec<u8>> {
    /// Constant-time comparison (the lengths are not secret).
    fn eq(&self, other: &Self) -> bool {
        ct::eq(&self.value, &other.value)
    }
}

impl Eq for Secret<Vec<u8>> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_behaviour() {
        let mut s = Secret::new(vec![1u8, 2, 3]);
        assert_eq!(s.expose_secret(), &vec![1, 2, 3]);
        s.expose_secret_mut().push(4);

        let copy = s.clone_secret();
        assert!(copy == s);
        assert!(Secret::new(vec![1u8]) != Secret::new(vec![2u8]));
        assert!(Secret::new(vec![1u8]) != Secret::new(vec![1u8, 1]));

        assert_eq!(format!("{:?}", s), "Secret([REDACTED])");
    }
}
