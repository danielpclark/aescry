//! Wiping secrets from memory.
//!
//! Ordinary writes of zeros to memory that is about to be freed can be
//! removed by the optimizer.  [`Zeroize`] uses volatile writes, which are
//! never removed, followed by a compiler fence.
//!
//! This crate's key schedules, hash and MAC states, and the buffers used for
//! AES Crypt streams are wiped when they are dropped.  [`Zeroizing`] does the
//! same for your own values:
//!
//! ```
//! use aescry::zeroize::{Zeroize, Zeroizing};
//!
//! let key = Zeroizing::new(aescry::random::bytes::<32>()?);
//! // ... use &*key ...
//! drop(key); // overwritten with zeros
//!
//! let mut password = String::from("hunter2").into_bytes();
//! password.zeroize();
//! assert!(password.is_empty());
//! # Ok::<(), aescry::Error>(())
//! ```
//!
//! Wiping cannot reach copies the program made earlier, such as a `Vec` that
//! was reallocated, values moved by the compiler, or pages the operating
//! system swapped to disk.

#![allow(unsafe_code)]

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{compiler_fence, Ordering};

/// Types whose contents can be securely overwritten with zeros.
pub trait Zeroize {
    /// Overwrite the value with zeros.
    fn zeroize(&mut self);
}

macro_rules! impl_zeroize_slice {
    ($($t:ty),*) => {$(
        impl Zeroize for [$t] {
            fn zeroize(&mut self) {
                for x in self.iter_mut() {
                    // SAFETY: `x` is a valid, aligned, exclusive reference.
                    unsafe { core::ptr::write_volatile(x, 0) };
                }
                compiler_fence(Ordering::SeqCst);
            }
        }

        impl<const N: usize> Zeroize for [$t; N] {
            fn zeroize(&mut self) {
                self[..].zeroize();
            }
        }
    )*};
}

impl_zeroize_slice!(u8, u16, u32, u64, u128);

impl Zeroize for Vec<u8> {
    /// Wipe the whole allocation (including unused capacity) and clear.
    fn zeroize(&mut self) {
        self.resize(self.capacity(), 0);
        self[..].zeroize();
        self.clear();
    }
}

impl Zeroize for String {
    /// Wipe the whole allocation (including unused capacity) and clear.
    fn zeroize(&mut self) {
        let mut bytes = core::mem::take(self).into_bytes();
        bytes.zeroize();
        // reuse the wiped allocation; it holds no characters now
        *self = String::from_utf8(bytes).unwrap_or_default();
    }
}

impl<T: Zeroize> Zeroize for Option<T> {
    fn zeroize(&mut self) {
        if let Some(value) = self {
            value.zeroize();
        }
    }
}

/// A value that is wiped when dropped.
///
/// Dereferences to the inner value.  `Debug` output never shows the contents.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    /// Wrap a value so it is wiped when dropped.
    pub fn new(value: T) -> Self {
        Zeroizing(value)
    }
}

impl<T: Zeroize + Default> Zeroizing<T> {
    /// Move the value out, leaving a default value to be wiped.
    ///
    /// The returned value is no longer protected.
    pub fn take(mut self) -> T {
        core::mem::take(&mut self.0)
    }
}

impl<T: Zeroize> Deref for Zeroizing<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> From<T> for Zeroizing<T> {
    fn from(value: T) -> Self {
        Zeroizing(value)
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Zeroizing(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipes_values() {
        let mut a = [0xAAu8; 32];
        a.zeroize();
        assert_eq!(a, [0u8; 32]);

        let mut w = [u32::MAX; 8];
        w.zeroize();
        assert_eq!(w, [0u32; 8]);

        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(b"secret");
        v.zeroize();
        assert!(v.is_empty());
        assert!(v.capacity() >= 64);

        let mut s = String::from("password");
        s.zeroize();
        assert!(s.is_empty());

        let mut o = Some([1u8; 4]);
        o.zeroize();
        assert_eq!(o, Some([0u8; 4]));
    }

    #[test]
    fn zeroizing_wrapper() {
        let z = Zeroizing::new(vec![1u8, 2, 3]);
        assert_eq!(&z[..], &[1, 2, 3]);
        assert_eq!(format!("{:?}", z), "Zeroizing(..)");
        assert_eq!(z.take(), vec![1, 2, 3]);
    }
}
