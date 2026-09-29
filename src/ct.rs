//! Constant-time comparison.
//!
//! Comparing secret values such as MACs with `==` can stop at the first
//! differing octet, and the time taken reveals how many leading octets
//! matched.  These functions examine every octet regardless.
//!
//! ```
//! assert!(aescry::ct::eq(b"tag value", b"tag value"));
//! assert!(!aescry::ct::eq(b"tag value", b"tag valuE"));
//! assert!(!aescry::ct::eq(b"short", b"longer"));
//! ```

/// Compare two slices in time that depends only on their lengths.
///
/// Slices of different lengths are unequal; lengths are not secret.
#[inline(never)]
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }

    is_zero(diff)
}

/// Branch-free test for zero, so the result is computed arithmetically
/// rather than by comparing `diff` with 0.
#[inline(never)]
fn is_zero(diff: u8) -> bool {
    // (diff - 1) has bit 8 set only when diff == 0
    let z = (diff as u16).wrapping_sub(1) >> 8;
    (z & 1) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_every_octet() {
        let a = [0x55u8; 64];
        assert!(eq(&a, &a));
        assert!(eq(&[], &[]));

        for i in 0..64 {
            for bit in 0..8 {
                let mut b = a;
                b[i] ^= 1 << bit;
                assert!(!eq(&a, &b));
            }
        }

        assert!(!eq(&a[..63], &a));
    }

    #[test]
    fn is_zero_all_values() {
        for v in 0..=255u8 {
            assert_eq!(is_zero(v), v == 0);
        }
    }
}
