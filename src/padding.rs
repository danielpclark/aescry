//! PKCS#7 padding (RFC 5652, section 6.3) for 16-octet blocks.
//!
//! Padding always adds between 1 and 16 octets, each equal to the number of
//! octets added, so a message that is already a multiple of 16 octets gains a
//! whole block of padding.
//!
//! ```
//! use aescry::padding::{pkcs7_pad, pkcs7_unpad};
//!
//! let padded = pkcs7_pad(b"YELLOW SUBMARINE!");
//! assert_eq!(padded.len(), 32);
//! assert_eq!(pkcs7_unpad(&padded).unwrap(), b"YELLOW SUBMARINE!");
//! ```

use crate::aes::BLOCK_SIZE;
use crate::Error;

/// The number of padding octets PKCS#7 adds to a message of `len` octets.
pub fn pkcs7_padding_len(len: usize) -> usize {
    BLOCK_SIZE - len % BLOCK_SIZE
}

/// Return a copy of `data` with PKCS#7 padding appended.
pub fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(data.len() + BLOCK_SIZE);
    buf.extend_from_slice(data);
    pkcs7_pad_in_place(&mut buf);
    buf
}

/// Append PKCS#7 padding to `buf`.
pub fn pkcs7_pad_in_place(buf: &mut Vec<u8>) {
    let n = pkcs7_padding_len(buf.len());
    buf.resize(buf.len() + n, n as u8);
}

/// Check and strip PKCS#7 padding, returning the message.
///
/// `data` must be a non-empty multiple of 16 octets.  The check examines every
/// octet of the final block without branching on their values, and reports a
/// single error for every kind of bad padding.
pub fn pkcs7_unpad(data: &[u8]) -> Result<&[u8], Error> {
    let len = pkcs7_unpadded_len(data)?;
    Ok(&data[..len])
}

/// Check and strip PKCS#7 padding from `buf` in place.
pub fn pkcs7_unpad_in_place(buf: &mut Vec<u8>) -> Result<(), Error> {
    let len = pkcs7_unpadded_len(buf)?;
    buf.truncate(len);
    Ok(())
}

fn pkcs7_unpadded_len(data: &[u8]) -> Result<usize, Error> {
    if data.is_empty() || data.len() % BLOCK_SIZE != 0 {
        return Err(Error::InvalidPadding);
    }

    let last = &data[data.len() - BLOCK_SIZE..];
    let n = last[BLOCK_SIZE - 1];

    // bad is non-zero if n is 0 or greater than 16 (the operands are small,
    // so bit 31 of a wrapped subtraction is set exactly when a < b)
    let mut bad = ((n as u32).wrapping_sub(1) >> 31) | (16u32.wrapping_sub(n as u32) >> 31);

    for (i, &b) in last.iter().enumerate() {
        // in_padding is all ones for the last n octets, 0 otherwise
        let distance = (BLOCK_SIZE - i) as u32; // 16 down to 1
        let outside = (n as u32).wrapping_sub(distance) >> 31; // 1 if n < distance
        let in_padding = outside.wrapping_sub(1);
        bad |= in_padding & (b ^ n) as u32;
    }

    if bad != 0 {
        return Err(Error::InvalidPadding);
    }

    Ok(data.len() - n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_every_length() {
        for len in 0..=48 {
            let data = vec![0xAAu8; len];
            let padded = pkcs7_pad(&data);
            let n = pkcs7_padding_len(len);

            assert!((1..=16).contains(&n));
            assert_eq!(padded.len(), len + n);
            assert_eq!(padded.len() % 16, 0);
            assert!(padded[len..].iter().all(|&b| b as usize == n));
            assert_eq!(pkcs7_unpad(&padded).unwrap(), &data[..]);

            let mut buf = padded.clone();
            pkcs7_unpad_in_place(&mut buf).unwrap();
            assert_eq!(buf, data);
        }
    }

    #[test]
    fn rejects_bad_padding() {
        let mut block = [16u8; 16];
        assert_eq!(pkcs7_unpad(&block).unwrap(), b"");

        block[15] = 0;
        assert!(matches!(pkcs7_unpad(&block), Err(Error::InvalidPadding)));

        block[15] = 17;
        assert!(matches!(pkcs7_unpad(&block), Err(Error::InvalidPadding)));

        // last octet says 3 but the previous octets disagree
        let mut block = [0u8; 16];
        block[13] = 2;
        block[14] = 3;
        block[15] = 3;
        assert!(matches!(pkcs7_unpad(&block), Err(Error::InvalidPadding)));

        block[13] = 3;
        assert_eq!(pkcs7_unpad(&block).unwrap(), &[0u8; 13][..]);

        assert!(matches!(pkcs7_unpad(&[]), Err(Error::InvalidPadding)));
        assert!(matches!(pkcs7_unpad(&[1u8; 15]), Err(Error::InvalidPadding)));
        assert!(matches!(pkcs7_unpad(&[1u8; 17]), Err(Error::InvalidPadding)));
    }
}
