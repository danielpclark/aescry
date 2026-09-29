//! SHA-256, FIPS 180-2 compliant.
//!
//! ```
//! use aescry::sha256::{sha256, Sha256};
//!
//! let mut hasher = Sha256::new();
//! hasher.update(b"a");
//! hasher.update(b"bc");
//! assert_eq!(hasher.finalize(), sha256(b"abc"));
//! ```

// Kernel code: 64-octet blocks and a 64-word schedule indexed by fixed
// loop bounds; buffer offsets are below the block size by construction.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::algorithms::*;

/// SHA-256 digest size in octets.
pub const OUTPUT_SIZE: usize = 32;

/// SHA-256 internal block size in octets.
pub const BLOCK_SIZE: usize = 64;

const INITIAL_STATE: [u32; 8] = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
];

/// Compute the SHA-256 digest of `data` in one call.
pub fn sha256(data: &[u8]) -> [u8; OUTPUT_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// An incremental SHA-256 hasher.
#[derive(Clone)]
pub struct Sha256 {
    total: u64, // total bytes processed
    state: [u32; 8], // H
    buffer: [u8; BLOCK_SIZE],
}

impl Drop for Sha256 {
    // the state and buffer are derived from the (possibly secret) input
    fn drop(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.state);
        crate::zeroize::Zeroize::zeroize(&mut self.buffer);
        self.total = 0;
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sha256 { .. }")
    }
}

impl Sha256 {
    /// Create a hasher in its initial state.
    pub fn new() -> Self {
        Sha256 { total: 0, state: INITIAL_STATE, buffer: [0u8; BLOCK_SIZE] }
    }

    /// Return the hasher to its initial state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Feed more data into the hash.
    pub fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() { return; }
        let mut left = (self.total & 0x3F) as usize;
        let fill = 64 - left;

        self.total = self.total.wrapping_add(input.len() as u64);

        if left != 0 && input.len() >= fill {
            self.buffer[left..].copy_from_slice(&input[..fill]);

            process(&mut self.state, &self.buffer);

            input = &input[fill..];
            left = 0;
        }

        while input.len() >= 64 {
            process(&mut self.state, &input[..64]);
            input = &input[64..];
        }

        if !input.is_empty() {
            self.buffer[left..left + input.len()].copy_from_slice(input);
        }
    }

    /// Finish the hash and return the digest.
    pub fn finalize(mut self) -> [u8; OUTPUT_SIZE] {
        let mut digest = [0u8; OUTPUT_SIZE];
        self.finish(&mut digest);
        digest
    }

    /// Finish the hash, write the digest and reset the hasher for reuse.
    pub fn finalize_reset(&mut self) -> [u8; OUTPUT_SIZE] {
        let mut digest = [0u8; OUTPUT_SIZE];
        self.finish(&mut digest);
        self.reset();
        digest
    }

    fn finish(&mut self, digest: &mut [u8; OUTPUT_SIZE]) {
        let mut last = (self.total & 0x3F) as usize;

        self.buffer[last] = 0x80;
        last += 1;

        if last <= 56 {
            // Enough room for padding + length in current block
            self.buffer[last..56].fill(0);
        } else {
            // We'll need an extra block.
            self.buffer[last..].fill(0);

            process(&mut self.state, &self.buffer);

            self.buffer[..56].fill(0);
        };

        let bits = self.total.wrapping_shl(3);
        let high: u32 = (bits >> 32) as u32;
        let low:  u32 = bits as u32;

        put_u32(high, &mut self.buffer, 56);
        put_u32(low , &mut self.buffer, 60);

        process(&mut self.state, &self.buffer);

        for (i, word) in self.state.iter().enumerate() {
            put_u32(*word, digest, i * 4);
        }
    }
}

pub(crate) fn process(state: &mut [u32; 8], data: &[u8]) {
    assert!(data.len() == 64, "invalid data length");
    let mut w: [u32; 64] = [0; 64];

    w[0]  = get_u32(data, 0);
    w[1]  = get_u32(data, 4);
    w[2]  = get_u32(data, 8);
    w[3]  = get_u32(data, 12);
    w[4]  = get_u32(data, 16);
    w[5]  = get_u32(data, 20);
    w[6]  = get_u32(data, 24);
    w[7]  = get_u32(data, 28);
    w[8]  = get_u32(data, 32);
    w[9]  = get_u32(data, 36);
    w[10] = get_u32(data, 40);
    w[11] = get_u32(data, 44);
    w[12] = get_u32(data, 48);
    w[13] = get_u32(data, 52);
    w[14] = get_u32(data, 56);
    w[15] = get_u32(data, 60);

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    p( a, b, c, &mut d, e, f, g, &mut h,         w[ 0], 0x428A2F98 );
    p( h, a, b, &mut c, d, e, f, &mut g,         w[ 1], 0x71374491 );
    p( g, h, a, &mut b, c, d, e, &mut f,         w[ 2], 0xB5C0FBCF );
    p( f, g, h, &mut a, b, c, d, &mut e,         w[ 3], 0xE9B5DBA5 );
    p( e, f, g, &mut h, a, b, c, &mut d,         w[ 4], 0x3956C25B );
    p( d, e, f, &mut g, h, a, b, &mut c,         w[ 5], 0x59F111F1 );
    p( c, d, e, &mut f, g, h, a, &mut b,         w[ 6], 0x923F82A4 );
    p( b, c, d, &mut e, f, g, h, &mut a,         w[ 7], 0xAB1C5ED5 );
    p( a, b, c, &mut d, e, f, g, &mut h,         w[ 8], 0xD807AA98 );
    p( h, a, b, &mut c, d, e, f, &mut g,         w[ 9], 0x12835B01 );
    p( g, h, a, &mut b, c, d, e, &mut f,         w[10], 0x243185BE );
    p( f, g, h, &mut a, b, c, d, &mut e,         w[11], 0x550C7DC3 );
    p( e, f, g, &mut h, a, b, c, &mut d,         w[12], 0x72BE5D74 );
    p( d, e, f, &mut g, h, a, b, &mut c,         w[13], 0x80DEB1FE );
    p( c, d, e, &mut f, g, h, a, &mut b,         w[14], 0x9BDC06A7 );
    p( b, c, d, &mut e, f, g, h, &mut a,         w[15], 0xC19BF174 );
    p( a, b, c, &mut d, e, f, g, &mut h, r(&mut w, 16), 0xE49B69C1 );
    p( h, a, b, &mut c, d, e, f, &mut g, r(&mut w, 17), 0xEFBE4786 );
    p( g, h, a, &mut b, c, d, e, &mut f, r(&mut w, 18), 0x0FC19DC6 );
    p( f, g, h, &mut a, b, c, d, &mut e, r(&mut w, 19), 0x240CA1CC );
    p( e, f, g, &mut h, a, b, c, &mut d, r(&mut w, 20), 0x2DE92C6F );
    p( d, e, f, &mut g, h, a, b, &mut c, r(&mut w, 21), 0x4A7484AA );
    p( c, d, e, &mut f, g, h, a, &mut b, r(&mut w, 22), 0x5CB0A9DC );
    p( b, c, d, &mut e, f, g, h, &mut a, r(&mut w, 23), 0x76F988DA );
    p( a, b, c, &mut d, e, f, g, &mut h, r(&mut w, 24), 0x983E5152 );
    p( h, a, b, &mut c, d, e, f, &mut g, r(&mut w, 25), 0xA831C66D );
    p( g, h, a, &mut b, c, d, e, &mut f, r(&mut w, 26), 0xB00327C8 );
    p( f, g, h, &mut a, b, c, d, &mut e, r(&mut w, 27), 0xBF597FC7 );
    p( e, f, g, &mut h, a, b, c, &mut d, r(&mut w, 28), 0xC6E00BF3 );
    p( d, e, f, &mut g, h, a, b, &mut c, r(&mut w, 29), 0xD5A79147 );
    p( c, d, e, &mut f, g, h, a, &mut b, r(&mut w, 30), 0x06CA6351 );
    p( b, c, d, &mut e, f, g, h, &mut a, r(&mut w, 31), 0x14292967 );
    p( a, b, c, &mut d, e, f, g, &mut h, r(&mut w, 32), 0x27B70A85 );
    p( h, a, b, &mut c, d, e, f, &mut g, r(&mut w, 33), 0x2E1B2138 );
    p( g, h, a, &mut b, c, d, e, &mut f, r(&mut w, 34), 0x4D2C6DFC );
    p( f, g, h, &mut a, b, c, d, &mut e, r(&mut w, 35), 0x53380D13 );
    p( e, f, g, &mut h, a, b, c, &mut d, r(&mut w, 36), 0x650A7354 );
    p( d, e, f, &mut g, h, a, b, &mut c, r(&mut w, 37), 0x766A0ABB );
    p( c, d, e, &mut f, g, h, a, &mut b, r(&mut w, 38), 0x81C2C92E );
    p( b, c, d, &mut e, f, g, h, &mut a, r(&mut w, 39), 0x92722C85 );
    p( a, b, c, &mut d, e, f, g, &mut h, r(&mut w, 40), 0xA2BFE8A1 );
    p( h, a, b, &mut c, d, e, f, &mut g, r(&mut w, 41), 0xA81A664B );
    p( g, h, a, &mut b, c, d, e, &mut f, r(&mut w, 42), 0xC24B8B70 );
    p( f, g, h, &mut a, b, c, d, &mut e, r(&mut w, 43), 0xC76C51A3 );
    p( e, f, g, &mut h, a, b, c, &mut d, r(&mut w, 44), 0xD192E819 );
    p( d, e, f, &mut g, h, a, b, &mut c, r(&mut w, 45), 0xD6990624 );
    p( c, d, e, &mut f, g, h, a, &mut b, r(&mut w, 46), 0xF40E3585 );
    p( b, c, d, &mut e, f, g, h, &mut a, r(&mut w, 47), 0x106AA070 );
    p( a, b, c, &mut d, e, f, g, &mut h, r(&mut w, 48), 0x19A4C116 );
    p( h, a, b, &mut c, d, e, f, &mut g, r(&mut w, 49), 0x1E376C08 );
    p( g, h, a, &mut b, c, d, e, &mut f, r(&mut w, 50), 0x2748774C );
    p( f, g, h, &mut a, b, c, d, &mut e, r(&mut w, 51), 0x34B0BCB5 );
    p( e, f, g, &mut h, a, b, c, &mut d, r(&mut w, 52), 0x391C0CB3 );
    p( d, e, f, &mut g, h, a, b, &mut c, r(&mut w, 53), 0x4ED8AA4A );
    p( c, d, e, &mut f, g, h, a, &mut b, r(&mut w, 54), 0x5B9CCA4F );
    p( b, c, d, &mut e, f, g, h, &mut a, r(&mut w, 55), 0x682E6FF3 );
    p( a, b, c, &mut d, e, f, g, &mut h, r(&mut w, 56), 0x748F82EE );
    p( h, a, b, &mut c, d, e, f, &mut g, r(&mut w, 57), 0x78A5636F );
    p( g, h, a, &mut b, c, d, e, &mut f, r(&mut w, 58), 0x84C87814 );
    p( f, g, h, &mut a, b, c, d, &mut e, r(&mut w, 59), 0x8CC70208 );
    p( e, f, g, &mut h, a, b, c, &mut d, r(&mut w, 60), 0x90BEFFFA );
    p( d, e, f, &mut g, h, a, b, &mut c, r(&mut w, 61), 0xA4506CEB );
    p( c, d, e, &mut f, g, h, a, &mut b, r(&mut w, 62), 0xBEF9A3F7 );
    p( b, c, d, &mut e, f, g, h, &mut a, r(&mut w, 63), 0xC67178F2 );

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::SliceToHex;

    fn hex(msg: &[u8]) -> String {
        <[u8]>::slice_to_hex(&sha256(msg))
    }

    #[test]
    fn one_block_message() {
        assert_eq!(hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn multi_block_message() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

        let mut ctx = Sha256::new();
        ctx.update(msg);

        // 56 octets fit in the buffer without being processed
        assert_eq!(ctx.state, INITIAL_STATE);

        assert_eq!(<[u8]>::slice_to_hex(&ctx.finalize()),
                   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn long_message() {
        let msg = "a".repeat(1000000);
        assert_eq!(hex(msg.as_bytes()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    #[test]
    fn padding_boundaries() {
        // 55 bytes fits padding + length in one block; 56 and 64 need an extra block
        let cases: [(usize, &str); 4] = [
            (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
            (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
            (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
        ];

        for &(len, val) in cases.iter() {
            assert_eq!(hex("a".repeat(len).as_bytes()), val, "length {}", len);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn chunked_message() {
        let msg = "a".repeat(1000000);

        let mut ctx = Sha256::new();

        for chunk in msg.as_bytes().chunks(37) {
            ctx.update(chunk);
        }

        assert_eq!(<[u8]>::slice_to_hex(&ctx.finalize_reset()),
                   "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

        // the hasher is reusable after finalize_reset
        ctx.update(b"abc");
        assert_eq!(ctx.finalize(), sha256(b"abc"));
    }
}
