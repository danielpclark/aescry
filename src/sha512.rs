//! SHA-512, FIPS 180-2 compliant.
//!
//! ```
//! use aescry::sha512::{sha512, Sha512};
//!
//! let mut hasher = Sha512::new();
//! hasher.update(b"a");
//! hasher.update(b"bc");
//! assert_eq!(hasher.finalize(), sha512(b"abc"));
//! ```

/// SHA-512 digest size in octets.
pub const OUTPUT_SIZE: usize = 64;

/// SHA-512 internal block size in octets.
pub const BLOCK_SIZE: usize = 128;

// K: first 64 bits of the fractional parts of the cube roots of the first
// 80 primes; INITIAL_STATE: the same for the square roots of the first 8.
const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

const INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Compute the SHA-512 digest of `data` in one call.
pub fn sha512(data: &[u8]) -> [u8; OUTPUT_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

/// An incremental SHA-512 hasher.
#[derive(Clone)]
pub struct Sha512 {
    total: u128, // total bytes processed
    state: [u64; 8],
    buffer: [u8; BLOCK_SIZE],
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Sha512 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sha512 { .. }")
    }
}

impl Sha512 {
    /// Create a hasher in its initial state.
    pub fn new() -> Self {
        Sha512 { total: 0, state: INITIAL_STATE, buffer: [0u8; BLOCK_SIZE] }
    }

    /// Return the hasher to its initial state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Feed more data into the hash.
    pub fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() { return; }
        let mut left = (self.total % BLOCK_SIZE as u128) as usize;
        let fill = BLOCK_SIZE - left;

        self.total = self.total.wrapping_add(input.len() as u128);

        if left != 0 && input.len() >= fill {
            self.buffer[left..].copy_from_slice(&input[..fill]);

            process(&mut self.state, &self.buffer);

            input = &input[fill..];
            left = 0;
        }

        while input.len() >= BLOCK_SIZE {
            process(&mut self.state, &input[..BLOCK_SIZE]);
            input = &input[BLOCK_SIZE..];
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
        let mut last = (self.total % BLOCK_SIZE as u128) as usize;

        self.buffer[last] = 0x80;
        last += 1;

        if last <= 112 {
            // Enough room for padding + 128-bit length in current block
            self.buffer[last..112].fill(0);
        } else {
            // We'll need an extra block.
            self.buffer[last..].fill(0);

            process(&mut self.state, &self.buffer);

            self.buffer[..112].fill(0);
        };

        let bits = self.total.wrapping_shl(3);
        self.buffer[112..].copy_from_slice(&bits.to_be_bytes());

        process(&mut self.state, &self.buffer);

        for (i, word) in self.state.iter().enumerate() {
            digest[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
    }
}

#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (!x & z) }
#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }
// Σ{512}0(x) = ROTR²⁸(x) ⊕ ROTR³⁴(x) ⊕ ROTR³⁹(x)
#[inline(always)]
fn big_sigma0(x: u64) -> u64 { x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39) }
// Σ{512}1(x) = ROTR¹⁴(x) ⊕ ROTR¹⁸(x) ⊕ ROTR⁴¹(x)
#[inline(always)]
fn big_sigma1(x: u64) -> u64 { x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41) }
// σ{512}0(x) = ROTR¹(x) ⊕ ROTR⁸(x) ⊕ SHR⁷(x)
#[inline(always)]
fn small_sigma0(x: u64) -> u64 { x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7) }
// σ{512}1(x) = ROTR¹⁹(x) ⊕ ROTR⁶¹(x) ⊕ SHR⁶(x)
#[inline(always)]
fn small_sigma1(x: u64) -> u64 { x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6) }

fn process(state: &mut [u64; 8], data: &[u8]) {
    assert!(data.len() == BLOCK_SIZE, "invalid data length");
    let mut w = [0u64; 80];

    for (t, chunk) in data.chunks_exact(8).enumerate() {
        w[t] = u64::from_be_bytes(chunk.try_into().expect("8-octet chunk"));
    }

    for t in 16..80 {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for t in 0..80 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::SliceToHex;

    fn hex(msg: &[u8]) -> String {
        <[u8]>::slice_to_hex(&sha512(msg))
    }

    #[test]
    fn padding_boundaries() {
        // 111 octets fit padding + length in one block; 112 and 128 need two
        let cases: [(usize, &str); 5] = [
            (0, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (111, "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2"),
            (112, "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca"),
            (128, "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321"),
            (1000000, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"),
        ];

        for &(len, val) in cases.iter() {
            assert_eq!(hex("a".repeat(len).as_bytes()), val, "length {}", len);
        }
    }

    #[test]
    fn chunked_message() {
        let msg: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
        let one_shot = sha512(&msg);

        for size in [1, 63, 64, 127, 128, 129, 1000] {
            let mut ctx = Sha512::new();
            for chunk in msg.chunks(size) {
                ctx.update(chunk);
            }
            assert_eq!(ctx.finalize_reset(), one_shot, "chunk size {}", size);

            ctx.update(b"abc");
            assert_eq!(ctx.finalize(), sha512(b"abc"));
        }
    }
}
