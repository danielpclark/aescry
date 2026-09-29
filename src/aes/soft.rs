//! Portable table-based AES implementation.
//!
//! This is a straightforward 32-bit table implementation of FIPS-197 in the
//! style of Christophe Devine's public domain `aes.c`.  Table lookups are
//! indexed by secret data, so this backend is not constant-time.

#![allow(clippy::needless_range_loop)]

use crate::algorithms::{get_u32, put_u32};
use crate::fixed_tables::{FORWARD_SBOX, REVERSE_SBOX};
use crate::zeroize::Zeroize;

// forward S-box & tables

pub(crate) struct ForwardTables {
    pub(crate) fsb: [u8; 256],
    pub(crate) ft0: [u32; 256],
    pub(crate) ft1: [u32; 256],
    pub(crate) ft2: [u32; 256],
    pub(crate) ft3: [u32; 256],
}

pub(crate) static FORWARD_TABLES: ForwardTables = ForwardTables {
    fsb: FORWARD_SBOX,
    ft0: forward_tables!(v_abcd),
    ft1: forward_tables!(v_dabc),
    ft2: forward_tables!(v_cdab),
    ft3: forward_tables!(v_bcda),
};

// reverse S-box & tables

pub(crate) struct ReverseTables {
    pub(crate) rsb: [u8; 256],
    pub(crate) rt0: [u32; 256],
    pub(crate) rt1: [u32; 256],
    pub(crate) rt2: [u32; 256],
    pub(crate) rt3: [u32; 256],
}

pub(crate) static REVERSE_TABLES: ReverseTables = ReverseTables {
    rsb: REVERSE_SBOX,
    rt0: reverse_tables!(v_abcd),
    rt1: reverse_tables!(v_dabc),
    rt2: reverse_tables!(v_cdab),
    rt3: reverse_tables!(v_bcda),
};

// round constants

pub(crate) const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
];

// decryption key schedule tables: KTn[i] = RTn[FSb[i]], i.e. InvMixColumns
// applied to a single byte

pub(crate) struct KeyTables {
    pub(crate) kt0: [u32; 256],
    pub(crate) kt1: [u32; 256],
    pub(crate) kt2: [u32; 256],
    pub(crate) kt3: [u32; 256],
}

const fn key_table(rt: &[u32; 256]) -> [u32; 256] {
    let mut kt = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        kt[i] = rt[FORWARD_SBOX[i] as usize];
        i += 1;
    }
    kt
}

pub(crate) static KEY_TABLES: KeyTables = KeyTables {
    kt0: key_table(&reverse_tables!(v_abcd)),
    kt1: key_table(&reverse_tables!(v_dabc)),
    kt2: key_table(&reverse_tables!(v_cdab)),
    kt3: key_table(&reverse_tables!(v_bcda)),
};

/// SubWord(x): apply the S-box to each byte of a word.
#[inline(always)]
fn sub_word(x: u32) -> u32 {
    let fsb = &FORWARD_TABLES.fsb;

    ((fsb[(x >> 24) as u8 as usize] as u32) << 24) ^
    ((fsb[(x >> 16) as u8 as usize] as u32) << 16) ^
    ((fsb[(x >>  8) as u8 as usize] as u32) <<  8) ^
     (fsb[ x        as u8 as usize] as u32)
}

/// Expanded encryption and decryption round keys.
#[derive(Clone)]
pub(crate) struct KeySchedule {
    pub(crate) erk: [u32; 64],
    pub(crate) drk: [u32; 64],
    pub(crate) nr: usize,
}

impl KeySchedule {
    /// Expand a 16, 24 or 32 octet key.  The caller guarantees the length.
    pub(crate) fn new(key: &[u8]) -> Self {
        let (erk, nr) = expand_encryption_key(key, sub_word);
        let mut ks = KeySchedule { erk, drk: [0u32; 64], nr };

        // setup decryption round keys
        //
        // The decryption round keys are the encryption round keys in reverse
        // order, with InvMixColumns applied to all but the first and last.

        let kt = &KEY_TABLES;
        let rk = &ks.erk;
        let sk = &mut ks.drk;

        for round in 0..=nr {
            let r = (nr - round) * 4;

            for j in 0..4 {
                let x = rk[r + j];

                sk[round * 4 + j] = if round == 0 || round == nr {
                    x
                } else {
                    kt.kt0[ (x >> 24) as u8 as usize ] ^
                    kt.kt1[ (x >> 16) as u8 as usize ] ^
                    kt.kt2[ (x >>  8) as u8 as usize ] ^
                    kt.kt3[ (x      ) as u8 as usize ]
                };
            }
        }

        ks
    }
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        Zeroize::zeroize(&mut self.erk[..]);
        Zeroize::zeroize(&mut self.drk[..]);
    }
}

/// Expand a 16, 24 or 32 octet key into encryption round key words
/// (FIPS-197 section 5.2) using the given SubWord, and return them with the
/// number of rounds.
pub(crate) fn expand_encryption_key(key: &[u8], sub_word: impl Fn(u32) -> u32) -> ([u32; 64], usize) {
    let nk = key.len() / 4;
    let nr = match key.len() {
        16 => 10,
        24 => 12,
        32 => 14,
        _ => unreachable!("invalid AES key length"),
    };

    let mut rk = [0u32; 64];

    for i in 0..nk {
        rk[i] = get_u32(key, i * 4);
    }

    for i in nk..(nr + 1) * 4 {
        let mut temp = rk[i - 1];

        if i % nk == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }

        rk[i] = rk[i - nk] ^ temp;
    }

    (rk, nr)
}

// AES 128-bit block encryption routine

pub(crate) fn encrypt(ks: &KeySchedule, block: &mut [u8; 16]) {
    let ft = &FORWARD_TABLES;
    let rk = &ks.erk;

    let mut x0 = get_u32(block,  0) ^ rk[0];
    let mut x1 = get_u32(block,  4) ^ rk[1];
    let mut x2 = get_u32(block,  8) ^ rk[2];
    let mut x3 = get_u32(block, 12) ^ rk[3];

    let mut offset = 0;

    for _ in 1..ks.nr {
        offset += 4;

        let temp_rk: &[u32] = &rk[offset..];

        let y0 = temp_rk[0] ^ ft.ft0[ (x0 >> 24) as u8 as usize ] ^
                              ft.ft1[ (x1 >> 16) as u8 as usize ] ^
                              ft.ft2[ (x2 >>  8) as u8 as usize ] ^
                              ft.ft3[  x3        as u8 as usize ];

        let y1 = temp_rk[1] ^ ft.ft0[ (x1 >> 24) as u8 as usize ] ^
                              ft.ft1[ (x2 >> 16) as u8 as usize ] ^
                              ft.ft2[ (x3 >>  8) as u8 as usize ] ^
                              ft.ft3[  x0        as u8 as usize ];

        let y2 = temp_rk[2] ^ ft.ft0[ (x2 >> 24) as u8 as usize ] ^
                              ft.ft1[ (x3 >> 16) as u8 as usize ] ^
                              ft.ft2[ (x0 >>  8) as u8 as usize ] ^
                              ft.ft3[  x1        as u8 as usize ];

        let y3 = temp_rk[3] ^ ft.ft0[ (x3 >> 24) as u8 as usize ] ^
                              ft.ft1[ (x0 >> 16) as u8 as usize ] ^
                              ft.ft2[ (x1 >>  8) as u8 as usize ] ^
                              ft.ft3[  x2        as u8 as usize ];

        x0 = y0; x1 = y1; x2 = y2; x3 = y3;
    }

    // last round

    offset += 4;
    let temp_rk: &[u32] = &rk[offset..];
    let fsb = &ft.fsb;

    let y0 = temp_rk[0] ^ ((fsb[ (x0 >> 24) as u8 as usize ] as u32) << 24) ^
                          ((fsb[ (x1 >> 16) as u8 as usize ] as u32) << 16) ^
                          ((fsb[ (x2 >>  8) as u8 as usize ] as u32) <<  8) ^
                          ( fsb[  x3        as u8 as usize ] as u32       );

    let y1 = temp_rk[1] ^ ((fsb[ (x1 >> 24) as u8 as usize ] as u32) << 24) ^
                          ((fsb[ (x2 >> 16) as u8 as usize ] as u32) << 16) ^
                          ((fsb[ (x3 >>  8) as u8 as usize ] as u32) <<  8) ^
                          ( fsb[  x0        as u8 as usize ] as u32       );

    let y2 = temp_rk[2] ^ ((fsb[ (x2 >> 24) as u8 as usize ] as u32) << 24) ^
                          ((fsb[ (x3 >> 16) as u8 as usize ] as u32) << 16) ^
                          ((fsb[ (x0 >>  8) as u8 as usize ] as u32) <<  8) ^
                          ( fsb[  x1        as u8 as usize ] as u32       );

    let y3 = temp_rk[3] ^ ((fsb[ (x3 >> 24) as u8 as usize ] as u32) << 24) ^
                          ((fsb[ (x0 >> 16) as u8 as usize ] as u32) << 16) ^
                          ((fsb[ (x1 >>  8) as u8 as usize ] as u32) <<  8) ^
                          ( fsb[  x2        as u8 as usize ] as u32       );

    put_u32( y0, block,  0 );
    put_u32( y1, block,  4 );
    put_u32( y2, block,  8 );
    put_u32( y3, block, 12 );
}

// AES 128-bit block decryption routine

pub(crate) fn decrypt(ks: &KeySchedule, block: &mut [u8; 16]) {
    let rt = &REVERSE_TABLES;
    let rk = &ks.drk;

    let mut x0 = get_u32(block,  0) ^ rk[0];
    let mut x1 = get_u32(block,  4) ^ rk[1];
    let mut x2 = get_u32(block,  8) ^ rk[2];
    let mut x3 = get_u32(block, 12) ^ rk[3];

    let mut offset = 0;

    for _ in 1..ks.nr {
        offset += 4;

        let temp_rk: &[u32] = &rk[offset..];

        let y0 = temp_rk[0] ^ rt.rt0[ (x0 >> 24) as u8 as usize ] ^
                              rt.rt1[ (x3 >> 16) as u8 as usize ] ^
                              rt.rt2[ (x2 >>  8) as u8 as usize ] ^
                              rt.rt3[  x1        as u8 as usize ];

        let y1 = temp_rk[1] ^ rt.rt0[ (x1 >> 24) as u8 as usize ] ^
                              rt.rt1[ (x0 >> 16) as u8 as usize ] ^
                              rt.rt2[ (x3 >>  8) as u8 as usize ] ^
                              rt.rt3[  x2        as u8 as usize ];

        let y2 = temp_rk[2] ^ rt.rt0[ (x2 >> 24) as u8 as usize ] ^
                              rt.rt1[ (x1 >> 16) as u8 as usize ] ^
                              rt.rt2[ (x0 >>  8) as u8 as usize ] ^
                              rt.rt3[  x3        as u8 as usize ];

        let y3 = temp_rk[3] ^ rt.rt0[ (x3 >> 24) as u8 as usize ] ^
                              rt.rt1[ (x2 >> 16) as u8 as usize ] ^
                              rt.rt2[ (x1 >>  8) as u8 as usize ] ^
                              rt.rt3[  x0        as u8 as usize ];

        x0 = y0; x1 = y1; x2 = y2; x3 = y3;
    }

    // last round

    offset += 4;
    let temp_rk: &[u32] = &rk[offset..];
    let rsb = &rt.rsb;

    let y0 = temp_rk[0] ^ ((rsb[ (x0 >> 24) as u8 as usize ] as u32) << 24) ^
                          ((rsb[ (x3 >> 16) as u8 as usize ] as u32) << 16) ^
                          ((rsb[ (x2 >>  8) as u8 as usize ] as u32) <<  8) ^
                          ( rsb[  x1        as u8 as usize ] as u32       );

    let y1 = temp_rk[1] ^ ((rsb[ (x1 >> 24) as u8 as usize ] as u32) << 24) ^
                          ((rsb[ (x0 >> 16) as u8 as usize ] as u32) << 16) ^
                          ((rsb[ (x3 >>  8) as u8 as usize ] as u32) <<  8) ^
                          ( rsb[  x2        as u8 as usize ] as u32       );

    let y2 = temp_rk[2] ^ ((rsb[ (x2 >> 24) as u8 as usize ] as u32) << 24) ^
                          ((rsb[ (x1 >> 16) as u8 as usize ] as u32) << 16) ^
                          ((rsb[ (x0 >>  8) as u8 as usize ] as u32) <<  8) ^
                          ( rsb[  x3        as u8 as usize ] as u32       );

    let y3 = temp_rk[3] ^ ((rsb[ (x3 >> 24) as u8 as usize ] as u32) << 24) ^
                          ((rsb[ (x2 >> 16) as u8 as usize ] as u32) << 16) ^
                          ((rsb[ (x1 >>  8) as u8 as usize ] as u32) <<  8) ^
                          ( rsb[  x0        as u8 as usize ] as u32       );

    put_u32( y0, block,  0 );
    put_u32( y1, block,  4 );
    put_u32( y2, block,  8 );
    put_u32( y3, block, 12 );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{rotr8, xtime};

    /// Generate the S-boxes and tables from first principles over GF(2^8)
    /// and check them against the hard-coded tables.
    #[test]
    fn generated_tables_match_fixed_tables() {
        let mut pow = [0u8; 256];
        let mut log = [0u8; 256];

        // compute pow and log tables over GF(2^8)

        let mut x: u8 = 1;
        for i in 0..256 {
            pow[i] = x;
            log[x as usize] = i as u8;

            x ^= xtime(x);
        }

        // calculate the round constants

        let mut x: u8 = 1;
        for i in 0..10 {
            assert_eq!(RCON[i], (x as u32) << 24);
            x = xtime(x);
        }

        // generate the forward and reverse S-boxes

        let mut fsb = [0u8; 256];
        let mut rsb = [0u8; 256];

        fsb[0x00] = 0x63;
        rsb[0x63] = 0x00;

        for i in 1..256 {
            let mut x = pow[255 - log[i] as usize];

            let mut y = x;
            for _ in 0..4 {
                y = y.rotate_left(1);
                x ^= y;
            }
            x ^= 0x63;

            fsb[i] = x;
            rsb[x as usize] = i as u8;
        }

        assert_eq!(&fsb[..], &FORWARD_TABLES.fsb[..]);
        assert_eq!(&rsb[..], &REVERSE_TABLES.rsb[..]);

        // generate the forward and reverse tables

        let mul = |a: u8, b: u8| -> u8 {
            if a != 0 && b != 0 {
                pow[(log[a as usize] as usize + log[b as usize] as usize) % 255]
            } else {
                0
            }
        };

        for i in 0..256 {
            let x = fsb[i];
            let y = xtime(x);

            let ft0 = (x ^ y) as u32 ^
                      ((x as u32) <<  8) ^
                      ((x as u32) << 16) ^
                      ((y as u32) << 24);

            assert_eq!(FORWARD_TABLES.ft0[i], ft0);
            assert_eq!(FORWARD_TABLES.ft1[i], rotr8(ft0));
            assert_eq!(FORWARD_TABLES.ft2[i], rotr8(rotr8(ft0)));
            assert_eq!(FORWARD_TABLES.ft3[i], rotr8(rotr8(rotr8(ft0))));

            let y = rsb[i];

            let rt0 =  (mul(0x0B, y) as u32)        ^
                      ((mul(0x0D, y) as u32) <<  8) ^
                      ((mul(0x09, y) as u32) << 16) ^
                      ((mul(0x0E, y) as u32) << 24);

            assert_eq!(REVERSE_TABLES.rt0[i], rt0);
            assert_eq!(REVERSE_TABLES.rt1[i], rotr8(rt0));
            assert_eq!(REVERSE_TABLES.rt2[i], rotr8(rotr8(rt0)));
            assert_eq!(REVERSE_TABLES.rt3[i], rotr8(rotr8(rotr8(rt0))));

            assert_eq!(KEY_TABLES.kt0[i], REVERSE_TABLES.rt0[fsb[i] as usize]);
            assert_eq!(KEY_TABLES.kt3[i], REVERSE_TABLES.rt3[fsb[i] as usize]);
        }
    }

    /// FIPS-197 Appendix A.3: expansion of a 256-bit cipher key.
    #[test]
    fn fips197_a3_key_expansion() {
        let key: Vec<u8> = (0..32).map(|i| [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ][i]).collect();

        let ks = KeySchedule::new(&key);

        assert_eq!(ks.erk[8], 0x9ba35411);
        assert_eq!(ks.erk[12], 0xa8b09c1a);
        assert_eq!(ks.erk[59], 0x706c631e);
    }
}
