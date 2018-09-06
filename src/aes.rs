use crate::fixed_tables::{FORWARD_SBOX, REVERSE_SBOX};

use crate::algorithms::{
    get_u32,
    put_u32,
    rotr8,
    xtime,
};

pub struct AesContext {
    erk: [u32; 64],
    drk: [u32; 64],
    nr: isize,
}

// forward S-box & tables

const FORWARD_TABLES: ForwardTables = ForwardTables::new();

pub struct ForwardTables {
    pub fsb: [u8; 256],
    pub ft0: [u32; 256],
    pub ft1: [u32; 256],
    pub ft2: [u32; 256],
    pub ft3: [u32; 256],
}

impl ForwardTables {
    const fn new() -> ForwardTables {
        ForwardTables {
            fsb: FORWARD_SBOX,
            ft0: forward_tables!(v_abcd),
            ft1: forward_tables!(v_dabc),
            ft2: forward_tables!(v_cdab),
            ft3: forward_tables!(v_bcda),
        }
    }
}

// reverse S-box & tables

const REVERSE_TABLES: ReverseTables = ReverseTables::new();

pub struct ReverseTables {
    pub rsb: [u8; 256],
    pub rt0: [u32; 256],
    pub rt1: [u32; 256],
    pub rt2: [u32; 256],
    pub rt3: [u32; 256],
}

impl ReverseTables {
    const fn new() -> ReverseTables {
        ReverseTables {
            rsb: REVERSE_SBOX,
            rt0: reverse_tables!(v_abcd),
            rt1: reverse_tables!(v_dabc),
            rt2: reverse_tables!(v_cdab),
            rt3: reverse_tables!(v_bcda),
        }
    }
}

// round constants

static RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
];

pub fn gen_tables() -> (ForwardTables, ReverseTables) {
    let mut pow: [u8; 256] = [0u8; 256];
    let mut log: [u8; 256] = [0u8; 256];

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
        RCON[i] = (x as u32) << 24;

        x = xtime(x)
    }

    // generate the forward and reverse S-boxes

    let mut fsb: [u8;  256] = [0; 256];
    let mut ft0: [u32; 256] = [0; 256];
    let mut ft1: [u32; 256] = [0; 256];
    let mut ft2: [u32; 256] = [0; 256];
    let mut ft3: [u32; 256] = [0; 256];
    let mut rsb: [u8;  256] = [0; 256];
    let mut rt0: [u32; 256] = [0; 256];
    let mut rt1: [u32; 256] = [0; 256];
    let mut rt2: [u32; 256] = [0; 256];
    let mut rt3: [u32; 256] = [0; 256];

    fsb[0x00] = 0x63;

    // Already zero so irrelevant
    // rsb[0x63] = 0x00;

    for i in 1..256 {
        let mut x = pow[255 - log[i as usize] as usize];

        let mut y = x;
        y = ( y << 1 ) | ( y >> 7 );

        x ^= y;
        y = ( y << 1 ) | ( y >> 7 );

        x ^= y;
        y = ( y << 1 ) | ( y >> 7 );

        x ^= y;
        y = ( y << 1 ) | ( y >> 7 );

        x ^= y ^ 0x63;

        fsb[i] = x;
        rsb[x as usize] = i as u8;
    }

    /* generate the forward and reverse tables */

    let mul = |a,b| {
        if a != 0 && b != 0 {
            pow[(log[a as usize] + log[b as usize]) as usize % 255] as u8
        } else {
            0
        }
    };

    for i in 0..256 {
        let x: u8 = fsb[i];
        let y = xtime( x );

        ft0[i] =   ( x ^ y ) as u32 ^
                 ( x <<  8 ) as u32 ^
                 ( x << 16 ) as u32 ^
                 ( y << 24 ) as u32;

        ft0[i] &= 0xFFFFFFFF;

        ft1[i] = rotr8( ft0[i] );
        ft2[i] = rotr8( ft1[i] );
        ft3[i] = rotr8( ft2[i] );

        let y: u8 = rsb[i];

        rt0[i] = ( (mul( 0x0B, y ) as u32)       ) ^
                 ( (mul( 0x0D, y ) as u32) <<  8 ) ^
                 ( (mul( 0x09, y ) as u32) << 16 ) ^
                 ( (mul( 0x0E, y ) as u32) << 24 );

        rt0[i] &= 0xFFFFFFFF;

        rt1[i] = rotr8( rt0[i] );
        rt2[i] = rotr8( rt1[i] );
        rt3[i] = rotr8( rt2[i] );
    }

    let ft = ForwardTables {
        fsb: fsb,
        ft0: ft0,
        ft1: ft1,
        ft2: ft2,
        ft3: ft3,
    };

    let rt = ReverseTables {
        rsb: rsb,
        rt0: rt0,
        rt1: rt1,
        rt2: rt2,
        rt3: rt3,
    };

    (ft, rt)
}

// AES key scheduling routine

pub fn set_key(context: AesContext, key: &u8, nbits: isize) {
}
