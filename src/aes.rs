use crate::fixed_tables::{FORWARD_SBOX, REVERSE_SBOX};
use crate::util::SliceToHex;

use crate::algorithms::{
    get_u32,
    put_u32,
    rotr8,
    xtime,
};

pub struct AesContext {
    erk: [u32; 64],
    drk: [u32; 64],
    nr: usize,
}

impl AesContext {
    fn new() -> Self {
        AesContext {
            erk: [0u32; 64],
            drk: [0u32; 64],
            nr: 0,
        }
    }
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

type Rcon = [u32; 10];

const RCON: Rcon = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
];

// decryption key schedule tables

pub struct KeyTables {
    pub kt0: [u32; 256],
    pub kt1: [u32; 256],
    pub kt2: [u32; 256],
    pub kt3: [u32; 256],
}

impl KeyTables {
    const fn new() -> KeyTables {
        KeyTables {
            kt0: [0u32; 256],
            kt1: [0u32; 256],
            kt2: [0u32; 256],
            kt3: [0u32; 256],
        }
    }
}

pub struct ContextTables {
    ft: ForwardTables,
    rt: ReverseTables,
    rc: Rcon,
    kt: KeyTables,
}

pub fn gen_tables() -> ContextTables {
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

    let mut rcon: Rcon = RCON;

    let mut x: u8 = 1;
    for i in 0..10 {
        rcon[i] = (x as u32) << 24;

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

    // generate the forward and reverse tables

    let mul = |a,b| {
        if a != 0 && b != 0 {
            pow[(log[a as usize] as usize + log[b as usize] as usize) % 255]
        } else {
            0
        }
    };

    for i in 0..256 {
        let x: u8 = fsb[i];
        let y = xtime( x );

        ft0[i] = ( x ^ y) as u32 ^
                 ( (x as u32) <<  8 ) ^
                 ( (x as u32) << 16 ) ^
                 ( (y as u32) << 24 );

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

    // generate the decryption key schedule tables

    let mut kt = KeyTables::new();

    for i in 0..256 {
        kt.kt0[i] = rt.rt0[ ft.fsb[i] as usize ];
        kt.kt1[i] = rt.rt1[ ft.fsb[i] as usize ];
        kt.kt2[i] = rt.rt2[ ft.fsb[i] as usize ];
        kt.kt3[i] = rt.rt3[ ft.fsb[i] as usize ];
    }

    ContextTables {
        ft: ft,
        rt: rt,
        rc: rcon,
        kt: kt,
    }
}

// AES key scheduling routine

#[derive(Debug, PartialEq)]
pub struct InvalidKeySize;

pub fn set_key(context: &mut AesContext, tables: &ContextTables, key: &[u8], nbits: usize) -> Result<(), InvalidKeySize> {
    context.nr = match nbits {
        128 => 10,
        192 => 12,
        256 => 14,
        _ => return Err(InvalidKeySize),
    };

    if key.len() < nbits / 8 { return Err(InvalidKeySize); }

    let fsb = &tables.ft.fsb;

    // SubWord(RotWord(x))
    let sub_rot = |x: u32| -> u32 {
        ((fsb[(x >> 16) as u8 as usize] as u32) << 24) ^
        ((fsb[(x >>  8) as u8 as usize] as u32) << 16) ^
        ((fsb[(x      ) as u8 as usize] as u32) <<  8) ^
        ((fsb[(x >> 24) as u8 as usize] as u32)      )
    };

    // SubWord(x)
    let sub = |x: u32| -> u32 {
        ((fsb[(x >> 24) as u8 as usize] as u32) << 24) ^
        ((fsb[(x >> 16) as u8 as usize] as u32) << 16) ^
        ((fsb[(x >>  8) as u8 as usize] as u32) <<  8) ^
        ((fsb[(x      ) as u8 as usize] as u32)      )
    };

    let rk = &mut context.erk;

    for i in 0..(nbits >> 5) {
        rk[i] = get_u32( key, i * 4 )
    }

    // setup encryption round keys

    match nbits {
        128 => {
            for i in 0..10 {
                let o = i * 4;

                rk[o + 4]  = rk[o    ] ^ tables.rc[i] ^ sub_rot(rk[o + 3]);
                rk[o + 5]  = rk[o + 1] ^ rk[o + 4];
                rk[o + 6]  = rk[o + 2] ^ rk[o + 5];
                rk[o + 7]  = rk[o + 3] ^ rk[o + 6];
            }
        },
        192 => {
            for i in 0..8 {
                let o = i * 6;

                rk[o + 6]  = rk[o    ] ^ tables.rc[i] ^ sub_rot(rk[o + 5]);
                rk[o + 7]  = rk[o + 1] ^ rk[o + 6];
                rk[o + 8]  = rk[o + 2] ^ rk[o + 7];
                rk[o + 9]  = rk[o + 3] ^ rk[o + 8];
                rk[o + 10] = rk[o + 4] ^ rk[o + 9];
                rk[o + 11] = rk[o + 5] ^ rk[o + 10];
            }
        },
        _ => {
            for i in 0..7 {
                let o = i * 8;

                rk[o + 8]  = rk[o    ] ^ tables.rc[i] ^ sub_rot(rk[o + 7]);
                rk[o + 9]  = rk[o + 1] ^ rk[o + 8];
                rk[o + 10] = rk[o + 2] ^ rk[o + 9];
                rk[o + 11] = rk[o + 3] ^ rk[o + 10];

                rk[o + 12] = rk[o + 4] ^ sub(rk[o + 11]);
                rk[o + 13] = rk[o + 5] ^ rk[o + 12];
                rk[o + 14] = rk[o + 6] ^ rk[o + 13];
                rk[o + 15] = rk[o + 7] ^ rk[o + 14];
            }
        },
    }

    // setup decryption round keys
    //
    // The decryption round keys are the encryption round keys in reverse
    // order, with InvMixColumns applied to all but the first and last.

    let kt = &tables.kt;
    let rk = &context.erk;
    let sk = &mut context.drk;

    let mut r = context.nr * 4;

    sk[..4].copy_from_slice(&rk[r..r + 4]);

    for i in 1..context.nr {
        r -= 4;

        for j in 0..4 {
            let x = rk[r + j];

            sk[i * 4 + j] = kt.kt0[ (x >> 24) as u8 as usize ] ^
                            kt.kt1[ (x >> 16) as u8 as usize ] ^
                            kt.kt2[ (x >>  8) as u8 as usize ] ^
                            kt.kt3[ (x      ) as u8 as usize ];
        }
    }

    r -= 4;

    let n = context.nr * 4;
    sk[n..n + 4].copy_from_slice(&rk[r..r + 4]);

    Ok(())
}

// AES 128-bit block encryption routine

pub fn encrypt(context: &AesContext, tables: &ContextTables, input: [u8; 16], output: &mut [u8; 16]) {
    let rk = &context.erk;

    let mut x0 = get_u32(&input,  0); x0 ^= rk[0];
    let mut x1 = get_u32(&input,  4); x1 ^= rk[1];
    let mut x2 = get_u32(&input,  8); x2 ^= rk[2];
    let mut x3 = get_u32(&input, 12); x3 ^= rk[3];

    let mut offset = 0;

    let mut aes_fround = |x0: &mut u32,
                          x1: &mut u32,
                          x2: &mut u32,
                          x3: &mut u32,
                          y0: &u32,
                          y1: &u32,
                          y2: &u32,
                          y3: &u32| {
        offset += 4;

        let temp_rk: &[u32] = &rk[offset..];

        *x0 = temp_rk[0] ^ tables.ft.ft0[ (*(y0) >> 24) as u8 as usize ] ^
                           tables.ft.ft1[ (*(y1) >> 16) as u8 as usize ] ^
                           tables.ft.ft2[ (*(y2) >>  8) as u8 as usize ] ^
                           tables.ft.ft3[  *(y3)        as u8 as usize ];

        *x1 = temp_rk[1] ^ tables.ft.ft0[ (*(y1) >> 24) as u8 as usize ] ^
                           tables.ft.ft1[ (*(y2) >> 16) as u8 as usize ] ^
                           tables.ft.ft2[ (*(y3) >>  8) as u8 as usize ] ^
                           tables.ft.ft3[  *(y0)        as u8 as usize ];

        *x2 = temp_rk[2] ^ tables.ft.ft0[ (*(y2) >> 24) as u8 as usize ] ^
                           tables.ft.ft1[ (*(y3) >> 16) as u8 as usize ] ^
                           tables.ft.ft2[ (*(y0) >>  8) as u8 as usize ] ^
                           tables.ft.ft3[  *(y1)        as u8 as usize ];

        *x3 = temp_rk[3] ^ tables.ft.ft0[ (*(y3) >> 24) as u8 as usize ] ^
                           tables.ft.ft1[ (*(y0) >> 16) as u8 as usize ] ^
                           tables.ft.ft2[ (*(y1) >>  8) as u8 as usize ] ^
                           tables.ft.ft3[  *(y2)        as u8 as usize ];
    };

    let mut y0: u32 = 0;
    let mut y1: u32 = 0;
    let mut y2: u32 = 0;
    let mut y3: u32 = 0;

    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 1
    aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       // round 2
    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 3
    aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       // round 4
    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 5
    aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       // round 6
    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 7
    aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       // round 8
    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 9

    if context.nr > 10 {
        aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );   // round 10
        aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );   // round 11
    }

    if context.nr > 12 {
        aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );   // round 12
        aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );   // round 13
    }


    // last round

    offset += 4;
    let temp_rk: &[u32] = &rk[offset..];

    x0 = temp_rk[0] ^ ((tables.ft.fsb[ (y0 >> 24) as u8 as usize ] as u32) << 24) ^
                      ((tables.ft.fsb[ (y1 >> 16) as u8 as usize ] as u32) << 16) ^
                      ((tables.ft.fsb[ (y2 >>  8) as u8 as usize ] as u32) <<  8) ^
                      ( tables.ft.fsb[  y3        as u8 as usize ] as u32       );

    x1 = temp_rk[1] ^ ((tables.ft.fsb[ (y1 >> 24) as u8 as usize ] as u32) << 24) ^
                      ((tables.ft.fsb[ (y2 >> 16) as u8 as usize ] as u32) << 16) ^
                      ((tables.ft.fsb[ (y3 >>  8) as u8 as usize ] as u32) <<  8) ^
                      ( tables.ft.fsb[  y0        as u8 as usize ] as u32       );

    x2 = temp_rk[2] ^ ((tables.ft.fsb[ (y2 >> 24) as u8 as usize ] as u32) << 24) ^
                      ((tables.ft.fsb[ (y3 >> 16) as u8 as usize ] as u32) << 16) ^
                      ((tables.ft.fsb[ (y0 >>  8) as u8 as usize ] as u32) <<  8) ^
                      ( tables.ft.fsb[  y1        as u8 as usize ] as u32       );

    x3 = temp_rk[3] ^ ((tables.ft.fsb[ (y3 >> 24) as u8 as usize ] as u32) << 24) ^
                      ((tables.ft.fsb[ (y0 >> 16) as u8 as usize ] as u32) << 16) ^
                      ((tables.ft.fsb[ (y1 >>  8) as u8 as usize ] as u32) <<  8) ^
                      ( tables.ft.fsb[  y2        as u8 as usize ] as u32       );

    put_u32( x0, output,  0 );
    put_u32( x1, output,  4 );
    put_u32( x2, output,  8 );
    put_u32( x3, output, 12 );
}

// AES 128-bit block decryption routine

pub fn decrypt(context: &AesContext, tables: &ContextTables, input: [u8; 16], output: &mut [u8; 16]) {
    let rk = &context.drk;

    let mut x0 = get_u32(&input,  0); x0 ^= rk[0];
    let mut x1 = get_u32(&input,  4); x1 ^= rk[1];
    let mut x2 = get_u32(&input,  8); x2 ^= rk[2];
    let mut x3 = get_u32(&input, 12); x3 ^= rk[3];

    let mut offset = 0;

    let mut aes_rround = |x0: &mut u32,
                          x1: &mut u32,
                          x2: &mut u32,
                          x3: &mut u32,
                          y0: &u32,
                          y1: &u32,
                          y2: &u32,
                          y3: &u32| {
        offset += 4;

        let temp_rk: &[u32] = &rk[offset..];

        *x0 = temp_rk[0] ^ tables.rt.rt0[ (*(y0) >> 24) as u8 as usize ] ^
                           tables.rt.rt1[ (*(y3) >> 16) as u8 as usize ] ^
                           tables.rt.rt2[ (*(y2) >>  8) as u8 as usize ] ^
                           tables.rt.rt3[  *(y1)        as u8 as usize ];

        *x1 = temp_rk[1] ^ tables.rt.rt0[ (*(y1) >> 24) as u8 as usize ] ^
                           tables.rt.rt1[ (*(y0) >> 16) as u8 as usize ] ^
                           tables.rt.rt2[ (*(y3) >>  8) as u8 as usize ] ^
                           tables.rt.rt3[  *(y2)        as u8 as usize ];

        *x2 = temp_rk[2] ^ tables.rt.rt0[ (*(y2) >> 24) as u8 as usize ] ^
                           tables.rt.rt1[ (*(y1) >> 16) as u8 as usize ] ^
                           tables.rt.rt2[ (*(y0) >>  8) as u8 as usize ] ^
                           tables.rt.rt3[  *(y3)        as u8 as usize ];

        *x3 = temp_rk[3] ^ tables.rt.rt0[ (*(y3) >> 24) as u8 as usize ] ^
                           tables.rt.rt1[ (*(y2) >> 16) as u8 as usize ] ^
                           tables.rt.rt2[ (*(y1) >>  8) as u8 as usize ] ^
                           tables.rt.rt3[  *(y0)        as u8 as usize ];
    };

    let mut y0: u32 = 0;
    let mut y1: u32 = 0;
    let mut y2: u32 = 0;
    let mut y3: u32 = 0;

    aes_rround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 1
    aes_rround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       // round 2
    aes_rround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 3
    aes_rround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       // round 4
    aes_rround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 5
    aes_rround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       // round 6
    aes_rround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 7
    aes_rround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       // round 8
    aes_rround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       // round 9

    if context.nr > 10 {
        aes_rround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );   // round 10
        aes_rround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );   // round 11
    }

    if context.nr > 12 {
        aes_rround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );   // round 12
        aes_rround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );   // round 13
    }


    // last round

    offset += 4;
    let temp_rk: &[u32] = &rk[offset..];

    x0 = temp_rk[0] ^ ((tables.rt.rsb[ (y0 >> 24) as u8 as usize ] as u32) << 24) ^
                      ((tables.rt.rsb[ (y3 >> 16) as u8 as usize ] as u32) << 16) ^
                      ((tables.rt.rsb[ (y2 >>  8) as u8 as usize ] as u32) <<  8) ^
                      ( tables.rt.rsb[  y1        as u8 as usize ] as u32       );

    x1 = temp_rk[1] ^ ((tables.rt.rsb[ (y1 >> 24) as u8 as usize ] as u32) << 24) ^
                      ((tables.rt.rsb[ (y0 >> 16) as u8 as usize ] as u32) << 16) ^
                      ((tables.rt.rsb[ (y3 >>  8) as u8 as usize ] as u32) <<  8) ^
                      ( tables.rt.rsb[  y2        as u8 as usize ] as u32       );

    x2 = temp_rk[2] ^ ((tables.rt.rsb[ (y2 >> 24) as u8 as usize ] as u32) << 24) ^
                      ((tables.rt.rsb[ (y1 >> 16) as u8 as usize ] as u32) << 16) ^
                      ((tables.rt.rsb[ (y0 >>  8) as u8 as usize ] as u32) <<  8) ^
                      ( tables.rt.rsb[  y3        as u8 as usize ] as u32       );

    x3 = temp_rk[3] ^ ((tables.rt.rsb[ (y3 >> 24) as u8 as usize ] as u32) << 24) ^
                      ((tables.rt.rsb[ (y2 >> 16) as u8 as usize ] as u32) << 16) ^
                      ((tables.rt.rsb[ (y1 >>  8) as u8 as usize ] as u32) <<  8) ^
                      ( tables.rt.rsb[  y0        as u8 as usize ] as u32       );

    put_u32( x0, output,  0 );
    put_u32( x1, output,  4 );
    put_u32( x2, output,  8 );
    put_u32( x3, output, 12 );
}


static AES_ENC_TEST: [[u8; 16]; 3] = [
    [ 0xA0, 0x43, 0x77, 0xAB, 0xE2, 0x59, 0xB0, 0xD0,
      0xB5, 0xBA, 0x2D, 0x40, 0xA5, 0x01, 0x97, 0x1B ],
    [ 0x4E, 0x46, 0xF8, 0xC5, 0x09, 0x2B, 0x29, 0xE2,
      0x9A, 0x97, 0x1A, 0x0C, 0xD1, 0xF6, 0x10, 0xFB ],
    [ 0x1F, 0x67, 0x63, 0xDF, 0x80, 0x7A, 0x7E, 0x70,
      0x96, 0x0D, 0x4C, 0xD3, 0x11, 0x8E, 0x60, 0x1A ]
];

static AES_DEC_TEST: [[u8; 16]; 3] = [
    [ 0xF5, 0xBF, 0x8B, 0x37, 0x13, 0x6F, 0x2E, 0x1F,
      0x6B, 0xEC, 0x6F, 0x57, 0x20, 0x21, 0xE3, 0xBA ],
    [ 0xF1, 0xA8, 0x1B, 0x68, 0xF6, 0xE5, 0xA6, 0x27,
      0x1A, 0x8C, 0xB2, 0x4E, 0x7D, 0x94, 0x91, 0xEF ],
    [ 0x4D, 0xE0, 0xC6, 0xDF, 0x7C, 0xB1, 0x69, 0x72,
      0x84, 0x60, 0x4D, 0x60, 0x27, 0x1B, 0xC5, 0x9A ]
];

#[cfg(test)]
fn fips197_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, k) in key.iter_mut().enumerate() { *k = i as u8; }
    key
}

#[cfg(test)]
const FIPS197_PLAINTEXT: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

#[cfg(test)]
fn fips197_roundtrip(nbits: usize, ciphertext: &str) {
    let key = fips197_key();
    let tables = gen_tables();
    let mut ctx = AesContext::new();

    set_key(&mut ctx, &tables, &key[..nbits / 8], nbits).unwrap();

    let mut buf = [0u8; 16];
    encrypt(&ctx, &tables, FIPS197_PLAINTEXT, &mut buf);
    assert_eq!(<[u8]>::slice_to_hex(&buf), ciphertext);

    let mut out = [0u8; 16];
    decrypt(&ctx, &tables, buf, &mut out);
    assert_eq!(out, FIPS197_PLAINTEXT);
}

#[test]
fn c1_aes128_nk4_nr10() {
    fips197_roundtrip(128, "69c4e0d86a7b0430d8cdb78070b4c55a");
}

#[test]
fn c2_aes192_nk6_nr12() {
    fips197_roundtrip(192, "dda97ca4864cdfe06eaf70a0ec0d7191");
}

#[test]
fn c3_aes256_nk8_nr14() {
    fips197_roundtrip(256, "8ea2b7ca516745bfeafc49904b496089");
}

#[test]
fn invalid_key_size() {
    let tables = gen_tables();
    let mut ctx = AesContext::new();

    assert_eq!(set_key(&mut ctx, &tables, &[0u8; 32], 64), Err(InvalidKeySize));
    assert_eq!(set_key(&mut ctx, &tables, &[0u8; 16], 256), Err(InvalidKeySize));
}

#[test]
fn generated_tables_match_fixed_tables() {
    let tables = gen_tables();

    assert_eq!(&tables.ft.fsb[..], &FORWARD_TABLES.fsb[..]);
    assert_eq!(&tables.ft.ft0[..], &FORWARD_TABLES.ft0[..]);
    assert_eq!(&tables.ft.ft1[..], &FORWARD_TABLES.ft1[..]);
    assert_eq!(&tables.ft.ft2[..], &FORWARD_TABLES.ft2[..]);
    assert_eq!(&tables.ft.ft3[..], &FORWARD_TABLES.ft3[..]);

    assert_eq!(&tables.rt.rsb[..], &REVERSE_TABLES.rsb[..]);
    assert_eq!(&tables.rt.rt0[..], &REVERSE_TABLES.rt0[..]);
    assert_eq!(&tables.rt.rt1[..], &REVERSE_TABLES.rt1[..]);
    assert_eq!(&tables.rt.rt2[..], &REVERSE_TABLES.rt2[..]);
    assert_eq!(&tables.rt.rt3[..], &REVERSE_TABLES.rt3[..]);

    assert_eq!(tables.rc, RCON);
}

// Rijndael Monte Carlo Test (ECB mode)
#[cfg(test)]
fn monte_carlo(expected: &[[u8; 16]; 3], cipher: fn(&AesContext, &ContextTables, [u8; 16], &mut [u8; 16])) {
    let mut ctx = AesContext::new();
    let tables = gen_tables();

    for n in 0..3 {
        let mut buf = [0u8; 16];
        let mut key = [0u8; 32];

        for _ in 0..400 {
            set_key(&mut ctx, &tables, &key, 128 + n * 64).unwrap();

            for _ in 0..9999 {
                cipher(&ctx, &tables, buf, &mut buf);
            }

            if n > 0 {
                for j in 0..(n << 3) {
                    key[j] ^= buf[j + 16 - (n << 3)];
                }
            }

            cipher(&ctx, &tables, buf, &mut buf);

            for j in 0..16 {
                key[j + (n << 3)] ^= buf[j];
            }
        }

        assert_eq!(buf, expected[n], "key size = {} bits", 128 + n * 64);
    }
}

#[test]
fn test_encrypt() {
    monte_carlo(&AES_ENC_TEST, encrypt);
}

#[test]
fn test_decrypt() {
    monte_carlo(&AES_DEC_TEST, decrypt);
}
