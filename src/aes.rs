use crate::fixed_tables::{FORWARD_SBOX, REVERSE_SBOX};
use std::slice;

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

type Rcon = [u32; 10];

const RCON: Rcon = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
];

// decryption key schedule tables

pub struct KeyTables {
    pub init: bool,
    pub kt0: [u32; 256],
    pub kt1: [u32; 256],
    pub kt2: [u32; 256],
    pub kt3: [u32; 256],
}

impl KeyTables {
    const fn new() -> KeyTables {
        KeyTables {
            init: false,
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

    ContextTables {
        ft: ft,
        rt: rt,
        rc: rcon,
        kt: KeyTables::new(),
    }
}

// AES key scheduling routine

pub fn set_key(context: &mut AesContext, tables: &mut ContextTables, key: &[u8], nbits: isize) {
    match nbits {
        128 => { context.nr = 10; },
        192 => { context.nr = 12; },
        256 => { context.nr = 14; },
        _ => (),
    }

    let mut rk = context.erk;
    
    for i in 0..(nbits as usize >> 5) {
        rk[i] = get_u32( key, i * 4 )
    }

    // setup encryption round keys
    
    let rk_ptr = rk.as_ptr() as *mut u32;
    
    match nbits {
        128 => {
            let shifting = 4;
            for i in 0..10 {
                let temp_rk: &mut [u32] = unsafe { slice::from_raw_parts_mut(rk_ptr, 64 - (i * shifting)) };

                temp_rk[4] = temp_rk[0] ^ tables.rc[i] ^
                    ((tables.ft.fsb[(temp_rk[3] >> 16) as u8 as usize] as u32) << 24) ^
                    ((tables.ft.fsb[(temp_rk[3] >>  8) as u8 as usize] as u32) << 16) ^
                    ((tables.ft.fsb[(temp_rk[3]      ) as u8 as usize] as u32) <<  8) ^
                    ((tables.ft.fsb[(temp_rk[3] >> 24) as u8 as usize] as u32)      );

                temp_rk[5]  = temp_rk[1] ^ temp_rk[4];
                temp_rk[6]  = temp_rk[2] ^ temp_rk[5];
                temp_rk[7]  = temp_rk[3] ^ temp_rk[6];

                unsafe { rk_ptr.add(shifting); }
            }
        },
        192 => {
            let shifting = 6;
            for i in 0..8 {
                let temp_rk: &mut [u32] = unsafe { slice::from_raw_parts_mut(rk_ptr, 64 - (i * shifting)) };

                temp_rk[6] = temp_rk[0] ^ tables.rc[i] ^
                    ((tables.ft.fsb[(temp_rk[5] >> 16) as u8 as usize] as u32) << 24) ^
                    ((tables.ft.fsb[(temp_rk[5] >>  8) as u8 as usize] as u32) << 16) ^
                    ((tables.ft.fsb[(temp_rk[5]      ) as u8 as usize] as u32) <<  8) ^
                    ((tables.ft.fsb[(temp_rk[5] >> 24) as u8 as usize] as u32)      );

                temp_rk[7]   = temp_rk[1] ^ temp_rk[6];
                temp_rk[8]   = temp_rk[2] ^ temp_rk[7];
                temp_rk[9]   = temp_rk[3] ^ temp_rk[8];
                temp_rk[10]  = temp_rk[4] ^ temp_rk[9];
                temp_rk[11]  = temp_rk[5] ^ temp_rk[10];

                unsafe { rk_ptr.add(shifting); }
            }
        },
        256 => {
            let shifting = 8;
            for i in 0..7 {
                let temp_rk: &mut [u32] = unsafe { slice::from_raw_parts_mut(rk_ptr, 64 - (i * shifting)) };

                temp_rk[8] = temp_rk[0] ^ tables.rc[i] ^
                    ((tables.ft.fsb[(temp_rk[7] >> 16) as u8 as usize] as u32) << 24) ^
                    ((tables.ft.fsb[(temp_rk[7] >>  8) as u8 as usize] as u32) << 16) ^
                    ((tables.ft.fsb[(temp_rk[7]      ) as u8 as usize] as u32) <<  8) ^
                    ((tables.ft.fsb[(temp_rk[7] >> 24) as u8 as usize] as u32)      );

                temp_rk[9]   = temp_rk[1] ^ temp_rk[8];
                temp_rk[10]  = temp_rk[2] ^ temp_rk[9];
                temp_rk[11]  = temp_rk[3] ^ temp_rk[10];

                temp_rk[12] = temp_rk[4] ^ tables.rc[i] ^
                    ((tables.ft.fsb[(temp_rk[11] >> 16) as u8 as usize] as u32) << 24) ^
                    ((tables.ft.fsb[(temp_rk[11] >>  8) as u8 as usize] as u32) << 16) ^
                    ((tables.ft.fsb[(temp_rk[11]      ) as u8 as usize] as u32) <<  8) ^
                    ((tables.ft.fsb[(temp_rk[11] >> 24) as u8 as usize] as u32)      );

                temp_rk[13]  = temp_rk[5] ^ temp_rk[12];
                temp_rk[14]  = temp_rk[6] ^ temp_rk[13];
                temp_rk[15]  = temp_rk[7] ^ temp_rk[14];

                unsafe { rk_ptr.add(shifting); }
            }
        },
        _ => ()
    }

    // setup decryption round keys
    
    if tables.kt.init {
        for i in 0..256 {
            tables.kt.kt0[i] = tables.rt.rt0[ tables.ft.fsb[i] as usize ];
            tables.kt.kt1[i] = tables.rt.rt1[ tables.ft.fsb[i] as usize ];
            tables.kt.kt2[i] = tables.rt.rt2[ tables.ft.fsb[i] as usize ];
            tables.kt.kt3[i] = tables.rt.rt3[ tables.ft.fsb[i] as usize ];
        }

        tables.kt.init = false
    }

    let sk = context.drk;

    let sk_ptr = sk.as_ptr() as *mut u32;

    // equivelant to C's
    //     *A++ == *B++
    let ptr_cp_incr = |a: *mut u32, b: *mut u32| {
        let ref_a: &mut u32 = unsafe { &mut *a };
        let ref_b: &u32 = unsafe { &*b };

        *ref_a = *ref_b;

        unsafe { a.add(1); b.add(1); }
    };

    for _ in 0..4 { ptr_cp_incr(sk_ptr, rk_ptr); }

    let sk_from_key_table_flip = || {
        let ref_sk: &mut u32 = unsafe { &mut *sk_ptr };
        let ref_rk: &u32 = unsafe { &*rk_ptr };

        *ref_sk = tables.kt.kt0[ (*(ref_rk) >> 24) as u8 as usize ] ^
                  tables.kt.kt1[ (*(ref_rk) >> 16) as u8 as usize ] ^
                  tables.kt.kt2[ (*(ref_rk) >>  8) as u8 as usize ] ^
                  tables.kt.kt3[ (*(ref_rk)      ) as u8 as usize ];

        unsafe { sk_ptr.add(1); rk_ptr.add(1); }
    };

    for i in 1..context.nr {
        unsafe { rk_ptr.sub(8); }

        for _ in 0..4 { sk_from_key_table_flip(); }
    }

    unsafe { rk_ptr.sub(8); }

    for _ in 0..4 { ptr_cp_incr(sk_ptr, rk_ptr); }
}

pub fn encrypt(context: &mut AesContext, tables: &mut ContextTables, input: [u8; 16], output: [u8; 16]) {
    let rk = context.erk;

    let mut x0 = get_u32(&input,  0); x0 ^= rk[0];
    let mut x1 = get_u32(&input,  4); x1 ^= rk[1];
    let mut x2 = get_u32(&input,  8); x2 ^= rk[2];
    let mut x3 = get_u32(&input, 12); x3 ^= rk[3];
    
    let rk_ptr = rk.as_ptr() as *const u32;

    let mut remaining = 0;

    let mut aes_fround = |x0: &mut u32,
                          x1: &mut u32,
                          x2: &mut u32,
                          x3: &mut u32,
                          y0: &u32,
                          y1: &u32,
                          y2: &u32,
                          y3: &u32| {
        unsafe { rk_ptr.add(4); } remaining += 4;

        let temp_rk: &[u32] = unsafe { slice::from_raw_parts(rk_ptr, 64 - remaining) };

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

    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       /* round 1 */
    aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       /* round 2 */
    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       /* round 3 */
    aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       /* round 4 */
    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       /* round 5 */
    aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       /* round 6 */
    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       /* round 7 */
    aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );       /* round 8 */
    aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );       /* round 9 */

    if context.nr > 10 {
        aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );   /* round 10 */
        aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );   /* round 11 */
    }

    if context.nr > 12 {
        aes_fround( &mut x0, &mut x1, &mut x2, &mut x3, &y0, &y1, &y2, &y3 );   /* round 12 */
        aes_fround( &mut y0, &mut y1, &mut y2, &mut y3, &x0, &x1, &x2, &x3 );   /* round 13 */
    }
}
