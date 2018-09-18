pub(crate) static SHA256_PADDING: [u8; 64] = [
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

#[inline(always)]
pub(crate) fn get_u32(data: &[u8], index: usize) -> u32 {
    (data[index] as u32) << 24
        | (data[index + 1] as u32) << 16
        | (data[index + 2] as u32) << 8
        | data[index + 3] as u32
}

#[inline(always)]
pub(crate) fn put_u32(state: u32, data: &mut [u8], index: usize) {
    data[index] = (state >> 24) as u8;
    data[index + 1] = (state >> 16) as u8;
    data[index + 2] = (state >> 8) as u8;
    data[index + 3] = state as u8;
}

#[inline(always)] pub(crate) fn xtime(x: u8) -> u8 {
    ( x << 1 ) ^ (
        if ( x & 0x80 ) != 0 {
            0x1B
        } else {
            0x00
        }
    )
}
#[inline(always)] pub(crate) fn rotr8(x: u32) -> u32 {  ( ( x.wrapping_shl(24) ) & 0xFFFFFFFF )
                                              | ( ( x & 0xFFFFFFFF ).wrapping_shr(8) ) }

// #define           SHR(x,      n     )          ((x & 0xFFFFFFFF) >> n)
#[inline(always)] fn shr(x: u32, n: u32)  -> u32 { (x & 0xFFFFFFFF).wrapping_shr(n)         }
// #define           ROTR(x,      n     )         (SHR(x,n) | (x << (32 - n)))
#[inline(always)] fn rotr(x: u32, n: u32) -> u32 { shr(x,n) | (x.wrapping_shl(32 - n))    }

// #define           S0(x     )         (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#[inline(always)] fn s0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x,18) ^  shr(x, 3)    }
// #define           S1(x     )         (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))
#[inline(always)] fn s1(x: u32) -> u32 { rotr(x,17) ^ rotr(x,19) ^  shr(x,10)    }
// #define           S2(x     )         (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#[inline(always)] fn s2(x: u32) -> u32 { rotr(x, 2) ^ rotr(x,13) ^ rotr(x,22)    }
// #define           S3(x     )         (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#[inline(always)] fn s3(x: u32) -> u32 { rotr(x, 6) ^ rotr(x,11) ^ rotr(x,25)    }

// #define           F0(x,      y,      z     )         ((x & y) | (z & (x | y)))
#[inline(always)] fn f0(x: u32, y: u32, z: u32) -> u32 { (x & y) | (z & (x | y)) }
// #define           F1(x,      y,      z     )         (z ^ (x & (y ^ z)))
#[inline(always)] fn f1(x: u32, y: u32, z: u32) -> u32 { z ^ (x & (y ^ z))       }

#[inline(always)] pub(crate) fn r(w: &mut [u32; 64], t: usize) -> u32 {
    w[t] = s1(w[t -  2]).wrapping_add(w[t -  7]).wrapping_add(s0(w[t - 15])).wrapping_add(w[t - 16]);
    w[t]
}

#[inline(always)]
pub(crate) fn p(a: u32, b: u32, c: u32, d: &mut u32, e: u32, f: u32, g: u32, h: &mut u32, x: u32, k: u32) {
    let temp1 = (*h).wrapping_add(s3(e)).wrapping_add(f1(e,f,g)).wrapping_add(k).wrapping_add(x);
    let temp2 = s2(a).wrapping_add(f0(a,b,c));
    *d = (*d).wrapping_add(temp1);
    *h = temp1.wrapping_add(temp2);
}

// #[inline(always)]
// pub(crate) fn p(a: u32, b: u32, c: u32, d: &mut u32, e: u32, f: u32, g: u32, h: &mut u32, x: u32, k: u32) {
//     let temp1 = (*h as u64) + s3(e) as u64 + f1(e,f,g) as u64 + k as u64 + x as u64;
//     let temp2 = s2(a) as u64 + f0(a,b,c) as u64;
// 
//     if temp1 > u32::max_value() as u64 { panic!("u32 exceeded! algorithms::p variable temp1 {:X} > {:X}", temp1, u32::max_value()); }
//     if temp2 > u32::max_value() as u64 { panic!("u32 exceeded! algorithms::p variable temp2 {:X} > {:X}", temp2, u32::max_value()); }
// 
//     let temp3 = temp1 + temp2;
//     if temp3 > u32::max_value() as u64 { panic!("u32 exceeded! algorithms::p variable temp3 {:X} > {:X}", temp3, u32::max_value()); }
// 
//     *d += temp1 as u32;
//     *h = temp3 as u32;
// }
