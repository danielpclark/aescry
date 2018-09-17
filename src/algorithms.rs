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
#[inline(always)] pub(crate) fn rotr8(x: u32) -> u32 {  ( ( x << 24 ) & 0xFFFFFFFF )
                                              | ( ( x & 0xFFFFFFFF ) >>  8 ) }

#[inline(always)] fn shr(x: u32, n: u32)  -> u32 { (x & 0xFFFFFFFF) >> n         }
#[inline(always)] fn rotr(x: u32, n: u32) -> u32 { shr(x,n) | (x << (32 - n))    }

#[inline(always)] fn s0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x,18) ^ shr(x,3)      }
#[inline(always)] fn s1(x: u32) -> u32 { rotr(x,17) ^ rotr(x,19) ^ shr(x,10)     }
#[inline(always)] fn s2(x: u32) -> u32 { rotr(x, 2) ^ rotr(x,13) ^ rotr(x,22)    }
#[inline(always)] fn s3(x: u32) -> u32 { rotr(x, 6) ^ rotr(x,11) ^ rotr(x,25)    }

#[inline(always)] fn f0(x: u32, y: u32, z: u32) -> u32 { (x & y) | (z & (x | y)) }
#[inline(always)] fn f1(x: u32, y: u32, z: u32) -> u32 { z ^ (x & (y ^ z))       }

#[inline(always)] pub(crate) fn r(w: &mut [u32; 64], t: usize) -> u32 {
    w[t] = s1(w[t - 2]) + w[t - 7] + s0(w[t - 15]) + w[t - 16];
    w[t]
}

#[inline(always)]
pub(crate) fn p(a: u32, b: u32, c: u32, d: &mut u32, e: u32, f: u32, g: u32, h: &mut u32, x: u32, k: u32) {
    let temp1 = *h + s3(e) + f1(e,f,g) + k + x;
    let temp2 = s2(a) + f0(a,b,c);
    *d += temp1;
    *h = temp1 + temp2;
}

