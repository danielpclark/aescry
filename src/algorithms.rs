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

// SHRⁿ(x) = x >> n
#[inline(always)] fn shr(x: u32, n: u32)  -> u32 { (x).wrapping_shr(n)    }
// ROTRⁿ(x) = (x >> n) ∨ (x << w - n)
#[inline(always)] fn rotr(x: u32, n: u32) -> u32 { shr(x,n) | (x.wrapping_shl(32 - n)) }

// Ch( x, y, z) = ( x ^ y) ⊕  ( ¬x ^ z)
#[inline(always)] fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
// Maj( x, y, z) = ( x ^ y) ⊕ ( x ^ z) ⊕ ( y ^ z)
#[inline(always)] fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }

// σ{256}0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ ROTR³(x)
#[inline(always)] fn s0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x,18) ^  shr(x, 3)    }
// σ{256}1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ ROTR¹⁰(x)
#[inline(always)] fn s1(x: u32) -> u32 { rotr(x,17) ^ rotr(x,19) ^  shr(x,10)    }
// Σ{256}0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
#[inline(always)] fn s2(x: u32) -> u32 { rotr(x, 2) ^ rotr(x,13) ^ rotr(x,22)    }
// Σ{256}1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
#[inline(always)] fn s3(x: u32) -> u32 { rotr(x, 6) ^ rotr(x,11) ^ rotr(x,25)    }

// schedule work
#[inline(always)] pub(crate) fn r(w: &mut [u32; 64], t: usize) -> u32 {
    w[t] = s1(w[t -  2]).wrapping_add(w[t -  7]).wrapping_add(s0(w[t - 15])).wrapping_add(w[t - 16]);
    w[t]
}

#[inline(always)]
pub(crate) fn p(a: u32, b: u32, c: u32, d: &mut u32, e: u32, f: u32, g: u32, h: &mut u32, x: u32, k: u32) {
    let temp1 = (*h).wrapping_add(s3(e)).wrapping_add(ch(e,f,g)).wrapping_add(k).wrapping_add(x);
    let temp2 = s2(a).wrapping_add(maj(a,b,c));
    *d = (*d).wrapping_add(temp1);
    *h = temp1.wrapping_add(temp2);
}
