

pub(crate) struct SHA256Context {
    pub(crate) total: [u32; 2],
    pub(crate) state: [u32; 8],
    pub(crate) buffer: [u8; 64],
}

#[inline]
fn get_u32(data: &[u8], index: usize) -> u32 {
    (data[index] as u32) << 24
        | (data[index + 1] as u32) << 16
        | (data[index + 2] as u32) << 8
        | data[index + 3] as u32
}

#[inline]
fn put_u32(state: u32, data: &mut [u8], index: usize) {
    data[index] = (state >> 24) as u8;
    data[index + 1] = (state >> 18) as u8;
    data[index + 2] = (state >> 8) as u8;
    data[index + 3] = state as u8;
}

pub(crate) fn starts(ctx: &mut SHA256Context) {
    ctx.total = [0; 2];
    ctx.state = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ];
}

pub(crate) fn process(ctx: &mut SHA256Context, data: [u8; 64]) {
    let mut w: [u32; 64] = [0; 64];

    w[0] = get_u32(&data, 0);
    w[1] = get_u32(&data, 4);
    w[2] = get_u32(&data, 8);
    w[3] = get_u32(&data, 12);
    w[4] = get_u32(&data, 16);
    w[5] = get_u32(&data, 20);
    w[6] = get_u32(&data, 24);
    w[7] = get_u32(&data, 28);
    w[8] = get_u32(&data, 32);
    w[9] = get_u32(&data, 36);
    w[10] = get_u32(&data, 40);
    w[11] = get_u32(&data, 44);
    w[12] = get_u32(&data, 48);
    w[13] = get_u32(&data, 52);
    w[14] = get_u32(&data, 56);
    w[15] = get_u32(&data, 60);

    let mut a = ctx.state[0];
    let mut b = ctx.state[1];
    let mut c = ctx.state[2];
    let mut d = ctx.state[3];
    let mut e = ctx.state[4];
    let mut f = ctx.state[5];
    let mut g = ctx.state[6];
    let mut h = ctx.state[7];

    p( a, b, c, &mut d, e, f, g, &mut h, w[ 0], 0x428A2F98 );
    p( h, a, b, &mut c, d, e, f, &mut g, w[ 1], 0x71374491 );
    p( g, h, a, &mut b, c, d, e, &mut f, w[ 2], 0xB5C0FBCF );
    p( f, g, h, &mut a, b, c, d, &mut e, w[ 3], 0xE9B5DBA5 );
    p( e, f, g, &mut h, a, b, c, &mut d, w[ 4], 0x3956C25B );
    p( d, e, f, &mut g, h, a, b, &mut c, w[ 5], 0x59F111F1 );
    p( c, d, e, &mut f, g, h, a, &mut b, w[ 6], 0x923F82A4 );
    p( b, c, d, &mut e, f, g, h, &mut a, w[ 7], 0xAB1C5ED5 );
    p( a, b, c, &mut d, e, f, g, &mut h, w[ 8], 0xD807AA98 );
    p( h, a, b, &mut c, d, e, f, &mut g, w[ 9], 0x12835B01 );
    p( g, h, a, &mut b, c, d, e, &mut f, w[10], 0x243185BE );
    p( f, g, h, &mut a, b, c, d, &mut e, w[11], 0x550C7DC3 );
    p( e, f, g, &mut h, a, b, c, &mut d, w[12], 0x72BE5D74 );
    p( d, e, f, &mut g, h, a, b, &mut c, w[13], 0x80DEB1FE );
    p( c, d, e, &mut f, g, h, a, &mut b, w[14], 0x9BDC06A7 );
    p( b, c, d, &mut e, f, g, h, &mut a, w[15], 0xC19BF174 );
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

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    ctx.state[5] += f;
    ctx.state[6] += g;
    ctx.state[7] += h;
}

#[inline] fn shr(x: u32, n: u32)  -> u32 { (x & 0xFFFFFFFF) >> n         }
#[inline] fn rotr(x: u32, n: u32) -> u32 { shr(x,n) | (x << (32 - n))    }

#[inline] fn s0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x,18) ^ shr(x,3)      }
#[inline] fn s1(x: u32) -> u32 { rotr(x,17) ^ rotr(x,19) ^ shr(x,10)     }
#[inline] fn s2(x: u32) -> u32 { rotr(x, 2) ^ rotr(x,13) ^ rotr(x,22)    }
#[inline] fn s3(x: u32) -> u32 { rotr(x, 6) ^ rotr(x,11) ^ rotr(x,25)    }

#[inline] fn f0(x: u32, y: u32, z: u32) -> u32 { (x & y) | (z & (x | y)) }
#[inline] fn f1(x: u32, y: u32, z: u32) -> u32 { z ^ (x & (y ^ z))       }

#[inline] fn r(w: &mut [u32; 64], t: usize) -> u32 {
    w[t] = s1(w[t - 2]) + w[t - 7] + s0(w[t - 15]) + w[t - 16];
    w[t]
}

#[inline]
fn p(a: u32, b: u32, c: u32, d: &mut u32, e: u32, f: u32, g: u32, h: &mut u32, x: u32, k: u32) {
    let temp1 = *h + s3(e) + f1(e,f,g) + k + x;
    let temp2 = s2(a) + f0(a,b,c);
    *d += temp1;
    *h = temp1 + temp2;
}


