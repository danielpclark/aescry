// FIPS 180-2 compliant
use core::array::FixedSizeArray; // for `as_slice`
use std::{slice, ptr};

use crate::algorithms::*;

#[derive(Clone)]
pub(crate) struct SHA256Context {
    pub(crate) total: [u32; 2],
    pub(crate) state: [u32; 8],
    pub(crate) buffer: [u8; 64],
}

pub(crate) fn starts(context: Option<&mut SHA256Context>) -> SHA256Context {
    let state = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ];

    match context {
        Some(ctx) => { ctx.total = [0u32; 2]; ctx.state = state; ctx.clone() },
        None => SHA256Context { total: [0u32; 2], state: state, buffer: [0u8; 64] },
    }
}

pub(crate) fn process(state: &mut [u32], data: &[u8]) {
    assert!(data.len() == 64, "invalid data length");
    assert!(state.len() == 8, "invalid state length");
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

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

pub(crate) fn update(context: &mut SHA256Context, input: &[u8], length: &mut u32) {
    let mut left = context.total[0] & 0x3F;
    let fill = 64 - left;

    context.total[0] += *length;
    context.total[0] &= 0xFFFFFFFF;

    if context.total[0] < *length {
        context.total[1] += 1;
    }

    let bfr_ptr = context.buffer.as_ptr() as *mut u8;
    let mut ipt_ptr = input.as_ptr() as *mut u8;

    if left != 0 && *length >= fill {
        // memcpy( (void *) (ctx->buffer + left),
        //         (void *) input, fill );
        unsafe { ptr::copy_nonoverlapping(ipt_ptr, bfr_ptr.add(left as usize), fill as usize); }

        process(&mut context.state, &context.buffer);

        *length -= fill;
        ipt_ptr = unsafe { ipt_ptr.add(fill as usize) };
        left = 0;
    }

    while *length >= 64 {
        let temp_input: &[u8] = unsafe { slice::from_raw_parts(ipt_ptr, 64) };
        process(&mut context.state, temp_input);
        *length -= 64;
        ipt_ptr = unsafe { ipt_ptr.add(64) };
    }

    if *length != 0 {
        // memcpy( (void *) (ctx->buffer + left),
        //         (void *) input, length );
        let temp_input: &[u8] = unsafe { slice::from_raw_parts(ipt_ptr, 64) };
        unsafe { ptr::copy_nonoverlapping(ipt_ptr, bfr_ptr.add(left as usize), fill as usize); }
    }
}

pub(crate) fn finish(context: &mut SHA256Context, digest: &mut [u8; 32]) {
    let high: u32 = (context.total[0] >> 29) | (context.total[1] <<  3);
    let low:  u32 =  context.total[0] <<  3;
    let msglen: &mut [u8] = &mut [0u8; 8];

    put_u32(high, msglen, 0);
    put_u32(low , msglen, 4);

    let last: u32 = context.total[0] & 0x3F;
    let mut padn: u32 = if last < 56 { 56 - last } else { 120 - last };

    update(context, SHA256_PADDING.as_slice(), &mut padn);
    update(context, msglen, &mut 8); // TODO: panic! attempt to add with overflow

    put_u32(context.state[0], digest,  0);
    put_u32(context.state[1], digest,  4);
    put_u32(context.state[2], digest,  8);
    put_u32(context.state[3], digest, 12);
    put_u32(context.state[4], digest, 16);
    put_u32(context.state[5], digest, 20);
    put_u32(context.state[6], digest, 24);
    put_u32(context.state[7], digest, 28);
}


#[test]
fn it_works() {
    let msg: [&'static str; 2] = ["abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"];
    let val: [&'static str; 3] = [
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    ];

    let mut buf: [u8; 1000] = [0u8; 1000];
    let mut sha256sum: [u8; 32] = [0u8; 32];

    let mut ctx = starts(None);

    for i in 0..3 {
        starts(Some(&mut ctx));

        if i < 2 {
            update(&mut ctx, msg[i].as_bytes(), &mut (msg[i].len() as u32));
        } else {
            buf = [b'a'; 1000];

            for j in 0..1000 {
                update(&mut ctx, &buf, &mut 1000);
            }
        }

        finish(&mut ctx, &mut sha256sum);

        for j in 0..32 {
            // TODO: More sensible testing
            assert!(sha256sum[j] != 0x00, "{}", sha256sum[j]);
        }
    }
}
