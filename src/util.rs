use std::slice;
use std::fmt::LowerHex;
use std::mem;

pub fn memset(t: *mut u8, val: u8, qty: usize) {
    let temp_target: &mut [u8] = unsafe { slice::from_raw_parts_mut(t, qty) };
    for i in temp_target { *i = val; }
}

pub trait SliceToHex<T: LowerHex> {
    fn slice_to_hex(&self) -> String;
}

impl<T> SliceToHex<T> for [T] where T: std::fmt::LowerHex {
    fn slice_to_hex(&self) -> String {
        let mut hex_digest = String::with_capacity(self.len() * mem::size_of::<T>() * 2);
        
        let format = String::with_capacity(10);

        for i in 0..self.len() {
            hex_digest.push_str(&format!("{:0>pad$x}", self[i], pad=mem::size_of::<T>() * 2));
        }

        hex_digest
    }
}

#[test]
fn test_slice_to_hex() {
    use crate::util::SliceToHex;
    let a: [u8; 1] = [0x65];
    assert_eq!(<[u8]>::slice_to_hex(&a), "65");
    let b: [u16; 1] = [0x65];
    assert_eq!(<[u16]>::slice_to_hex(&b), "0065");
    let c: [u32; 1] = [0x65];
    assert_eq!(<[u32]>::slice_to_hex(&c), "00000065");
    let d: [u64; 1] = [0x65];
    assert_eq!(<[u64]>::slice_to_hex(&d), "0000000000000065");
}
