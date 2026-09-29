//! CBC with PKCS#7: arbitrary ciphertexts never panic, and encryption with
//! any key and IV round-trips.
#![no_main]

use aescry::cbc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if input.len() < 48 {
        return;
    }
    let (key, rest) = input.split_at(32);
    let (iv, data) = rest.split_at(16);
    let key = &key[..[16, 24, 32][data.len() % 3]];

    let _ = cbc::decrypt(key, iv, data);
    let _ = cbc::decrypt_no_padding(key, iv, data);
    let _ = cbc::decrypt_with_iv_prefix(key, data);

    let ciphertext = cbc::encrypt(key, iv, data).unwrap();
    assert_eq!(ciphertext.len() % 16, 0);
    assert_eq!(cbc::decrypt(key, iv, &ciphertext).unwrap(), data);
});
