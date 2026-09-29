//! The security toolkit's decryptors with keys and streams chosen by the
//! fuzzer: must never panic, and verified decryption must only succeed on
//! authentic streams.
#![no_main]

use aescry::security::{verify, DecryptKey, Limits, RawDecryptor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some((&selector, rest)) = input.split_first() else { return };
    if rest.len() < 48 {
        return;
    }
    let (key_bytes, data) = rest.split_at(48);

    let key = || match selector % 3 {
        0 => DecryptKey::raw_password(key_bytes[..(selector as usize % 17)].to_vec()),
        1 => DecryptKey::derived(&key_bytes[..32]).unwrap(),
        _ => DecryptKey::session(&key_bytes[..16], &key_bytes[16..48]).unwrap(),
    };
    let limits = Limits::DEFAULT.max_iterations(4);

    let verified = RawDecryptor::new(key()).limits(limits).decrypt(data);
    let unverified = RawDecryptor::new(key()).limits(limits).skip_verification().decrypt(data);
    let checked = verify(&key(), data);

    if let Ok(opened) = &verified {
        // verified success implies the checks passed and the unverified
        // decryptor produced the same plaintext
        assert!(opened.report().verification().is_authentic());
        let unverified = unverified.expect("unverified failed where verified succeeded");
        assert!(unverified.is_authentic());
        assert_eq!(unverified.peek_unauthenticated().plaintext(), opened.plaintext());
    }
    if let (Ok(v), Ok(_)) = (&checked, &verified) {
        assert!(v.is_authentic());
    }
});
