//! Every password-free parser on arbitrary input: must never panic, and
//! must agree with each other about what the input is.
#![no_main]

use aescry::aescrypt;
use aescry::security::{inspect_with_limits, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let header = aescrypt::read_header(data);
    let _ = aescry::detect::from_header(data);
    let _ = aescry::detect::from_bytes(data);
    let _ = aescry::padding::pkcs7_unpad(data);

    let layout = inspect_with_limits(data, Limits::DEFAULT);
    if let Ok(layout) = &layout {
        // a successfully mapped stream has a header the header reader accepts
        let header = header.as_ref().expect("inspect accepted a stream read_header rejects");
        assert_eq!(&layout.header, header);
        assert_eq!(layout.total_len, data.len());
        assert!(layout.ciphertext.end <= data.len());
        assert_eq!(layout.ciphertext.len() % 16, 0);
        assert_eq!(layout.message_hmac.0.end, data.len());
    }
});
