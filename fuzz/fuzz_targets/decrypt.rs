//! The password API on arbitrary streams: must never panic, and anything it
//! accepts must decrypt consistently in memory and as a stream.
#![no_main]

use aescry::aescrypt::{Decryptor, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // keep key derivation cheap so the fuzzer explores the parser
    let decryptor = Decryptor::new("pw").unwrap().limits(Limits::DEFAULT.max_iterations(4));

    let in_memory = decryptor.decrypt(data);

    let mut streamed = Vec::new();
    let stream_result = decryptor.decrypt_stream(data, &mut streamed);

    match (in_memory, stream_result) {
        (Ok(plaintext), Ok(len)) => {
            assert_eq!(plaintext, streamed);
            assert_eq!(plaintext.len() as u64, len);
        }
        (Err(_), Err(_)) => {}
        (a, b) => panic!("in-memory and streaming disagree: {:?} vs {:?}", a.map(|p| p.len()), b),
    }
});
