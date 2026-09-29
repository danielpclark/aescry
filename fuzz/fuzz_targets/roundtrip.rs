//! Encrypting any plaintext with any password, IVs, key and version, then
//! decrypting, returns the plaintext; deterministic encryption is
//! reproducible; any single-bit change is rejected.
#![no_main]

use aescry::security::{
    DecryptKey, EncryptKey, Iterations, PublicIv, RawDecryptor, RawEncryptor, SessionIv, SessionKey,
};
use aescry::Version;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if input.len() < 66 {
        return;
    }
    let (params, rest) = input.split_at(66);
    let version = Version::from_u8(params[0] % 4).unwrap();
    let password_len = (params[1] as usize) % 32;
    let public_iv = PublicIv::try_from(&params[2..18]).unwrap();
    let session_iv = SessionIv::try_from(&params[18..34]).unwrap();
    let session_key = SessionKey::try_from(&params[34..66]).unwrap();
    let (password, plaintext) = rest.split_at(password_len.min(rest.len()));

    let encryptor = RawEncryptor::new(EncryptKey::raw_password(password))
        .version(version)
        .iterations(Iterations::new(1).unwrap())
        .deterministic(public_iv, session_iv, session_key);

    let stream = encryptor.encrypt(plaintext).unwrap();
    assert_eq!(stream, encryptor.encrypt(plaintext).unwrap(), "not deterministic");
    assert_eq!(aescry::detect::from_bytes(&stream), Some(version));

    let opened = RawDecryptor::new(DecryptKey::raw_password(password)).decrypt(&stream).unwrap();
    assert_eq!(opened.plaintext(), plaintext);

    // flip one bit after the (unauthenticated) header
    let header_len = aescry::aescrypt::read_header(&stream[..]).unwrap().len();
    let span = stream.len() - header_len;
    let position = header_len + (params[1] as usize * 7919 + plaintext.len()) % span;
    let mut altered = stream.clone();
    altered[position] ^= 1 << (params[0] % 8);
    let result = RawDecryptor::new(DecryptKey::raw_password(password)).decrypt(&altered);

    let final_block_size_at = stream.len() - 33;
    if matches!(version, Version::V1 | Version::V2) && position == final_block_size_at {
        // versions 1-2 don't authenticate this octet (a format weakness);
        // a change must at least be reported as inconsistent
        let opened = result.expect("the HMACs do not cover this octet");
        let out = opened.plaintext();
        if opened.report().verification().is_consistent() && out != plaintext {
            // the one undetectable change: size set to 0 ("full block"),
            // which appends the padding octets to the plaintext
            assert_eq!(altered[position] & 0x0f, 0);
            assert!(out.starts_with(plaintext));
            let pad = (16 - plaintext.len() % 16) as u8;
            assert!(out[plaintext.len()..].iter().all(|&b| b == pad));
        }
    } else {
        assert!(result.is_err(), "undetected change at octet {} of a {} stream", position, version);
    }
});
