mod common;

use aescry::aes::{Aes, Aes256};
use aescry::cbc::{self, CbcDecryptor, CbcEncryptor};
use common::{array, hex, load_vectors, unhex};

/// RustCrypto's NIST CAVP multiblock message vectors (no padding).
fn check_cavp(file: &str) {
    for (i, v) in load_vectors(file).iter().enumerate() {
        let ct = cbc::encrypt_no_padding(&v["key"], &v["iv"], &v["pt"]).unwrap();
        assert_eq!(hex(&ct), hex(&v["ct"]), "{} vector {} encrypt", file, i);

        let pt = cbc::decrypt_no_padding(&v["key"], &v["iv"], &v["ct"]).unwrap();
        assert_eq!(hex(&pt), hex(&v["pt"]), "{} vector {} decrypt", file, i);

        // the stateful API, one block at a time
        let cipher = Aes::new(&v["key"]).unwrap();
        let mut enc = CbcEncryptor::new(&cipher, &array(&v["iv"]));
        let mut buf = v["pt"].clone();
        for chunk in buf.chunks_mut(16) {
            enc.encrypt_in_place(chunk).unwrap();
        }
        assert_eq!(buf, v["ct"], "{} vector {} streaming encrypt", file, i);

        let mut dec = CbcDecryptor::new(&cipher, &array(&v["iv"]));
        for chunk in buf.chunks_mut(16) {
            dec.decrypt_in_place(chunk).unwrap();
        }
        assert_eq!(buf, v["pt"], "{} vector {} streaming decrypt", file, i);
    }
}

#[test]
fn rustcrypto_cavp_aes128() {
    check_cavp("rustcrypto/cbc_aes128.txt");
}

#[test]
fn rustcrypto_cavp_aes192() {
    check_cavp("rustcrypto/cbc_aes192.txt");
}

#[test]
fn rustcrypto_cavp_aes256() {
    check_cavp("rustcrypto/cbc_aes256.txt");
}

// NIST SP 800-38A, Appendix F.2 (CBC-AES128/192/256 encrypt and decrypt)

const SP800_38A_IV: &str = "000102030405060708090a0b0c0d0e0f";
const SP800_38A_PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                            30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

fn sp800_38a(key: &str, ct: &str) {
    let (key, iv, pt) = (unhex(key), unhex(SP800_38A_IV), unhex(SP800_38A_PT));

    let encrypted = cbc::encrypt_no_padding(&key, &iv, &pt).unwrap();
    assert_eq!(hex(&encrypted), ct);
    assert_eq!(cbc::decrypt_no_padding(&key, &iv, &encrypted).unwrap(), pt);

    // with padding, the ciphertext gains exactly one extra block
    let padded = cbc::encrypt(&key, &iv, &pt).unwrap();
    assert_eq!(hex(&padded[..64]), ct);
    assert_eq!(padded.len(), 80);
    assert_eq!(cbc::decrypt(&key, &iv, &padded).unwrap(), pt);
}

#[test]
fn sp800_38a_f21_f22_aes128() {
    sp800_38a(
        "2b7e151628aed2a6abf7158809cf4f3c",
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
         73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
    );
}

#[test]
fn sp800_38a_f23_f24_aes192() {
    sp800_38a(
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a\
         571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
    );
}

#[test]
fn sp800_38a_f25_f26_aes256() {
    sp800_38a(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
         39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
    );
}

/// PKCS#7 padded output matches OpenSSL's `enc -aes-128-cbc` default.
#[test]
fn padded_matches_openssl() {
    let key = unhex("000102030405060708090a0b0c0d0e0f");
    let iv = unhex("0f0e0d0c0b0a09080706050403020100");

    // printf 'hello world' | openssl enc -aes-128-cbc -K <key> -iv <iv> | xxd -p
    let expected = "3fb51c0ccbcb533bb82a08e6817013ea";
    let ct = cbc::encrypt(&key, &iv, b"hello world").unwrap();
    assert_eq!(hex(&ct), expected);
}

#[test]
fn iv_state_continues_the_chain() {
    let cipher = Aes256::new(&[0x11; 32]);
    let iv = [0x22; 16];
    let mut data = [0x33u8; 64];

    let mut enc = CbcEncryptor::new(&cipher, &iv);
    enc.encrypt_in_place(&mut data[..32]).unwrap();

    // a fresh encryptor started from the chaining value continues the stream
    let mut resumed = CbcEncryptor::new(&cipher, &enc.iv_state());
    let mut rest = [0x33u8; 32];
    resumed.encrypt_in_place(&mut rest).unwrap();
    enc.encrypt_in_place(&mut data[32..]).unwrap();
    assert_eq!(&data[32..], &rest);

}
