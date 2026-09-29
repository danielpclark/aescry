mod common;

use aescry::kdf;
use common::{hex, load_vectors, unhex};

/// PBKDF2 vectors from RustCrypto/password-hashes `pbkdf2/tests/pbkdf2.rs`
/// (MIT; see tests/data/rustcrypto).  RustCrypto checks the first 20 octets.
#[test]
fn rustcrypto_pbkdf2_hmac_sha256() {
    let cases: &[(&[u8], &[u8], u32, &str)] = &[
        (b"password", b"salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c9"),
        (b"password", b"salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"),
        (b"password", b"salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a0"),
        (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347e"),
        (b"pass\0word", b"sa\0lt", 600_000, "efc5286bfbd0681c9600b5c024b8ba1b5ae0f0ab"),
    ];

    for &(password, salt, iterations, expected) in cases {
        let out: [u8; 20] = kdf::pbkdf2_hmac_sha256_array(password, salt, iterations).unwrap();
        assert_eq!(hex(&out), expected, "{} iterations", iterations);
    }
}

#[test]
fn rustcrypto_pbkdf2_hmac_sha512() {
    let cases: &[(&[u8], &[u8], u32, &str)] = &[
        (b"password", b"salt", 1, "867f70cf1ade02cff3752599a3a53dc4af34c7a6"),
        (b"password", b"salt", 2, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e"),
        (b"password", b"salt", 4096, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc"),
        (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
            "8c0511f4c6e597c6ac6315d8f0362e225f3c5014"),
        (b"pass\0word", b"sa\0lt", 210_000, "4941abc239d618e79f63d3d300e5f81954164bc1"),
    ];

    for &(password, salt, iterations, expected) in cases {
        let out: [u8; 20] = kdf::pbkdf2_hmac_sha512_array(password, salt, iterations).unwrap();
        assert_eq!(hex(&out), expected, "{} iterations", iterations);
    }
}

/// Multi-block outputs and odd lengths, cross-checked with Python hashlib.
#[test]
fn pbkdf2_matches_hashlib() {
    for (i, v) in load_vectors("pbkdf2_hashlib.txt").iter().enumerate() {
        let iterations = u32::from_be_bytes(v["iterations"].as_slice().try_into().unwrap());

        let mut out = vec![0u8; v["sha256"].len()];
        kdf::pbkdf2_hmac_sha256(&v["password"], &v["salt"], iterations, &mut out).unwrap();
        assert_eq!(hex(&out), hex(&v["sha256"]), "vector {} sha256", i);

        let mut out = vec![0u8; v["sha512"].len()];
        kdf::pbkdf2_hmac_sha512(&v["password"], &v["salt"], iterations, &mut out).unwrap();
        assert_eq!(hex(&out), hex(&v["sha512"]), "vector {} sha512", i);
    }
}

/// The AES Crypt version 0-2 derivation, cross-checked with Python hashlib.
#[test]
fn aescrypt_legacy_matches_python() {
    for (i, v) in load_vectors("aescrypt_legacy_kdf.txt").iter().enumerate() {
        let iv: [u8; 16] = v["iv"].as_slice().try_into().unwrap();
        assert_eq!(hex(&kdf::aescrypt_legacy(&v["password"], &iv)), hex(&v["key"]), "vector {}", i);
    }

    assert_eq!(kdf::utf16le("password"), unhex("700061007300730077006f0072006400"));
}
