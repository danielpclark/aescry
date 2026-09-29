mod common;

use aescry::digest::Digest;
use aescry::hmac::{hmac_sha256, hmac_sha512, Hmac};
use aescry::sha256::Sha256;
use aescry::sha512::Sha512;
use aescry::Error;
use common::{hex, load_vectors};

/// Check RustCrypto HMAC vectors.  Wycheproof tags may be truncated: the
/// expected tag is the leftmost octets of the full tag.
fn check<H: Digest>(file: &str) {
    for (i, v) in load_vectors(file).iter().enumerate() {
        let (key, input, tag) = (&v["key"], &v["input"], &v["tag"]);

        let mut mac = Hmac::<H>::new(key);
        mac.update(input);
        let full = mac.clone().finalize();
        assert_eq!(hex(&full.as_ref()[..tag.len()]), hex(tag), "{} vector {}", file, i);

        if tag.len() == H::OUTPUT_SIZE {
            mac.clone().verify(tag).unwrap();
        } else {
            assert!(matches!(mac.clone().verify(tag), Err(Error::AuthenticationFailed)));
        }
        mac.clone().verify_truncated(tag).unwrap();

        // a changed tag is rejected
        let mut bad = tag.clone();
        bad[0] ^= 1;
        assert!(mac.verify_truncated(&bad).is_err());
    }
}

#[test]
fn rustcrypto_hmac_sha256_rfc4231() {
    check::<Sha256>("rustcrypto/hmac_sha256_rfc4231.txt");
}

#[test]
fn rustcrypto_hmac_sha512_rfc4231() {
    check::<Sha512>("rustcrypto/hmac_sha512_rfc4231.txt");
}

#[test]
fn rustcrypto_hmac_sha256_wycheproof() {
    check::<Sha256>("rustcrypto/hmac_sha256_wycheproof.txt");
}

#[test]
fn rustcrypto_hmac_sha512_wycheproof() {
    check::<Sha512>("rustcrypto/hmac_sha512_wycheproof.txt");
}

#[test]
fn one_shot_helpers_match() {
    let mut mac = Hmac::<Sha256>::new(b"k");
    mac.update(b"data");
    assert_eq!(hmac_sha256(b"k", b"data"), mac.finalize());

    let mut mac = Hmac::<Sha512>::new(b"k");
    mac.update(b"data");
    assert_eq!(hmac_sha512(b"k", b"data"), mac.finalize());
}

#[test]
fn truncated_tags_have_limits() {
    let tag = hmac_sha256(b"k", b"data");
    let mac = || {
        let mut m = Hmac::<Sha256>::new(b"k");
        m.update(b"data");
        m
    };

    assert!(mac().verify_truncated(&tag[..10]).is_ok());
    assert!(mac().verify_truncated(&tag[..9]).is_err()); // too short
    assert!(mac().verify_truncated(&[tag.as_slice(), &[0]].concat()).is_err()); // too long
    assert!(mac().verify(&tag[..16]).is_err()); // verify wants the full tag
}
