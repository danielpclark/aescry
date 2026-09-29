mod common;

use aescry::digest::Digest;
use aescry::sha256::{sha256, Sha256};
use aescry::sha512::{sha512, Sha512};
use common::{hex, load_vectors};

fn check_kat<H: Digest>(file: &str) {
    for (i, v) in load_vectors(file).iter().enumerate() {
        assert_eq!(hex(H::digest(&v["input"]).as_ref()), hex(&v["output"]), "{} vector {}", file, i);

        // byte at a time
        let mut h = H::new();
        for b in &v["input"] {
            h.update(std::slice::from_ref(b));
        }
        assert_eq!(hex(h.finalize().as_ref()), hex(&v["output"]), "{} vector {} incremental", file, i);
    }
}

#[test]
fn rustcrypto_sha256_kat() {
    check_kat::<Sha256>("rustcrypto/sha256_kat.txt");
}

#[test]
fn rustcrypto_sha512_kat() {
    check_kat::<Sha512>("rustcrypto/sha512_kat.txt");
}

// FIPS 180-2 Appendix B / C examples

#[test]
fn fips180_2_sha256() {
    assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn fips180_2_sha512() {
    assert_eq!(
        hex(&sha512(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        hex(&sha512(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        )),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
         501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    );
}
