//! Property tests: invariants that must hold for every input, checked on
//! randomly generated (and, on failure, minimized) cases.

use aescry::aes::{Aes, BlockCipher};
use aescry::hmac::HmacSha256;
use aescry::padding::{pkcs7_pad, pkcs7_unpad};
use aescry::security::{DecryptKey, EncryptKey, Iterations, PublicIv, RawDecryptor, RawEncryptor, SessionIv, SessionKey};
use aescry::sha256::{sha256, Sha256};
use aescry::sha512::{sha512, Sha512};
use aescry::{cbc, Version};
use proptest::collection::vec;
use proptest::prelude::*;

fn key_len() -> impl Strategy<Value = usize> {
    prop_oneof![Just(16usize), Just(24usize), Just(32usize)]
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..max)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn pkcs7_roundtrip(data in bytes(100)) {
        let padded = pkcs7_pad(&data);
        prop_assert_eq!(padded.len() % 16, 0);
        prop_assert!(padded.len() > data.len() && padded.len() <= data.len() + 16);
        prop_assert_eq!(pkcs7_unpad(&padded).unwrap(), &data[..]);
    }

    #[test]
    fn aes_block_roundtrip(len in key_len(), key in vec(any::<u8>(), 32), block in any::<[u8; 16]>()) {
        let cipher = Aes::new(&key[..len]).unwrap();
        let mut b = block;
        cipher.encrypt_block(&mut b);
        cipher.decrypt_block(&mut b);
        prop_assert_eq!(b, block);
    }

    #[test]
    fn cbc_roundtrip(len in key_len(), key in vec(any::<u8>(), 32), iv in any::<[u8; 16]>(), data in bytes(200)) {
        let key = &key[..len];
        let ct = cbc::encrypt(key, &iv, &data).unwrap();
        prop_assert_eq!(ct.len(), (data.len() / 16 + 1) * 16);
        prop_assert_eq!(cbc::decrypt(key, &iv, &ct).unwrap(), data);
    }

    #[test]
    fn cbc_decrypt_never_panics(len in key_len(), key in vec(any::<u8>(), 32), iv in any::<[u8; 16]>(), data in bytes(100)) {
        let _ = cbc::decrypt(&key[..len], &iv, &data);
        let _ = cbc::decrypt_with_iv_prefix(&key[..len], &data);
    }

    #[test]
    fn hashes_are_split_invariant(data in bytes(400), split in any::<prop::sample::Index>()) {
        let at = split.index(data.len() + 1);
        let (a, b) = data.split_at(at);

        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        prop_assert_eq!(h.finalize(), sha256(&data));

        let mut h = Sha512::new();
        h.update(a);
        h.update(b);
        prop_assert_eq!(h.finalize().to_vec(), sha512(&data).to_vec());

        let mut whole = HmacSha256::new(b"key");
        whole.update(&data);
        let mut parts = HmacSha256::new(b"key");
        parts.update(a);
        parts.update(b);
        prop_assert_eq!(whole.finalize(), parts.finalize());
    }
}

proptest! {
    // each case runs key derivation, so fewer cases
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any password octets, IVs, key, version and plaintext round-trip, and
    /// fixed values give identical streams.
    #[test]
    fn aescrypt_roundtrip(
        version in 0u8..4,
        password in bytes(40),
        public_iv in any::<[u8; 16]>(),
        session_iv in any::<[u8; 16]>(),
        session_key in any::<[u8; 32]>(),
        plaintext in bytes(100),
    ) {
        let version = Version::from_u8(version).unwrap();
        let encryptor = RawEncryptor::new(EncryptKey::raw_password(password.clone()))
            .version(version)
            .iterations(Iterations::new(1).unwrap())
            .deterministic(PublicIv::from(public_iv), SessionIv::from(session_iv), SessionKey::from(session_key));

        let stream = encryptor.encrypt(&plaintext).unwrap();
        prop_assert_eq!(&stream, &encryptor.encrypt(&plaintext).unwrap());

        let opened = RawDecryptor::new(DecryptKey::raw_password(password)).decrypt(&stream).unwrap();
        prop_assert_eq!(opened.plaintext(), &plaintext[..]);
        prop_assert!(opened.report().verification().is_consistent());
    }

    /// In version 3 every octet after the header is authenticated: any
    /// single-bit change is rejected.
    #[test]
    fn aescrypt_v3_rejects_any_bit_flip(
        plaintext in bytes(80),
        position in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let stream = RawEncryptor::new(EncryptKey::password("pw").unwrap())
            .iterations(Iterations::new(1).unwrap())
            .encrypt(&plaintext)
            .unwrap();
        let header_len = aescry::aescrypt::read_header(&stream[..]).unwrap().len();

        let at = header_len + position.index(stream.len() - header_len);
        let mut altered = stream.clone();
        altered[at] ^= 1 << bit;

        let result = RawDecryptor::new(DecryptKey::password("pw").unwrap()).decrypt(&altered);
        prop_assert!(result.is_err(), "undetected change at octet {}", at);
    }
}
