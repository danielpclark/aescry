mod common;

use aescry::aescrypt;
use aescry::security::{
    derive_key, ecb_decrypt, ecb_encrypt, inspect, password_bytes, verify, Extension, Key, RawDecryptor,
    RawEncryptor,
};
use aescry::{Error, Version};
use common::{hex, load_vectors, unhex};

fn version(byte: u8) -> Version {
    Version::from_u8(byte).unwrap()
}

/// aescry reproduces, octet for octet, the streams written by the
/// independent Python writer (each also verified with the official
/// AES Crypt tool), and decrypts them.
#[test]
fn known_answer_streams() {
    let vectors = load_vectors("aescrypt/kat.txt");
    assert_eq!(vectors.len(), 12);

    for (i, v) in vectors.iter().enumerate() {
        let version = version(v["version"][0]);
        let iterations = u32::from_be_bytes(v["iterations"].as_slice().try_into().unwrap());

        let mut encryptor = RawEncryptor::new(Key::RawPassword(&v["password"]))
            .version(version)
            .iterations(iterations)
            .public_iv(&v["public_iv"])
            .unwrap()
            .session_iv(&v["session_iv"])
            .unwrap()
            .session_key(&v["session_key"])
            .unwrap();
        if !v["extension"].is_empty() {
            encryptor = encryptor.extension(Extension::from_bytes(v["extension"].clone()).unwrap());
        }

        let stream = encryptor.encrypt(&v["plaintext"]).unwrap();
        assert_eq!(hex(&stream), hex(&v["stream"]), "vector {} ({})", i, version);

        // the normal API opens it with the text password
        assert_eq!(aescrypt::decrypt("kat password ✓", &v["stream"]).unwrap(), v["plaintext"]);

        let decrypted = RawDecryptor::new(Key::RawPassword(&v["password"])).decrypt(&v["stream"]).unwrap();
        assert_eq!(&decrypted.plaintext[..], &v["plaintext"][..]);
        assert!(decrypted.report.is_authentic());

        if version != Version::V0 {
            assert_eq!(decrypted.report.session_iv()[..], v["session_iv"][..]);
            assert_eq!(decrypted.report.session_key()[..], v["session_key"][..]);
        }
    }
}

#[test]
fn text_and_raw_passwords_agree() {
    for v in [Version::V0, Version::V1, Version::V2, Version::V3] {
        let raw = password_bytes(v, "pässwörd 😀");
        let fixed = |key| {
            RawEncryptor::new(key)
                .version(v)
                .iterations(100)
                .public_iv(&[1; 16])
                .unwrap()
                .session_iv(&[2; 16])
                .unwrap()
                .session_key(&[3; 32])
                .unwrap()
                .encrypt(b"data")
                .unwrap()
        };

        assert_eq!(fixed(Key::Text("pässwörd 😀")), fixed(Key::RawPassword(&raw)), "{}", v);
    }

    assert_eq!(&password_bytes(Version::V2, "A")[..], &[0x41, 0x00][..]);
    assert_eq!(&password_bytes(Version::V3, "A")[..], b"A");
}

#[test]
fn arbitrary_password_octets() {
    let passwords: [&[u8]; 4] = [&[0xFF, 0xFE], &[0x00], &[0xC3, 0x28, 0xA0, 0xA1], &[0xD8, 0x00]];

    for v in [Version::V0, Version::V1, Version::V2, Version::V3] {
        for password in passwords {
            let stream = RawEncryptor::new(Key::RawPassword(password))
                .version(v)
                .iterations(10)
                .encrypt(b"raw")
                .unwrap();

            let out = RawDecryptor::new(Key::RawPassword(password)).decrypt(&stream).unwrap();
            assert_eq!(&out.plaintext[..], b"raw");

            let wrong = RawDecryptor::new(Key::RawPassword(&[0x01])).decrypt(&stream);
            assert!(matches!(wrong, Err(Error::InvalidPassword)));
        }
    }
}

#[test]
fn recovered_keys_open_the_stream() {
    for v in [Version::V0, Version::V1, Version::V2, Version::V3] {
        let stream = RawEncryptor::new(Key::Text("pw")).version(v).iterations(50).encrypt(b"forensics").unwrap();
        let report = RawDecryptor::new(Key::Text("pw")).decrypt(&stream).unwrap().report;

        // the derived key can be recomputed and used directly
        let derived = report.derived_key().unwrap();
        let iv = report.header().iv();
        let expected = derive_key(v, &password_bytes(v, "pw"), iv, 50).unwrap();
        assert_eq!(derived, &*expected);

        let by_derived = RawDecryptor::new(Key::DerivedKey(derived)).decrypt(&stream).unwrap();
        assert_eq!(&by_derived.plaintext[..], b"forensics");

        let session = Key::Session { iv: report.session_iv(), key: report.session_key() };
        let by_session = RawDecryptor::new(session).decrypt(&stream).unwrap();
        assert_eq!(&by_session.plaintext[..], b"forensics");
        assert!(by_session.report.derived_key().is_none());
        assert_eq!(by_session.report.key_block_authentic(), None);

        if v == Version::V0 {
            // version 0 has no session key: it is the derived key and public IV
            assert_eq!(report.session_key(), derived);
            assert_eq!(report.session_iv(), iv);
        }
    }
}

#[test]
fn derived_keys_skip_iteration_limits() {
    let key = [9u8; 32];
    let stream = RawEncryptor::new(Key::DerivedKey(&key)).iterations(u32::MAX).encrypt(b"x").unwrap();

    assert_eq!(inspect(&stream).unwrap().header.iterations(), Some(u32::MAX));
    assert!(matches!(aescrypt::decrypt("pw", &stream), Err(Error::InvalidIterations(u32::MAX))));
    assert!(matches!(
        RawDecryptor::new(Key::Text("pw")).decrypt(&stream),
        Err(Error::InvalidIterations(u32::MAX))
    ));
    assert_eq!(&RawDecryptor::new(Key::DerivedKey(&key)).decrypt(&stream).unwrap().plaintext[..], b"x");
}

#[test]
fn unverified_decryption_and_verify() {
    let stream = RawEncryptor::new(Key::Text("pw")).iterations(10).encrypt(&[0x42; 64]).unwrap();
    let layout = inspect(&stream).unwrap();

    let good = verify(Key::Text("pw"), &stream).unwrap();
    assert_eq!(good.key_block, Some(true));
    assert!(good.message);
    assert!(good.is_authentic());

    let wrong = verify(Key::Text("wrong"), &stream).unwrap();
    assert_eq!(wrong.key_block, Some(false));
    assert!(!wrong.is_authentic());

    // modify the first ciphertext block
    let mut tampered = stream.clone();
    tampered[layout.ciphertext.start] ^= 0x80;

    let checked = verify(Key::Text("pw"), &tampered).unwrap();
    assert_eq!(checked.key_block, Some(true));
    assert!(!checked.message);

    assert!(matches!(RawDecryptor::new(Key::Text("pw")).decrypt(&tampered), Err(Error::AlteredMessage)));

    let forensic = RawDecryptor::new(Key::Text("pw")).skip_verification().decrypt(&tampered).unwrap();
    assert!(!forensic.report.message_authentic());
    assert!(!forensic.report.is_authentic());
    assert_eq!(forensic.plaintext.len(), 64);
    assert_eq!(&forensic.plaintext[32..], &[0x42; 32][..]); // later blocks are intact
}

#[test]
fn inspect_layout() {
    for v in [Version::V0, Version::V1, Version::V2, Version::V3] {
        for len in [0usize, 5, 16, 20] {
            let mut enc = RawEncryptor::new(Key::Text("pw")).version(v).iterations(10);
            if v >= Version::V2 {
                enc = enc.extension(Extension::new("CREATED_BY", "inspect").unwrap());
            }
            let stream = enc.encrypt(&vec![7u8; len]).unwrap();
            let layout = inspect(&stream).unwrap();

            assert_eq!(layout.header.version(), v);
            assert_eq!(layout.total_len, stream.len());
            assert_eq!(layout.message_hmac.0.end, stream.len());
            assert_eq!(&stream[layout.message_hmac.0.clone()], &layout.message_hmac.1[..]);
            assert_eq!(layout.key_block.is_some(), v >= Version::V1);

            if v >= Version::V2 {
                let (range, ext) = &layout.extensions[0];
                assert_eq!(&stream[range.clone()], ext.as_bytes());
                assert_eq!(ext.value(), b"inspect");
            }

            match v {
                Version::V3 => {
                    assert_eq!(layout.ciphertext_len(), (len / 16 + 1) * 16);
                    assert_eq!(layout.plaintext_len(), None);
                }
                _ => assert_eq!(layout.plaintext_len(), Some(len), "{} length {}", v, len),
            }
        }
    }

    let stream = RawEncryptor::new(Key::Text("pw")).iterations(10).encrypt(b"x").unwrap();
    assert!(inspect(&stream[..stream.len() - 1]).is_err());
    assert!(matches!(inspect(b"nope"), Err(Error::InvalidStream(_)) | Err(Error::NotAesCrypt)));
}

#[test]
fn malformed_extensions_for_parser_testing() {
    // no NUL terminator, and an empty-identifier container
    let stream = RawEncryptor::new(Key::Text("pw"))
        .iterations(10)
        .extension(Extension::from_bytes(b"NO_TERMINATOR".to_vec()).unwrap())
        .extension(Extension::container(8).unwrap())
        .encrypt(b"ok")
        .unwrap();

    let header = aescrypt::read_header(&stream[..]).unwrap();
    assert_eq!(header.extensions()[0].identifier(), b"NO_TERMINATOR");
    assert!(header.extensions()[1].is_container());
    assert_eq!(aescrypt::decrypt("pw", &stream).unwrap(), b"ok");

    assert!(Extension::from_bytes(Vec::new()).is_err());
    assert!(Extension::from_bytes(vec![0u8; 65536]).is_err());

    let v1 = RawEncryptor::new(Key::Text("pw"))
        .version(Version::V1)
        .extension(Extension::container(8).unwrap())
        .encrypt(b"x");
    assert!(matches!(v1, Err(Error::InvalidExtension(_))));
}

#[test]
fn input_validation() {
    assert!(matches!(RawEncryptor::new(Key::Text("pw")).public_iv(&[0; 15]), Err(Error::InvalidIvLength(15))));
    assert!(matches!(RawEncryptor::new(Key::Text("pw")).session_iv(&[0; 17]), Err(Error::InvalidIvLength(17))));
    assert!(matches!(RawEncryptor::new(Key::Text("pw")).session_key(&[0; 16]), Err(Error::InvalidKeyLength(16))));
    assert!(matches!(RawEncryptor::new(Key::Text("pw")).iterations(0).encrypt(b""), Err(Error::InvalidIterations(0))));

    assert!(matches!(RawEncryptor::new(Key::DerivedKey(&[0; 31])).encrypt(b""), Err(Error::InvalidKeyLength(31))));
    assert!(RawEncryptor::new(Key::Session { iv: &[0; 16], key: &[0; 32] }).encrypt(b"").is_err());

    let stream = RawEncryptor::new(Key::Text("pw")).iterations(10).encrypt(b"").unwrap();
    assert!(matches!(
        RawDecryptor::new(Key::Session { iv: &[0; 8], key: &[0; 32] }).decrypt(&stream),
        Err(Error::InvalidIvLength(8))
    ));
    assert!(matches!(derive_key(Version::V3, b"pw", &[0; 12], 10), Err(Error::InvalidIvLength(12))));

    // secrets never appear in Debug output
    let debug = format!("{:?}", RawEncryptor::new(Key::Text("hunter2")).session_key(&[0xAB; 32]).unwrap());
    assert!(!debug.contains("hunter2") && !debug.contains("171"));
}

#[test]
fn ecb_primitive() {
    // first NESSIE AES-128 vector (tests/data/rustcrypto/aes128.txt)
    let key = unhex("80000000000000000000000000000000");
    let ct = ecb_encrypt(&key, &[0u8; 32]).unwrap();
    assert_eq!(hex(&ct[..16]), "0edd33d3c621e546455bd8ba1418bec8");
    assert_eq!(ct[..16], ct[16..]); // equal blocks, equal ciphertext
    assert_eq!(ecb_decrypt(&key, &ct).unwrap(), vec![0u8; 32]);
    assert!(matches!(ecb_encrypt(&key, &[0u8; 10]), Err(Error::InvalidCiphertextLength(10))));
    assert!(matches!(ecb_encrypt(&key[..5], &[0u8; 16]), Err(Error::InvalidKeyLength(5))));
}

#[test]
fn files_and_streams() {
    let dir = std::env::temp_dir().join(format!("aescry-security-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (plain, enc, dec) = (dir.join("p"), dir.join("p.aes"), dir.join("d"));
    std::fs::write(&plain, b"file data").unwrap();

    let key: &[u8] = &[0x00, 0xFF];
    RawEncryptor::new(Key::RawPassword(key)).version(Version::V2).encrypt_file(&plain, &enc).unwrap();
    let report = RawDecryptor::new(Key::RawPassword(key)).decrypt_file(&enc, &dec).unwrap();
    assert_eq!(std::fs::read(&dec).unwrap(), b"file data");
    assert_eq!(report.plaintext_len(), 9);

    let mut out = Vec::new();
    let data = std::fs::read(&enc).unwrap();
    RawDecryptor::new(Key::RawPassword(key)).decrypt_stream(&data[..], &mut out).unwrap();
    assert_eq!(out, b"file data");

    std::fs::remove_dir_all(&dir).unwrap();
}
