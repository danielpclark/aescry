mod common;

use aescry::aes::{AesKey, KeySize};
use aescry::aescrypt;
use aescry::security::{
    ecb_decrypt, ecb_encrypt, inspect, inspect_with_limits, verify, DecryptKey, DerivedKey, EncryptKey, Extension,
    Iterations, Limits, Password, PublicIv, RawDecryptor, RawEncryptor, SessionIv, SessionKey,
};
use aescry::{Error, ExtensionError, Limit, StreamError, Version};
use common::{hex, load_vectors, unhex};

const VERSIONS: [Version; 4] = [Version::V0, Version::V1, Version::V2, Version::V3];

fn version(byte: u8) -> Version {
    Version::from_u8(byte).unwrap()
}

fn iterations(n: u32) -> Iterations {
    Iterations::new(n).unwrap()
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
        let count = u32::from_be_bytes(v["iterations"].as_slice().try_into().unwrap());

        let mut encryptor = RawEncryptor::new(EncryptKey::raw_password(v["password"].clone()))
            .version(version)
            .iterations(iterations(count));
        if !v["extension"].is_empty() {
            encryptor = encryptor.extension(Extension::from_bytes(v["extension"].clone()).unwrap());
        }
        let encryptor = encryptor.deterministic(
            PublicIv::try_from(&v["public_iv"][..]).unwrap(),
            SessionIv::try_from(&v["session_iv"][..]).unwrap(),
            SessionKey::try_from(&v["session_key"][..]).unwrap(),
        );

        let stream = encryptor.encrypt(&v["plaintext"]).unwrap();
        assert_eq!(hex(&stream), hex(&v["stream"]), "vector {} ({})", i, version);

        // the normal API opens it with the text password
        assert_eq!(aescrypt::decrypt("kat password ✓", &v["stream"]).unwrap(), v["plaintext"]);

        let opened = RawDecryptor::new(DecryptKey::raw_password(v["password"].clone())).decrypt(&v["stream"]).unwrap();
        assert_eq!(opened.plaintext(), &v["plaintext"][..]);
        assert!(opened.report().verification().is_authentic());

        if version != Version::V0 {
            assert_eq!(opened.report().session_iv().as_bytes()[..], v["session_iv"][..]);
            assert_eq!(opened.report().session_key().expose_secret()[..], v["session_key"][..]);
        }
    }
}

fn fixed(key: EncryptKey, v: Version) -> Vec<u8> {
    RawEncryptor::new(key)
        .version(v)
        .iterations(iterations(100))
        .deterministic(PublicIv::from([1; 16]), SessionIv::from([2; 16]), SessionKey::from([3; 32]))
        .encrypt(b"data")
        .unwrap()
}

#[test]
fn text_and_raw_passwords_agree() {
    for v in VERSIONS {
        let text = Password::new("pässwörd 😀").unwrap();
        let raw = text.encoded(v).expose_secret().clone();

        assert_eq!(fixed(EncryptKey::password("pässwörd 😀").unwrap(), v), fixed(EncryptKey::raw_password(raw), v), "{}", v);
    }
}

#[test]
fn deterministic_output_is_reproducible_and_random_is_not() {
    for v in VERSIONS {
        assert_eq!(fixed(EncryptKey::raw_password(b"k".to_vec()), v), fixed(EncryptKey::raw_password(b"k".to_vec()), v));

        let random = RawEncryptor::new(EncryptKey::raw_password(b"k".to_vec())).version(v).iterations(iterations(10));
        assert_ne!(random.encrypt(b"x").unwrap(), random.encrypt(b"x").unwrap());
    }
}

#[test]
fn arbitrary_password_octets() {
    let passwords: [&[u8]; 5] = [&[], &[0xFF, 0xFE], &[0x00], &[0xC3, 0x28, 0xA0, 0xA1], &[0xD8, 0x00]];

    for v in VERSIONS {
        for password in passwords {
            let stream = RawEncryptor::new(EncryptKey::raw_password(password))
                .version(v)
                .iterations(iterations(10))
                .encrypt(b"raw")
                .unwrap();

            let opened = RawDecryptor::new(DecryptKey::raw_password(password)).decrypt(&stream).unwrap();
            assert_eq!(opened.plaintext(), b"raw");

            let wrong = RawDecryptor::new(DecryptKey::raw_password(vec![0x01])).decrypt(&stream);
            assert!(matches!(wrong, Err(Error::InvalidPassword)));
        }
    }
}

#[test]
fn recovered_keys_open_the_stream() {
    for v in VERSIONS {
        let stream = RawEncryptor::new(EncryptKey::password("pw").unwrap())
            .version(v)
            .iterations(iterations(50))
            .encrypt(b"forensics")
            .unwrap();
        let opened = RawDecryptor::new(DecryptKey::password("pw").unwrap()).decrypt(&stream).unwrap();
        let report = opened.report();

        // the derived key can be recomputed and used directly
        let derived = report.derived_key().unwrap();
        let iv = PublicIv::from(*report.header().iv());
        let recomputed = DerivedKey::derive(v, &Password::new("pw").unwrap(), &iv, iterations(50)).unwrap();
        assert_eq!(derived, &recomputed);

        let by_derived = RawDecryptor::new(DecryptKey::Derived(derived.clone_secret())).decrypt(&stream).unwrap();
        assert_eq!(by_derived.plaintext(), b"forensics");

        let session = DecryptKey::Session(*report.session_iv(), report.session_key().clone_secret());
        let by_session = RawDecryptor::new(session).decrypt(&stream).unwrap();
        assert_eq!(by_session.plaintext(), b"forensics");
        assert!(by_session.report().derived_key().is_none());
        assert_eq!(by_session.report().verification().key_block, None);

        // raw bytes work too, once validated
        let raw = DecryptKey::session(report.session_iv().as_bytes(), report.session_key().expose_secret()).unwrap();
        assert_eq!(RawDecryptor::new(raw).decrypt(&stream).unwrap().plaintext(), b"forensics");

        if v == Version::V0 {
            // version 0 has no session key: it is the derived key and public IV
            assert_eq!(report.session_key().expose_secret(), derived.expose_secret());
            assert_eq!(report.session_iv().as_bytes(), iv.as_bytes());
        }
    }
}

#[test]
fn limits_can_only_be_raised_here() {
    let key = [9u8; 32];
    let huge = Iterations::new_unbounded(u32::MAX).unwrap();
    let stream = RawEncryptor::new(EncryptKey::derived(&key).unwrap()).iterations(huge).encrypt(b"x").unwrap();

    assert_eq!(inspect(&stream).unwrap().header.iterations(), Some(u32::MAX));

    let limit = Err::<(), _>(Limit::Iterations { found: u32::MAX, max: 5_000_000 });
    assert_eq!(aescrypt::decrypt("pw", &stream).map(|_| ()).map_err(|e| match e {
        Error::LimitExceeded(l) => l,
        other => panic!("{:?}", other),
    }), limit);
    assert!(matches!(
        RawDecryptor::new(DecryptKey::password("pw").unwrap()).decrypt(&stream),
        Err(Error::LimitExceeded(Limit::Iterations { .. }))
    ));

    // a derived key needs no key derivation, so the count doesn't matter
    let opened = RawDecryptor::new(DecryptKey::derived(&key).unwrap()).decrypt(&stream).unwrap();
    assert_eq!(opened.plaintext(), b"x");

    // raising the limit is explicit (not run: it would take hours)
    let _lenient = RawDecryptor::new(DecryptKey::password("pw").unwrap()).limits(Limits::DEFAULT.max_iterations(u32::MAX));
}

#[test]
fn unverified_results_are_wrapped() {
    let stream = RawEncryptor::new(EncryptKey::password("pw").unwrap())
        .iterations(iterations(10))
        .encrypt(&[0x42; 64])
        .unwrap();
    let layout = inspect(&stream).unwrap();

    let good = verify(&DecryptKey::password("pw").unwrap(), &stream).unwrap();
    assert_eq!(good.key_block, Some(true));
    assert!(good.message && good.is_authentic());

    let wrong = verify(&DecryptKey::password("wrong").unwrap(), &stream).unwrap();
    assert_eq!(wrong.key_block, Some(false));
    assert!(!wrong.is_authentic());

    // modify the first ciphertext block
    let mut tampered = stream.clone();
    tampered[layout.ciphertext.start] ^= 0x80;

    let checked = verify(&DecryptKey::password("pw").unwrap(), &tampered).unwrap();
    assert_eq!(checked.key_block, Some(true));
    assert!(!checked.message);

    let verified = RawDecryptor::new(DecryptKey::password("pw").unwrap());
    assert!(matches!(verified.decrypt(&tampered), Err(Error::AlteredMessage)));

    let unverified = verified.skip_verification();
    let forensic = unverified.decrypt(&tampered).unwrap();
    assert!(!forensic.is_authentic());
    assert!(!forensic.verification().message);
    assert_eq!(forensic.peek_unauthenticated().plaintext().len(), 64);

    // the checked accessor refuses; taking it anyway must be explicit
    let forensic_again = unverified.decrypt(&tampered).unwrap();
    assert!(matches!(forensic_again.into_authentic(), Err(Error::AuthenticationFailed)));
    let data = forensic.assume_authentic();
    assert_eq!(&data.plaintext()[32..], &[0x42; 32][..]); // later blocks are intact

    // an authentic stream passes the checked accessor
    let fine = unverified.decrypt(&stream).unwrap().into_authentic().unwrap();
    assert_eq!(fine.plaintext(), &[0x42; 64][..]);
}

#[test]
fn inspect_layout() {
    for v in VERSIONS {
        for len in [0usize, 5, 16, 20] {
            let mut enc = RawEncryptor::new(EncryptKey::password("pw").unwrap()).version(v).iterations(iterations(10));
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

    let stream = RawEncryptor::new(EncryptKey::password("pw").unwrap()).iterations(iterations(10)).encrypt(b"x").unwrap();
    assert!(matches!(inspect(&stream[..stream.len() - 1]), Err(Error::InvalidStream(StreamError::UnalignedCiphertext))));
    assert!(matches!(inspect(&stream[..40]), Err(Error::InvalidStream(_))));
    assert!(matches!(inspect(b"nope"), Err(Error::InvalidStream(StreamError::TruncatedHeader))));
    assert!(matches!(inspect(b"nope, not this"), Err(Error::NotAesCrypt)));
    assert!(matches!(
        inspect_with_limits(&stream, Limits::DEFAULT.max_header_len(10)),
        Err(Error::LimitExceeded(Limit::HeaderLength { max: 10 }))
    ));
}

#[test]
fn malformed_extensions_for_parser_testing() {
    // no NUL terminator, and an empty-identifier container
    let stream = RawEncryptor::new(EncryptKey::password("pw").unwrap())
        .iterations(iterations(10))
        .extension(Extension::from_bytes(b"NO_TERMINATOR".to_vec()).unwrap())
        .extension(Extension::container(8).unwrap())
        .encrypt(b"ok")
        .unwrap();

    let header = aescrypt::read_header(&stream[..]).unwrap();
    assert_eq!(header.extensions()[0].identifier(), b"NO_TERMINATOR");
    assert!(header.extensions()[1].is_container());
    assert_eq!(aescrypt::decrypt("pw", &stream).unwrap(), b"ok");

    assert!(matches!(Extension::from_bytes(Vec::new()), Err(Error::InvalidExtension(ExtensionError::InvalidLength))));
    assert!(Extension::from_bytes(vec![0u8; 65536]).is_err());

    let v1 = RawEncryptor::new(EncryptKey::password("pw").unwrap())
        .version(Version::V1)
        .extension(Extension::container(8).unwrap())
        .encrypt(b"x");
    assert!(matches!(v1, Err(Error::InvalidExtension(ExtensionError::UnsupportedVersion))));
}

#[test]
fn raw_bytes_are_validated_at_the_edge() {
    assert!(matches!(PublicIv::try_from(&[0u8; 15][..]), Err(Error::InvalidIvLength(15))));
    assert!(matches!(SessionIv::try_from(&[0u8; 17][..]), Err(Error::InvalidIvLength(17))));
    assert!(matches!(SessionKey::try_from(&[0u8; 16][..]), Err(Error::InvalidKeyLength(16))));
    assert!(matches!(EncryptKey::derived(&[0; 31]), Err(Error::InvalidKeyLength(31))));
    assert!(matches!(DecryptKey::session(&[0; 8], &[0; 32]), Err(Error::InvalidIvLength(8))));
    assert!(matches!(DecryptKey::session(&[0; 16], &[0; 8]), Err(Error::InvalidKeyLength(8))));
    assert!(matches!(DecryptKey::password(""), Err(Error::EmptyPassword)));
    assert!(matches!(Iterations::new(0), Err(Error::InvalidIterations(0))));
    assert!(matches!(Iterations::new_unbounded(0), Err(Error::InvalidIterations(0))));

    // secrets never appear in Debug output
    let key = EncryptKey::password("hunter2").unwrap();
    let debug = format!("{:?}", RawEncryptor::new(key).deterministic(
        PublicIv::from([0; 16]),
        SessionIv::from([0; 16]),
        SessionKey::from([0xAB; 32]),
    ));
    assert!(!debug.contains("hunter2") && !debug.contains("171") && !debug.contains("ab, ab"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn ecb_primitive() {
    // first NESSIE AES-128 vector (tests/data/rustcrypto/aes128.txt)
    let key = AesKey::try_from(&unhex("80000000000000000000000000000000")[..]).unwrap();
    let ct = ecb_encrypt(&key, &[0u8; 32]).unwrap();
    assert_eq!(hex(&ct[..16]), "0edd33d3c621e546455bd8ba1418bec8");
    assert_eq!(ct[..16], ct[16..]); // equal blocks, equal ciphertext
    assert_eq!(ecb_decrypt(&key, &ct).unwrap(), vec![0u8; 32]);
    assert!(matches!(ecb_encrypt(&key, &[0u8; 10]), Err(Error::InvalidCiphertextLength(10))));
    assert!(matches!(AesKey::try_from(&[0u8; 5][..]), Err(Error::InvalidKeyLength(5))));
    assert_eq!(AesKey::generate(KeySize::Aes192).unwrap().size(), KeySize::Aes192);
}

#[test]
fn files_and_streams() {
    let dir = std::env::temp_dir().join(format!("aescry-security-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (plain, enc, dec, damaged_out) = (dir.join("p"), dir.join("p.aes"), dir.join("d"), dir.join("damaged"));
    std::fs::write(&plain, b"file data").unwrap();

    let key: &[u8] = &[0x00, 0xFF];
    RawEncryptor::new(EncryptKey::raw_password(key)).version(Version::V2).encrypt_file(&plain, &enc).unwrap();
    let report = RawDecryptor::new(DecryptKey::raw_password(key)).decrypt_file(&enc, &dec).unwrap();
    assert_eq!(std::fs::read(&dec).unwrap(), b"file data");
    assert_eq!(report.plaintext_len(), 9);

    let mut out = Vec::new();
    let data = std::fs::read(&enc).unwrap();
    let _ = RawDecryptor::new(DecryptKey::raw_password(key)).decrypt_stream(&data[..], &mut out).unwrap();
    assert_eq!(out, b"file data");

    // damaged file: the verified decryptor writes nothing, the unverified one
    // recovers what it can and says so
    let mut damaged = data.clone();
    let n = damaged.len();
    damaged[n - 1] ^= 1; // message HMAC
    std::fs::write(&enc, &damaged).unwrap();
    assert!(RawDecryptor::new(DecryptKey::raw_password(key)).decrypt_file(&enc, &damaged_out).is_err());
    assert!(!damaged_out.exists());

    let recovered = RawDecryptor::new(DecryptKey::raw_password(key))
        .skip_verification()
        .decrypt_file(&enc, &damaged_out)
        .unwrap();
    assert!(!recovered.is_authentic());
    assert_eq!(std::fs::read(&damaged_out).unwrap(), b"file data");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// A small deterministic generator for the hostile-input test.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Random and mutated streams never panic any parser or decryptor: they
/// either decrypt or return an error.
#[test]
fn hostile_input_never_panics() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);

    let seeds: Vec<Vec<u8>> = VERSIONS
        .iter()
        .map(|&v| {
            let mut enc = RawEncryptor::new(EncryptKey::password("pw").unwrap()).version(v).iterations(iterations(1));
            if v >= Version::V2 {
                enc = enc.extension(Extension::container(4).unwrap());
            }
            enc.encrypt(b"seed plaintext").unwrap()
        })
        .collect();

    let keys = [
        DecryptKey::password("pw").unwrap(),
        DecryptKey::raw_password(Vec::new()),
        DecryptKey::derived(&[5; 32]).unwrap(),
        DecryptKey::session(&[6; 16], &[7; 32]).unwrap(),
    ];
    let small = Limits::DEFAULT.max_iterations(16);

    // debug builds also check arithmetic overflow, but run much slower
    let rounds = if cfg!(debug_assertions) { 500 } else { 3000 };

    for round in 0..rounds {
        let mut data = if round % 4 == 0 {
            // pure noise, sometimes with a valid magic and version
            let len = rng.below(200);
            let mut d: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if len >= 4 && rng.below(2) == 0 {
                d[..3].copy_from_slice(b"AES");
                d[3] = rng.below(5) as u8;
            }
            d
        } else {
            seeds[rng.below(seeds.len())].clone()
        };

        // mutate: flip bits, truncate, extend, or overwrite length fields
        for _ in 0..rng.below(4) {
            if data.is_empty() {
                break;
            }
            match rng.below(4) {
                0 => {
                    let i = rng.below(data.len());
                    data[i] ^= 1 << rng.below(8);
                }
                1 => data.truncate(rng.below(data.len())),
                2 => data.extend((0..rng.below(40)).map(|_| rng.next() as u8)),
                _ => {
                    let i = rng.below(data.len());
                    data[i] = [0x00, 0xFF, 0x7F, 0x80][rng.below(4)];
                }
            }
        }

        let _ = inspect(&data);
        let _ = aescrypt::read_header(&data[..]);
        let _ = aescry::detect::from_bytes(&data);
        let _ = aescry::padding::pkcs7_unpad(&data);

        let key = &keys[rng.below(keys.len())];
        let _ = verify(key, &data);

        let checked = match key {
            DecryptKey::Password(p) => DecryptKey::Password(p.clone_secret()),
            DecryptKey::Derived(k) => DecryptKey::Derived(k.clone_secret()),
            DecryptKey::Session(iv, k) => DecryptKey::Session(*iv, k.clone_secret()),
        };
        let decryptor = RawDecryptor::new(checked).limits(small);
        let _ = decryptor.decrypt(&data);
        let _ = decryptor.skip_verification().decrypt(&data);
    }
}
