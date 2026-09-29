mod common;

use aescry::aescrypt::{self, Decryptor, Encryptor, Extension, Iterations, Limits};
use aescry::{detect, Error, Limit, StreamError, Version};
use std::io::{self, Read};
use std::path::PathBuf;

const PASSWORD: &str = "aescry test ✓";
const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog\n";

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/aescrypt").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e))
}

fn fast(password: &str) -> Encryptor {
    Encryptor::new(password).unwrap().iterations(Iterations::new(1000).unwrap())
}

#[test]
fn decrypts_fixtures_of_every_version() {
    for (v, version) in [(0, Version::V0), (1, Version::V1), (2, Version::V2), (3, Version::V3)] {
        let fox = fixture(&format!("fox.v{}.aes", v));
        let empty = fixture(&format!("empty.v{}.aes", v));

        assert_eq!(detect::from_bytes(&fox), Some(version));
        assert_eq!(detect::from_bytes(&empty), Some(version));

        assert_eq!(aescrypt::decrypt(PASSWORD, &fox).unwrap(), FOX, "fox v{}", v);
        assert_eq!(aescrypt::decrypt(PASSWORD, &empty).unwrap(), b"", "empty v{}", v);

        assert!(matches!(aescrypt::decrypt("aescry test", &fox), Err(Error::InvalidPassword)), "v{}", v);
    }

    // the smallest streams of versions 0-2 are exactly the documented minimum
    for v in [Version::V0, Version::V1, Version::V2] {
        assert_eq!(fixture(&format!("empty.v{}.aes", v.as_u8())).len(), v.min_stream_len());
    }
}

#[test]
fn roundtrip_many_sizes() {
    let enc = fast("pw");
    let dec = Decryptor::new("pw").unwrap();

    for len in [0, 1, 15, 16, 17, 31, 32, 33, 1000, 65535, 65536, 65537, 70000] {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let encrypted = enc.encrypt(&data).unwrap();

        assert_eq!(detect::from_bytes(&encrypted), Some(Version::V3));
        // header + key block + HMACs + PKCS#7 padded ciphertext
        let header = aescrypt::read_header(&encrypted[..]).unwrap();
        assert_eq!(encrypted.len(), header.len() + 48 + 32 + (len / 16 + 1) * 16 + 32);

        assert_eq!(dec.decrypt(&encrypted).unwrap(), data, "length {}", len);
    }
}

#[test]
fn every_encryption_is_different() {
    let a = fast("pw").encrypt(b"same").unwrap();
    let b = fast("pw").encrypt(b"same").unwrap();
    assert_ne!(a, b);
}

#[test]
fn header_contents() {
    let encrypted = fast("pw")
        .extension(Extension::new("urn:example:note", "hello").unwrap())
        .encrypt(b"x")
        .unwrap();

    let header = aescrypt::read_header(&encrypted[..]).unwrap();
    assert_eq!(header.version(), Version::V3);
    assert_eq!(header.iterations(), Some(1000));
    assert_eq!(header.reserved(), 0);
    let created_by = format!("aescry {}", env!("CARGO_PKG_VERSION"));
    assert_eq!(header.extension("CREATED_BY"), Some(created_by.as_bytes()));
    assert_eq!(header.extension("urn:example:note"), Some(&b"hello"[..]));

    let exts = header.extensions();
    assert_eq!(exts.len(), 3);
    assert!(exts[2].is_container());
    assert_eq!(exts[2].as_bytes().len(), 128);

    let bare = fast("pw").without_default_extensions().encrypt(b"x").unwrap();
    assert!(aescrypt::read_header(&bare[..]).unwrap().extensions().is_empty());
    assert_eq!(bare.len(), 155 + 16 - 16); // minimum stream: one padded block
}

#[test]
fn rejects_bad_parameters() {
    assert!(matches!(Encryptor::new(""), Err(Error::EmptyPassword)));
    assert!(matches!(Decryptor::new(""), Err(Error::EmptyPassword)));
    assert!(matches!(aescrypt::encrypt("", b"x"), Err(Error::EmptyPassword)));

    // iteration counts are checked when the value is created
    assert!(matches!(Iterations::new(0), Err(Error::InvalidIterations(0))));
    assert!(matches!(Iterations::new(5_000_001), Err(Error::InvalidIterations(5_000_001))));
    assert!(Iterations::try_from(5_000_000u32).is_ok());
}

#[test]
fn refuses_excessive_iterations_in_a_stream() {
    let mut encrypted = fast("pw").without_default_extensions().encrypt(b"x").unwrap();
    // iterations follow "AES", version, reserved and the empty extension list
    encrypted[7..11].copy_from_slice(&5_000_001u32.to_be_bytes());
    assert!(matches!(
        aescrypt::decrypt("pw", &encrypted),
        Err(Error::LimitExceeded(Limit::Iterations { found: 5_000_001, max: 5_000_000 }))
    ));

    encrypted[7..11].copy_from_slice(&0u32.to_be_bytes());
    assert!(matches!(aescrypt::decrypt("pw", &encrypted), Err(Error::InvalidStream(StreamError::ZeroIterations))));

    let encrypted = fast("pw").encrypt(b"x").unwrap();
    let strict = Decryptor::new("pw").unwrap().limits(Limits::DEFAULT.max_iterations(999));
    assert!(matches!(
        strict.decrypt(&encrypted),
        Err(Error::LimitExceeded(Limit::Iterations { found: 1000, max: 999 }))
    ));

    // the normal API cannot raise limits above the defaults
    encrypted_with(5_000_001);
    fn encrypted_with(n: u32) {
        let lenient = Decryptor::new("pw").unwrap().limits(Limits::DEFAULT.max_iterations(u32::MAX));
        let mut stream = fast("pw").without_default_extensions().encrypt(b"x").unwrap();
        stream[7..11].copy_from_slice(&n.to_be_bytes());
        assert!(matches!(lenient.decrypt(&stream), Err(Error::LimitExceeded(Limit::Iterations { .. }))));
    }
}

#[test]
fn detects_tampering_everywhere() {
    let encrypted = fast("pw").without_default_extensions().encrypt(&[0x42; 40]).unwrap();
    let header_len = aescrypt::read_header(&encrypted[..]).unwrap().len();
    let key_block = header_len..header_len + 80;

    for i in 0..encrypted.len() {
        let mut altered = encrypted.clone();
        altered[i] ^= 0x01;

        let result = aescrypt::decrypt("pw", &altered);

        if i == 4 {
            // the reserved octet is not covered by either HMAC, and AES Crypt
            // ignores it when reading
            assert!(result.is_ok());
            continue;
        }

        assert!(result.is_err(), "flipping octet {} was not detected", i);

        if i >= 11 && i < header_len {
            // the public IV feeds key derivation, so the key HMAC fails
            assert!(matches!(result, Err(Error::InvalidPassword)), "octet {}: {:?}", i, result);
        } else if key_block.contains(&i) {
            assert!(matches!(result, Err(Error::InvalidPassword)), "octet {}: {:?}", i, result);
        } else if i >= key_block.end {
            assert!(matches!(result, Err(Error::AlteredMessage)), "octet {}: {:?}", i, result);
        }
    }

    for len in 0..encrypted.len() {
        assert!(aescrypt::decrypt("pw", &encrypted[..len]).is_err(), "truncated to {}", len);
    }

    let mut extended = encrypted.clone();
    extended.push(0);
    assert!(aescrypt::decrypt("pw", &extended).is_err());
}

#[test]
fn extensions_are_not_authenticated() {
    // documented behavior: extensions can change without failing decryption
    let mut encrypted = fast("pw").encrypt(b"data").unwrap();
    let pos = encrypted.windows(6).position(|w| w == b"aescry").unwrap();
    encrypted[pos] = b'X';
    assert_eq!(aescrypt::decrypt("pw", &encrypted).unwrap(), b"data");
}

#[test]
fn not_aes_crypt() {
    assert!(matches!(aescrypt::decrypt("pw", b"hello world"), Err(Error::NotAesCrypt)));
    assert!(matches!(aescrypt::decrypt("pw", b"AES\x04\x00"), Err(Error::UnsupportedVersion(4))));
    assert!(matches!(aescrypt::decrypt("pw", b"AES"), Err(Error::InvalidStream(_))));
    assert!(matches!(aescrypt::decrypt("pw", b""), Err(Error::InvalidStream(_))));
}

/// A reader that returns at most `n` octets per read.
struct Trickle<'a> {
    data: &'a [u8],
    n: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.n.min(buf.len()).min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

#[test]
fn streams_with_small_reads() {
    let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();

    for n in [1, 7, 16, 33, 4096] {
        let mut encrypted = Vec::new();
        let read = fast("pw").encrypt_stream(Trickle { data: &data, n }, &mut encrypted).unwrap();
        assert_eq!(read, data.len() as u64);

        let mut decrypted = Vec::new();
        let written = Decryptor::new("pw")
            .unwrap()
            .decrypt_stream(Trickle { data: &encrypted, n }, &mut decrypted)
            .unwrap();

        assert_eq!(written, data.len() as u64);
        assert_eq!(decrypted, data, "read size {}", n);
    }
}

#[test]
fn files() {
    let dir = std::env::temp_dir().join(format!("aescry-files-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let plain = dir.join("plain.bin");
    let encrypted = dir.join("plain.bin.aes");
    let decrypted = dir.join("decrypted.bin");
    std::fs::write(&plain, FOX).unwrap();

    assert_eq!(fast("pw").encrypt_file(&plain, &encrypted).unwrap(), FOX.len() as u64);
    assert_eq!(detect::get_file(&encrypted).unwrap().version(), Version::V3);

    let dec = Decryptor::new("pw").unwrap();
    assert_eq!(dec.decrypt_file(&encrypted, &decrypted).unwrap(), FOX.len() as u64);
    assert_eq!(std::fs::read(&decrypted).unwrap(), FOX);

    // a failed decryption leaves no output behind
    let missing = dir.join("never-created.bin");
    let wrong = Decryptor::new("wrong").unwrap();
    assert!(matches!(wrong.decrypt_file(&encrypted, &missing), Err(Error::InvalidPassword)));
    assert!(!missing.exists());

    // ...and does not replace an existing file
    std::fs::write(&decrypted, b"keep me").unwrap();
    assert!(wrong.decrypt_file(&encrypted, &decrypted).is_err());
    assert_eq!(std::fs::read(&decrypted).unwrap(), b"keep me");

    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("aescry-tmp"))
        .collect();
    assert!(leftovers.is_empty());

    assert!(matches!(dec.decrypt_file(dir.join("nope.aes"), &decrypted), Err(Error::Io(_))));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn require_constant_time() {
    let ct = aescry::aes::Backend::constant_time();
    let enc = fast("pw").require_constant_time().encrypt(b"x");
    let dec = Decryptor::new("pw").unwrap().require_constant_time();

    match ct {
        Ok(backend) => {
            assert!(backend.is_constant_time());
            assert_eq!(dec.decrypt(&enc.unwrap()).unwrap(), b"x");
        }
        Err(_) => {
            assert!(matches!(enc, Err(Error::BackendUnavailable)));
            let stream = fast("pw").encrypt(b"x").unwrap();
            assert!(matches!(dec.decrypt(&stream), Err(Error::BackendUnavailable)));
        }
    }
}
