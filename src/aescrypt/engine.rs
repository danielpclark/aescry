//! The AES Crypt stream encryption and decryption engine, shared by the
//! password-based API and the security toolkit.

use super::format::{read_header, truncated, write_header, Extension, Header};
use crate::aes::Aes256;
use crate::cbc::{CbcDecryptor, CbcEncryptor};
use crate::detect::Version;
use crate::hmac::HmacSha256;
use crate::padding::pkcs7_unpad;
use crate::{ct, kdf, Error};
use std::io::{self, Read, Write};

/// Size of the buffer used to stream data.
const CHUNK_SIZE: usize = 64 * 1024;

/// The largest PBKDF2 iteration count accepted by default, matching the
/// AES Crypt reference implementation.
pub(crate) const MAX_ITERATIONS: u32 = 5_000_000;

/// How the key for a stream is obtained.
#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))] // key credentials are used by the security toolkit
pub(crate) enum Credential<'a> {
    /// A text password, encoded as each version expects (UTF-16LE for
    /// versions 0-2, UTF-8 for version 3).
    Text(&'a str),
    /// Password octets passed to the key derivation unchanged.
    Raw(&'a [u8]),
    /// The key derived from the password, skipping key derivation.
    DerivedKey(&'a [u8; 32]),
    /// The session IV and key, skipping the password and key block entirely.
    Session { iv: &'a [u8; 16], key: &'a [u8; 32] },
}

impl Credential<'_> {
    /// The password octets for `version`, or `None` for key credentials.
    fn password_bytes(&self, version: Version) -> Option<Vec<u8>> {
        match *self {
            Credential::Text(text) if version >= Version::V3 => Some(text.as_bytes().to_vec()),
            Credential::Text(text) => Some(kdf::utf16le(text)),
            Credential::Raw(raw) => Some(raw.to_vec()),
            _ => None,
        }
    }
}

/// Derive the 32-octet key for `version` from password octets.
pub(crate) fn derive_key(version: Version, password: &[u8], iv: &[u8; 16], iterations: u32) -> Result<[u8; 32], Error> {
    if version >= Version::V3 {
        kdf::pbkdf2_hmac_sha512_array(password, iv, iterations)
    } else {
        Ok(kdf::aescrypt_legacy(password, iv))
    }
}

/// Parameters for writing a stream.  Every random value is chosen by the
/// caller, which makes encryption deterministic for testing.
pub(crate) struct EncryptParams<'a> {
    pub(crate) version: Version,
    pub(crate) credential: Credential<'a>,
    pub(crate) iterations: u32,
    pub(crate) extensions: &'a [Extension],
    pub(crate) public_iv: [u8; 16],
    pub(crate) session_iv: [u8; 16],
    pub(crate) session_key: [u8; 32],
}

/// Encrypt everything `reader` produces, writing an AES Crypt stream.
/// Returns the number of plaintext octets.
pub(crate) fn encrypt<R: Read, W: Write>(params: &EncryptParams<'_>, reader: R, mut writer: W) -> Result<u64, Error> {
    if params.version == Version::V0 {
        // version 0 records the final block size in the header, so the
        // stream is assembled in memory
        let mut out = Vec::new();
        let (len, modulo) = encrypt_inner(params, reader, &mut out)?;
        out[4] = modulo;
        writer.write_all(&out)?;
        writer.flush()?;
        return Ok(len);
    }

    let (len, _) = encrypt_inner(params, reader, &mut writer)?;
    writer.flush()?;
    Ok(len)
}

fn encrypt_inner<R: Read, W: Write>(params: &EncryptParams<'_>, mut reader: R, writer: &mut W) -> Result<(u64, u8), Error> {
    let version = params.version;

    if version >= Version::V3 && params.iterations == 0 {
        return Err(Error::InvalidIterations(params.iterations));
    }

    let mut header = Vec::new();
    write_header(&mut header, version, 0, params.extensions, params.iterations, &params.public_iv)?;

    let derived = match params.credential {
        Credential::DerivedKey(key) => *key,
        Credential::Session { .. } => {
            return Err(Error::InvalidStream("a session key cannot be used to write a stream"))
        }
        credential => {
            let password = credential.password_bytes(version).expect("password credential");
            derive_key(version, &password, &params.public_iv, params.iterations)?
        }
    };

    // versions 1+ encrypt a session IV and key with the derived key
    let (bulk_key, bulk_iv) = if version == Version::V0 {
        (derived, params.public_iv)
    } else {
        let mut block = [0u8; 48];
        block[..16].copy_from_slice(&params.session_iv);
        block[16..].copy_from_slice(&params.session_key);

        CbcEncryptor::new(Aes256::new(&derived), &params.public_iv).encrypt_in_place(&mut block)?;

        let mut mac = HmacSha256::new(&derived);
        mac.update(&block);
        if version >= Version::V3 {
            mac.update(&[version.as_u8()]);
        }

        header.extend_from_slice(&block);
        header.extend_from_slice(&mac.finalize());

        (params.session_key, params.session_iv)
    };

    writer.write_all(&header)?;

    let mut encryptor = CbcEncryptor::new(Aes256::new(&bulk_key), &bulk_iv);
    let mut mac = HmacSha256::new(&bulk_key);
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut filled = 0;
    let mut total = 0u64;

    loop {
        let n = match reader.read(&mut buf[filled..]) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }

        filled += n;
        total += n as u64;

        let whole = filled - filled % 16;
        if filled == buf.len() {
            encryptor.encrypt_in_place(&mut buf[..whole])?;
            mac.update(&buf[..whole]);
            writer.write_all(&buf[..whole])?;
            buf.copy_within(whole..filled, 0);
            filled -= whole;
        }
    }

    // encrypt the remaining whole blocks and the final partial block
    let whole = filled - filled % 16;
    let rem = filled - whole;

    let modulo = if version >= Version::V3 {
        // PKCS#7: 1 to 16 octets of padding, always
        let pad = 16 - rem;
        buf[filled..filled + pad].fill(pad as u8);
        filled += pad;
        0
    } else if rem > 0 {
        // versions 0-2: the final block size is recorded separately; the
        // padding contents are not significant
        let pad = 16 - rem;
        buf[filled..filled + pad].fill(pad as u8);
        filled += pad;
        rem as u8
    } else {
        0
    };

    encryptor.encrypt_in_place(&mut buf[..filled])?;
    mac.update(&buf[..filled]);
    writer.write_all(&buf[..filled])?;

    if version == Version::V1 || version == Version::V2 {
        writer.write_all(&[modulo])?;
    }
    writer.write_all(&mac.finalize())?;

    Ok((total, modulo))
}

/// Options for reading a stream.
pub(crate) struct DecryptOptions {
    /// The largest PBKDF2 iteration count to accept.
    pub(crate) max_iterations: u32,
    /// Check the HMACs.  Only the security toolkit turns this off.
    pub(crate) verify: bool,
}

impl Default for DecryptOptions {
    fn default() -> Self {
        DecryptOptions { max_iterations: MAX_ITERATIONS, verify: true }
    }
}

/// What was learned while decrypting a stream.
#[cfg_attr(not(test), allow(dead_code))] // read by the security toolkit
pub(crate) struct DecryptInfo {
    pub(crate) header: Header,
    pub(crate) plaintext_len: u64,
    pub(crate) derived_key: Option<[u8; 32]>,
    pub(crate) session_iv: [u8; 16],
    pub(crate) session_key: [u8; 32],
    /// Whether the key block HMAC matched (None if it was not checked).
    pub(crate) key_hmac_ok: Option<bool>,
    /// Whether the ciphertext HMAC matched (None if it was not checked).
    pub(crate) message_hmac_ok: Option<bool>,
}

/// Decrypt an AES Crypt stream from `reader` to `writer`.
///
/// All plaintext except the final block is written before the ciphertext
/// HMAC is checked; callers must discard the output if this fails.
pub(crate) fn decrypt<R: Read, W: Write>(
    credential: Credential<'_>,
    options: &DecryptOptions,
    mut reader: R,
    mut writer: W,
) -> Result<DecryptInfo, Error> {
    let header = read_header(&mut reader, true)?;
    let version = header.version;

    if let Some(iterations) = header.iterations {
        let derives_key = !matches!(credential, Credential::DerivedKey(_) | Credential::Session { .. });
        if derives_key && (iterations == 0 || iterations > options.max_iterations) {
            return Err(Error::InvalidIterations(iterations));
        }
    }

    let derived_key = match credential {
        Credential::DerivedKey(key) => Some(*key),
        Credential::Session { .. } => None,
        credential => {
            let password = credential.password_bytes(version).expect("password credential");
            Some(derive_key(version, &password, &header.iv, header.iterations.unwrap_or(0))?)
        }
    };

    let mut key_hmac_ok = None;

    let (bulk_key, bulk_iv) = if version == Version::V0 {
        match (credential, derived_key) {
            (Credential::Session { iv, key }, _) => (*key, *iv),
            (_, Some(derived)) => (derived, header.iv),
            _ => unreachable!(),
        }
    } else {
        let mut block = [0u8; 80];
        reader.read_exact(&mut block).map_err(|e| truncated(e, "truncated key block"))?;
        let (encrypted, tag) = block.split_at_mut(48);

        match (credential, derived_key) {
            (Credential::Session { iv, key }, _) => (*key, *iv),
            (_, Some(derived)) => {
                if options.verify {
                    let mut mac = HmacSha256::new(&derived);
                    mac.update(encrypted);
                    if version >= Version::V3 {
                        mac.update(&[version.as_u8()]);
                    }

                    let ok = ct::eq(&mac.finalize(), tag);
                    key_hmac_ok = Some(ok);
                    if !ok {
                        return Err(Error::InvalidPassword);
                    }
                }

                CbcDecryptor::new(Aes256::new(&derived), &header.iv).decrypt_in_place(encrypted)?;

                let mut iv = [0u8; 16];
                let mut key = [0u8; 32];
                iv.copy_from_slice(&encrypted[..16]);
                key.copy_from_slice(&encrypted[16..]);
                encrypted.fill(0);
                (key, iv)
            }
            _ => unreachable!(),
        }
    };

    // the stream ends with the HMAC, preceded in versions 1 and 2 by the
    // final block size
    let trailer_len = match version {
        Version::V1 | Version::V2 => 33,
        _ => 32,
    };

    let mut decryptor = CbcDecryptor::new(Aes256::new(&bulk_key), &bulk_iv);
    let mut mac = HmacSha256::new(&bulk_key);
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK_SIZE + trailer_len + 32);
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut written = 0u64;

    loop {
        let n = match reader.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }

        buf.extend_from_slice(&chunk[..n]);

        // hold back the trailer and the final block
        if buf.len() > trailer_len + 16 {
            let ready = (buf.len() - trailer_len - 16) / 16 * 16;
            if ready > 0 {
                mac.update(&buf[..ready]);
                decryptor.decrypt_in_place(&mut buf[..ready])?;
                writer.write_all(&buf[..ready])?;
                written += ready as u64;
                buf.drain(..ready);
            }
        }
    }

    if buf.len() < trailer_len {
        return Err(Error::InvalidStream("truncated stream"));
    }

    let ciphertext_len = buf.len() - trailer_len;
    if ciphertext_len % 16 != 0 {
        return Err(Error::InvalidStream("ciphertext length is not a multiple of 16"));
    }

    let (last, trailer) = buf.split_at_mut(ciphertext_len);
    mac.update(last);

    let (modulo, tag) = match version {
        Version::V1 | Version::V2 => (trailer[0], &trailer[1..]),
        _ => (header.reserved, &trailer[..]),
    };

    let mut message_hmac_ok = None;
    if options.verify {
        let ok = ct::eq(&mac.finalize(), tag);
        message_hmac_ok = Some(ok);
        if !ok {
            // version 0 has only one HMAC, which also covers the password
            return Err(if version == Version::V0 { Error::InvalidPassword } else { Error::AlteredMessage });
        }
    }

    decryptor.decrypt_in_place(last)?;

    let plaintext: &[u8] = if version >= Version::V3 {
        if written + last.len() as u64 == 0 {
            return Err(Error::InvalidStream("missing final block"));
        }
        match pkcs7_unpad(last) {
            Ok(plaintext) => plaintext,
            // unverified (forensic) decryption keeps the damaged final block
            Err(_) if !options.verify => last,
            Err(_) => return Err(Error::InvalidStream("invalid padding")),
        }
    } else if last.is_empty() {
        last
    } else {
        match modulo & 0x0f {
            0 => last,
            n => &last[..n as usize],
        }
    };

    writer.write_all(plaintext)?;
    writer.flush()?;
    written += plaintext.len() as u64;

    Ok(DecryptInfo {
        header,
        plaintext_len: written,
        derived_key,
        session_iv: bulk_iv,
        session_key: bulk_key,
        key_hmac_ok,
        message_hmac_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSIONS: [Version; 4] = [Version::V0, Version::V1, Version::V2, Version::V3];

    fn params<'a>(version: Version, credential: Credential<'a>, extensions: &'a [Extension]) -> EncryptParams<'a> {
        EncryptParams {
            version,
            credential,
            iterations: 10,
            extensions,
            public_iv: [1; 16],
            session_iv: [2; 16],
            session_key: [3; 32],
        }
    }

    fn write(p: &EncryptParams<'_>, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        assert_eq!(encrypt(p, data, &mut out).unwrap(), data.len() as u64);
        out
    }

    fn read(credential: Credential<'_>, data: &[u8]) -> Result<(Vec<u8>, DecryptInfo), Error> {
        let mut out = Vec::new();
        let info = decrypt(credential, &DecryptOptions::default(), data, &mut out)?;
        Ok((out, info))
    }

    #[test]
    fn every_version_roundtrips() {
        let ext = [Extension::new("CREATED_BY", "test").unwrap()];

        for version in VERSIONS {
            let extensions: &[Extension] = if version >= Version::V2 { &ext } else { &[] };

            for len in [0usize, 1, 15, 16, 17, 100] {
                let data = vec![0xA5u8; len];
                let stream = write(&params(version, Credential::Text("pässword"), extensions), &data);

                assert_eq!(crate::detect::from_bytes(&stream), Some(version));
                if version == Version::V0 {
                    assert_eq!(stream[4] as usize, len % 16);
                }

                let (plain, info) = read(Credential::Text("pässword"), &stream).unwrap();
                assert_eq!(plain, data, "{} length {}", version, len);
                assert_eq!(info.plaintext_len, len as u64);
                assert_eq!(info.message_hmac_ok, Some(true));
                assert_eq!(info.key_hmac_ok, if version == Version::V0 { None } else { Some(true) });

                assert!(matches!(read(Credential::Text("password"), &stream), Err(Error::InvalidPassword)));
            }
        }
    }

    #[test]
    fn deterministic_with_fixed_parameters() {
        for version in VERSIONS {
            let p = params(version, Credential::Text("pw"), &[]);
            assert_eq!(write(&p, b"same"), write(&p, b"same"));
        }
    }

    #[test]
    fn raw_passwords_match_text_encoding() {
        let utf16 = kdf::utf16le("pässword");

        for version in VERSIONS {
            let raw: &[u8] = if version >= Version::V3 { "pässword".as_bytes() } else { &utf16 };
            let from_text = write(&params(version, Credential::Text("pässword"), &[]), b"data");
            let from_raw = write(&params(version, Credential::Raw(raw), &[]), b"data");
            assert_eq!(from_text, from_raw, "{}", version);

            // arbitrary octets, including invalid UTF-8 and UTF-16
            let odd = [0xFFu8, 0x00, 0xD8];
            let stream = write(&params(version, Credential::Raw(&odd), &[]), b"data");
            assert_eq!(read(Credential::Raw(&odd), &stream).unwrap().0, b"data");
        }
    }

    #[test]
    fn decrypts_with_recovered_keys() {
        for version in VERSIONS {
            let stream = write(&params(version, Credential::Text("pw"), &[]), b"secret data");
            let (_, info) = read(Credential::Text("pw"), &stream).unwrap();

            let derived = info.derived_key.unwrap();
            let (plain, _) = read(Credential::DerivedKey(&derived), &stream).unwrap();
            assert_eq!(plain, b"secret data");

            let session = Credential::Session { iv: &info.session_iv, key: &info.session_key };
            let (plain, info) = read(session, &stream).unwrap();
            assert_eq!(plain, b"secret data");
            assert_eq!(info.key_hmac_ok, None);
            assert!(info.header.extensions.is_empty());

            if version != Version::V0 {
                assert_eq!(info.session_iv, [2; 16]);
                assert_eq!(info.session_key, [3; 32]);
            }
        }
    }

    #[test]
    fn unverified_decryption_reports_failures() {
        let mut stream = write(&params(Version::V3, Credential::Text("pw"), &[]), &[7u8; 40]);
        let n = stream.len();
        stream[n - 32 - 48] ^= 1; // first ciphertext block

        assert!(matches!(read(Credential::Text("pw"), &stream), Err(Error::AlteredMessage)));

        let options = DecryptOptions { verify: false, ..DecryptOptions::default() };
        let mut out = Vec::new();
        let info = decrypt(Credential::Text("pw"), &options, &stream[..], &mut out).unwrap();
        assert_eq!(info.message_hmac_ok, None);
        assert_eq!(out.len(), 40);
        // CBC: the damaged block is garbled and the same bit flips in the next
        assert_eq!(out[16], 7 ^ 1);
        assert_eq!(&out[17..], &[7u8; 23][..]);

        // damage to the final block breaks the padding; the block is kept
        stream[n - 32 - 1] ^= 1;
        let mut out = Vec::new();
        decrypt(Credential::Text("pw"), &options, &stream[..], &mut out).unwrap();
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn key_credentials_cannot_write_session_streams() {
        let p = params(Version::V3, Credential::Session { iv: &[0; 16], key: &[0; 32] }, &[]);
        assert!(encrypt(&p, &b""[..], Vec::new()).is_err());

        let derived = derive_key(Version::V3, b"pw", &[1; 16], 10).unwrap();
        let from_key = write(&params(Version::V3, Credential::DerivedKey(&derived), &[]), b"x");
        let from_pw = write(&params(Version::V3, Credential::Raw(b"pw"), &[]), b"x");
        assert_eq!(from_key, from_pw);
    }
}
