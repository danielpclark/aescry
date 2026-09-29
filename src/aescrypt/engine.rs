//! The AES Crypt stream encryption and decryption engine, shared by the
//! password-based API and the security toolkit.
//!
//! Every input arrives as a validated type (see `types.rs`), so the engine
//! has no length checks to get wrong and no unreachable states.

use super::format::{read_header, truncated, write_header, Extension, Header};
use super::types::{DerivedKey, Iterations, Limits, Password, PublicIv, SessionIv, SessionKey};
use crate::aes::Aes256;
use crate::cbc::{CbcDecryptor, CbcEncryptor};
use crate::detect::Version;
use crate::hmac::HmacSha256;
use crate::padding::pkcs7_unpad;
use crate::zeroize::Zeroizing;
use crate::{ct, Error, Limit, StreamError};
use std::io::{self, Read, Write};

/// Size of the buffer used to stream data.
const CHUNK_SIZE: usize = 64 * 1024;

/// What can create a stream.
#[derive(Clone, Copy)]
pub(crate) enum EncryptKey<'a> {
    /// Derive the key from a password.
    Password(&'a Password),
    /// Use an already derived key.
    Derived(&'a DerivedKey),
}

/// What can open a stream.
#[derive(Clone, Copy)]
pub(crate) enum DecryptKey<'a> {
    /// Derive the key from a password.
    Password(&'a Password),
    /// Use an already derived key, skipping key derivation.
    Derived(&'a DerivedKey),
    /// Use the session IV and key, skipping the password and key block.
    Session(&'a SessionIv, &'a SessionKey),
}

/// Parameters for writing a stream.  Every random value is chosen by the
/// caller, which makes encryption deterministic for testing.
pub(crate) struct EncryptParams<'a> {
    pub(crate) version: Version,
    pub(crate) key: EncryptKey<'a>,
    pub(crate) iterations: Iterations,
    pub(crate) extensions: &'a [Extension],
    pub(crate) public_iv: PublicIv,
    pub(crate) session_iv: SessionIv,
    pub(crate) session_key: &'a SessionKey,
}

/// Encrypt everything `reader` produces, writing an AES Crypt stream.
/// Returns the number of plaintext octets.
pub(crate) fn encrypt<R: Read, W: Write>(params: &EncryptParams<'_>, reader: R, mut writer: W) -> Result<u64, Error> {
    if params.version == Version::V0 {
        // version 0 records the final block size in the header, so the
        // stream is assembled in memory
        let mut out = Vec::new();
        let (len, modulo) = encrypt_inner(params, reader, &mut out)?;
        if let Some(reserved) = out.get_mut(4) {
            *reserved = modulo;
        }
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

    let mut header = Vec::new();
    write_header(&mut header, version, 0, params.extensions, params.iterations.get(), params.public_iv.as_bytes())?;

    let derived = match params.key {
        EncryptKey::Derived(key) => key.clone_secret(),
        EncryptKey::Password(password) => DerivedKey::derive(version, password, &params.public_iv, params.iterations)?,
    };

    // versions 1+ encrypt a session IV and key with the derived key
    let (bulk_key, bulk_iv) = if version == Version::V0 {
        (Zeroizing::new(*derived.expose_secret()), *params.public_iv.as_bytes())
    } else {
        let mut block = Zeroizing::new([0u8; 48]);
        block[..16].copy_from_slice(params.session_iv.as_bytes());
        block[16..].copy_from_slice(params.session_key.expose_secret());

        CbcEncryptor::new(Aes256::new(derived.expose_secret()), params.public_iv.as_bytes())
            .encrypt_in_place(&mut *block)?;

        let mut mac = HmacSha256::new(derived.expose_secret());
        mac.update(&*block);
        if version >= Version::V3 {
            mac.update(&[version.as_u8()]);
        }

        header.extend_from_slice(&*block);
        header.extend_from_slice(&mac.finalize());

        (Zeroizing::new(*params.session_key.expose_secret()), *params.session_iv.as_bytes())
    };

    writer.write_all(&header)?;

    let mut encryptor = CbcEncryptor::new(Aes256::new(&bulk_key), &bulk_iv);
    let mut mac = HmacSha256::new(&*bulk_key);
    // a multiple of 16, so the final padded block always fits
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
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

        if filled == buf.len() {
            encryptor.encrypt_in_place(&mut buf[..])?;
            mac.update(&buf[..]);
            writer.write_all(&buf[..])?;
            filled = 0;
        }
    }

    // encrypt the remaining whole blocks and the final partial block;
    // filled < CHUNK_SIZE here, and rounding it up to a block stays within it
    let rem = filled % 16;

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
#[derive(Default)]
pub(crate) struct DecryptOptions {
    pub(crate) limits: Limits,
    /// Fail if an HMAC does not match.  Only the security toolkit turns
    /// this off; the HMACs are still computed and reported.
    pub(crate) verify: bool,
}

impl DecryptOptions {
    pub(crate) fn verified(limits: Limits) -> Self {
        DecryptOptions { limits, verify: true }
    }
}

/// What was learned while decrypting a stream.
pub(crate) struct DecryptInfo {
    pub(crate) header: Header,
    pub(crate) plaintext_len: u64,
    pub(crate) derived_key: Option<DerivedKey>,
    pub(crate) session_iv: SessionIv,
    pub(crate) session_key: SessionKey,
    /// Whether the key block HMAC matched (None if there is no key block or
    /// it was bypassed with a session key).
    pub(crate) key_hmac_ok: Option<bool>,
    /// Whether the ciphertext HMAC matched.
    pub(crate) message_hmac_ok: bool,
}

/// Decrypt an AES Crypt stream from `reader` to `writer`.
///
/// All plaintext except the final block is written before the ciphertext
/// HMAC is checked; callers must discard the output if this fails.
pub(crate) fn decrypt<R: Read, W: Write>(
    key: DecryptKey<'_>,
    options: &DecryptOptions,
    mut reader: R,
    mut writer: W,
) -> Result<DecryptInfo, Error> {
    let header = read_header(&mut reader, true, &options.limits)?;
    let version = header.version;

    let mut key_hmac_ok = None;

    let (derived_key, bulk_key, bulk_iv) = match key {
        DecryptKey::Session(iv, key) => {
            if version != Version::V0 {
                // skip the key block without checking it
                let mut block = [0u8; 80];
                reader.read_exact(&mut block).map_err(|e| truncated(e, StreamError::TruncatedKeyBlock))?;
            }
            (None, key.clone_secret(), *iv)
        }
        DecryptKey::Derived(derived) => {
            let (key, iv) = open_key_block(&header, derived, options.verify, &mut key_hmac_ok, &mut reader)?;
            (Some(derived.clone_secret()), key, iv)
        }
        DecryptKey::Password(password) => {
            // only key derivation depends on the iteration count
            let iterations = match header.iterations {
                None => Iterations::DEFAULT, // versions 0-2 ignore it
                Some(0) => return Err(Error::InvalidStream(StreamError::ZeroIterations)),
                Some(n) if n > options.limits.max_iterations => {
                    return Err(Error::LimitExceeded(Limit::Iterations {
                        found: n,
                        max: options.limits.max_iterations,
                    }))
                }
                Some(n) => Iterations::new_unbounded(n)?,
            };
            let derived = DerivedKey::derive(version, password, &PublicIv::from(header.iv), iterations)?;
            let (key, iv) = open_key_block(&header, &derived, options.verify, &mut key_hmac_ok, &mut reader)?;
            (Some(derived), key, iv)
        }
    };

    // the stream ends with the HMAC, preceded in versions 1 and 2 by the
    // final block size
    let trailer_len = match version {
        Version::V1 | Version::V2 => 33,
        _ => 32,
    };

    let mut decryptor = CbcDecryptor::new(Aes256::new(bulk_key.expose_secret()), bulk_iv.as_bytes());
    let mut mac = HmacSha256::new(bulk_key.expose_secret());
    // sized so it never reallocates (which would leave unwiped copies)
    let mut buf = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + trailer_len + 32));
    let mut chunk = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
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

    let ciphertext_len = buf.len().checked_sub(trailer_len).ok_or(Error::InvalidStream(StreamError::Truncated))?;
    if ciphertext_len % 16 != 0 {
        return Err(Error::InvalidStream(StreamError::UnalignedCiphertext));
    }

    let (last, trailer) = buf.split_at_mut(ciphertext_len);
    mac.update(last);

    let (modulo, tag) = match version {
        Version::V1 | Version::V2 => match trailer.split_first() {
            Some((modulo, tag)) => (*modulo, tag),
            None => return Err(Error::InvalidStream(StreamError::Truncated)),
        },
        _ => (header.reserved, &trailer[..]),
    };

    let message_hmac_ok = ct::eq(&mac.finalize(), tag);
    if !message_hmac_ok && options.verify {
        // version 0 has only one HMAC, which also covers the password
        return Err(if version == Version::V0 { Error::InvalidPassword } else { Error::AlteredMessage });
    }

    decryptor.decrypt_in_place(last)?;

    let plaintext: &[u8] = if version >= Version::V3 {
        if written == 0 && last.is_empty() {
            return Err(Error::InvalidStream(StreamError::MissingFinalBlock));
        }
        match pkcs7_unpad(last) {
            Ok(plaintext) => plaintext,
            // unverified (forensic) decryption keeps the damaged final block
            Err(_) if !options.verify => last,
            Err(_) => return Err(Error::InvalidStream(StreamError::InvalidPadding)),
        }
    } else {
        // versions 0-2: the low 4 bits give the final block's length, 0
        // meaning a full block; `last` is empty or one 16-octet block
        match (modulo & 0x0f) as usize {
            0 => last,
            n => last.get(..n).unwrap_or(last),
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

/// Find the key and IV that encrypt the message: for version 0 these are
/// the derived key and public IV; for versions 1+ they are read from the key
/// block, whose HMAC is checked first.
fn open_key_block<R: Read>(
    header: &Header,
    derived: &DerivedKey,
    verify: bool,
    key_hmac_ok: &mut Option<bool>,
    reader: &mut R,
) -> Result<(SessionKey, SessionIv), Error> {
    let version = header.version;
    if version == Version::V0 {
        return Ok((SessionKey::from(*derived.expose_secret()), SessionIv::from(header.iv)));
    }

    let mut block = Zeroizing::new([0u8; 80]);
    reader.read_exact(&mut *block).map_err(|e| truncated(e, StreamError::TruncatedKeyBlock))?;
    let (encrypted, tag) = block.split_at_mut(48);

    let mut mac = HmacSha256::new(derived.expose_secret());
    mac.update(encrypted);
    if version >= Version::V3 {
        mac.update(&[version.as_u8()]);
    }

    let ok = ct::eq(&mac.finalize(), tag);
    *key_hmac_ok = Some(ok);
    if !ok && verify {
        return Err(Error::InvalidPassword);
    }

    CbcDecryptor::new(Aes256::new(derived.expose_secret()), &header.iv).decrypt_in_place(encrypted)?;

    let (iv, key) = encrypted.split_at(16);
    Ok((SessionKey::try_from(key)?, SessionIv::try_from(iv)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSIONS: [Version; 4] = [Version::V0, Version::V1, Version::V2, Version::V3];

    fn session_key() -> SessionKey {
        SessionKey::from([3; 32])
    }

    fn params<'a>(version: Version, key: EncryptKey<'a>, extensions: &'a [Extension], session_key: &'a SessionKey) -> EncryptParams<'a> {
        EncryptParams {
            version,
            key,
            iterations: Iterations::new(10).unwrap(),
            extensions,
            public_iv: PublicIv::from([1; 16]),
            session_iv: SessionIv::from([2; 16]),
            session_key,
        }
    }

    fn write(p: &EncryptParams<'_>, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        assert_eq!(encrypt(p, data, &mut out).unwrap(), data.len() as u64);
        out
    }

    fn read(key: DecryptKey<'_>, data: &[u8]) -> Result<(Vec<u8>, DecryptInfo), Error> {
        let mut out = Vec::new();
        let info = decrypt(key, &DecryptOptions::verified(Limits::DEFAULT), data, &mut out)?;
        Ok((out, info))
    }

    fn text(p: &str) -> Password {
        Password::new(p).unwrap()
    }

    #[test]
    fn every_version_roundtrips() {
        let ext = [Extension::new("CREATED_BY", "test").unwrap()];
        let sk = session_key();
        let (right, wrong) = (text("pässword"), text("password"));

        for version in VERSIONS {
            let extensions: &[Extension] = if version >= Version::V2 { &ext } else { &[] };

            for len in [0usize, 1, 15, 16, 17, 100] {
                let data = vec![0xA5u8; len];
                let stream = write(&params(version, EncryptKey::Password(&right), extensions, &sk), &data);

                assert_eq!(crate::detect::from_bytes(&stream), Some(version));
                if version == Version::V0 {
                    assert_eq!(stream[4] as usize, len % 16);
                }

                let (plain, info) = read(DecryptKey::Password(&right), &stream).unwrap();
                assert_eq!(plain, data, "{} length {}", version, len);
                assert_eq!(info.plaintext_len, len as u64);
                assert!(info.message_hmac_ok);
                assert_eq!(info.key_hmac_ok, if version == Version::V0 { None } else { Some(true) });

                assert!(matches!(read(DecryptKey::Password(&wrong), &stream), Err(Error::InvalidPassword)));
            }
        }
    }

    #[test]
    fn deterministic_with_fixed_parameters() {
        let (sk, pw) = (session_key(), text("pw"));
        for version in VERSIONS {
            let p = params(version, EncryptKey::Password(&pw), &[], &sk);
            assert_eq!(write(&p, b"same"), write(&p, b"same"));
        }
    }

    #[test]
    fn raw_passwords_match_text_encoding() {
        let sk = session_key();
        let pw = text("pässword");

        for version in VERSIONS {
            let raw = Password::from_raw_bytes(pw.encoded(version).expose_secret().clone());
            let from_text = write(&params(version, EncryptKey::Password(&pw), &[], &sk), b"data");
            let from_raw = write(&params(version, EncryptKey::Password(&raw), &[], &sk), b"data");
            assert_eq!(from_text, from_raw, "{}", version);

            // arbitrary octets, including invalid UTF-8 and UTF-16
            let odd = Password::from_raw_bytes(vec![0xFF, 0x00, 0xD8]);
            let stream = write(&params(version, EncryptKey::Password(&odd), &[], &sk), b"data");
            assert_eq!(read(DecryptKey::Password(&odd), &stream).unwrap().0, b"data");
        }
    }

    #[test]
    fn decrypts_with_recovered_keys() {
        let (sk, pw) = (session_key(), text("pw"));
        for version in VERSIONS {
            let stream = write(&params(version, EncryptKey::Password(&pw), &[], &sk), b"secret data");
            let (_, info) = read(DecryptKey::Password(&pw), &stream).unwrap();

            let derived = info.derived_key.unwrap();
            let (plain, _) = read(DecryptKey::Derived(&derived), &stream).unwrap();
            assert_eq!(plain, b"secret data");

            let (plain, session_info) = read(DecryptKey::Session(&info.session_iv, &info.session_key), &stream).unwrap();
            assert_eq!(plain, b"secret data");
            assert_eq!(session_info.key_hmac_ok, None);
            assert!(session_info.header.extensions.is_empty());

            if version != Version::V0 {
                assert_eq!(info.session_iv, SessionIv::from([2; 16]));
                assert_eq!(info.session_key, session_key());
            }
        }
    }

    #[test]
    fn unverified_decryption_reports_failures() {
        let (sk, pw) = (session_key(), text("pw"));
        let mut stream = write(&params(Version::V3, EncryptKey::Password(&pw), &[], &sk), &[7u8; 40]);
        let n = stream.len();
        stream[n - 32 - 48] ^= 1; // first ciphertext block

        assert!(matches!(read(DecryptKey::Password(&pw), &stream), Err(Error::AlteredMessage)));

        let options = DecryptOptions { limits: Limits::DEFAULT, verify: false };
        let mut out = Vec::new();
        let info = decrypt(DecryptKey::Password(&pw), &options, &stream[..], &mut out).unwrap();
        assert!(!info.message_hmac_ok);
        assert_eq!(info.key_hmac_ok, Some(true));
        assert_eq!(out.len(), 40);
        // CBC: the damaged block is garbled and the same bit flips in the next
        assert_eq!(out[16], 7 ^ 1);
        assert_eq!(&out[17..], &[7u8; 23][..]);

        // damage to the final block breaks the padding; the block is kept
        stream[n - 32 - 1] ^= 1;
        let mut out = Vec::new();
        decrypt(DecryptKey::Password(&pw), &options, &stream[..], &mut out).unwrap();
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn derived_key_writes_the_same_stream() {
        let (sk, pw) = (session_key(), Password::from_raw_bytes(b"pw".to_vec()));
        let derived = DerivedKey::derive(Version::V3, &pw, &PublicIv::from([1; 16]), Iterations::new(10).unwrap()).unwrap();
        let from_key = write(&params(Version::V3, EncryptKey::Derived(&derived), &[], &sk), b"x");
        let from_pw = write(&params(Version::V3, EncryptKey::Password(&pw), &[], &sk), b"x");
        assert_eq!(from_key, from_pw);
    }

    #[test]
    fn iteration_limits() {
        let (sk, pw) = (session_key(), text("pw"));
        let mut p = params(Version::V3, EncryptKey::Password(&pw), &[], &sk);
        p.iterations = Iterations::new(100).unwrap();
        let stream = write(&p, b"x");

        let strict = DecryptOptions::verified(Limits::DEFAULT.max_iterations(99));
        let result = decrypt(DecryptKey::Password(&pw), &strict, &stream[..], Vec::new());
        assert!(matches!(result, Err(Error::LimitExceeded(Limit::Iterations { found: 100, max: 99 }))));

        let mut zero = stream.clone();
        zero[7..11].copy_from_slice(&[0; 4]);
        assert!(matches!(
            read(DecryptKey::Password(&pw), &zero),
            Err(Error::InvalidStream(StreamError::ZeroIterations))
        ));
    }
}
