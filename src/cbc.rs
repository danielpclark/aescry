//! Cipher Block Chaining (CBC) mode, NIST SP 800-38A.
//!
//! The simplest way to encrypt byte buffers is with [`encrypt`] and
//! [`decrypt`], which take a raw key and IV and apply PKCS#7 padding:
//!
//! ```
//! use aescry::cbc;
//!
//! let key = aescry::random::bytes::<32>()?;
//! let iv = aescry::random::iv()?;
//!
//! let ciphertext = cbc::encrypt(&key, &iv, b"attack at dawn")?;
//! let plaintext = cbc::decrypt(&key, &iv, &ciphertext)?;
//! assert_eq!(plaintext, b"attack at dawn");
//! # Ok::<(), aescry::Error>(())
//! ```
//!
//! [`encrypt_with_random_iv`] generates the IV and puts it in front of the
//! ciphertext, so only the key needs to be kept:
//!
//! ```
//! use aescry::cbc;
//!
//! let key = aescry::random::bytes::<16>()?;
//! let message = cbc::encrypt_with_random_iv(&key, b"attack at dawn")?;
//! assert_eq!(cbc::decrypt_with_iv_prefix(&key, &message)?, b"attack at dawn");
//! # Ok::<(), aescry::Error>(())
//! ```
//!
//! # Security
//!
//! CBC provides confidentiality only.  Anyone who can modify the ciphertext
//! can make predictable changes to the decrypted data, and a decryptor that
//! reveals whether padding was valid can be used to decrypt messages (a
//! "padding oracle").  Authenticate ciphertext with a MAC before decrypting
//! it, and never reuse an IV with the same key.
//!
//! [`CbcEncryptor`] and [`CbcDecryptor`] are the unpadded building blocks for
//! streaming data through CBC one or more blocks at a time.

use crate::aes::{Aes, Block, BlockCipher, BLOCK_SIZE};
use crate::padding::{pkcs7_pad_in_place, pkcs7_unpad_in_place};
use crate::zeroize::Zeroize;
use crate::{random, Error};

#[inline]
fn xor_block(a: &mut Block, b: &Block) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= *y;
    }
}

fn to_iv(iv: &[u8]) -> Result<Block, Error> {
    iv.try_into().map_err(|_| Error::InvalidIvLength(iv.len()))
}

fn check_block_multiple(len: usize) -> Result<(), Error> {
    if len % BLOCK_SIZE != 0 {
        return Err(Error::InvalidCiphertextLength(len));
    }
    Ok(())
}

/// CBC encryption without padding.
///
/// The chaining value carries over between calls, so a long message can be
/// encrypted in pieces as long as each piece is a whole number of blocks.
#[derive(Clone, Debug)]
pub struct CbcEncryptor<C: BlockCipher> {
    cipher: C,
    iv: Block,
}

impl<C: BlockCipher> CbcEncryptor<C> {
    /// Start encrypting with `cipher` and a 16-octet IV.
    pub fn new(cipher: C, iv: &Block) -> Self {
        CbcEncryptor { cipher, iv: *iv }
    }

    /// Encrypt one block in place.
    pub fn encrypt_block(&mut self, block: &mut Block) {
        xor_block(block, &self.iv);
        self.cipher.encrypt_block(block);
        self.iv = *block;
    }

    /// Encrypt a sequence of blocks in place.
    pub fn encrypt_blocks(&mut self, blocks: &mut [Block]) {
        for block in blocks {
            self.encrypt_block(block);
        }
    }

    /// Encrypt `buf` in place; its length must be a multiple of 16.
    pub fn encrypt_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        check_block_multiple(buf.len())?;

        for chunk in buf.chunks_exact_mut(BLOCK_SIZE) {
            let mut block: Block = (&*chunk).try_into().expect("16-octet chunk");
            self.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        Ok(())
    }

    /// The current chaining value: the IV for the next block.
    pub fn iv_state(&self) -> Block {
        self.iv
    }

    /// Consume the encryptor and return the block cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

/// CBC decryption without padding.
///
/// The chaining value carries over between calls, so a long message can be
/// decrypted in pieces as long as each piece is a whole number of blocks.
#[derive(Clone, Debug)]
pub struct CbcDecryptor<C: BlockCipher> {
    cipher: C,
    iv: Block,
}

impl<C: BlockCipher> CbcDecryptor<C> {
    /// Start decrypting with `cipher` and a 16-octet IV.
    pub fn new(cipher: C, iv: &Block) -> Self {
        CbcDecryptor { cipher, iv: *iv }
    }

    /// Decrypt one block in place.
    pub fn decrypt_block(&mut self, block: &mut Block) {
        let next_iv = *block;
        self.cipher.decrypt_block(block);
        xor_block(block, &self.iv);
        self.iv = next_iv;
    }

    /// Decrypt a sequence of blocks in place.
    pub fn decrypt_blocks(&mut self, blocks: &mut [Block]) {
        for block in blocks {
            self.decrypt_block(block);
        }
    }

    /// Decrypt `buf` in place; its length must be a multiple of 16.
    pub fn decrypt_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        check_block_multiple(buf.len())?;

        for chunk in buf.chunks_exact_mut(BLOCK_SIZE) {
            let mut block: Block = (&*chunk).try_into().expect("16-octet chunk");
            self.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        Ok(())
    }

    /// The current chaining value: the IV for the next block.
    pub fn iv_state(&self) -> Block {
        self.iv
    }

    /// Consume the decryptor and return the block cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

/// Encrypt `plaintext` with AES-CBC and PKCS#7 padding.
///
/// `key` must be 16, 24 or 32 octets and `iv` 16 octets.  The result is
/// 1 to 16 octets longer than the plaintext.
pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encryptor = CbcEncryptor::new(Aes::new(key)?, &to_iv(iv)?);

    let mut buf = Vec::with_capacity(plaintext.len() + BLOCK_SIZE);
    buf.extend_from_slice(plaintext);
    pkcs7_pad_in_place(&mut buf);

    encryptor.encrypt_in_place(&mut buf)?;
    Ok(buf)
}

/// Decrypt AES-CBC `ciphertext` and remove PKCS#7 padding.
///
/// Returns [`Error::InvalidPadding`] if the padding is wrong, which usually
/// means the key or IV is wrong or the ciphertext was modified.
pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decryptor = CbcDecryptor::new(Aes::new(key)?, &to_iv(iv)?);

    if ciphertext.is_empty() {
        return Err(Error::InvalidCiphertextLength(0));
    }

    let mut buf = ciphertext.to_vec();
    decryptor.decrypt_in_place(&mut buf)?;
    if let Err(e) = pkcs7_unpad_in_place(&mut buf) {
        buf.zeroize();
        return Err(e);
    }
    Ok(buf)
}

/// Encrypt with AES-CBC without padding; `plaintext` must be a multiple of
/// 16 octets.
pub fn encrypt_no_padding(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encryptor = CbcEncryptor::new(Aes::new(key)?, &to_iv(iv)?);
    let mut buf = plaintext.to_vec();
    encryptor.encrypt_in_place(&mut buf)?;
    Ok(buf)
}

/// Decrypt AES-CBC without removing padding; `ciphertext` must be a multiple
/// of 16 octets.
pub fn decrypt_no_padding(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decryptor = CbcDecryptor::new(Aes::new(key)?, &to_iv(iv)?);
    let mut buf = ciphertext.to_vec();
    decryptor.decrypt_in_place(&mut buf)?;
    Ok(buf)
}

/// Encrypt with a freshly generated random IV and return `IV || ciphertext`.
pub fn encrypt_with_random_iv(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let iv = random::iv()?;
    let ciphertext = encrypt(key, &iv, plaintext)?;

    let mut out = Vec::with_capacity(BLOCK_SIZE + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `IV || ciphertext` as produced by [`encrypt_with_random_iv`].
pub fn decrypt_with_iv_prefix(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < 2 * BLOCK_SIZE {
        return Err(Error::InvalidCiphertextLength(data.len()));
    }

    let (iv, ciphertext) = data.split_at(BLOCK_SIZE);
    decrypt(key, iv, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::Aes128;

    #[test]
    fn roundtrip_every_length() {
        let key = [3u8; 24];
        let iv = [9u8; 16];

        for len in 0..=64 {
            let plaintext: Vec<u8> = (0..len as u8).collect();
            let ciphertext = encrypt(&key, &iv, &plaintext).unwrap();

            assert_eq!(ciphertext.len(), (len / 16 + 1) * 16);
            assert_eq!(decrypt(&key, &iv, &ciphertext).unwrap(), plaintext);
        }
    }

    #[test]
    fn chunked_matches_one_shot() {
        let cipher = Aes128::new(&[1u8; 16]);
        let iv = [2u8; 16];
        let data = [0x5Au8; 96];

        let mut whole = data;
        CbcEncryptor::new(&cipher, &iv).encrypt_in_place(&mut whole).unwrap();

        let mut pieces = data;
        let mut enc = CbcEncryptor::new(&cipher, &iv);
        let (a, b) = pieces.split_at_mut(32);
        enc.encrypt_in_place(a).unwrap();
        enc.encrypt_in_place(b).unwrap();
        assert_eq!(whole, pieces);
        assert_eq!(enc.iv_state(), <Block>::try_from(&whole[80..]).unwrap());

        let mut dec = CbcDecryptor::new(&cipher, &iv);
        let (a, b) = pieces.split_at_mut(48);
        dec.decrypt_in_place(a).unwrap();
        dec.decrypt_in_place(b).unwrap();
        assert_eq!(pieces, data);
    }

    #[test]
    fn rejects_bad_inputs() {
        let key = [0u8; 16];
        let iv = [0u8; 16];

        assert!(matches!(encrypt(&key[..15], &iv, b""), Err(Error::InvalidKeyLength(15))));
        assert!(matches!(encrypt(&key, &iv[..8], b""), Err(Error::InvalidIvLength(8))));
        assert!(matches!(decrypt(&key, &iv, &[0u8; 17]), Err(Error::InvalidCiphertextLength(17))));
        assert!(matches!(decrypt(&key, &iv, &[]), Err(Error::InvalidCiphertextLength(0))));
        assert!(matches!(encrypt_no_padding(&key, &iv, &[0u8; 5]), Err(Error::InvalidCiphertextLength(5))));
        assert!(matches!(decrypt_with_iv_prefix(&key, &[0u8; 16]), Err(Error::InvalidCiphertextLength(16))));

        // wrong key: padding check fails (or, rarely, yields garbage)
        let ciphertext = encrypt(&key, &iv, b"hello").unwrap();
        let other = decrypt(&[1u8; 16], &iv, &ciphertext);
        assert!(other.is_err() || other.unwrap() != b"hello");
    }

    #[test]
    fn random_iv_prefix() {
        let key = [7u8; 32];
        let a = encrypt_with_random_iv(&key, b"same message").unwrap();
        let b = encrypt_with_random_iv(&key, b"same message").unwrap();

        assert_ne!(a, b);
        assert_eq!(decrypt_with_iv_prefix(&key, &a).unwrap(), b"same message");
        assert_eq!(decrypt_with_iv_prefix(&key, &b).unwrap(), b"same message");
    }
}
