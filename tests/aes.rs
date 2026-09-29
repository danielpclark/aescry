mod common;

use aescry::aes::{Aes, Aes128, Aes192, Aes256, Backend, Block, BlockCipher};
use aescry::Error;
use common::{array, hex, load_vectors};

/// Check a cipher against RustCrypto's NESSIE vectors, both directions.
fn check_vectors<C: BlockCipher>(file: &str, key_len: usize, new: impl Fn(&[u8]) -> C) {
    let vectors = load_vectors(file);

    for (i, v) in vectors.iter().enumerate() {
        assert_eq!(v["key"].len(), key_len);

        let cipher = new(&v["key"]);

        let mut block: Block = array(&v["pt"]);
        cipher.encrypt_block(&mut block);
        assert_eq!(hex(&block), hex(&v["ct"]), "{} vector {} encrypt", file, i);

        cipher.decrypt_block(&mut block);
        assert_eq!(hex(&block), hex(&v["pt"]), "{} vector {} decrypt", file, i);
    }
}

/// The backends this CPU supports.
fn backends() -> Vec<Backend> {
    [Backend::Software, Backend::AesNi].into_iter().filter(|b| b.is_available()).collect()
}

#[test]
fn rustcrypto_aes128() {
    check_vectors("rustcrypto/aes128.txt", 16, |k| Aes128::new(&array(k)));
    for backend in backends() {
        check_vectors("rustcrypto/aes128.txt", 16, |k| Aes128::with_backend(&array(k), backend).unwrap());
        check_vectors("rustcrypto/aes128.txt", 16, |k| Aes::with_backend(k, backend).unwrap());
    }
}

#[test]
fn rustcrypto_aes192() {
    check_vectors("rustcrypto/aes192.txt", 24, |k| Aes192::new(&array(k)));
    for backend in backends() {
        check_vectors("rustcrypto/aes192.txt", 24, |k| Aes192::with_backend(&array(k), backend).unwrap());
        check_vectors("rustcrypto/aes192.txt", 24, |k| Aes::with_backend(k, backend).unwrap());
    }
}

#[test]
fn rustcrypto_aes256() {
    check_vectors("rustcrypto/aes256.txt", 32, |k| Aes256::new(&array(k)));
    for backend in backends() {
        check_vectors("rustcrypto/aes256.txt", 32, |k| Aes256::with_backend(&array(k), backend).unwrap());
        check_vectors("rustcrypto/aes256.txt", 32, |k| Aes::with_backend(k, backend).unwrap());
    }
}

#[test]
fn backend_selection() {
    let best = Backend::detect();
    assert!(best.is_available());
    assert_eq!(Aes::new(&[0; 16]).unwrap().backend(), best);
    assert_eq!(Aes256::new(&[0; 32]).backend(), best);

    let soft = Aes::with_backend(&[0; 16], Backend::Software).unwrap();
    assert_eq!(soft.backend(), Backend::Software);
    assert!(!Backend::Software.is_constant_time());
    assert!(Backend::AesNi.is_constant_time());

    if !Backend::AesNi.is_available() {
        assert!(matches!(Aes::with_backend(&[0; 16], Backend::AesNi), Err(Error::BackendUnavailable)));
    }
}

/// Random keys and blocks give the same results on every backend.
#[test]
fn backends_agree() {
    let backends = backends();

    for key_len in [16, 24, 32] {
        for _ in 0..200 {
            let key = aescry::random::key(key_len).unwrap();
            let block: Block = aescry::random::bytes().unwrap();

            let results: Vec<(Block, Block)> = backends
                .iter()
                .map(|&b| {
                    let cipher = Aes::with_backend(&key, b).unwrap();
                    let (mut enc, mut dec) = (block, block);
                    cipher.encrypt_block(&mut enc);
                    cipher.decrypt_block(&mut dec);
                    (enc, dec)
                })
                .collect();

            assert!(results.windows(2).all(|w| w[0] == w[1]), "backends disagree");
        }
    }
}

const FIPS197_PLAINTEXT: Block = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn fips197_roundtrip(key_len: usize, ciphertext: &str) {
    let key: Vec<u8> = (0..key_len as u8).collect();
    let cipher = Aes::new(&key).unwrap();

    assert_eq!(cipher.key_size(), key_len);

    let mut block = FIPS197_PLAINTEXT;
    cipher.encrypt_block(&mut block);
    assert_eq!(hex(&block), ciphertext);

    cipher.decrypt_block(&mut block);
    assert_eq!(block, FIPS197_PLAINTEXT);
}

#[test]
fn fips197_c1_aes128() {
    fips197_roundtrip(16, "69c4e0d86a7b0430d8cdb78070b4c55a");
}

#[test]
fn fips197_c2_aes192() {
    fips197_roundtrip(24, "dda97ca4864cdfe06eaf70a0ec0d7191");
}

#[test]
fn fips197_c3_aes256() {
    fips197_roundtrip(32, "8ea2b7ca516745bfeafc49904b496089");
}

#[test]
fn invalid_key_lengths() {
    for len in [0, 8, 15, 17, 20, 31, 33, 64] {
        assert!(matches!(Aes::new(&vec![0u8; len]), Err(Error::InvalidKeyLength(n)) if n == len));
    }

    assert!(Aes128::from_slice(&[0u8; 32]).is_err());
    assert!(Aes256::from_slice(&[0u8; 32]).is_ok());
}

#[test]
fn ecb_blocks_match_single_blocks() {
    let cipher = Aes256::new(&[7u8; 32]);
    let mut blocks = [[1u8; 16], [2u8; 16], [1u8; 16]];
    let original = blocks;

    cipher.encrypt_blocks(&mut blocks);

    let mut single = original[1];
    cipher.encrypt_block(&mut single);
    assert_eq!(blocks[1], single);
    assert_eq!(blocks[0], blocks[2]); // ECB leaks equal blocks

    cipher.decrypt_blocks(&mut blocks);
    assert_eq!(blocks, original);
}

#[test]
fn debug_does_not_print_key_material() {
    assert_eq!(format!("{:?}", Aes128::new(&[0x41; 16])), "Aes128 { .. }");
    assert_eq!(format!("{:?}", Aes::new(&[0x41; 24]).unwrap()), "Aes192 { .. }");
}

// Rijndael Monte Carlo Test (ECB mode), from the self-test in
// Christophe Devine's aes.c; the expected values were checked with OpenSSL.

const MONTE_CARLO_ENCRYPT: [Block; 3] = [
    [ 0xA0, 0x43, 0x77, 0xAB, 0xE2, 0x59, 0xB0, 0xD0,
      0xB5, 0xBA, 0x2D, 0x40, 0xA5, 0x01, 0x97, 0x1B ],
    [ 0x4E, 0x46, 0xF8, 0xC5, 0x09, 0x2B, 0x29, 0xE2,
      0x9A, 0x97, 0x1A, 0x0C, 0xD1, 0xF6, 0x10, 0xFB ],
    [ 0x1F, 0x67, 0x63, 0xDF, 0x80, 0x7A, 0x7E, 0x70,
      0x96, 0x0D, 0x4C, 0xD3, 0x11, 0x8E, 0x60, 0x1A ],
];

const MONTE_CARLO_DECRYPT: [Block; 3] = [
    [ 0xF5, 0xBF, 0x8B, 0x37, 0x13, 0x6F, 0x2E, 0x1F,
      0x6B, 0xEC, 0x6F, 0x57, 0x20, 0x21, 0xE3, 0xBA ],
    [ 0xF1, 0xA8, 0x1B, 0x68, 0xF6, 0xE5, 0xA6, 0x27,
      0x1A, 0x8C, 0xB2, 0x4E, 0x7D, 0x94, 0x91, 0xEF ],
    [ 0x4D, 0xE0, 0xC6, 0xDF, 0x7C, 0xB1, 0x69, 0x72,
      0x84, 0x60, 0x4D, 0x60, 0x27, 0x1B, 0xC5, 0x9A ],
];

fn monte_carlo(expected: &[Block; 3], decrypt: bool) {
    for backend in backends() {
        monte_carlo_with(expected, decrypt, backend);
    }
}

fn monte_carlo_with(expected: &[Block; 3], decrypt: bool, backend: Backend) {
    for n in 0..3 {
        let key_len = 16 + n * 8;
        let mut buf = [0u8; 16];
        let mut key = [0u8; 32];

        for _ in 0..400 {
            let cipher = Aes::with_backend(&key[..key_len], backend).unwrap();
            let run = |buf: &mut Block| {
                if decrypt { cipher.decrypt_block(buf) } else { cipher.encrypt_block(buf) }
            };

            for _ in 0..9999 {
                run(&mut buf);
            }

            if n > 0 {
                for j in 0..(n << 3) {
                    key[j] ^= buf[j + 16 - (n << 3)];
                }
            }

            run(&mut buf);

            for j in 0..16 {
                key[j + (n << 3)] ^= buf[j];
            }
        }

        assert_eq!(buf, expected[n], "{:?}, key size = {} bits", backend, key_len * 8);
    }
}

#[test]
fn monte_carlo_encrypt() {
    monte_carlo(&MONTE_CARLO_ENCRYPT, false);
}

#[test]
fn monte_carlo_decrypt() {
    monte_carlo(&MONTE_CARLO_DECRYPT, true);
}
