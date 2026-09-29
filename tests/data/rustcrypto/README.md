# RustCrypto test vectors

The files in this directory are test vectors from the
[RustCrypto](https://github.com/RustCrypto) project, which is dual licensed
under the MIT and Apache-2.0 licenses. They are used here under the MIT license;
each source repository's notice is reproduced in a `LICENSE-MIT-<repository>` file.

RustCrypto stores its vectors in the binary [`blobby`](https://crates.io/crates/blobby)
format. They were decoded with `blobby` 0.4.0 and written out unchanged as
`name = hex` lines, one blank line between vectors.

| File | Source | Fields | Origin of the vectors |
|------|--------|--------|------------------------|
| `aes128.txt`, `aes192.txt`, `aes256.txt` | [`RustCrypto/block-ciphers`](https://github.com/RustCrypto/block-ciphers) @ `b99ebe6a2d394833a14a84b79aac60c0c0611577`, `aes/tests/data/*.blb` | `key`, `pt`, `ct` | NESSIE |
| `cbc_aes128.txt`, `cbc_aes192.txt`, `cbc_aes256.txt` | [`RustCrypto/block-modes`](https://github.com/RustCrypto/block-modes) @ `2fbded9b3a375351212b6bdcc48988f60a27a2b5`, `cbc/tests/data/*.blb` | `key`, `iv`, `pt`, `ct` | NIST CAVP AES Multiblock Message Test (MMT) |
| `sha256_kat.txt`, `sha512_kat.txt` | [`RustCrypto/hashes`](https://github.com/RustCrypto/hashes) @ `eadfd90f0dd6272d20530a2cdb69d96319e4a85f`, `sha2/tests/data/*_kat.blb` | `input`, `output` | Known-answer tests |
| `hmac_sha256_rfc4231.txt`, `hmac_sha512_rfc4231.txt` | [`RustCrypto/MACs`](https://github.com/RustCrypto/MACs) @ `e905def365b4a53b2530f4dce64a5f49276985c2`, `hmac/tests/data/*.blb` | `key`, `input`, `tag` | RFC 4231 |
| `hmac_sha256_wycheproof.txt`, `hmac_sha512_wycheproof.txt` | same as above | `key`, `input`, `tag` (tags may be truncated; compare the leftmost octets) | Project Wycheproof |

The PBKDF2 vectors in `tests/kdf.rs` are from `pbkdf2/tests/pbkdf2.rs` in
[`RustCrypto/password-hashes`](https://github.com/RustCrypto/password-hashes) @
`958527c7d855e1687e28f9e592e537003833ed1e`.
