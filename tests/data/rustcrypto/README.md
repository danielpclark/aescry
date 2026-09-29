# RustCrypto test vectors

The files in this directory are test vectors from the
[RustCrypto](https://github.com/RustCrypto) project, which is dual licensed
under the MIT and Apache-2.0 licenses. They are used here under the MIT license;
its notice is reproduced in [LICENSE-MIT](LICENSE-MIT).

RustCrypto stores its vectors in the binary [`blobby`](https://crates.io/crates/blobby)
format. They were decoded with `blobby` 0.4.0 and written out unchanged as
`name = hex` lines, one blank line between vectors.

| File | Source | Fields | Origin of the vectors |
|------|--------|--------|------------------------|
| `aes128.txt`, `aes192.txt`, `aes256.txt` | [`RustCrypto/block-ciphers`](https://github.com/RustCrypto/block-ciphers) @ `b99ebe6a2d394833a14a84b79aac60c0c0611577`, `aes/tests/data/*.blb` | `key`, `pt`, `ct` | NESSIE |
