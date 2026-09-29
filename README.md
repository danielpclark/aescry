# aescry

A Rust library for detecting files encrypted in the
[AES Crypt](https://www.aescrypt.com/aes_file_format.html) file format, with
the goal of supporting encryption and decryption of those files.

> **Status:** early development. File detection is available today. The
> AES-128/192/256 block cipher and SHA-256 implementations that encryption and
> decryption will be built on are implemented and tested inside the crate, but
> are not yet part of the public API.

## Installation

`aescry` is not yet published on crates.io. Add it to your `Cargo.toml` as a
git dependency:

```toml
[dependencies]
aescry = { git = "https://github.com/danielpclark/aescry" }
```

## Usage

### Detecting an AES Crypt file

`aescry::detect::get_file` takes a path and returns `Some(AesFile)` if the file
starts with a valid AES Crypt header, or `None` otherwise.

```rust,no_run
use aescry::detect;

fn main() {
    match detect::get_file("secrets.txt.aes") {
        Some(file) => {
            println!("{} is AES Crypt format version {}", file.path(), file.version());
        }
        None => println!("not an AES Crypt file"),
    }
}
```

`get_file` returns `None` (it never panics) when:

- the file can't be opened (missing, permission denied, …),
- it doesn't begin with the `AES` magic bytes,
- it's too short to contain a version byte, or
- the version byte isn't a known format version.

### `AesFile`

| Method      | Returns | Description                                         |
|-------------|---------|-----------------------------------------------------|
| `version()` | `u8`    | The AES Crypt format version from the header.       |
| `path()`    | `&str`  | The path that was passed to `detect::get_file`.     |

## Supported file format versions

Every AES Crypt file starts with the three bytes `AES` followed by a one-byte
version number:

| Version | Layout summary                                                                                              |
|---------|-------------------------------------------------------------------------------------------------------------|
| `0`     | Header, file size mod 16, IV, encrypted message, HMAC.                                                      |
| `1`     | Header, IV, encrypted IV + 256-bit key, HMAC, encrypted message, file size mod 16, HMAC.                    |
| `2`     | Like version 1, plus a block of extensions (e.g. `CREATED_BY`) after the header.                            |

See the [AES Crypt file format specification](https://www.aescrypt.com/aes_file_format.html)
for the full layout of each version.

## Development

```sh
cargo build
cargo test            # use --release for a faster run of the AES Monte Carlo tests
```

The test suite checks the AES implementation against the FIPS-197 examples
and the Rijndael Monte Carlo (ECB) tests, and checks SHA-256 against the
FIPS 180-2 examples.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
