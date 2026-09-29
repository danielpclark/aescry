#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
// No panics on any input: these are errors outside tests.  Crypto kernels
// that index fixed-size tables allow indexing locally, with the reason.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]
// Every unsafe operation is in its own block with a SAFETY comment.
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]
#![warn(missing_docs, rust_2018_idioms)]

#[macro_use]
mod fixed_tables;

mod algorithms;
mod error;
#[cfg(test)]
mod util;

pub mod aes;
pub mod aescrypt;
pub mod cbc;
pub mod ct;
pub mod detect;
pub mod digest;
pub mod hmac;
pub mod kdf;
pub mod padding;
pub mod random;
pub mod secret;
pub mod security;
pub mod sha256;
pub mod sha512;
pub mod zeroize;

pub use crate::detect::Version;
pub use crate::error::{Error, ExtensionError, Limit, StreamError};
