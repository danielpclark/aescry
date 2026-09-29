#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[macro_use]
mod fixed_tables;

mod algorithms;
mod error;
#[cfg(test)]
mod util;

pub mod aes;
pub mod cbc;
pub mod ct;
pub mod detect;
pub mod digest;
pub mod hmac;
pub mod kdf;
pub mod padding;
pub mod random;
pub mod sha256;
pub mod sha512;

pub use crate::detect::Version;
pub use crate::error::Error;
