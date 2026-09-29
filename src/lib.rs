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
pub mod detect;
pub mod sha256;

pub use crate::detect::Version;
pub use crate::error::Error;
