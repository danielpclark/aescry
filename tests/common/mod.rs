//! Shared helpers for integration tests.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Decode a hex string.
pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

/// Encode bytes as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A test vector: field name -> value.
pub type Vector = HashMap<String, Vec<u8>>;

/// Load `name = hex` vectors separated by blank lines from `tests/data/<file>`.
pub fn load_vectors(file: &str) -> Vec<Vector> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(file);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));

    let mut vectors = Vec::new();
    let mut current = Vector::new();

    for line in text.lines() {
        let line = line.trim();

        if line.is_empty() {
            if !current.is_empty() {
                vectors.push(std::mem::take(&mut current));
            }
            continue;
        }

        if line.starts_with('#') {
            continue;
        }

        let (name, value) = line.split_once('=').expect("expected `name = hex`");
        current.insert(name.trim().to_string(), unhex(value.trim()));
    }

    if !current.is_empty() {
        vectors.push(current);
    }

    assert!(!vectors.is_empty(), "no vectors in {}", file);
    vectors
}

/// Convert a slice to a fixed-size array.
pub fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("wrong length")
}
