//! Detection of AES Crypt streams.
//!
//! Every AES Crypt stream starts with the three octets `"AES"` followed by a
//! one-octet format version.  The functions here check for that header and,
//! where the whole stream (or its length) is available, that the stream is at
//! least as long as the smallest valid stream of that version.
//!
//! ```
//! use aescry::detect::{self, Version};
//!
//! let mut stream = b"AES\x02\x00".to_vec();
//! stream.resize(136, 0);
//!
//! assert_eq!(detect::from_bytes(&stream), Some(Version::V2));
//! assert_eq!(detect::from_bytes(b"plain text"), None);
//! ```
//!
//! Formats (see the [AES Crypt stream format]):
//!
//! ```text
//! Version 3                         Version 2
//!   3  "AES"                          3  "AES"
//!   1  0x03                           1  0x02
//!   1  reserved (0x00)                1  reserved (0x00)
//!   .. extensions                     .. extensions
//!   4  PBKDF2 iterations              16 IV
//!   16 IV                             48 encrypted session IV + key
//!   48 encrypted session IV + key     32 HMAC-SHA256
//!   32 HMAC-SHA256                    nn ciphertext
//!   nn ciphertext (PKCS#7 padded)     1  ciphertext size modulo 16
//!   32 HMAC-SHA256                    32 HMAC-SHA256
//!
//! Version 1                         Version 0
//!   3  "AES"                          3  "AES"
//!   1  0x01                           1  0x00
//!   1  reserved (0x00)                1  ciphertext size modulo 16
//!   16 IV                             16 IV
//!   48 encrypted session IV + key     nn ciphertext
//!   32 HMAC-SHA256                    32 HMAC-SHA256
//!   nn ciphertext
//!   1  ciphertext size modulo 16
//!   32 HMAC-SHA256
//! ```
//!
//! [AES Crypt stream format]: https://www.aescrypt.com/aes_stream_format.html

use core::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// The three octets every AES Crypt stream starts with.
pub const MAGIC: &[u8; 3] = b"AES";

/// An AES Crypt stream format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Version {
    /// Version 0: no session key; AES-256-CBC with the password-derived key.
    V0,
    /// Version 1: adds an encrypted session IV and key.
    V1,
    /// Version 2: adds header extensions.
    V2,
    /// Version 3: PBKDF2-HMAC-SHA512 key derivation and PKCS#7 padding.
    V3,
}

impl Version {
    /// The newest stream format version.
    pub const LATEST: Version = Version::V3;

    /// Map a version octet to a `Version`.
    pub fn from_u8(version: u8) -> Option<Version> {
        match version {
            0 => Some(Version::V0),
            1 => Some(Version::V1),
            2 => Some(Version::V2),
            3 => Some(Version::V3),
            _ => None,
        }
    }

    /// The version octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Version::V0 => 0,
            Version::V1 => 1,
            Version::V2 => 2,
            Version::V3 => 3,
        }
    }

    /// The length in octets of the smallest valid stream of this version.
    pub fn min_stream_len(self) -> usize {
        match self {
            Version::V0 => 53,
            Version::V1 => 134,
            Version::V2 => 136,
            Version::V3 => 155,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AES Crypt stream format version {}", self.as_u8())
    }
}

/// Check only the four header octets (`"AES"` and a known version).
pub fn from_header(header: &[u8]) -> Option<Version> {
    match header {
        [b'A', b'E', b'S', version, ..] => Version::from_u8(*version),
        _ => None,
    }
}

/// Check the header of a complete stream held in memory, and that it is long
/// enough to be a valid stream of the detected version.
pub fn from_bytes(data: &[u8]) -> Option<Version> {
    from_header(data).filter(|v| data.len() >= v.min_stream_len())
}

/// Read the four header octets from `reader` and check them.
///
/// Returns `Ok(None)` if the stream ends before four octets or does not have
/// an AES Crypt header.  Only the header is read, so the stream length is not
/// checked.
pub fn from_reader<R: Read>(mut reader: R) -> io::Result<Option<Version>> {
    let mut header = [0u8; 4];

    match reader.read_exact(&mut header) {
        Ok(()) => Ok(from_header(&header)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

/// Check the header and length of a file.
///
/// I/O errors (such as a missing file) are returned as errors; use
/// [`get_file`] if you only care whether the file is an AES Crypt file.
pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Option<Version>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();

    Ok(from_reader(file)?.filter(|v| len >= v.min_stream_len() as u64))
}

/// A file detected as an AES Crypt stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesFile {
    version: Version,
    path: PathBuf,
}

impl AesFile {
    /// The AES Crypt stream format version read from the header.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The path the file was detected at.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Detect whether the file at `path` is an AES Crypt file.
///
/// Returns `None` (it never panics) if the file can't be read, doesn't start
/// with an AES Crypt header, has an unknown version, or is too short.
pub fn get_file<P: AsRef<Path>>(path: P) -> Option<AesFile> {
    let path = path.as_ref();
    let version = from_file(path).ok()??;

    Some(AesFile { version, path: path.to_path_buf() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(version: u8, len: usize) -> Vec<u8> {
        let mut data = vec![b'A', b'E', b'S', version, 0];
        data.resize(len, 0);
        data
    }

    #[test]
    fn detects_every_version_at_minimum_length() {
        for v in [Version::V0, Version::V1, Version::V2, Version::V3] {
            let len = v.min_stream_len();

            assert_eq!(from_bytes(&stream(v.as_u8(), len)), Some(v));
            assert_eq!(from_bytes(&stream(v.as_u8(), len - 1)), None);
            assert_eq!(from_header(&stream(v.as_u8(), 4)), Some(v));
        }
    }

    #[test]
    fn rejects_non_aes_crypt_data() {
        assert_eq!(from_bytes(&stream(4, 1000)), None);
        assert_eq!(from_header(b"AES"), None);
        assert_eq!(from_header(b"aes\x02"), None);
        assert_eq!(from_header(b""), None);
    }

    #[test]
    fn reader_detection() {
        assert_eq!(from_reader(&b"AES\x03"[..]).unwrap(), Some(Version::V3));
        assert_eq!(from_reader(&b"AES"[..]).unwrap(), None);
        assert_eq!(from_reader(&b"PK\x03\x04"[..]).unwrap(), None);
    }

    #[test]
    fn file_detection() {
        let dir = std::env::temp_dir().join(format!("aescry-detect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let write = |name: &str, bytes: &[u8]| {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        };

        let v2 = write("v2.aes", &stream(2, 136));
        let v3_short = write("v3short.aes", &stream(3, 154));
        let bad_version = write("v9.aes", &stream(9, 200));
        let truncated = write("short.aes", b"AES");
        let plain = write("plain.txt", b"hello");

        let file = get_file(&v2).unwrap();
        assert_eq!(file.version(), Version::V2);
        assert_eq!(file.path(), v2.as_path());

        assert!(get_file(&v3_short).is_none());
        assert!(get_file(&bad_version).is_none());
        assert!(get_file(&truncated).is_none());
        assert!(get_file(&plain).is_none());
        assert!(get_file(dir.join("missing.aes")).is_none());
        assert!(from_file(dir.join("missing.aes")).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
