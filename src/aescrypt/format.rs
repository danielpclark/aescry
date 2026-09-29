//! AES Crypt stream header parsing and encoding.

use crate::detect::Version;
use crate::Error;
use std::io::{self, Read};

/// A header extension: an identifier and its contents.
///
/// Extensions are neither encrypted nor authenticated, so their contents
/// must not be trusted.  An extension whose identifier is empty is a
/// "container": reserved space that tools can later fill with extensions
/// without rewriting the stream.
#[derive(Clone, PartialEq, Eq)]
pub struct Extension {
    raw: Vec<u8>,
}

/// The maximum encoded length of one extension (identifier, NUL and value).
pub const MAX_EXTENSION_LEN: usize = 65535;

/// The size of the container extension AES Crypt tools conventionally add.
pub const DEFAULT_CONTAINER_LEN: usize = 128;

impl Extension {
    /// Create an extension from an identifier (such as `"CREATED_BY"` or a
    /// URI) and its contents.
    ///
    /// The identifier must be non-empty and must not contain a NUL octet, and
    /// the encoded extension must fit in 65535 octets.
    pub fn new(identifier: &str, value: impl AsRef<[u8]>) -> Result<Self, Error> {
        let value = value.as_ref();

        if identifier.is_empty() {
            return Err(Error::InvalidExtension("the identifier is empty"));
        }
        if identifier.contains('\0') {
            return Err(Error::InvalidExtension("the identifier contains a NUL octet"));
        }
        if identifier.len() + 1 + value.len() > MAX_EXTENSION_LEN {
            return Err(Error::InvalidExtension("the extension is longer than 65535 octets"));
        }

        let mut raw = Vec::with_capacity(identifier.len() + 1 + value.len());
        raw.extend_from_slice(identifier.as_bytes());
        raw.push(0);
        raw.extend_from_slice(value);

        Ok(Extension { raw })
    }

    /// Create an empty container extension of `len` octets (1 to 65535).
    pub fn container(len: usize) -> Result<Self, Error> {
        if len == 0 || len > MAX_EXTENSION_LEN {
            return Err(Error::InvalidExtension("container length must be 1 to 65535 octets"));
        }

        Ok(Extension { raw: vec![0u8; len] })
    }

    /// Wrap the raw octets of an extension exactly as they appear in a stream.
    pub(crate) fn from_raw(raw: Vec<u8>) -> Self {
        Extension { raw }
    }

    fn split(&self) -> usize {
        self.raw.iter().position(|&b| b == 0).unwrap_or(self.raw.len())
    }

    /// The identifier octets, up to the first NUL octet.
    pub fn identifier(&self) -> &[u8] {
        &self.raw[..self.split()]
    }

    /// The identifier as text, if it is valid UTF-8.
    pub fn identifier_str(&self) -> Option<&str> {
        core::str::from_utf8(self.identifier()).ok()
    }

    /// The contents after the identifier's NUL terminator.
    pub fn value(&self) -> &[u8] {
        let split = self.split();
        self.raw.get(split + 1..).unwrap_or(&[])
    }

    /// Whether this is a container extension (empty identifier).
    pub fn is_container(&self) -> bool {
        self.split() == 0
    }

    /// The extension exactly as encoded in the stream (without the length).
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl core::fmt::Debug for Extension {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_container() {
            return write!(f, "Extension::container({})", self.raw.len());
        }

        f.debug_struct("Extension")
            .field("identifier", &String::from_utf8_lossy(self.identifier()))
            .field("value", &String::from_utf8_lossy(self.value()))
            .finish()
    }
}

/// The unencrypted header of an AES Crypt stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub(crate) version: Version,
    pub(crate) reserved: u8,
    pub(crate) extensions: Vec<Extension>,
    pub(crate) iterations: Option<u32>,
    pub(crate) iv: [u8; 16],
    pub(crate) len: usize,
}

impl Header {
    /// The stream format version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The octet after the version: reserved (0) in versions 1–3, and the
    /// ciphertext length modulo 16 in version 0.
    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    /// Header extensions (versions 2 and 3).
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// The value of the first extension with the given identifier.
    pub fn extension(&self, identifier: &str) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|e| e.identifier() == identifier.as_bytes())
            .map(Extension::value)
    }

    /// The PBKDF2 iteration count (version 3 only).
    pub fn iterations(&self) -> Option<u32> {
        self.iterations
    }

    /// The public IV, which is also the key derivation salt.
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// The header length in octets, up to and including the public IV.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always false: a header is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Map a premature end of stream to a format error.
pub(crate) fn truncated(e: io::Error, what: &'static str) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        Error::InvalidStream(what)
    } else {
        Error::Io(e)
    }
}

/// Read and parse a header, up to and including the public IV.
pub(crate) fn read_header<R: Read>(reader: &mut R, keep_extensions: bool) -> Result<Header, Error> {
    let mut start = [0u8; 5];
    reader.read_exact(&mut start).map_err(|e| truncated(e, "truncated header"))?;

    if &start[..3] != crate::detect::MAGIC {
        return Err(Error::NotAesCrypt);
    }

    let version = Version::from_u8(start[3]).ok_or(Error::UnsupportedVersion(start[3]))?;
    let mut len = 5;

    let mut extensions = Vec::new();
    if version >= Version::V2 {
        loop {
            let mut ext_len = [0u8; 2];
            reader.read_exact(&mut ext_len).map_err(|e| truncated(e, "truncated extensions"))?;
            len += 2;

            let ext_len = u16::from_be_bytes(ext_len) as usize;
            if ext_len == 0 {
                break;
            }

            let mut raw = vec![0u8; ext_len];
            reader.read_exact(&mut raw).map_err(|e| truncated(e, "truncated extensions"))?;
            len += ext_len;

            if keep_extensions {
                extensions.push(Extension::from_raw(raw));
            }
        }
    }

    let mut iterations = None;
    if version >= Version::V3 {
        let mut n = [0u8; 4];
        reader.read_exact(&mut n).map_err(|e| truncated(e, "truncated header"))?;
        iterations = Some(u32::from_be_bytes(n));
        len += 4;
    }

    let mut iv = [0u8; 16];
    reader.read_exact(&mut iv).map_err(|e| truncated(e, "truncated header"))?;
    len += 16;

    Ok(Header { version, reserved: start[4], extensions, iterations, iv, len })
}

/// Encode a header, up to and including the public IV.
pub(crate) fn write_header(
    out: &mut Vec<u8>,
    version: Version,
    reserved: u8,
    extensions: &[Extension],
    iterations: u32,
    iv: &[u8; 16],
) -> Result<(), Error> {
    out.extend_from_slice(crate::detect::MAGIC);
    out.push(version.as_u8());
    out.push(reserved);

    if version >= Version::V2 {
        for ext in extensions {
            let len = ext.raw.len();
            if len == 0 || len > MAX_EXTENSION_LEN {
                return Err(Error::InvalidExtension("extension length must be 1 to 65535 octets"));
            }
            out.extend_from_slice(&(len as u16).to_be_bytes());
            out.extend_from_slice(&ext.raw);
        }
        out.extend_from_slice(&[0, 0]);
    } else if !extensions.is_empty() {
        return Err(Error::InvalidExtension("versions 0 and 1 do not support extensions"));
    }

    if version >= Version::V3 {
        out.extend_from_slice(&iterations.to_be_bytes());
    }

    out.extend_from_slice(iv);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_accessors() {
        let ext = Extension::new("CREATED_BY", "aescry").unwrap();
        assert_eq!(ext.identifier(), b"CREATED_BY");
        assert_eq!(ext.identifier_str(), Some("CREATED_BY"));
        assert_eq!(ext.value(), b"aescry");
        assert_eq!(ext.as_bytes(), b"CREATED_BY\0aescry");
        assert!(!ext.is_container());

        let container = Extension::container(128).unwrap();
        assert!(container.is_container());
        assert_eq!(container.as_bytes().len(), 128);

        // no terminator: everything is the identifier
        let raw = Extension::from_raw(b"NO_TERMINATOR".to_vec());
        assert_eq!(raw.identifier(), b"NO_TERMINATOR");
        assert_eq!(raw.value(), b"");
    }

    #[test]
    fn extension_validation() {
        assert!(Extension::new("", "x").is_err());
        assert!(Extension::new("A\0B", "x").is_err());
        assert!(Extension::new("ID", vec![0u8; 65535 - 3]).is_ok());
        assert!(Extension::new("ID", vec![0u8; 65535 - 2]).is_err());
        assert!(Extension::container(0).is_err());
        assert!(Extension::container(65536).is_err());
    }

    #[test]
    fn header_roundtrip() {
        let exts = vec![Extension::new("CREATED_BY", "test").unwrap(), Extension::container(128).unwrap()];

        for version in [Version::V0, Version::V1, Version::V2, Version::V3] {
            let e: &[Extension] = if version >= Version::V2 { &exts } else { &[] };
            let mut out = Vec::new();
            write_header(&mut out, version, 7, e, 1234, &[9u8; 16]).unwrap();

            let header = read_header(&mut &out[..], true).unwrap();
            assert_eq!(header.version(), version);
            assert_eq!(header.reserved(), 7);
            assert_eq!(header.extensions(), e);
            assert_eq!(header.iterations(), if version == Version::V3 { Some(1234) } else { None });
            assert_eq!(header.iv(), &[9u8; 16]);
            assert_eq!(header.len(), out.len());
        }
    }

    #[test]
    fn header_errors() {
        assert!(matches!(read_header(&mut &b"XYZ\x03\x00"[..], true), Err(Error::NotAesCrypt)));
        assert!(matches!(read_header(&mut &b"AES\x07\x00"[..], true), Err(Error::UnsupportedVersion(7))));
        assert!(matches!(read_header(&mut &b"AES\x02"[..], true), Err(Error::InvalidStream(_))));
        assert!(matches!(read_header(&mut &b"AES\x02\x00\x00\x05ab"[..], true), Err(Error::InvalidStream(_))));
        assert!(write_header(&mut Vec::new(), Version::V1, 0, &[Extension::container(4).unwrap()], 0, &[0; 16]).is_err());
    }
}
