//! AES Crypt stream header parsing and encoding.

use super::types::Limits;
use crate::detect::Version;
use crate::{Error, ExtensionError, Limit, StreamError};
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
            return Err(Error::InvalidExtension(ExtensionError::EmptyIdentifier));
        }
        if identifier.contains('\0') {
            return Err(Error::InvalidExtension(ExtensionError::NulInIdentifier));
        }
        let len = identifier.len().saturating_add(1).saturating_add(value.len());
        if len > MAX_EXTENSION_LEN {
            return Err(Error::InvalidExtension(ExtensionError::InvalidLength));
        }

        let mut raw = Vec::with_capacity(len);
        raw.extend_from_slice(identifier.as_bytes());
        raw.push(0);
        raw.extend_from_slice(value);

        Ok(Extension { raw })
    }

    /// Create an empty container extension of `len` octets (1 to 65535).
    pub fn container(len: usize) -> Result<Self, Error> {
        if len == 0 || len > MAX_EXTENSION_LEN {
            return Err(Error::InvalidExtension(ExtensionError::InvalidLength));
        }

        Ok(Extension { raw: vec![0u8; len] })
    }

    /// An extension made of arbitrary octets, written to the stream exactly
    /// as given (1 to 65535 octets).  No identifier or terminator is
    /// required, which allows malformed extensions for testing parsers.
    pub fn from_bytes(raw: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let raw = raw.into();
        if raw.is_empty() || raw.len() > MAX_EXTENSION_LEN {
            return Err(Error::InvalidExtension(ExtensionError::InvalidLength));
        }
        Ok(Extension { raw })
    }

    /// Wrap the raw octets of an extension exactly as they appear in a stream.
    pub(crate) fn from_raw(raw: Vec<u8>) -> Self {
        Extension { raw }
    }

    /// The identifier (up to the first NUL) and the value (after it).
    fn parts(&self) -> (&[u8], &[u8]) {
        let mut parts = self.raw.splitn(2, |&b| b == 0);
        let identifier = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        (identifier, value)
    }

    /// The identifier octets, up to the first NUL octet.
    pub fn identifier(&self) -> &[u8] {
        self.parts().0
    }

    /// The identifier as text, if it is valid UTF-8.
    pub fn identifier_str(&self) -> Option<&str> {
        core::str::from_utf8(self.identifier()).ok()
    }

    /// The contents after the identifier's NUL terminator.
    pub fn value(&self) -> &[u8] {
        self.parts().1
    }

    /// Whether this is a container extension (empty identifier).
    pub fn is_container(&self) -> bool {
        self.parts().0.is_empty()
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
pub(crate) fn truncated(e: io::Error, what: StreamError) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        Error::InvalidStream(what)
    } else {
        Error::Io(e)
    }
}

/// Read and parse a header, up to and including the public IV, within
/// `limits`.  Nothing is allocated for an extension until its length has
/// been checked against the limits.
pub(crate) fn read_header<R: Read>(reader: &mut R, keep_extensions: bool, limits: &Limits) -> Result<Header, Error> {
    let mut start = [0u8; 5];
    reader.read_exact(&mut start).map_err(|e| truncated(e, StreamError::TruncatedHeader))?;

    if &start[..3] != crate::detect::MAGIC {
        return Err(Error::NotAesCrypt);
    }

    let version = Version::from_u8(start[3]).ok_or(Error::UnsupportedVersion(start[3]))?;
    let mut len: usize = 5;

    // the fixed fields after the extensions: iterations (v3) and the IV
    let tail_len: usize = if version >= Version::V3 { 20 } else { 16 };
    let header_too_long = Error::LimitExceeded(Limit::HeaderLength { max: limits.max_header_len });

    let mut extensions = Vec::new();
    let mut count = 0usize;
    if version >= Version::V2 {
        loop {
            let mut ext_len = [0u8; 2];
            reader.read_exact(&mut ext_len).map_err(|e| truncated(e, StreamError::TruncatedExtensions))?;
            len = len.saturating_add(2);

            let ext_len = u16::from_be_bytes(ext_len) as usize;
            if ext_len == 0 {
                break;
            }

            count = count.saturating_add(1);
            if count > limits.max_extensions {
                return Err(Error::LimitExceeded(Limit::Extensions { max: limits.max_extensions }));
            }
            // this extension, the terminator and the fixed fields must fit
            if len.saturating_add(ext_len).saturating_add(2).saturating_add(tail_len) > limits.max_header_len {
                return Err(header_too_long);
            }

            let mut raw = vec![0u8; ext_len];
            reader.read_exact(&mut raw).map_err(|e| truncated(e, StreamError::TruncatedExtensions))?;
            len = len.saturating_add(ext_len);

            if keep_extensions {
                extensions.push(Extension::from_raw(raw));
            }
        }
    }

    if len.saturating_add(tail_len) > limits.max_header_len {
        return Err(header_too_long);
    }

    let mut iterations = None;
    if version >= Version::V3 {
        let mut n = [0u8; 4];
        reader.read_exact(&mut n).map_err(|e| truncated(e, StreamError::TruncatedHeader))?;
        iterations = Some(u32::from_be_bytes(n));
        len = len.saturating_add(4);
    }

    let mut iv = [0u8; 16];
    reader.read_exact(&mut iv).map_err(|e| truncated(e, StreamError::TruncatedHeader))?;
    len = len.saturating_add(16);

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
                return Err(Error::InvalidExtension(ExtensionError::InvalidLength));
            }
            out.extend_from_slice(&(len as u16).to_be_bytes());
            out.extend_from_slice(&ext.raw);
        }
        out.extend_from_slice(&[0, 0]);
    } else if !extensions.is_empty() {
        return Err(Error::InvalidExtension(ExtensionError::UnsupportedVersion));
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

    /// A reader that repeats one extension forever.
    struct EndlessExtensions {
        pos: usize,
    }

    impl Read for EndlessExtensions {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            const HEADER: &[u8] = b"AES\x03\x00";
            const EXT: &[u8] = b"\x00\x04ABC\x00";
            for b in buf.iter_mut() {
                *b = if self.pos < HEADER.len() {
                    HEADER[self.pos]
                } else {
                    EXT[(self.pos - HEADER.len()) % EXT.len()]
                };
                self.pos += 1;
            }
            Ok(buf.len())
        }
    }

    #[test]
    fn limits_bound_hostile_headers() {
        let result = read_header(&mut EndlessExtensions { pos: 0 }, true, &Limits::DEFAULT);
        assert!(matches!(result, Err(Error::LimitExceeded(Limit::Extensions { max: 256 }))));

        let small = Limits::DEFAULT.max_header_len(64).max_extensions(1_000_000);
        let result = read_header(&mut EndlessExtensions { pos: 0 }, false, &small);
        assert!(matches!(result, Err(Error::LimitExceeded(Limit::HeaderLength { max: 64 }))));

        // a single maximum-size extension needs a larger header limit
        let mut big = b"AES\x02\x00\xff\xff".to_vec();
        big.extend(vec![b'A'; 65535]);
        big.extend([0u8; 18]);
        assert!(read_header(&mut &big[..], true, &Limits::DEFAULT).is_ok());
        let tight = Limits::DEFAULT.max_header_len(1000);
        assert!(matches!(read_header(&mut &big[..], true, &tight), Err(Error::LimitExceeded(_))));
    }

    #[test]
    fn header_roundtrip() {
        let exts = vec![Extension::new("CREATED_BY", "test").unwrap(), Extension::container(128).unwrap()];

        for version in [Version::V0, Version::V1, Version::V2, Version::V3] {
            let e: &[Extension] = if version >= Version::V2 { &exts } else { &[] };
            let mut out = Vec::new();
            write_header(&mut out, version, 7, e, 1234, &[9u8; 16]).unwrap();

            let header = read_header(&mut &out[..], true, &Limits::DEFAULT).unwrap();
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
        let limits = Limits::DEFAULT;
        assert!(matches!(read_header(&mut &b"XYZ\x03\x00"[..], true, &limits), Err(Error::NotAesCrypt)));
        assert!(matches!(read_header(&mut &b"AES\x07\x00"[..], true, &limits), Err(Error::UnsupportedVersion(7))));
        assert!(matches!(
            read_header(&mut &b"AES\x02"[..], true, &limits),
            Err(Error::InvalidStream(StreamError::TruncatedHeader))
        ));
        assert!(matches!(
            read_header(&mut &b"AES\x02\x00\x00\x05ab"[..], true, &limits),
            Err(Error::InvalidStream(StreamError::TruncatedExtensions))
        ));
        assert!(write_header(&mut Vec::new(), Version::V1, 0, &[Extension::container(4).unwrap()], 0, &[0; 16]).is_err());
    }
}
