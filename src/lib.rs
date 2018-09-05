#![allow(unused_imports, dead_code, unused_variables)]
// ---------------------- Version 2 ------------------------
//
//   3 Octets - 'AES'
//   1 Octet  - 0x02 (Version)
//   1 Octet  - Reserved (set to 0x00)
//   .... Start of repeating extension block section
//   2 Octet  - Length in octets (in network byte order) of an extension
//              identifier and contents.  If 0x0000, then no further
//              extensions exist and the next octet is the start of the
//              Initialization Vector (IV).  Following an extension,
//              this length indicator would appear again to indicate
//              presence or absense of another extension and the size of
//              any such extension.
//  nn Octets - Extension identifier.  This is either a URI or an
//              identifier defined by the AES developer community and
//              documented on the standard extensions page, either
//              of which is terminated by a single 0x00 octet.  All
//              extension identifiers are case sensitive.
//                Examples of URIs:
//                   http://www.aescrypt.com/extensions/creator/
//                   urn:oid:1.3.6.1.4.1.17090.55.14
//                   urn:uuid:85519EA3-1DA6-45b9-9041-8CD368D8C086
//                Note:
//                   A URI was used to allow anybody to define extension
//                   types, though we should strive to define a standard
//                   set of extensions.
//                Examples of standard extension identifiers:
//                   CREATED-DATE
//                   CREATED-BY
//              A special extension is defined that has no name, but is
//              merely a "container" for extensions to be added after the
//              AES file is initially created.  Such an extension avoids
//              the need to read and re-write the entire file in order to
//              add a small extension.  Software tools that create AES
//              files should insert a 128-octet "container" extension,
//              placing a 0x00 in the first octet of the extension
//              identifier field.  Developers may then insert extensions
//              into this "container" area and reduce the size of this
//              "container" as necessary.  If larger extensions are added
//              or the "container" area is filled entirely, then reading
//              and re-writing the entire file would be necessary to add
//              additional extensions.
//  nn Octets - The contents of the extension
//  .... End of repeating extension block section
//  16 Octets - Initialization Vector (IV) used for encrypting the
//              IV and symmetric key that is actually used to encrypt
//              the bulk of the plaintext file.
//  48 Octets - Encrypted IV and 256-bit AES key used to encrypt the
//              bulk of the file
//              16 octets - initialization vector
//              32 octets - encryption key
//  32 Octets - HMAC
//  nn Octets - Encrypted message (2^64 octets max)
//   1 Octet  - File size modulo 16 in least significant bit positions
//  32 Octets - HMAC
//  
//  Thus, the footprint of the file is at least 134 octets.
//
// ---------------------- Version 1 ------------------------
//
//   3 Octets - 'AES'
//   1 Octet  - 0x01 (Version)
//   1 Octet  - Reserved (set to 0x00)
//  16 Octets - Initialization Vector (IV) used for encrypting the
//              IV and symmetric key that is actually used to encrypt
//              the bulk of the plaintext file.
//  48 Octets - Encrypted IV and 256-bit AES key used to encrypt the
//              bulk of the file
//              16 octets - initialization vector
//              32 octets - encryption key
//  32 Octets - HMAC
//  nn Octets - Encrypted message (2^64 octets max)
//   1 Octet  - File size modulo 16 in least significant bit positions
//  32 Octets - HMAC
//  
//  Thus, the footprint of the file is at least 134 octets.
//
// ---------------------- Version 0 ------------------------
//
//   3 Octets - 'AES'
//   1 Octet  - 0x00 (Version)
//   1 Octet  - File size modulo 16 in least significant bit positions
//  16 Octets - Initialization Vector (IV)
//  nn Octets - Encrypted message (2^64 octets max)
//  32 Octets - HMAC
//  
//  Thus, the footprint of the file is at least 53 octets.

type BytesProcessed = usize;

extern crate byteorder;
use byteorder::{BigEndian,ByteOrder};
use std::io::prelude::*;
use std::fs::File;
use std::str;

mod sha256;
use crate::sha256::*;

pub struct Extension;

pub struct AesFileData {
    pub version: u8,
    pub extensions: Vec<Extension>,
    pub data: Vec<u8>,
}

pub struct AesFile {
    version: u8,
    file: String,
}

impl AesFile {
    pub fn new(v: u8, file: &str) -> Self {
        AesFile {version: v, file: file.to_string()}
    }
}

pub mod detect {
    use super::*;

    pub fn get_file(file: &str) -> Option<AesFile> {
        let mut f = File::open(file).unwrap();
        if is_aes_header(&mut f).is_err() { return None }
        match byte_as_version(&mut f) {
            2 => Some(AesFile::new(2, file)),
            1 => Some(AesFile::new(1, file)),
            0 => Some(AesFile::new(0, file)),
            _ => None,
        }
    }

    fn is_aes_header(file: &mut File) -> Result<(), ()> {
        let mut aes = [0u8; 3];

        if file.read_exact(&mut aes).is_err() {
            return Err(());
        }

        if &aes == b"AES" { Ok(()) } else { Err(()) }
    }

    fn byte_as_version(file: &mut File) -> u8 {
        let mut version = [0; 1];
        file.read_exact(&mut version).unwrap();
        version[0]
    }

    fn skip_byte(file: &mut File) {
      let mut b = [0; 1];
      file.read_exact(&mut b).unwrap();
    }

    fn read_extension_length_from_bytes(file: &mut File) -> u16 {
      let mut ext_len = [0; 2];
      file.read_exact(&mut ext_len).unwrap();
      BigEndian::read_u16(&ext_len)
    }

    fn read_extension_contents(file: &mut File, length: usize) -> String {
      let mut buf = vec![0; length].into_boxed_slice();
      file.read_exact(&mut buf).unwrap();
      str::from_utf8(&buf).unwrap().to_string()
    }

    fn is_uninitialized(s: &str) -> bool {
      s.chars().all(|v| v == '\u{0}')
    }

    fn read_iv1(file: &mut File) -> [u8; 16] {
      let mut iv = [0; 16];
      file.read_exact(&mut iv).unwrap();
      iv
    }

    fn read_iv_and_key(file: &mut File) -> ([u8; 16], [u8; 32]) {
      let mut iv = [0; 16];
      let mut key = [0; 32];
      file.read_exact(&mut iv).unwrap();
      file.read_exact(&mut key).unwrap();
      (iv, key)
    }

    fn hmac_sha256(file: &mut File) -> [u8; 32] {
      let mut hmac = [0; 32];
      file.read_exact(&mut hmac).unwrap();
      hmac 
    }
}
