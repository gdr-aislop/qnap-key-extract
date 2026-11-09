//! Decoder for QNAP volume-encryption ".key" files.
//!
//! Reverse engineered from QTS 5.x `libuLinux_Storage.so`:
//!   - `Keyfile_to_Keystring()`   @ 0xbcb90  (file reading + truncation)
//!   - `decode_user_key()`        @ 0xb4270  (the actual deobfuscation)
//!
//! Format (as decoded by QTS):
//!   * The file content is read with fgets() semantics (stops at the first
//!     '\n' or EOF, at most 512 bytes + NUL).
//!   * If the *file size* is > 512 bytes, only the first 512 bytes are used.
//!     If it is 257..=512 bytes, only the first 256 bytes are used.
//!   * The resulting blob must then be EXACTLY 256 or 512 bytes long,
//!     otherwise decoding fails.
//!   * The last two bytes of the 8-byte-aligned tail (offset 248 for the
//!     256-byte format, offset 504 for the 512-byte format) hold two ASCII
//!     decimal digits: the number N of key bytes.
//!       - 256-byte format: N in 1..=28
//!       - 512-byte format: N in 1..=64
//!   * Key byte i (0-based) is stored at file offset 8 + 9*i, i.e. one key
//!     byte is hidden in every 9-byte padding record. All other bytes are
//!     random junk (which is why every exported .key file looks different).
//!   * If the "index" flag is set (not used by the file-based entry points,
//!     which pass 0, but used e.g. by Volume_Open_Encrypt_Device_With_KeyString
//!     for CGI-uploaded key strings), the byte value additionally has i
//!     subtracted: key[i] = file[8 + 9*i] - i.
//!
//! The decoded key string is the volume's *plaintext password*, which QTS
//! then wraps via crypt(pw, "$1$YCCaQNAP$") before handing it to cryptsetup.

use std::fmt;

/// Result of decoding a .key file.
#[derive(Debug, Clone)]
pub struct DecodedKey {
    /// The recovered key string (normally the volume password).
    pub key: Vec<u8>,
    /// Which variant was decoded.
    pub format: KeyFormat,
    /// Whether the index-subtraction variant was needed.
    pub index_subtracted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// Classic 256-byte .key file.
    Blob256,
    /// Extended 512-byte blob.
    Blob512,
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFormat::Blob256 => write!(f, "256-byte"),
            KeyFormat::Blob512 => write!(f, "512-byte"),
        }
    }
}

#[derive(Debug)]
pub enum DecodeError {
    /// Content length after QTS-style truncation is not exactly 256/512.
    BadLength(usize),
    /// The count field is not two decimal digits or is out of range.
    BadCount,
    /// The decoded key contains bytes that make no sense for a passphrase.
    Implausible,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::BadLength(n) => write!(
                f,
                "content is {} bytes after truncation, need exactly 256 or 512",
                n
            ),
            DecodeError::BadCount => write!(f, "invalid or out-of-range key length field"),
            DecodeError::Implausible => write!(f, "decoded bytes do not look like a key"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Emulate the fgets()+stat() truncation done by `Keyfile_to_Keystring`
/// on raw file content.
pub fn truncate_like_qts(file_size: usize, content: &[u8]) -> Vec<u8> {
    // fgets(buf, 0x201, f): at most 512 bytes, stops after a newline.
    let mut buf: Vec<u8> = content.iter().take(512).copied().collect();
    if let Some(nl) = buf.iter().position(|&b| b == b'\n') {
        buf.truncate(nl + 1);
    }
    // Note: fgets keeps the '\n'. QTS then relies on strlen(), so anything
    // after a NUL would be ignored as well; binary .key files normally have
    // neither.
    if let Some(nul) = buf.iter().position(|&b| b == 0) {
        buf.truncate(nul);
    }
    // QTS truncation (from the stat()-based branches at 0xbcc27/0xbcca0):
    //   file_size > 512  -> use first 512 bytes
    //   256 < size <= 512 -> use first 256 bytes
    //   size <= 256      -> no truncation
    if file_size > 512 {
        buf.truncate(512);
    } else if file_size > 256 {
        buf.truncate(256);
    }
    buf
}

/// Decode an exactly-256- or exactly-512-byte blob (the `decode_user_key`
/// function). `index_subtract` corresponds to the third argument.
pub fn decode_blob(blob: &[u8], index_subtract: bool) -> Result<Vec<u8>, DecodeError> {
    let (count_off, max_count) = match blob.len() {
        256 => (248usize, 28usize),
        512 => (504, 64),
        n => return Err(DecodeError::BadLength(n)),
    };

    let d0 = blob[count_off];
    let d1 = blob[count_off + 1];
    if !d0.is_ascii_digit() || !d1.is_ascii_digit() {
        return Err(DecodeError::BadCount);
    }
    let count = (d0 - b'0') as usize * 10 + (d1 - b'0') as usize;
    if count == 0 || count > max_count {
        return Err(DecodeError::BadCount);
    }

    let mut key = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + 9 * i;
        if off >= blob.len() {
            return Err(DecodeError::BadCount);
        }
        let mut b = blob[off];
        if index_subtract {
            b = b.wrapping_sub(i as u8);
        }
        key.push(b);
    }
    Ok(key)
}

/// Quick plausibility check: QTS treats the result as a C string passphrase
/// typed in the web UI, so it should be printable ASCII without NUL bytes.
fn plausible(key: &[u8]) -> bool {
    !key.is_empty() && key.iter().all(|&b| (0x20..=0x7e).contains(&b))
}

/// Full decode of raw .key file bytes, mirroring `Keyfile_to_Keystring`.
///
/// The entry point decides whether the index is subtracted: file-based
/// entry points pass flag=0, while `Volume_Open_Encrypt_Device_With_KeyString`
/// (CGI `keyStr` path) passes flag=1. Since a blob alone does not reveal
/// which entry point produced it, both plausible variants are returned
/// (flag=0 first).
pub fn decode_keyfile(content: &[u8]) -> Result<Vec<DecodedKey>, DecodeError> {
    let blob = truncate_like_qts(content.len(), content);
    match decode_blob_content(&blob) {
        Ok(r) => Ok(r),
        Err(DecodeError::BadLength(n)) => {
            // Be more forgiving than QTS for ASCII-transported files:
            // a trailing '\n' (or CRLF) makes fgets' effective length 257+,
            // which QTS rejects outright. Retry without it.
            let mut trimmed = blob.clone();
            while matches!(trimmed.last(), Some(b'\n') | Some(b'\r')) {
                trimmed.pop();
            }
            if trimmed.len() != blob.len() {
                if let Ok(r) = decode_blob_content(&trimmed) {
                    return Ok(r);
                }
            }
            Err(DecodeError::BadLength(n))
        }
        Err(e) => Err(e),
    }
}

fn decode_blob_content(blob: &[u8]) -> Result<Vec<DecodedKey>, DecodeError> {
    let format = match blob.len() {
        256 => KeyFormat::Blob256,
        512 => KeyFormat::Blob512,
        n => return Err(DecodeError::BadLength(n)),
    };

    let mut out = Vec::new();
    for &index_subtracted in &[false, true] {
        if let Ok(key) = decode_blob(blob, index_subtracted) {
            if plausible(&key) {
                out.push(DecodedKey {
                    key,
                    format,
                    index_subtracted,
                });
            }
        }
    }
    if out.is_empty() {
        // Nothing printable in either variant; return the raw flag=0 decode
        // (if any) so the caller can still inspect it, else the original error.
        match decode_blob(blob, false) {
            Ok(key) if !key.contains(&0) => out.push(DecodedKey {
                key,
                format,
                index_subtracted: false,
            }),
            Ok(_) => return Err(DecodeError::Implausible),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// A key file that is not a 256/512-byte blob but a plain text file:
/// QTS 5.x `Volume_Encrypt_Gen_KeyFile` exports the raw 34-char wrapped
/// passphrase, and `storage_util --encrypt_pwd > file` writes the hash
/// (optionally with an "Encrypted passwd is:" prefix).
#[derive(Debug, Clone)]
pub enum RawKeyString {
    /// The full "$1$YCCaQNAP$<22>" wrapped passphrase, usable directly.
    WrappedPassphrase(String),
    /// A plain passphrase (needs crypt() wrapping).
    PlainPassphrase(String),
}

/// Interpret raw file content as a plain-text key file. Returns None if the
/// content is not a printable single line.
pub fn decode_raw_string(content: &[u8]) -> Option<RawKeyString> {
    // First line, at most 512 bytes (fgets semantics), NUL/newline end it.
    let mut line: Vec<u8> = Vec::new();
    for &b in content.iter().take(512) {
        if b == b'\n' || b == 0 {
            break;
        }
        line.push(b);
    }
    while line.last().is_some_and(|&b| b == b'\r') {
        line.pop();
    }
    if line.is_empty() || !line.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    let s = String::from_utf8_lossy(&line).into_owned();

    // Look for an embedded md5-crypt hash (handles the
    // "Encrypted passwd is:$1$YCCaQNAP$..." prefix from storage_util).
    if let Some(pos) = s.find("$1$") {
        let candidate = &s[pos..];
        if candidate.len() == 34 && candidate.starts_with("$1$YCCaQNAP$") {
            return Some(RawKeyString::WrappedPassphrase(candidate.to_string()));
        }
    }
    if s.len() == 34 && s.starts_with("$1$YCCaQNAP$") {
        return Some(RawKeyString::WrappedPassphrase(s));
    }
    Some(RawKeyString::PlainPassphrase(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic 256-byte .key blob for `key` (plain variant).
    fn make_blob256(key: &[u8]) -> Vec<u8> {
        let mut blob = vec![0xA5u8; 256];
        for (i, &b) in key.iter().enumerate() {
            blob[8 + 9 * i] = b;
        }
        let n = key.len();
        blob[248] = b'0' + (n / 10) as u8;
        blob[249] = b'0' + (n % 10) as u8;
        blob
    }

    #[test]
    fn roundtrip_256_plain() {
        let blob = make_blob256(b"SecretPwd123");
        let decoded = decode_keyfile(&blob).unwrap();
        // Plain blob: flag=1 variant decodes to different printable garbage,
        // so both variants may be reported; flag=0 must be first and correct.
        assert!(!decoded.is_empty());
        assert_eq!(decoded[0].key, b"SecretPwd123");
        assert_eq!(decoded[0].format, KeyFormat::Blob256);
        assert!(!decoded[0].index_subtracted);
    }

    #[test]
    fn roundtrip_256_index_subtracted() {
        let key = b"AnotherKey!!";
        let mut blob = vec![0x42u8; 256];
        for (i, &b) in key.iter().enumerate() {
            blob[8 + 9 * i] = b.wrapping_add(i as u8);
        }
        blob[248] = b'1';
        blob[249] = b'2';
        let decoded = decode_keyfile(&blob).unwrap();
        // The index-subtracted variant must be among the candidates.
        let found = decoded.iter().find(|d| d.key == key && d.index_subtracted);
        assert!(found.is_some(), "index-subtracted candidate missing");
    }

    #[test]
    fn roundtrip_512() {
        let key = b"LongKeyMaterialFor512ByteFormat000"; // 35 chars
        let mut blob = vec![0x11u8; 512];
        for (i, &b) in key.iter().enumerate() {
            blob[8 + 9 * i] = b;
        }
        let n = key.len();
        blob[504] = b'0' + (n / 10) as u8;
        blob[505] = b'0' + (n % 10) as u8;
        // NOTE: QTS truncates files of 257..=512 bytes to 256, so the
        // 512-byte blob format only survives inside files LARGER than 512.
        let mut file = blob.clone();
        file.extend_from_slice(&[0x00u8; 64]);
        let decoded = decode_keyfile(&file).unwrap();
        assert!(!decoded.is_empty());
        assert_eq!(decoded[0].key, key);
        assert_eq!(decoded[0].format, KeyFormat::Blob512);
    }

    #[test]
    fn exact_512_file_is_truncated_to_256() {
        // Authentic QTS quirk: a 512-byte file decodes as a 256-byte blob.
        let key = b"Exact512File";
        let mut blob = vec![0x33u8; 512];
        for (i, &b) in key.iter().enumerate() {
            blob[8 + 9 * i] = b;
        }
        blob[248] = b'1';
        blob[249] = b'2';
        let decoded = decode_keyfile(&blob).unwrap();
        assert_eq!(decoded[0].key, key);
        assert_eq!(decoded[0].format, KeyFormat::Blob256);
    }

    #[test]
    fn raw_string_key_files() {
        // QTS5 exported key file: raw wrapped passphrase.
        let hash = b"$1$YCCaQNAP$T.iz.UhPF80sdn/f9n0kl.";
        match decode_raw_string(hash).unwrap() {
            RawKeyString::WrappedPassphrase(s) => assert_eq!(s.as_bytes(), hash),
            _ => panic!("wrong kind"),
        }
        // storage_util --encrypt_pwd output with prefix.
        let prefixed = b"Encrypted passwd is:$1$YCCaQNAP$T.iz.UhPF80sdn/f9n0kl.\n";
        match decode_raw_string(prefixed).unwrap() {
            RawKeyString::WrappedPassphrase(s) => {
                assert_eq!(s.as_bytes(), &hash[..])
            }
            _ => panic!("wrong kind"),
        }
        // Plain passphrase file.
        match decode_raw_string(b"JustAPassphrase\n").unwrap() {
            RawKeyString::PlainPassphrase(s) => assert_eq!(s, "JustAPassphrase"),
            _ => panic!("wrong kind"),
        }
        // Binary junk is not a raw key string.
        assert!(decode_raw_string(&[0x00u8; 64]).is_none());
    }

    #[test]
    fn tolerates_trailing_newline() {
        // QTS itself rejects these (fgets keeps the newline -> length 257),
        // but ASCII transport (mail, editors) often adds one.
        let mut blob = make_blob256(b"SecretPwd123");
        blob.push(b'\n');
        let decoded = decode_keyfile(&blob).unwrap();
        assert_eq!(decoded[0].key, b"SecretPwd123");

        blob.push(b'\r');
        let decoded = decode_keyfile(&blob).unwrap();
        assert_eq!(decoded[0].key, b"SecretPwd123");
    }

    #[test]
    fn rejects_wrong_size() {
        // All-NUL content: strlen() semantics make the effective length 0.
        assert!(matches!(
            decode_keyfile(&[0u8; 100]),
            Err(DecodeError::BadLength(0))
        ));
        // Non-NUL but wrong size: length is preserved.
        assert!(matches!(
            decode_keyfile(&[0xA5u8; 100]),
            Err(DecodeError::BadLength(100))
        ));
    }

    #[test]
    fn rejects_bad_count() {
        let mut blob = make_blob256(b"abc");
        blob[248] = b'9';
        blob[249] = b'9'; // 99 > 28
        assert!(decode_keyfile(&blob).is_err());
    }

    #[test]
    fn truncates_large_file_like_qts() {
        // File > 256 bytes: QTS uses only the first 256.
        let mut blob = make_blob256(b"Truncated");
        blob.extend_from_slice(&[0x00u8; 300]); // file now 556 bytes
        let decoded = decode_keyfile(&blob).unwrap();
        assert_eq!(decoded[0].key, b"Truncated");
    }
}
