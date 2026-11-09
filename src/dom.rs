//! Scanner for QNAP DOM / config-flash dd images.
//!
//! Reverse engineered from QTS 5.x `libuLinux_Storage.so`:
//!   - `sed_pool_get_encrypt_conf()` / `b3e10()`: read 0x27 (39) bytes from
//!     the flash, NUL-terminate, `strstr("ENCK=")`, `strncpy(dst, p+5, 0x22)`
//!     (34 bytes) -> the saved key value.
//!   - `b35e0()` (write path): accepts total lengths of 37 or 39 chars,
//!     i.e. "ENCK=" + 32 (legacy) or "ENCK=" + 34 (modern md5-crypt) values.
//!   - "UKF=" blocks: 4-byte header + 32 per-volume flag bytes ('K' = key
//!     saved to DOM, 'M' = master-key mode), one flag per volume id within
//!     a group of 32 volumes.
//!
//! Modern QTS stores the *wrapped passphrase* (md5-crypt with the fixed
//! salt "YCCaQNAP", 34 chars, "$1$YCCaQNAP$<22>") directly in ENCK=.
//! Old (pre-3.1.2, CVE-2009-3200) firmware stored a random 32-char
//! backdoor key, obfuscated by moving its first characters (reversed) to
//! the end of the string.

use crate::md5crypt::qnap_wrap_password;

#[derive(Debug, Clone, PartialEq)]
pub enum EnckKind {
    /// "$1$YCCaQNAP$<22>" - the wrapped passphrase, usable directly as the
    /// LUKS passphrase.
    ModernWrapped,
    /// 32 chars of [a-z0-9]: legacy CVE-2009-3200 backdoor key (possibly
    /// obfuscated).
    LegacyBackdoor,
    /// Anything else.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct EnckEntry {
    /// Byte offset of "ENCK=" inside the image.
    pub offset: usize,
    /// The raw value following "ENCK=" (up to 34 printable chars).
    pub raw: String,
    pub kind: EnckKind,
    /// Interpretations of the value with explanations.
    pub candidates: Vec<KeyCandidate>,
}

#[derive(Debug, Clone)]
pub struct KeyCandidate {
    /// Human-readable description of this interpretation.
    pub description: String,
    /// The key string to use.
    pub key: String,
    /// The resulting LUKS passphrase (equals `key` when it is already a
    /// wrapped hash, or the md5-crypt of `key` when it is a password).
    pub luks_passphrase: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UkfBlock {
    pub offset: usize,
    /// The 32 flag bytes following "UKF=".
    pub flags: [u8; 32],
}

/// Deobfuscate a legacy backdoor key: `n` chars from the end, reversed,
/// moved to the front (inverse of "first n chars reversed, appended").
pub fn legacy_deobfuscate(value: &str, n: usize) -> Option<String> {
    let b = value.as_bytes();
    if b.len() < n || n == 0 {
        return None;
    }
    let tail = &b[b.len() - n..];
    let head = &b[..b.len() - n];
    let mut out = Vec::with_capacity(b.len());
    out.extend(tail.iter().rev());
    out.extend_from_slice(head);
    String::from_utf8(out).ok()
}

fn classify(value: &str) -> EnckKind {
    if value.len() == 34 && value.starts_with("$1$YCCaQNAP$") {
        EnckKind::ModernWrapped
    } else if value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        EnckKind::LegacyBackdoor
    } else {
        EnckKind::Unknown
    }
}

fn candidates_for(value: &str, kind: &EnckKind) -> Vec<KeyCandidate> {
    match kind {
        EnckKind::ModernWrapped => vec![KeyCandidate {
            description: "wrapped passphrase saved by QTS (modern)".into(),
            key: value.to_string(),
            // Already the md5-crypt hash: used verbatim by cryptsetup.
            luks_passphrase: Some(value.to_string()),
        }],
        EnckKind::LegacyBackdoor => {
            let mut v = vec![KeyCandidate {
                description: "raw legacy 32-char backdoor key (try as-is)".into(),
                key: value.to_string(),
                luks_passphrase: Some(value.to_string()),
            }];
            // CVE-2009-3200 example clearly moves 8 chars; advisory text
            // says 6 - offer both deobfuscations.
            for n in [8usize, 6] {
                if let Some(deob) = legacy_deobfuscate(value, n) {
                    v.push(KeyCandidate {
                        description: format!(
                            "legacy key deobfuscated (last {} chars reversed to front)",
                            n
                        ),
                        key: deob.clone(),
                        // The raw 32-char key was added to a LUKS slot
                        // directly (no crypt() wrapping).
                        luks_passphrase: Some(deob),
                    });
                }
            }
            v
        }
        EnckKind::Unknown => {
            let mut v = Vec::new();
            if let Some(pw) = printable(value) {
                v.push(KeyCandidate {
                    description: "unrecognised value - try as LUKS passphrase".into(),
                    key: pw.clone(),
                    luks_passphrase: Some(pw.clone()),
                });
                // If it is printable it may also be a plaintext password
                // that QTS would have wrapped.
                v.push(KeyCandidate {
                    description: "unrecognised value - try as password (wrapped)".into(),
                    luks_passphrase: Some(qnap_wrap_password(&pw)),
                    key: pw,
                });
            }
            v
        }
    }
}

fn printable(s: &str) -> Option<String> {
    if s.is_empty() || !s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        None
    } else {
        Some(s.to_string())
    }
}

/// Find all non-overlapping occurrences of `needle` in `haystack`,
/// skipping occurrences that overlap the previous value region.
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

/// Scan a DOM / config-flash image for ENCK= entries and UKF= blocks.
pub fn scan_dom(image: &[u8]) -> (Vec<EnckEntry>, Vec<UkfBlock>) {
    let mut entries = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for off in find_all(image, b"ENCK=") {
        // QTS reads up to 34 chars after "ENCK=".
        let start = off + 5;
        let end = (start + 34).min(image.len());
        let mut raw: Vec<u8> = Vec::new();
        for &b in &image[start..end] {
            if b == 0 || !(0x20..=0x7e).contains(&b) {
                break;
            }
            raw.push(b);
        }
        let raw = String::from_utf8_lossy(&raw).into_owned();
        if raw.is_empty() {
            continue;
        }
        if seen.contains(&raw) {
            continue;
        }
        seen.push(raw.clone());
        let kind = classify(&raw);
        let candidates = candidates_for(&raw, &kind);
        entries.push(EnckEntry {
            offset: off,
            raw,
            kind,
            candidates,
        });
    }

    let blocks = find_all(image, b"UKF=")
        .into_iter()
        .filter_map(|off| {
            let start = off + 4;
            let end = start + 32;
            if end > image.len() {
                return None;
            }
            let mut flags = [0u8; 32];
            flags.copy_from_slice(&image[start..end]);
            Some(UkfBlock { offset: off, flags })
        })
        .collect();

    (entries, blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_modern_enck() {
        let mut img = vec![0xffu8; 4096];
        let val = b"$1$YCCaQNAP$T.iz.UhPF80sdn/f9n0kl.";
        img[100..105].copy_from_slice(b"ENCK=");
        img[105..105 + val.len()].copy_from_slice(val);
        img[105 + val.len()] = 0;
        let (entries, _) = scan_dom(&img);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].raw.as_bytes(), val);
        assert_eq!(entries[0].kind, EnckKind::ModernWrapped);
        assert_eq!(entries[0].candidates.len(), 1);
        assert_eq!(
            entries[0].candidates[0].luks_passphrase.as_deref(),
            Some("$1$YCCaQNAP$T.iz.UhPF80sdn/f9n0kl.")
        );
    }

    #[test]
    fn finds_legacy_enck() {
        let mut img = vec![0u8; 2048];
        // CVE-2009-3200 example: obfuscated backdoor key.
        img[10..15].copy_from_slice(b"ENCK=");
        img[15..47].copy_from_slice(b"ijklmnopqrstuvwxyz012345hgfedcba");
        img[47] = 0;
        let (entries, _) = scan_dom(&img);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, EnckKind::LegacyBackdoor);
        let deob8 = entries[0]
            .candidates
            .iter()
            .find(|c| c.description.contains("8 chars"))
            .unwrap();
        assert_eq!(deob8.key, "abcdefghijklmnopqrstuvwxyz012345");
    }

    #[test]
    fn deobfuscate_roundtrip() {
        // first 8 reversed appended to end
        let obf = "ijklmnopqrstuvwxyz012345hgfedcba";
        assert_eq!(
            legacy_deobfuscate(obf, 8).unwrap(),
            "abcdefghijklmnopqrstuvwxyz012345"
        );
        // first 6 reversed appended to end
        let key = "abcdefghijklmnopqrstuvwxyz012345";
        let obf6: String = format!(
            "{}{}",
            &key[6..],
            key[..6].chars().rev().collect::<String>()
        );
        assert_eq!(obf6.len(), 32);
        assert_eq!(legacy_deobfuscate(&obf6, 6).unwrap(), key);
    }

    #[test]
    fn dedups_and_reports_ukf() {
        let mut img = vec![0u8; 1024];
        img[0..4].copy_from_slice(b"UKF=");
        for i in 0..32 {
            img[4 + i] = 0xff;
        }
        img[4] = b'K';
        img[5] = b'M';
        img[100..105].copy_from_slice(b"ENCK=");
        img[105..139].copy_from_slice(b"$1$YCCaQNAP$T.iz.UhPF80sdn/f9n0kl.");
        img[300..305].copy_from_slice(b"ENCK=");
        img[305..339].copy_from_slice(b"$1$YCCaQNAP$T.iz.UhPF80sdn/f9n0kl.");
        let (entries, blocks) = scan_dom(&img);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].offset, 100);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].flags[0], b'K');
        assert_eq!(blocks[0].flags[1], b'M');
    }
}
