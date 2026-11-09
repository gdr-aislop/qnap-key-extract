//! Pure-Rust implementation of md5-crypt ("$1$" magic), as used by QNAP QTS
//! to wrap volume encryption passphrases with the fixed salt "YCCaQNAP".
//!
//! Algorithm: Poul-Henning Kamp's MD5-based crypt(3), i.e. what
//! `openssl passwd -1 -salt YCCaQNAP <pwd>` computes.

use md5::{Digest, Md5};

const B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn b64_from_24bit(b2: u8, b1: u8, b0: u8, n: usize, out: &mut Vec<u8>) {
    // NOTE: the argument order matches the reference C code:
    // the call sites pass (v0, v1, v2) of three consecutive digest bytes.
    let mut w = ((b2 as u32) << 16) | ((b1 as u32) << 8) | (b0 as u32);
    for _ in 0..n {
        out.push(B64[(w & 0x3f) as usize]);
        w >>= 6;
    }
}

/// Compute md5-crypt of `password` with the given salt (without "$1$" magic
/// and without the trailing "$"). Returns the full "$1$<salt>$<hash>" string.
pub fn md5_crypt(password: &[u8], salt: &str) -> String {
    let magic = b"$1$";
    let salt = salt.as_bytes();

    // 1. primary = md5(pw + "$1$" + salt)
    let mut ctx = Md5::new();
    ctx.update(password);
    ctx.update(magic);
    ctx.update(salt);

    // 2. alternate = md5(pw + salt + pw)
    let mut alt = Md5::new();
    alt.update(password);
    alt.update(salt);
    alt.update(password);
    let alt = alt.finalize();

    // 3. mix in `alternate` repeatedly for plen bytes
    let mut i = password.len();
    while i > 0 {
        let take = i.min(16);
        ctx.update(&alt[..take]);
        i -= take;
    }

    // 4. for each bit of plen: odd -> NUL, even -> pw[0]
    let mut i = password.len();
    while i > 0 {
        if i & 1 == 1 {
            ctx.update([0u8]);
        } else {
            ctx.update(&password[..1]);
        }
        i >>= 1;
    }

    let mut final_digest = ctx.finalize();

    // 5. 1000 rounds of stirring
    for round in 0..1000u32 {
        let mut c = Md5::new();
        if round & 1 == 1 {
            c.update(password);
        } else {
            c.update(final_digest);
        }
        if round % 3 != 0 {
            c.update(salt);
        }
        if round % 7 != 0 {
            c.update(password);
        }
        if round & 1 == 1 {
            c.update(final_digest);
        } else {
            c.update(password);
        }
        final_digest = c.finalize();
    }

    // 6. custom base64 of the digest with the md5-crypt byte permutation
    let d = &final_digest;
    let mut out = Vec::with_capacity(22);
    b64_from_24bit(d[0], d[6], d[12], 4, &mut out);
    b64_from_24bit(d[1], d[7], d[13], 4, &mut out);
    b64_from_24bit(d[2], d[8], d[14], 4, &mut out);
    b64_from_24bit(d[3], d[9], d[15], 4, &mut out);
    b64_from_24bit(d[4], d[10], d[5], 4, &mut out);
    b64_from_24bit(0, 0, d[11], 2, &mut out);

    format!(
        "$1${}${}",
        String::from_utf8_lossy(salt),
        String::from_utf8(out).expect("b64 alphabet is ascii")
    )
}

/// The fixed salt used by QNAP QTS for volume passphrase wrapping.
pub const QNAP_SALT: &str = "YCCaQNAP";

/// Wrap a plaintext QNAP volume password into the LUKS passphrase:
/// md5-crypt with the fixed salt "YCCaQNAP" -> "$1$YCCaQNAP$<22 chars>".
pub fn qnap_wrap_password(password: &str) -> String {
    md5_crypt(password.as_bytes(), QNAP_SALT)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors produced with: openssl passwd -1 -salt YCCaQNAP '<pwd>'
    #[test]
    fn openssl_vector_test() {
        assert_eq!(
            md5_crypt(b"test", "YCCaQNAP"),
            "$1$YCCaQNAP$T.iz.UhPF80sdn/f9n0kl."
        );
    }

    #[test]
    fn openssl_vector_helloworld() {
        assert_eq!(
            md5_crypt(b"HelloWorld123", "YCCaQNAP"),
            "$1$YCCaQNAP$zvt6agyTuE/jUoXE1t0/e/"
        );
    }

    #[test]
    fn openssl_vector_default_key() {
        assert_eq!(
            qnap_wrap_password("QnapBenjamin2012"),
            "$1$YCCaQNAP$z5eCw.l3Yw1I7H2P3pll2/"
        );
    }

    #[test]
    fn empty_password() {
        // openssl passwd -1 -salt YCCaQNAP ''
        // (self-consistency: length must be 34)
        let h = qnap_wrap_password("");
        assert!(h.starts_with("$1$YCCaQNAP$"));
        assert_eq!(h.len(), 34);
    }
}
