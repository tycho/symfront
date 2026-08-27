//! RFC 6238 TOTP (SHA-1, 6 digits, 30 s period) with a ±1-step verification
//! window to tolerate generator clock drift.

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;

pub const PERIOD: u64 = 30;
pub const DIGITS: u32 = 6;

const B32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' || c == b' ' {
            continue;
        }
        let v = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Fresh 160-bit secret, base32-encoded.
pub fn generate_secret() -> String {
    let mut buf = [0u8; 20];
    OsRng.fill_bytes(&mut buf);
    base32_encode(&buf)
}

/// The code for one time step (unix_time / PERIOD).
pub fn code_at_step(secret_b32: &str, step: u64) -> Option<String> {
    let key = base32_decode(secret_b32)?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    Some(format!("{:06}", bin % 10u32.pow(DIGITS)))
}

/// Accept the previous, current, and next step to allow generator clock drift.
pub fn verify(secret_b32: &str, code: &str, unix_time: u64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let step = unix_time / PERIOD;
    for s in [step.wrapping_sub(1), step, step + 1] {
        if code_at_step(secret_b32, s).as_deref() == Some(code) {
            return true;
        }
    }
    false
}

pub fn otpauth_url(account: &str, secret_b32: &str) -> String {
    // Minimal percent-encoding for the label; account names are already
    // restricted to [A-Za-z0-9-_.@].
    format!(
        "otpauth://totp/symfront:{account}?secret={secret_b32}&issuer=symfront&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        for data in [&b"hello"[..], b"", b"\x00\xff\x01", b"12345678901234567890"] {
            assert_eq!(base32_decode(&base32_encode(data)).unwrap(), data);
        }
        assert_eq!(base32_encode(b"hello"), "NBSWY3DP");
        assert!(base32_decode("!!").is_none());
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B, secret "12345678901234567890", 8→6 digit trim.
        let secret = base32_encode(b"12345678901234567890");
        for (t, code8) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
        ] {
            assert_eq!(
                code_at_step(&secret, t / PERIOD).unwrap(),
                &code8[2..],
                "t={t}"
            );
        }
    }

    #[test]
    fn drift_window() {
        let secret = generate_secret();
        let now = 1_787_850_000u64;
        let cur = code_at_step(&secret, now / PERIOD).unwrap();
        let prev = code_at_step(&secret, now / PERIOD - 1).unwrap();
        let next = code_at_step(&secret, now / PERIOD + 1).unwrap();
        let far = code_at_step(&secret, now / PERIOD + 2).unwrap();
        assert!(verify(&secret, &cur, now));
        assert!(verify(&secret, &prev, now));
        assert!(verify(&secret, &next, now));
        // Two steps out is rejected (unless it collides, which is 1e-6).
        if far != cur && far != prev && far != next {
            assert!(!verify(&secret, &far, now));
        }
        assert!(!verify(&secret, "12345", now)); // wrong length
        assert!(!verify(&secret, "abcdef", now));
    }
}
