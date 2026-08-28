//! Cache keys: sha256 of the full upstream URL. Per-upstream by
//! construction (the base URL is embedded), and identical to the Python
//! implementation's keying — which is what makes a full cache import
//! possible.

use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct CacheKey {
    pub upstream_name: String,
    pub full_url: String,
    pub hash: [u8; 32],
}

impl CacheKey {
    pub fn new(upstream_name: &str, full_url: &str) -> CacheKey {
        let hash = Sha256::digest(full_url.as_bytes()).into();
        CacheKey {
            upstream_name: upstream_name.to_string(),
            full_url: full_url.to_string(),
            hash,
        }
    }

    pub fn hex(&self) -> String {
        hex(&self.hash)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Parse a 64-char lowercase/uppercase hex string into a 32-byte key.
pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}
