//! Mirrors the `[target.'cfg(not(windows))'.dependencies]` table in
//! Cargo.toml: `webauthn-rs` (and with it passkey login) is only available
//! where its OpenSSL dependency is a system library. Keep the two in sync.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(passkeys)");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        println!("cargo:rustc-cfg=passkeys");
    }
}
