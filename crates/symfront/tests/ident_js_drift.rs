//! Drift guard for the browser-side ident port.
//!
//! The upload page embeds a JS port of symfront-ident (between IDENT-BEGIN
//! and IDENT-END markers in index.html). This test extracts that block,
//! runs it under node against the same pinned fixtures as the Rust tests,
//! and compares the results — so the two implementations can't silently
//! diverge. Skips (with a note) when node isn't installed.

use std::path::{Path, PathBuf};

fn fixtures() -> Vec<PathBuf> {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../symfront-store/tests/data");
    let mut out = vec![data.join("symfronttest.exe")];
    for name in ["a.exe", "b.exe", "shared.exe", "tiny.exe", "tiny.pdb"] {
        out.push(data.join("inputs").join(name));
    }
    out.retain(|p| p.is_file());
    assert!(out.len() >= 5, "fixture files missing");
    out
}

#[test]
fn js_ident_matches_rust() {
    let node = match std::process::Command::new("node").arg("--version").output() {
        Ok(o) if o.status.success() => "node",
        _ => {
            eprintln!("skipping: node not available");
            return;
        }
    };

    let html = include_str!("../src/ui/index.html");
    let start = html
        .find("/* IDENT-BEGIN")
        .expect("IDENT-BEGIN marker missing");
    let end = html.find("/* IDENT-END").expect("IDENT-END marker missing");
    let block = &html[start..end];

    // Node driver: shim the browser File API over a Buffer and identify
    // every path given on argv.
    let driver = format!(
        r#"
{block}
const fs = require('fs');
class FileShim {{
  constructor(buf) {{ this.buf = buf; this.size = buf.length; }}
  slice(a, b) {{
    const part = this.buf.subarray(a, b);
    return {{ arrayBuffer: async () =>
      part.buffer.slice(part.byteOffset, part.byteOffset + part.byteLength) }};
  }}
}}
(async () => {{
  const out = {{}};
  for (const path of process.argv.slice(2)) {{
    const r = await identifyFile(new FileShim(fs.readFileSync(path)));
    out[path] = r ? {{ kind: r.kind, hash: r.hash }} : null;
  }}
  console.log(JSON.stringify(out));
}})();
"#
    );
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("ident.js");
    std::fs::write(&script, driver).unwrap();

    let files = fixtures();
    let output = std::process::Command::new(node)
        .arg(&script)
        .args(&files)
        .output()
        .expect("running node");
    assert!(
        output.status.success(),
        "node driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    for path in &files {
        let rust = symfront_ident::identify(path).unwrap();
        let js = &got[path.to_str().unwrap()];
        match rust {
            Some((kind, hash)) => {
                let kind = match kind {
                    symfront_ident::FileKind::Pe => "pe",
                    symfront_ident::FileKind::Pdb => "pdb",
                };
                assert_eq!(
                    js["kind"].as_str(),
                    Some(kind),
                    "{}: kind drifted",
                    path.display()
                );
                assert_eq!(
                    js["hash"].as_str(),
                    Some(hash.as_str()),
                    "{}: hash drifted",
                    path.display()
                );
            }
            None => assert!(js.is_null(), "{}: JS identified what Rust didn't", path.display()),
        }
    }
}
