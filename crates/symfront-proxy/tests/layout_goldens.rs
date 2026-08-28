//! Layout behavior is pinned by golden vectors generated from the Python
//! reference implementation (435 cases, including 400 real request paths
//! from the live proxy's logs). Any divergence is a bug here, not there.

use serde::Deserialize;
use symfront_proxy::query::{classify_request, render, Family, LayoutKind, Role};

#[derive(Deserialize)]
struct Goldens {
    bases: Bases,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Bases {
    symstore: String,
    debuginfod: String,
}

#[derive(Deserialize)]
struct Case {
    path: String,
    classified: Option<Classified>,
    #[serde(default)]
    render: Option<Rendered>,
}

#[derive(Deserialize)]
struct Classified {
    family: String,
    role: Option<String>,
    ext: Option<String>,
    inbound_layout: String,
    ident: Option<String>,
    source_path: Option<String>,
}

#[derive(Deserialize)]
struct Rendered {
    symstore: Option<String>,
    debuginfod: Option<String>,
}

fn family_name(f: Family) -> &'static str {
    match f {
        Family::Pe => "pe",
        Family::Elf => "elf",
        Family::Macho => "macho",
    }
}

fn role_name(r: Role) -> &'static str {
    match r {
        Role::Image => "image",
        Role::Debug => "debug",
        Role::Source => "source",
    }
}

#[test]
fn matches_python_reference() {
    let raw = include_str!("data/layout-goldens.json");
    let goldens: Goldens = serde_json::from_str(raw).expect("parsing goldens");
    assert!(goldens.cases.len() >= 400, "unexpectedly few golden cases");

    let mut failures = Vec::new();
    for case in &goldens.cases {
        let got = classify_request(&case.path);
        match (&case.classified, &got) {
            (None, None) => continue,
            (None, Some(q)) => {
                failures.push(format!("{}: expected unclassified, got {q:?}", case.path));
                continue;
            }
            (Some(want), None) => {
                failures.push(format!(
                    "{}: expected {}/{:?}, got unclassified",
                    case.path, want.family, want.role
                ));
                continue;
            }
            (Some(want), Some(q)) => {
                let mut check = |what: &str, expect: &str, got: &str| {
                    if expect != got {
                        failures.push(format!(
                            "{}: {what} mismatch: want {expect:?}, got {got:?}",
                            case.path
                        ));
                    }
                };
                check("family", &want.family, family_name(q.family));
                check(
                    "role",
                    want.role.as_deref().unwrap_or("<none>"),
                    q.role.map(role_name).unwrap_or("<none>"),
                );
                check(
                    "ext",
                    want.ext.as_deref().unwrap_or("<none>"),
                    q.ext.as_deref().unwrap_or("<none>"),
                );
                check("inbound_layout", &want.inbound_layout, q.inbound_layout.name());
                check(
                    "ident",
                    want.ident.as_deref().unwrap_or("<none>"),
                    q.ident.as_deref().unwrap_or("<none>"),
                );
                check(
                    "source_path",
                    want.source_path.as_deref().unwrap_or("<none>"),
                    q.source_path.as_deref().unwrap_or("<none>"),
                );

                if let Some(want_render) = &case.render {
                    let got_sym = render(LayoutKind::Symstore, &goldens.bases.symstore, q);
                    let got_dbg = render(LayoutKind::Debuginfod, &goldens.bases.debuginfod, q);
                    if got_sym != want_render.symstore {
                        failures.push(format!(
                            "{}: symstore render: want {:?}, got {:?}",
                            case.path, want_render.symstore, got_sym
                        ));
                    }
                    if got_dbg != want_render.debuginfod {
                        failures.push(format!(
                            "{}: debuginfod render: want {:?}, got {:?}",
                            case.path, want_render.debuginfod, got_dbg
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} golden mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
