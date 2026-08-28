//! Remote mode: the same CLI verbs, executed against a symfront server's
//! HTTP API. Selected by `--server` / `SYMFRONT_SERVER`.
//!
//! Authentication precedence: an API token (`--token` / `SYMFRONT_TOKEN`)
//! wins over a stored login session — tokens have indefinite lifetime, so
//! automation keeps working even when someone also happens to be logged in.
//! `symfront login` exists so a human can tinker without minting a token;
//! sessions are stored per-server in `~/.config/symfront/sessions.json`.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde_json::{json, Value};

use crate::cli::human;
use symfront_store::TransactionId;

pub enum Credentials {
    Token(String),
    Session(String),
    None,
}

fn sessions_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            home.join(".config")
        });
    base.join("symfront").join("sessions.json")
}

fn load_sessions() -> HashMap<String, Value> {
    std::fs::read(sessions_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_sessions(sessions: &HashMap<String, Value>) -> Result<()> {
    let path = sessions_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(sessions)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn norm(server: &str) -> String {
    server.trim_end_matches('/').to_string()
}

impl Credentials {
    /// Token (CLI flag or env, already merged by clap) beats stored session.
    pub fn resolve(server: &str, token: Option<String>) -> Result<Credentials> {
        if let Some(t) = token {
            return Ok(Credentials::Token(t));
        }
        let sessions = load_sessions();
        if let Some(entry) = sessions.get(&norm(server)) {
            if let Some(s) = entry.get("session").and_then(|v| v.as_str()) {
                return Ok(Credentials::Session(s.to_string()));
            }
        }
        Ok(Credentials::None)
    }
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(None) // uploads and job polling can be long
        .build()?)
}

fn apply_creds(
    req: reqwest::blocking::RequestBuilder,
    creds: &Credentials,
) -> reqwest::blocking::RequestBuilder {
    match creds {
        Credentials::Token(t) => req.bearer_auth(t),
        Credentials::Session(s) => req.header("Cookie", format!("symfront_session={s}")),
        Credentials::None => req,
    }
}

fn parse_response(resp: reqwest::blocking::Response) -> Result<Value> {
    let status = resp.status();
    let body: Value = resp.json().unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        let msg = body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("request failed");
        if status == reqwest::StatusCode::UNAUTHORIZED {
            bail!("{msg} (use `symfront login --server …` or provide --token)");
        }
        bail!("{msg} (HTTP {status})");
    }
    Ok(body)
}

fn get(server: &str, creds: &Credentials, path: &str) -> Result<Value> {
    let c = client()?;
    parse_response(apply_creds(c.get(format!("{}{path}", norm(server))), creds).send()?)
}

fn post(server: &str, creds: &Credentials, path: &str, body: &Value) -> Result<Value> {
    let c = client()?;
    parse_response(
        apply_creds(c.post(format!("{}{path}", norm(server))), creds)
            .json(body)
            .send()?,
    )
}

fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

// ---------- login / logout ----------

pub fn login(server: &str) -> Result<()> {
    let username = prompt_line("username: ")?;
    let password = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("password: ")?
    } else {
        prompt_line("")?
    };
    let c = client()?;
    let resp = c
        .post(format!("{}/api/login", norm(server)))
        .json(&json!({ "username": username, "password": password }))
        .send()?;
    let (resp, body) = {
        let status = resp.status();
        let headers = resp.headers().clone();
        let body: Value = resp.json().unwrap_or_else(|_| json!({}));
        if !status.is_success() {
            bail!(
                "{}",
                body.get("error").and_then(|e| e.as_str()).unwrap_or("login failed")
            );
        }
        (headers, body)
    };
    let (headers, body) = if body.get("totp_required").and_then(|v| v.as_bool()) == Some(true) {
        let code = prompt_line("authenticator code: ")?;
        let login_token = body
            .get("login_token")
            .and_then(|v| v.as_str())
            .context("malformed server response")?;
        let resp = c
            .post(format!("{}/api/login/totp", norm(server)))
            .json(&json!({ "login_token": login_token, "code": code }))
            .send()?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body: Value = resp.json().unwrap_or_else(|_| json!({}));
        if !status.is_success() {
            bail!(
                "{}",
                body.get("error").and_then(|e| e.as_str()).unwrap_or("login failed")
            );
        }
        (headers, body)
    } else {
        (resp, body)
    };

    let session = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            c.split(';')
                .next()
                .and_then(|kv| kv.trim().strip_prefix("symfront_session="))
                .map(str::to_string)
        })
        .context("server did not set a session cookie")?;
    let user = body.get("user").and_then(|v| v.as_str()).unwrap_or("?");
    let role = body.get("role").and_then(|v| v.as_str()).unwrap_or("?");
    let mut sessions = load_sessions();
    sessions.insert(
        norm(server),
        json!({ "session": session, "user": user, "role": role }),
    );
    save_sessions(&sessions)?;
    println!("logged in to {} as {user} ({role})", norm(server));
    println!("note: an API token (--token / SYMFRONT_TOKEN) takes precedence over this session");
    Ok(())
}

pub fn logout(server: &str) -> Result<()> {
    let mut sessions = load_sessions();
    if let Some(entry) = sessions.remove(&norm(server)) {
        if let Some(s) = entry.get("session").and_then(|v| v.as_str()) {
            let _ = post(
                server,
                &Credentials::Session(s.to_string()),
                "/api/logout",
                &json!({}),
            );
        }
        save_sessions(&sessions)?;
        println!("logged out of {}", norm(server));
    } else {
        println!("no stored session for {}", norm(server));
    }
    Ok(())
}

// ---------- read commands ----------

pub fn status(server: &str, creds: &Credentials) -> Result<()> {
    let s = get(server, creds, "/api/summary")?;
    println!("server:       {}", norm(server));
    println!("store:        {}", s["store"].as_str().unwrap_or("?"));
    println!(
        "last id:      {}",
        s["lastid"].as_u64().map(|i| format!("{:010}", i)).unwrap_or_else(|| "?".into())
    );
    println!(
        "transactions: {} active, {} deleted",
        s["transactions_active"], s["transactions_deleted"]
    );
    println!("entries:      {} indexed files", s["entries"]);
    if let Some(t) = s["scan"]["totals"].as_object() {
        println!(
            "size:         {} apparent, {} on disk",
            human(t["apparent"].as_u64().unwrap_or(0)),
            human(t["disk"].as_u64().unwrap_or(0))
        );
    }
    Ok(())
}

pub fn search(server: &str, creds: &Credentials, query: &str, limit: usize) -> Result<()> {
    let s = get(
        server,
        creds,
        &format!("/api/search?q={}&limit={limit}", urlenc(query)),
    )?;
    let hits = s["hits"].as_array().cloned().unwrap_or_default();
    if hits.is_empty() {
        println!("no matches");
        return Ok(());
    }
    for h in &hits {
        println!(
            "{}/{}  tx {:010} ({} {})  <- {}",
            h["name"].as_str().unwrap_or(""),
            h["hash"].as_str().unwrap_or(""),
            h["tx"].as_u64().unwrap_or(0),
            h["product"].as_str().unwrap_or("?"),
            h["version"].as_str().unwrap_or(""),
            h["source"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

pub fn tx_list(server: &str, creds: &Credentials, all: bool) -> Result<()> {
    let s = get(server, creds, "/api/transactions")?;
    println!(
        "{:>10}  {:<10} {:>7}  {:>10} {:>10}  {:<28} {}",
        "id", "date", "entries", "apparent", "exclusive", "product", "version"
    );
    for t in s["transactions"].as_array().cloned().unwrap_or_default() {
        let active = t["active"].as_bool().unwrap_or(false);
        if !all && !active {
            continue;
        }
        let sizes = &t["sizes"];
        println!(
            "{}  {:<10} {:>7}  {:>10} {:>10}  {:<28} {}{}",
            t["id_str"].as_str().unwrap_or(""),
            t["record"]["date"].as_str().unwrap_or(""),
            t["entry_count"].as_u64().unwrap_or(0),
            sizes["apparent"].as_u64().map(human).unwrap_or_else(|| "…".into()),
            sizes["exclusive_apparent"].as_u64().map(human).unwrap_or_default(),
            t["record"]["product"].as_str().unwrap_or("—"),
            t["record"]["version"].as_str().unwrap_or(""),
            if active { "" } else { " [inactive]" },
        );
    }
    Ok(())
}

pub fn tx_show(server: &str, creds: &Credentials, id: TransactionId) -> Result<()> {
    let t = get(server, creds, &format!("/api/transactions/{}", id.0))?;
    println!("transaction {id}");
    println!("  product: {}", t["record"]["product"].as_str().unwrap_or("—"));
    println!("  version: {}", t["record"]["version"].as_str().unwrap_or(""));
    println!(
        "  added:   {} {}",
        t["record"]["date"].as_str().unwrap_or(""),
        t["record"]["time"].as_str().unwrap_or("")
    );
    let entries = t["entries"].as_array().cloned().unwrap_or_default();
    println!("  entries: {}", entries.len());
    for e in &entries {
        println!(
            "{:>12}  {}/{}{}   <- {}",
            e["apparent"].as_u64().map(human).unwrap_or_default(),
            e["name"].as_str().unwrap_or(""),
            e["hash"].as_str().unwrap_or(""),
            if e["present"].as_bool() == Some(false) { "  [MISSING]" } else { "" },
            e["source"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

pub fn tx_del(
    server: &str,
    creds: &Credentials,
    id: TransactionId,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    if !dry_run && !yes {
        let typed = prompt_line(&format!("delete transaction {id} on {}? type the id to confirm: ", norm(server)))?;
        if typed != id.to_string() && typed != id.0.to_string() {
            bail!("aborted");
        }
    }
    let c = client()?;
    let resp = apply_creds(
        c.delete(format!(
            "{}/api/transactions/{}?dry_run={dry_run}",
            norm(server),
            id.0
        )),
        creds,
    )
    .send()?;
    let body = parse_response(resp)?;
    if dry_run {
        println!(
            "would delete {id}: {} files, {} freed",
            body["files_removed"],
            human(body["freed_apparent"].as_u64().unwrap_or(0))
        );
    } else if let Some(job) = body["job"].as_u64() {
        let outcome = wait_for_job(server, creds, job)?;
        println!(
            "deleted {id}: {} files removed, {} apparent / {} on disk freed",
            outcome["files_removed"],
            human(outcome["freed_apparent"].as_u64().unwrap_or(0)),
            human(outcome["freed_disk"].as_u64().unwrap_or(0))
        );
    }
    Ok(())
}

// ---------- upload ----------

pub fn upload(
    server: &str,
    creds: &Credentials,
    paths: &[PathBuf],
    product: &str,
    version: &str,
    comment: &str,
    dry_run: bool,
    jobs: usize,
) -> Result<()> {
    if paths.is_empty() {
        bail!("no paths given");
    }
    let (candidates, skipped) = symfront_ident::collect(paths)?;
    for s in &skipped {
        println!("skipped (not a PE or PDB): {}", s.display());
    }
    if candidates.is_empty() {
        bail!("no identifiable PE/PDB files found");
    }
    println!("{} file(s) identified", candidates.len());
    if dry_run {
        for c in &candidates {
            println!("  {:?}  {}/{}  <- {}", c.kind, c.name, c.hash, c.path.display());
        }
        return Ok(());
    }

    let begin = post(
        server,
        creds,
        "/api/upload/begin",
        &json!({ "product": product, "version": version, "comment": comment }),
    )?;
    let upload_id = begin["upload_id"]
        .as_str()
        .context("malformed server response")?
        .to_string();

    // Ask which payloads the store already has and skip those uploads.
    let check_body = json!({
        "files": candidates.iter().map(|c| json!({ "name": c.name, "hash": c.hash })).collect::<Vec<_>>()
    });
    // Skip payloads the store already has, and (on resume) already-staged ones.
    let check_resp = post(
        server,
        creds,
        &format!("/api/upload/{upload_id}/check"),
        &check_body,
    )?;
    let present = check_resp["present"].as_array().cloned().unwrap_or_default();
    let staged = check_resp["staged"].as_array().cloned();
    let todo: Vec<usize> = (0..candidates.len())
        .filter(|i| {
            present.get(*i).and_then(|v| v.as_bool()) != Some(true)
                && staged
                    .as_ref()
                    .and_then(|s| s.get(*i))
                    .and_then(|v| v.as_bool())
                    != Some(true)
        })
        .collect();
    let deduped = candidates.len() - todo.len();

    // Upload in parallel: symbol files are many and independent, so a few
    // concurrent streams fill fast LANs far better than one.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let http = client()?;
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let failure: std::sync::Mutex<Option<anyhow::Error>> = std::sync::Mutex::new(None);
    let workers = jobs.clamp(1, 16).min(todo.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                if failure.lock().unwrap().is_some() {
                    return;
                }
                let k = next.fetch_add(1, Ordering::SeqCst);
                let Some(&i) = todo.get(k) else { return };
                let c = &candidates[i];
                let result = (|| -> Result<()> {
                    let file = std::fs::File::open(&c.path)?;
                    let resp = apply_creds(
                        http.post(format!(
                            "{}/api/upload/{upload_id}/file?name={}&hash={}&source={}",
                            norm(server),
                            urlenc(&c.name),
                            urlenc(&c.hash),
                            urlenc(&c.path.to_string_lossy()),
                        )),
                        creds,
                    )
                    .body(reqwest::blocking::Body::from(file))
                    .send()?;
                    parse_response(resp)
                        .with_context(|| format!("uploading {}", c.path.display()))?;
                    Ok(())
                })();
                match result {
                    Ok(()) => {
                        let d = done.fetch_add(1, Ordering::SeqCst) + 1;
                        eprint!("\r\x1b[Kuploading {d}/{} ({workers} parallel)", todo.len());
                        let _ = std::io::stderr().flush();
                    }
                    Err(e) => {
                        *failure.lock().unwrap() = Some(e);
                        return;
                    }
                }
            });
        }
    });
    eprint!("\r\x1b[K");
    if let Some(e) = failure.into_inner().unwrap() {
        eprintln!("upload interrupted — re-run the same command to resume (staged files are kept)");
        return Err(e);
    }
    println!("{} uploaded, {deduped} already in store/staged", todo.len());

    let commit_body = json!({
        "files": candidates.iter().map(|c| json!({
            "name": c.name, "hash": c.hash,
            "source": c.path.to_string_lossy(),
        })).collect::<Vec<_>>()
    });
    let commit = post(
        server,
        creds,
        &format!("/api/upload/{upload_id}/commit"),
        &commit_body,
    )?;
    let job = commit["job"].as_u64().context("malformed server response")?;
    let outcome = wait_for_job(server, creds, job)?;
    println!(
        "added transaction {:010}: {} new payload(s) ({}), {} deduplicated",
        outcome["id"].as_u64().unwrap_or(0),
        outcome["files_new"],
        human(outcome["bytes_copied"].as_u64().unwrap_or(0)),
        outcome["files_deduped"]
    );
    for w in outcome["warnings"].as_array().cloned().unwrap_or_default() {
        println!("  warning: {}", w.as_str().unwrap_or(""));
    }
    Ok(())
}

fn wait_for_job(server: &str, creds: &Credentials, job: u64) -> Result<Value> {
    loop {
        let j = get(server, creds, &format!("/api/jobs/{job}"))?;
        match j["state"].as_str() {
            Some("running") => {
                let p = &j["progress"];
                eprint!(
                    "\r\x1b[Kserver: {}/{} files, {}",
                    p["done"],
                    p["total"],
                    human(p["freed_apparent"].as_u64().unwrap_or(0))
                );
                let _ = std::io::stderr().flush();
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Some("done") => {
                eprint!("\r\x1b[K");
                return Ok(j["outcome"].clone());
            }
            Some("failed") => {
                eprint!("\r\x1b[K");
                bail!("server job failed: {}", j["error"].as_str().unwrap_or("unknown"));
            }
            _ => bail!("malformed job status"),
        }
    }
}

fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn strays(server: &str, creds: &Credentials, prune: bool, dry_run: bool) -> Result<()> {
    let s = match get(server, creds, "/api/strays") {
        Ok(s) => s,
        Err(e) if e.to_string().contains("scan not finished") => {
            println!("server scan still running; try again shortly");
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let strays = s["strays"]["strays"].as_array().cloned().unwrap_or_default();
    let missing = s["strays"]["missing"].as_array().cloned().unwrap_or_default();
    if strays.is_empty() && missing.is_empty() {
        println!("store is clean: every file is accounted for by an active transaction");
        return Ok(());
    }
    for x in &strays {
        println!(
            "{:>12}  {:<22} {}  ({})",
            human(x["size"].as_u64().unwrap_or(0)),
            x["kind"].as_str().unwrap_or(""),
            x["rel_path"].as_str().unwrap_or(""),
            x["detail"].as_str().unwrap_or("")
        );
    }
    let t = &s["strays"]["totals"];
    println!(
        "\n{} stray files, {} apparent / {} on disk",
        t["files"].as_u64().unwrap_or(0),
        human(t["apparent"].as_u64().unwrap_or(0)),
        human(t["disk"].as_u64().unwrap_or(0))
    );
    for m in &missing {
        println!(
            "MISSING payload: {}/{} (tx {:010})",
            m["name"].as_str().unwrap_or(""),
            m["hash"].as_str().unwrap_or(""),
            m["tx"].as_u64().unwrap_or(0)
        );
    }
    if prune {
        if !dry_run {
            let typed = prompt_line("permanently delete ALL strays listed? type 'prune' to confirm: ")?;
            if typed != "prune" {
                bail!("aborted");
            }
        }
        let r = post(
            server,
            creds,
            "/api/strays/prune",
            &json!({ "all": true, "dry_run": dry_run }),
        )?;
        if dry_run {
            println!(
                "would remove {} files ({})",
                r["files_removed"],
                human(r["freed_apparent"].as_u64().unwrap_or(0))
            );
        } else if let Some(job) = r["job"].as_u64() {
            let outcome = wait_for_job(server, creds, job)?;
            println!(
                "removed {} files and {} dirs, freeing {} apparent / {} on disk",
                outcome["files_removed"],
                outcome["dirs_removed"],
                human(outcome["freed_apparent"].as_u64().unwrap_or(0)),
                human(outcome["freed_disk"].as_u64().unwrap_or(0))
            );
        }
    } else if !strays.is_empty() {
        println!("\nrun with --prune to remove these (add --dry-run to preview)");
    }
    Ok(())
}

pub fn check(server: &str, creds: &Credentials) -> Result<()> {
    let d = get(server, creds, "/api/check")?;
    let mut rows: Vec<Value> = d["admin"].as_array().cloned().unwrap_or_default();
    let deep_ran = !d["deep"].is_null();
    rows.extend(d["deep"].as_array().cloned().unwrap_or_default());
    let missing = d["missing_payloads"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() && missing.is_empty() {
        println!(
            "no problems found{}",
            if deep_ran { "" } else { " (deep results pending; server scan still running)" }
        );
        return Ok(());
    }
    for f in &rows {
        println!(
            "{:<7} {:<20} {}: {}",
            f["severity"].as_str().unwrap_or(""),
            f["code"].as_str().unwrap_or(""),
            f["subject"].as_str().unwrap_or(""),
            f["message"].as_str().unwrap_or("")
        );
    }
    for m in &missing {
        println!(
            "error   missing-payload      {}/{}: recorded by tx {:010} but not on disk",
            m["name"].as_str().unwrap_or(""),
            m["hash"].as_str().unwrap_or(""),
            m["tx"].as_u64().unwrap_or(0)
        );
    }
    Ok(())
}
