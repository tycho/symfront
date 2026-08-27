//! CLI subcommands for managing the auth database (`symfront user`,
//! `symfront token`).

use std::io::IsTerminal;
use std::path::Path;

use anyhow::{bail, Result};
use clap::Subcommand;

use crate::auth::{AuthDb, Role};

#[derive(Subcommand)]
pub enum UserCommand {
    /// Create a user. Prompts for a password unless --no-password.
    Add {
        name: String,
        #[arg(long, value_enum, default_value_t = Role::Rw)]
        role: Role,
        /// Token-only user (no web login) — for headless clients.
        #[arg(long)]
        no_password: bool,
    },
    /// List users.
    List,
    /// Remove a user (revokes their tokens and sessions).
    Rm { name: String },
    /// Set a user's password.
    Passwd { name: String },
    /// Change a user's role.
    Role {
        name: String,
        #[arg(value_enum)]
        role: Role,
    },
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Create an API token for a user. The token is printed exactly once.
    Create {
        user: String,
        /// Free-form note, e.g. "ci uploads".
        #[arg(long, default_value = "")]
        label: String,
        /// Token capability (further capped by the user's role).
        #[arg(long, value_enum, default_value_t = Role::Rw)]
        cap: Role,
    },
    /// List tokens (hashes only; plaintext is never stored).
    List,
    /// Revoke a token by id (see `token list`).
    Revoke { id: i64 },
}

/// Read a password: interactive prompt on a tty, first line of stdin
/// otherwise (for scripting).
fn read_password(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password(format!("{prompt}: "))?;
        let second = rpassword::prompt_password("repeat: ")?;
        if first != second {
            bail!("passwords do not match");
        }
        Ok(first)
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

fn ts(secs: i64) -> String {
    // Render as UTC date without pulling in chrono: days since epoch is
    // enough precision for token bookkeeping.
    let days = secs / 86400;
    let (mut y, mut rem) = (1970i64, days);
    loop {
        let len = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 366 } else { 365 };
        if rem < len {
            break;
        }
        rem -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let months = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0;
    while rem >= months[m] {
        rem -= months[m];
        m += 1;
    }
    format!("{y}-{:02}-{:02}", m + 1, rem + 1)
}

pub fn user(db_path: &Path, cmd: UserCommand) -> Result<()> {
    let db = AuthDb::open(db_path)?;
    match cmd {
        UserCommand::Add {
            name,
            role,
            no_password,
        } => {
            let password = if no_password {
                None
            } else {
                Some(read_password(&format!("password for {name}"))?)
            };
            db.add_user(&name, password.as_deref(), role)?;
            println!(
                "created user {name} (role {role}{})",
                if no_password { ", token-only" } else { "" }
            );
        }
        UserCommand::List => {
            let users = db.list_users()?;
            if users.is_empty() {
                println!("no users; create one with `symfront user add <name>`");
            }
            for u in users {
                println!(
                    "{:<20} {:<6} {}  {} token(s)",
                    u.name,
                    u.role.to_string(),
                    if u.has_password { "password" } else { "token-only" },
                    u.tokens
                );
            }
        }
        UserCommand::Rm { name } => {
            db.remove_user(&name)?;
            println!("removed user {name}");
        }
        UserCommand::Passwd { name } => {
            let password = read_password(&format!("new password for {name}"))?;
            db.set_password(&name, &password)?;
            println!("password updated for {name}");
        }
        UserCommand::Role { name, role } => {
            db.set_role(&name, role)?;
            println!("role of {name} set to {role}");
        }
    }
    Ok(())
}

pub fn token(db_path: &Path, cmd: TokenCommand) -> Result<()> {
    let db = AuthDb::open(db_path)?;
    match cmd {
        TokenCommand::Create { user, label, cap } => {
            let token = db.create_token(&user, &label, cap)?;
            println!("{token}");
            eprintln!("(shown once — store it now; use as `Authorization: Bearer <token>`)");
        }
        TokenCommand::List => {
            let tokens = db.list_tokens(None)?;
            if tokens.is_empty() {
                println!("no tokens");
            }
            for t in tokens {
                println!(
                    "{:<4} {:<20} {:<4} created {}  last used {}  {}",
                    t.id,
                    t.user,
                    t.cap.to_string(),
                    ts(t.created_at),
                    t.last_used_at.map(ts).unwrap_or_else(|| "never".into()),
                    t.label
                );
            }
        }
        TokenCommand::Revoke { id } => {
            db.revoke_token(id, None)?;
            println!("revoked token {id}");
        }
    }
    Ok(())
}
