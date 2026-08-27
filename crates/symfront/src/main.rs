mod auth;
mod cli;
mod cli_auth;
mod symbols;
mod totp;
mod web;
mod web_account;

use clap::{Parser, Subcommand};
use symfront_core::TransactionId;

/// Manage a Windows NT symbol store on a POSIX host.
#[derive(Parser)]
#[command(name = "symfront", version, about)]
struct Args {
    /// Path to the symbol store root.
    #[arg(long, global = true, env = "SYMFRONT_STORE", default_value = "/srv/symstore")]
    store: std::path::PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the web UI / HTTP API server.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:8710")]
        listen: String,
        /// SQLite auth database; enables authentication. Manage users with
        /// `symfront user` / `symfront token`. Without this the server is open.
        #[arg(long, env = "SYMFRONT_AUTH_DB")]
        auth_db: Option<std::path::PathBuf>,
        /// Public origin for WebAuthn/passkeys, e.g. https://syms.example.com.
        /// Defaults to http://localhost:<port>. Browsers require a secure
        /// context: localhost, or HTTPS via a reverse proxy.
        #[arg(long, env = "SYMFRONT_WEBAUTHN_ORIGIN")]
        webauthn_origin: Option<String>,
        /// Number of trusted reverse-proxy hops. When > 0, the client IP for
        /// audit logs is taken from X-Forwarded-For (capped at this depth)
        /// and X-Forwarded-Proto: https marks session cookies Secure.
        #[arg(long, default_value_t = 0, env = "SYMFRONT_TRUSTED_PROXIES")]
        trusted_proxies: usize,
        /// Serve the store read-only (no browsing) at /symbols/ for
        /// dbghelp/symsrv HTTP clients. Always unauthenticated.
        #[arg(long)]
        serve_symbols: bool,
        /// With --serve-symbols: forward local misses to this upstream symbol
        /// server and proxy the response through (repeatable, tried in order).
        /// Example: --upstream https://msdl.microsoft.com/download/symbols
        #[arg(long)]
        upstream: Vec<String>,
    },
    /// Create an empty symbol store at --store (000Admin/ and pingme.txt).
    Init,
    /// Quick store summary (admin records only; no tree walk).
    Status,
    /// List transactions.
    Tx {
        #[command(subcommand)]
        command: TxCommand,
    },
    /// Search indexed files by name substring, hash prefix, or source path.
    Search {
        query: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Detect stray files not accounted for by any active transaction.
    Strays {
        /// Delete the strays found.
        #[arg(long)]
        prune: bool,
        /// With --prune: show what would be removed without removing it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Consistency checks over the admin records (and refs.ptr with --deep).
    Check {
        /// Also read every refs.ptr and cross-check against the manifests.
        #[arg(long)]
        deep: bool,
    },
    /// Manage users in the auth database.
    User {
        /// SQLite auth database (created on first use).
        #[arg(long, env = "SYMFRONT_AUTH_DB")]
        auth_db: std::path::PathBuf,
        #[command(subcommand)]
        command: cli_auth::UserCommand,
    },
    /// Manage API tokens in the auth database.
    Token {
        /// SQLite auth database (created on first use).
        #[arg(long, env = "SYMFRONT_AUTH_DB")]
        auth_db: std::path::PathBuf,
        #[command(subcommand)]
        command: cli_auth::TokenCommand,
    },
}

#[derive(Subcommand)]
enum TxCommand {
    /// List transactions (active by default).
    List {
        /// Include deleted and anomalous transactions.
        #[arg(long)]
        all: bool,
        /// Walk the tree to compute per-transaction sizes.
        #[arg(long)]
        sizes: bool,
    },
    /// Show one transaction in detail (walks the tree for sizes).
    Show { id: TransactionId },
    /// Delete a transaction (like `symstore del`).
    Del {
        id: TransactionId,
        /// Show what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "symfront=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();
    match args.command {
        Command::Serve {
            listen,
            auth_db,
            webauthn_origin,
            trusted_proxies,
            serve_symbols,
            upstream,
        } => web::serve(
            args.store,
            listen,
            auth_db,
            webauthn_origin,
            trusted_proxies,
            serve_symbols,
            upstream,
        ),
        Command::Init => cli::init(&args.store),
        Command::Status => cli::status(&args.store),
        Command::Tx { command } => match command {
            TxCommand::List { all, sizes } => cli::tx_list(&args.store, all, sizes),
            TxCommand::Show { id } => cli::tx_show(&args.store, id),
            TxCommand::Del { id, dry_run, yes } => cli::tx_del(&args.store, id, dry_run, yes),
        },
        Command::Search { query, limit } => cli::search(&args.store, &query, limit),
        Command::Strays { prune, dry_run } => cli::strays(&args.store, prune, dry_run),
        Command::Check { deep } => cli::check(&args.store, deep),
        Command::User { auth_db, command } => cli_auth::user(&auth_db, command),
        Command::Token { auth_db, command } => cli_auth::token(&auth_db, command),
    }
}
