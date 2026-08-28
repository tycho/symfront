mod auth;
mod cli;
mod cli_auth;
mod cli_proxy;
mod config;
mod config_store;
mod pipeline;
mod proxy_admin;
mod remote;
mod symbols;
mod totp;
mod web;
mod web_account;
mod web_upload;

use clap::{Parser, Subcommand};
use symfront_store::TransactionId;

/// Manage a Windows NT symbol store on a POSIX host.
#[derive(Parser)]
#[command(name = "symfront", version, about)]
struct Args {
    /// Configuration tree directory (server/store/proxy/upstreams/blacklist
    /// TOML files). Missing directory = flag-only operation.
    #[arg(
        long,
        global = true,
        env = "SYMFRONT_CONFIG_DIR",
        default_value = "/etc/symfront"
    )]
    config_dir: std::path::PathBuf,

    /// Path to the symbol store root (local mode). Overrides store.toml;
    /// defaults to /srv/symstore.
    #[arg(long, global = true, env = "SYMFRONT_STORE")]
    store: Option<std::path::PathBuf>,

    /// symfront server URL — switches supported commands to remote mode
    /// (status, search, tx list/show/del, upload).
    #[arg(long, global = true, env = "SYMFRONT_SERVER")]
    server: Option<String>,

    /// API token for remote mode. Takes precedence over a stored login
    /// session (tokens have indefinite lifetime).
    #[arg(long, global = true, env = "SYMFRONT_TOKEN")]
    token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the web UI / HTTP API server.
    Serve {
        /// TCP address to listen on. Overrides server.toml; defaults to
        /// 127.0.0.1:8710.
        #[arg(long)]
        listen: Option<String>,
        /// Unix domain socket to listen on instead of TCP (Unix only).
        /// Overrides server.toml.
        #[cfg_attr(unix, arg(long))]
        #[cfg_attr(not(unix), arg(long, hide = true))]
        uds: Option<std::path::PathBuf>,
        /// Socket file mode for --uds, octal (e.g. 0666). Overrides
        /// server.toml; default is umask-derived.
        #[cfg_attr(unix, arg(long))]
        #[cfg_attr(not(unix), arg(long, hide = true))]
        uds_mode: Option<String>,
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
        #[arg(long, env = "SYMFRONT_TRUSTED_PROXIES")]
        trusted_proxies: Option<usize>,
        /// Serve only the symbol pipeline: no admin UI/API/auth. The store
        /// (if present) is tier 0, read-only; the proxy config comes from
        /// the config tree.
        #[arg(long)]
        proxy_only: bool,
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
    /// Add files to the store as one transaction (like `symstore add`):
    /// recursively identifies PE binaries of any kind and PDBs by content.
    /// Local against --store, or remote against --server.
    Upload {
        /// Files and/or directories to scan.
        paths: Vec<std::path::PathBuf>,
        /// Product name recorded in the transaction.
        #[arg(long, short = 't')]
        product: String,
        /// Version recorded in the transaction.
        #[arg(long, short = 'v', default_value = "")]
        version: String,
        /// Comment recorded in the transaction.
        #[arg(long, short = 'c', default_value = "")]
        comment: String,
        /// Identify and report without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Parallel upload streams (remote mode).
        #[arg(long, short = 'j', default_value_t = 4)]
        jobs: usize,
    },
    /// Sign in to a --server and store the session locally.
    Login,
    /// Sign out of a --server and forget the stored session.
    Logout,
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
    /// Caching-proxy operations (cache summary, maintenance, import).
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
    /// Inspect and manage the configuration tree (git-backed history).
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
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
enum ProxyCommand {
    /// Cache summary (local) or live request/upstream stats (--server).
    Stats,
    /// Upstream health/enabled table (requires --server).
    Health,
    /// Run a size-budget eviction pass now.
    Evict,
    /// Patrol scrub: cross-check metadata against the data tree.
    Scrub {
        /// Only report; don't delete anything.
        #[arg(long)]
        report_only: bool,
    },
    /// One-shot import of a Python symsrv cache (metadata + payloads).
    Import {
        /// The symsrv cache root (containing db/ and storage/data/).
        from: std::path::PathBuf,
        /// Copy payload files instead of hardlinking.
        #[arg(long)]
        copy: bool,
        /// Walk and report without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Create the config directory with a commented starter tree (files that
    /// already exist are left untouched) and initialize its history repo.
    Init,
    /// Show the config change history.
    Log {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Show a diff: no args = uncommitted changes vs HEAD; one rev = that
    /// commit vs the working tree; two revs = between commits.
    Diff {
        from: Option<String>,
        to: Option<String>,
    },
    /// Restore the tree to an earlier commit (recorded as a new commit).
    Rollback { rev: String },
    /// Ask a running server to reload its config tree (requires --server;
    /// locally, send the server SIGHUP instead).
    Reload,
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

/// Parse a socket mode like "0666" / "666" / "0o666" (always octal).
fn parse_octal_mode(s: &str) -> anyhow::Result<u32> {
    let digits = s.trim().trim_start_matches("0o");
    let mode = u32::from_str_radix(digits, 8)
        .map_err(|_| anyhow::anyhow!("bad socket mode {s:?} (expected octal like \"0666\")"))?;
    if mode > 0o777 {
        anyhow::bail!("bad socket mode {s:?} (expected octal like \"0666\")");
    }
    Ok(mode)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // The config tree is optional; flags override anything it says.
    let cfg = config::ConfigTree::load(&args.config_dir)?;

    // Log filter precedence: RUST_LOG > server.toml log_filter > default.
    let default_filter = cfg
        .server
        .log_filter
        .clone()
        .unwrap_or_else(|| "symfront=info,tower_http=info".into());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.into()),
        )
        .init();

    // Remote mode: --server routes supported commands through the HTTP API.
    if let Some(server) = &args.server {
        let creds = remote::Credentials::resolve(server, args.token.clone())?;
        match args.command {
            Command::Login => return remote::login(server),
            Command::Logout => return remote::logout(server),
            Command::Status => return remote::status(server, &creds),
            Command::Search { query, limit } => {
                return remote::search(server, &creds, &query, limit)
            }
            Command::Tx { command } => match command {
                TxCommand::List { all, sizes: _ } => return remote::tx_list(server, &creds, all),
                TxCommand::Show { id } => return remote::tx_show(server, &creds, id),
                TxCommand::Del { id, dry_run, yes } => {
                    return remote::tx_del(server, &creds, id, dry_run, yes)
                }
            },
            Command::Upload {
                paths,
                product,
                version,
                comment,
                dry_run,
                jobs,
            } => {
                return remote::upload(
                    server,
                    &creds,
                    &remote::UploadRequest {
                        paths: &paths,
                        product: &product,
                        version: &version,
                        comment: &comment,
                        dry_run,
                        jobs,
                    },
                )
            }
            Command::Strays { prune, dry_run } => {
                return remote::strays(server, &creds, prune, dry_run)
            }
            Command::Check { deep: _ } => return remote::check(server, &creds),
            Command::Proxy { command } => match command {
                ProxyCommand::Stats => return remote::proxy_stats(server, &creds),
                ProxyCommand::Health => return remote::proxy_health(server, &creds),
                ProxyCommand::Evict => return remote::proxy_evict(server, &creds),
                ProxyCommand::Scrub { report_only } => {
                    return remote::proxy_scrub(server, &creds, !report_only)
                }
                ProxyCommand::Import { .. } => {
                    anyhow::bail!("proxy import is local-only; run it on the server host")
                }
            },
            Command::Config {
                command: ConfigCommand::Reload,
            } => return remote::config_reload(server, &creds),
            _ => anyhow::bail!(
                "this command is local-only; drop --server or run it on the server host"
            ),
        }
    }

    // Store path precedence: --store > store.toml > /srv/symstore.
    let store = args
        .store
        .clone()
        .or_else(|| cfg.store.path.clone())
        .unwrap_or_else(|| "/srv/symstore".into());

    match args.command {
        Command::Login | Command::Logout => {
            anyhow::bail!("login/logout need --server (or SYMFRONT_SERVER)")
        }
        Command::Upload {
            paths,
            product,
            version,
            comment,
            dry_run,
            jobs: _,
        } => cli::upload(&store, &paths, &product, &version, &comment, dry_run),
        Command::Serve {
            listen,
            uds,
            uds_mode,
            auth_db,
            webauthn_origin,
            trusted_proxies,
            proxy_only,
        } => {
            // An explicit --listen means "TCP, this address": it must not be
            // silently outranked by a uds= line in server.toml (a uds always
            // beats a listen when both come from the config file).
            let explicit_listen = listen.is_some();
            web::serve(web::ServeOptions {
                store,
                listen: listen
                    .or_else(|| cfg.server.listen.clone())
                    .unwrap_or_else(|| "127.0.0.1:8710".into()),
                uds: uds.or_else(|| {
                    if explicit_listen {
                        None
                    } else {
                        cfg.server.uds.clone()
                    }
                }),
                uds_mode: uds_mode
                    .or_else(|| cfg.server.uds_mode.clone())
                    .map(|m| parse_octal_mode(&m))
                    .transpose()?,
                auth_db: auth_db.or_else(|| cfg.server.auth_db.clone()),
                webauthn_origin: webauthn_origin.or_else(|| cfg.server.webauthn_origin.clone()),
                trusted_proxies: trusted_proxies.or(cfg.server.trusted_proxies).unwrap_or(0),
                proxy_only,
                config_dir: cfg.dir.clone(),
            })
        }
        Command::Init => cli::init(&store),
        Command::Status => cli::status(&store),
        Command::Tx { command } => match command {
            TxCommand::List { all, sizes } => cli::tx_list(&store, all, sizes),
            TxCommand::Show { id } => cli::tx_show(&store, id),
            TxCommand::Del { id, dry_run, yes } => cli::tx_del(&store, id, dry_run, yes),
        },
        Command::Search { query, limit } => cli::search(&store, &query, limit),
        Command::Strays { prune, dry_run } => cli::strays(&store, prune, dry_run),
        Command::Check { deep } => cli::check(&store, deep),
        Command::Proxy { command } => match command {
            ProxyCommand::Stats => cli_proxy::stats(&args.config_dir),
            ProxyCommand::Health => {
                anyhow::bail!("health is a live-server view; use --server (or SYMFRONT_SERVER)")
            }
            ProxyCommand::Evict => cli_proxy::evict(&args.config_dir),
            ProxyCommand::Scrub { report_only } => cli_proxy::scrub(&args.config_dir, !report_only),
            ProxyCommand::Import {
                from,
                copy,
                dry_run,
            } => cli_proxy::import(&args.config_dir, &from, copy, dry_run),
        },
        Command::Config { command } => match command {
            ConfigCommand::Init => cli::config_init(&args.config_dir),
            ConfigCommand::Log { limit } => cli::config_log(&args.config_dir, limit),
            ConfigCommand::Diff { from, to } => {
                cli::config_diff(&args.config_dir, from.as_deref(), to.as_deref())
            }
            ConfigCommand::Rollback { rev } => cli::config_rollback(&args.config_dir, &rev),
            ConfigCommand::Reload => {
                anyhow::bail!("config reload needs --server (or send the local server SIGHUP)")
            }
        },
        Command::User { auth_db, command } => cli_auth::user(&auth_db, command),
        Command::Token { auth_db, command } => cli_auth::token(&auth_db, command),
    }
}
