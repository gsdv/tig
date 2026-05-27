//! `tigd` binary entrypoint.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "tigd", version, about = "tig daemon — HTTP API for one tig repo")]
struct Cli {
    /// Path to the repo working directory (the parent of `.tig/`) or
    /// directly to the `.tig/` directory itself.
    repo: PathBuf,

    /// Address to bind. Defaults to a local-only port.
    #[arg(long, default_value = "127.0.0.1:7400")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let repo_root = if cli.repo.ends_with(tig_store::TIG_DIR) {
        cli.repo
    } else {
        cli.repo.join(tig_store::TIG_DIR)
    };

    tigd::serve(tigd::ServerConfig {
        repo_root,
        bind: cli.bind,
    })
    .await
}
