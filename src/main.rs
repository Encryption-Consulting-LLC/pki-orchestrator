use anyhow::Result;
use clap::Parser;
use pki_orchestrator::cli::{Cli, Command};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Console-path logging only — `service run` sets up its own file-based
    // subscriber in `service::scm` (a Windows Service has no attached
    // console to write to), and must be the only one to call `.init()`.
    if !matches!(cli.command, Command::Service { .. }) {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
    }

    pki_orchestrator::cli::run(cli)
}
