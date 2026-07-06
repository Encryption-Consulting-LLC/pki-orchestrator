use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = pki_orchestrator::cli::Cli::parse();
    pki_orchestrator::cli::run(cli)
}
