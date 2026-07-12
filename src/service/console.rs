//! The core run-loop body, shared by both the console dev/CI path (`connect`
//! CLI subcommand) and the real Windows-Service-invoked path (see
//! `service::scm`). There is exactly one control-flow implementation, not
//! two.
//!
//! This bridges the sync CLI/SCM entry points to the async phone-home loop
//! (`crate::phonehome::run_forever`) with a dedicated Tokio runtime — the
//! rest of the crate stays synchronous; only the networking layer is async.

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::{
    commands::build_default_registry,
    config::OrchestratorConfig,
    phonehome,
    powershell::{PowerShellExecutor, RealPowerShell},
};

pub fn run_loop(config: &OrchestratorConfig) -> Result<()> {
    let registry = Arc::new(build_default_registry());
    let shell: Arc<dyn PowerShellExecutor> =
        Arc::new(RealPowerShell::new(config.execution.shell_binary.clone()));

    tracing::info!(
        vm_id = %config.identity.vm_id,
        command_count = registry.len(),
        "orchestrator connecting to backend"
    );

    let runtime = tokio::runtime::Runtime::new()
        .context("building the phone-home tokio runtime")?;
    runtime.block_on(phonehome::run_forever(config, registry, shell))
}
