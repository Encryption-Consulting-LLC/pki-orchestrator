//! Windows Service Control Manager integration. `service install` /
//! `uninstall` register/remove this binary with the SCM; `service run` is
//! what the SCM actually launches (also directly runnable for manual
//! testing on a real Windows box).
//!
//! Windows-only: on any other OS, `handle` returns a clear error rather than
//! silently doing nothing, and the `scm` module is not compiled at all.

use anyhow::{Result, bail};

use crate::cli::ServiceAction;

pub mod console;

#[cfg(windows)]
mod scm;

pub fn handle(action: ServiceAction) -> Result<()> {
    #[cfg(windows)]
    {
        return match action {
            ServiceAction::Install => scm::install(),
            ServiceAction::Uninstall => scm::uninstall(),
            ServiceAction::Run => scm::run(),
        };
    }

    #[cfg(not(windows))]
    {
        let _ = action;
        bail!("service mode is Windows-only — use `run` for local dev/testing")
    }
}
