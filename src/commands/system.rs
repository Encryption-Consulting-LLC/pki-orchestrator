//! System-level commands (Phase L).
//!
//! `system.reboot` is the one command whose *success* looks like a dropped
//! connection: rebooting cmdlets in this catalog never self-reboot
//! (`Install-ADDSForest -NoRebootOnCompletion`, `Add-Computer` without
//! `-Restart`) — the backend sequence engine dispatches this as a separate
//! step it marks `expects_disconnect`, then waits for the agent's next
//! phone-home. The `shutdown /r /t <delay>` grace window is what lets the
//! done-frame flush over the socket before the OS goes down.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{invalid, param, require_success},
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `shutdown /r /t <delaySeconds>` — schedule a reboot and report done.
pub struct SystemReboot;

impl CommandHandler for SystemReboot {
    fn name(&self) -> &'static str {
        "system.reboot"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let delay = param(ctx, "delaySeconds").unwrap_or("10");
        match delay.parse::<u32>() {
            Ok(d) if (5..=120).contains(&d) => {}
            _ => {
                return Err(invalid(
                    "delaySeconds",
                    "must be an integer in 5-120",
                ));
            }
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "scheduling reboot",
            50.0,
        ));

        let script = "param([string]$Delay) \
            shutdown /r /t $Delay /c 'pki-orchestrator plan reboot'; \
            exit $LASTEXITCODE";
        let output =
            require_success(ctx.shell.run(script, &[delay.to_string()])?)?;
        drop(output);

        let result = json!({ "rebooting": true, "delay_seconds": delay });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{powershell::MockPowerShell, report::NullProgressSink};
    use std::{collections::HashMap, sync::Arc};

    fn ctx_params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn reboot_defaults_to_ten_seconds() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = SystemReboot.execute(&ctx).unwrap();
        assert_eq!(result["rebooting"], true);
        assert_eq!(result["delay_seconds"], "10");
    }

    #[test]
    fn reboot_rejects_out_of_range_delay() {
        for delay in ["0", "3", "300", "-1", "ten"] {
            let params = ctx_params(&[("delaySeconds", delay)]);
            let sink = NullProgressSink;
            let ctx = CommandContext {
                params: &params,
                progress: &sink,
                shell: Arc::new(MockPowerShell::new()),
            };
            assert!(matches!(
                SystemReboot.execute(&ctx),
                Err(CommandError::InvalidParam { .. })
            ));
        }
    }

    #[test]
    fn reboot_propagates_shutdown_failure() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "Access is denied.(5)");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            SystemReboot.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }
}
