use serde_json::json;

use crate::{
    authz::Capability,
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `[System.Net.Dns]::GetHostName()` — the read half of `hostname.rename`,
/// giving the console read-write parity on the one attribute every template
/// machine carries. Guest-eligible (`Capability::VmRead`) like `cert.verify`:
/// reading a name grants nothing a guest couldn't already see.
pub struct HostnameRead;

impl CommandHandler for HostnameRead {
    fn name(&self) -> &'static str {
        "hostname.read"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress
            .report(crate::report::OpRunState::running("reading", 50.0));

        let script = "[System.Net.Dns]::GetHostName()";
        let output = ctx.shell.run(script, &[])?;
        if !output.succeeded() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: output.exit_code,
                    stderr: output.stderr,
                },
            ));
        }

        let result = json!({ "hostname": output.stdout.trim() });
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

    #[test]
    fn returns_trimmed_hostname() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("CA02\r\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = HostnameRead.execute(&ctx).unwrap();
        assert_eq!(result["hostname"], "CA02");
    }

    #[test]
    fn nonzero_exit_is_a_shell_error() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "boom");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            HostnameRead.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }
}
