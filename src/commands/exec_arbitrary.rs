use serde_json::json;

use crate::{
    authz::Capability,
    registry::{CommandContext, CommandError, CommandHandler},
};

/// Runs an arbitrary PowerShell script verbatim. This is the reserved
/// escape hatch behind `Capability::VmExecArbitrary` — it MUST stay
/// unreachable for `Role::Guest`. See
/// `authz::tests::guest_cannot_exec_arbitrary` and
/// `tests/commands_with_mock_shell.rs::guest_cannot_exec_arbitrary_end_to_end`
/// for the tests that pin this invariant.
pub struct ExecArbitrary;

impl CommandHandler for ExecArbitrary {
    fn name(&self) -> &'static str {
        "powershell.exec_arbitrary"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmExecArbitrary
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let script = ctx
            .params
            .get("script")
            .ok_or_else(|| CommandError::MissingParam("script".into()))?;

        ctx.progress
            .report(crate::report::OpRunState::running("executing", 50.0));

        let output = ctx.shell.run(script, &[])?;
        if !output.succeeded() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: output.exit_code,
                    stderr: output.stderr,
                },
            ));
        }

        let result =
            json!({ "stdout": output.stdout, "stderr": output.stderr });
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
    fn runs_script_and_returns_stdout() {
        let mut params = HashMap::new();
        params.insert("script".to_string(), "Get-Date".to_string());
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("Tuesday, July 7, 2026");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = ExecArbitrary.execute(&ctx).unwrap();
        assert_eq!(result["stdout"], "Tuesday, July 7, 2026");
    }

    #[test]
    fn propagates_shell_failure() {
        let mut params = HashMap::new();
        params.insert("script".to_string(), "exit 1".to_string());
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "boom");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            ExecArbitrary.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }
}
