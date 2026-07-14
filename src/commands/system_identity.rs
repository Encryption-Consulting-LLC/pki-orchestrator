use crate::{
    authz::Capability,
    commands::util::{parse_json, require_success},
    registry::{CommandContext, CommandError, CommandHandler},
};

/// Runtime hostname and Windows edition facts used by the final aggregate to
/// prove it is talking to the expected four deployed machines.
pub struct SystemIdentity;

impl CommandHandler for SystemIdentity {
    fn name(&self) -> &'static str {
        "system.identity"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "reading system identity",
            50.0,
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            $os = Get-CimInstance Win32_OperatingSystem; \
            @{ hostname = $env:COMPUTERNAME; operating_system = $os.Caption; version = $os.Version; product_type = [int]$os.ProductType; server = ([int]$os.ProductType -ne 1) } | ConvertTo-Json -Compress";
        let output = require_success(ctx.shell.run(script, &[])?)?;
        let result = parse_json(&output.stdout);
        if !result.is_object() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: 1,
                    stderr: "system.identity returned invalid JSON".into(),
                },
            ));
        }

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
    fn reports_hostname_and_server_identity() {
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"hostname":"DC01","operating_system":"Microsoft Windows Server 2025 Standard","version":"10.0.26100","product_type":2,"server":true}"#,
        );
        let params = HashMap::new();
        let ctx = CommandContext {
            params: &params,
            progress: &NullProgressSink,
            shell,
        };

        let result = SystemIdentity.execute(&ctx).unwrap();

        assert_eq!(result["hostname"], "DC01");
        assert_eq!(result["server"], true);
    }
}
