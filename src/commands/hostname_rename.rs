use serde_json::json;

use crate::{
    authz::Capability,
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `Rename-Computer -NewName <name>` — the pattern used repeatedly across
/// `vm-building.md` (CA01/CA02/SRV1/WIN11). v0 never restarts: an
/// unattended restart mid dev/test run is undesirable. The real firstboot
/// flow will need `-Restart` once wired up.
pub struct HostnameRename;

impl CommandHandler for HostnameRename {
    fn name(&self) -> &'static str {
        "hostname.rename"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmUpdate
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let new_name = ctx
            .params
            .get("name")
            .ok_or_else(|| CommandError::MissingParam("name".into()))?;

        let valid = !new_name.is_empty()
            && new_name.len() <= 15
            && new_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !valid {
            return Err(CommandError::InvalidParam {
                name: "name".into(),
                reason:
                    "must be 1-15 chars of [A-Za-z0-9-] (NetBIOS name limit)"
                        .into(),
            });
        }

        ctx.progress
            .report(crate::report::OpRunState::running("renaming", 10.0));

        let script = "param([string]$NewName) Rename-Computer -NewName $NewName -Restart:$false -Force";
        let output = ctx.shell.run(script, std::slice::from_ref(new_name))?;
        if !output.succeeded() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: output.exit_code,
                    stderr: output.stderr,
                },
            ));
        }

        let result = json!({ "renamed_to": new_name });
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
    fn rejects_name_over_netbios_limit() {
        let mut params = HashMap::new();
        params.insert(
            "name".to_string(),
            "ThisNameIsWayTooLongForNetBIOS".to_string(),
        );
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            HostnameRename.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn renames_on_valid_input() {
        let mut params = HashMap::new();
        params.insert("name".to_string(), "CA02".to_string());
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = HostnameRename.execute(&ctx).unwrap();
        assert_eq!(result["renamed_to"], "CA02");
    }

    #[test]
    fn missing_name_param_is_reported() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            HostnameRename.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }
}
