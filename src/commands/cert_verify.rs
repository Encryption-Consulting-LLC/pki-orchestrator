use serde_json::json;

use crate::{
    authz::Capability,
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `certutil -verify -urlfetch <path>` — the guide's own read-only chain +
/// revocation health check (`vm-building.md`'s "Health Verification"
/// section). Deliberately guest-eligible (`Capability::VmRead`) to prove the
/// *allowed* path through the registry, not just the forbidden one.
pub struct CertVerify;

impl CommandHandler for CertVerify {
    fn name(&self) -> &'static str {
        "cert.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let path = ctx
            .params
            .get("path")
            .ok_or_else(|| CommandError::MissingParam("path".into()))?;

        ctx.progress
            .report(crate::report::OpRunState::running("verifying", 50.0));

        let script = "param([string]$Path) certutil -verify -urlfetch $Path";
        let output = ctx.shell.run(script, std::slice::from_ref(path))?;

        let chain_ok = output.succeeded()
            && output.stdout.contains("completed successfully");
        let result = json!({ "chain_ok": chain_ok, "raw": output.stdout });

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
    fn reports_chain_ok_on_success_marker() {
        let mut params = HashMap::new();
        params.insert("path".to_string(), "C:\\win11.cer".to_string());
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            "...\nCertUtil: -verify command completed successfully.\n",
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CertVerify.execute(&ctx).unwrap();
        assert_eq!(result["chain_ok"], true);
    }

    #[test]
    fn reports_chain_not_ok_when_marker_absent() {
        let mut params = HashMap::new();
        params.insert("path".to_string(), "C:\\win11.cer".to_string());
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("some unrelated output");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CertVerify.execute(&ctx).unwrap();
        assert_eq!(result["chain_ok"], false);
    }

    #[test]
    fn missing_path_param_is_reported() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CertVerify.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }
}
