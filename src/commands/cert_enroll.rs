//! Certificate enrollment (Phase L) — `Get-Certificate` against a published
//! template: SRV1's OCSP Response Signing cert and WIN11's Workstation
//! Authentication cert (the lab's step-9 client proof). Template/enrollment
//! propagation through AD is slow, so a failure here is a normal "retry
//! later" signal to the backend engine's backoff window.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, parse_json, require_success, required,
        valid_windows_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

fn valid_template_cn(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// Enroll a machine cert from a template; optionally refresh group policy
/// first (`refreshPolicy=true` — gpupdate + certutil -pulse) and export the
/// issued cert DER (no private key) to `exportPath` for verification.
pub struct CertEnroll;

impl CommandHandler for CertEnroll {
    fn name(&self) -> &'static str {
        "cert.enroll"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let template = required(ctx, "template")?;
        if !valid_template_cn(template) {
            return Err(invalid(
                "template",
                "must be a template CN of [A-Za-z0-9._-], max 64 chars",
            ));
        }
        let export_path = param(ctx, "exportPath").unwrap_or_default();
        if !export_path.is_empty() && !valid_windows_path(export_path) {
            return Err(invalid(
                "exportPath",
                "must be an absolute Windows path",
            ));
        }
        let refresh = param(ctx, "refreshPolicy").unwrap_or("false");
        if !["true", "false"].contains(&refresh) {
            return Err(invalid("refreshPolicy", "must be 'true' or 'false'"));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "enrolling certificate",
            30.0,
        ));

        let script = "param([string]$Template,[string]$ExportPath,[string]$Refresh) \
            $ErrorActionPreference = 'Stop'; \
            if ($Refresh -eq 'true') { gpupdate /target:computer /force | Out-Null; certutil -pulse | Out-Null }; \
            $req = Get-Certificate -Template $Template -CertStoreLocation Cert:\\LocalMachine\\My; \
            if (\"$($req.Status)\" -ne 'Issued') { throw \"enrollment status: $($req.Status)\" }; \
            $cert = $req.Certificate; \
            if ($ExportPath) { \
                New-Item -ItemType Directory -Force -Path (Split-Path $ExportPath) | Out-Null; \
                Export-Certificate -Cert $cert -FilePath $ExportPath -Type CERT | Out-Null \
            }; \
            @{ thumbprint = $cert.Thumbprint; subject = $cert.Subject } | ConvertTo-Json";
        let args = [
            template.to_string(),
            export_path.to_string(),
            refresh.to_string(),
        ];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let issued = parse_json(&output.stdout);
        let result = json!({
            "template": template,
            "thumbprint": issued["thumbprint"],
            "subject": issued["subject"],
            "export_path": if export_path.is_empty() { serde_json::Value::Null } else { json!(export_path) }
        });
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
    fn enroll_requires_template() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CertEnroll.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn enroll_reports_the_issued_cert() {
        let params = ctx_params(&[
            ("template", "Workstation"),
            ("exportPath", "C:\\win11.cer"),
            ("refreshPolicy", "true"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"thumbprint":"AB12CD34","subject":"CN=win11.EncryptionConsulting.com"}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CertEnroll.execute(&ctx).unwrap();
        assert_eq!(result["thumbprint"], "AB12CD34");
        assert_eq!(result["export_path"], "C:\\win11.cer");
    }

    #[test]
    fn enroll_rejects_bad_refresh_flag() {
        let params = ctx_params(&[
            ("template", "Workstation"),
            ("refreshPolicy", "yes please"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CertEnroll.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn enroll_fails_when_not_issued() {
        // Get-Certificate returned Pending/Denied → the script throws → the
        // backend engine retries within its propagation window.
        let params = ctx_params(&[("template", "OCSPResponseSigning")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "enrollment status: Pending");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            CertEnroll.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }
}
