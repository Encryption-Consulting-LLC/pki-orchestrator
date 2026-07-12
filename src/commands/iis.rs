//! IIS / CertEnroll web-hosting commands (Phase L).
//!
//! `iis.setup_certenroll` builds SRV1's HTTP CDP/AIA distribution point in
//! two independently-runnable halves, selected by `scope`:
//!
//! * `share` — the folder + SMB share + Cert Publishers ACL. Must exist
//!   *before* CA02 publishes the root cert to it, and needs the domain join
//!   (the Cert Publishers group) — the sequence engine runs this half as the
//!   web host's domain-join tail.
//! * `web` — the IIS role, CertEnroll virtual directory, directory
//!   browsing, and the double-escaping override that lets IIS serve Delta
//!   CRLs (`+` in filenames).
//! * `all` (default) — both.
//!
//! Every part is idempotent (existence-checked or natively re-runnable), so
//! converging plans re-run clean.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, require_success, required, valid_windows_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

const SCOPES: &[&str] = &["share", "web", "all"];

fn valid_netbios(value: &str) -> bool {
    (1..=15).contains(&value.len())
        && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Folder + share + ACL and/or IIS vdir for the CertEnroll content.
pub struct IisSetupCertEnroll;

impl CommandHandler for IisSetupCertEnroll {
    fn name(&self) -> &'static str {
        "iis.setup_certenroll"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let path = param(ctx, "path").unwrap_or("C:\\CertEnroll");
        if !valid_windows_path(path) {
            return Err(invalid("path", "must be an absolute Windows path"));
        }
        let scope = param(ctx, "scope").unwrap_or("all");
        if !SCOPES.contains(&scope) {
            return Err(invalid("scope", "must be 'share', 'web' or 'all'"));
        }
        // The down-level Cert Publishers name needs the NetBIOS domain — only
        // for the share/ACL half.
        let netbios = if scope == "web" {
            String::new()
        } else {
            let n = required(ctx, "netbiosName")?;
            if !valid_netbios(n) {
                return Err(invalid(
                    "netbiosName",
                    "must be 1-15 chars of [A-Za-z0-9-]",
                ));
            }
            n.to_string()
        };

        ctx.progress.report(crate::report::OpRunState::running(
            "configuring CertEnroll hosting",
            20.0,
        ));

        let script = "param([string]$Path,[string]$Netbios,[string]$Scope) \
            $ErrorActionPreference = 'Stop'; \
            if ($Scope -ne 'web') { \
                New-Item -Path $Path -ItemType Directory -Force | Out-Null; \
                if (-not (Get-SmbShare -Name 'CertEnroll' -ErrorAction SilentlyContinue)) { \
                    New-SmbShare -Name 'CertEnroll' -Path $Path -ChangeAccess \"$Netbios\\Cert Publishers\" | Out-Null \
                }; \
                icacls $Path /grant \"${Netbios}\\Cert Publishers:(OI)(CI)M\" | Out-Null; \
                if ($LASTEXITCODE -ne 0) { throw 'icacls grant failed' } \
            }; \
            if ($Scope -ne 'share') { \
                Install-WindowsFeature Web-Server -IncludeManagementTools | Out-Null; \
                Import-Module WebAdministration; \
                if (-not (Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertEnroll')) { \
                    New-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertEnroll' -PhysicalPath $Path | Out-Null \
                }; \
                Set-WebConfigurationProperty -PSPath 'IIS:\\Sites\\Default Web Site\\CertEnroll' -Filter '/system.webServer/directoryBrowse' -Name enabled -Value $true; \
                Set-WebConfigurationProperty -PSPath 'IIS:\\Sites\\Default Web Site' -Filter '/system.webServer/security/requestFiltering' -Name allowDoubleEscaping -Value $true; \
                iisreset | Out-Null \
            }";
        let args = [path.to_string(), netbios.clone(), scope.to_string()];
        require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "path": path,
            "scope": scope,
            "share_configured": scope != "web",
            "web_configured": scope != "share"
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
    fn setup_requires_netbios_for_the_share_half() {
        for scope in ["share", "all"] {
            let params = ctx_params(&[("scope", scope)]);
            let sink = NullProgressSink;
            let ctx = CommandContext {
                params: &params,
                progress: &sink,
                shell: Arc::new(MockPowerShell::new()),
            };
            assert!(matches!(
                IisSetupCertEnroll.execute(&ctx),
                Err(CommandError::MissingParam(_))
            ));
        }
    }

    #[test]
    fn setup_web_half_needs_no_netbios() {
        let params = ctx_params(&[("scope", "web")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = IisSetupCertEnroll.execute(&ctx).unwrap();
        assert_eq!(result["share_configured"], false);
        assert_eq!(result["web_configured"], true);
        assert_eq!(result["path"], "C:\\CertEnroll");
    }

    #[test]
    fn setup_rejects_unknown_scope() {
        let params = ctx_params(&[
            ("scope", "everything"),
            ("netbiosName", "ENCRYPTIONCONSU"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            IisSetupCertEnroll.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn setup_all_reports_both_halves() {
        let params = ctx_params(&[
            ("netbiosName", "ENCRYPTIONCONSU"),
            ("path", "C:\\CertEnroll"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = IisSetupCertEnroll.execute(&ctx).unwrap();
        assert_eq!(result["share_configured"], true);
        assert_eq!(result["web_configured"], true);
    }
}
