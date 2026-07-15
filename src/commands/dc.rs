//! Domain-controller commands (Phase L).
//!
//! `dc.install_forest` never self-reboots (`-NoRebootOnCompletion`): the
//! backend sequence engine follows it with an explicit `system.reboot` step
//! and then polls `dc.verify` — the post-promotion readiness probe.
//! `Get-ADDomain` keeps failing until AD Web Services is up, which can lag
//! the reboot by minutes, so that handler is deliberately single-shot; the
//! engine owns the retry/backoff window and a failure is a normal "not
//! ready yet" signal, not a fault.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, parse_json, require_success, required, valid_dns_name,
        valid_secret,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `-ForestMode`/`-DomainMode` values the templates can produce: the 2016
/// functional level covers the 2016/2019/2022 guest OSes (no new level was
/// introduced between them); Windows Server 2025 added its own.
const FOREST_MODES: &[&str] = &["Default", "WinThreshold", "Win2025"];

/// `Install-WindowsFeature AD-Domain-Services` + `Install-ADDSForest` with
/// `-NoRebootOnCompletion`. The DSRM password arrives as a secret param and
/// is never echoed back.
pub struct DcInstallForest;

impl CommandHandler for DcInstallForest {
    fn name(&self) -> &'static str {
        "dc.install_forest"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let domain = required(ctx, "domainName")?;
        if !valid_dns_name(domain) || !domain.contains('.') {
            return Err(invalid(
                "domainName",
                "must be a dotted DNS domain name",
            ));
        }
        let netbios = required(ctx, "netbiosName")?;
        let netbios_ok = (1..=15).contains(&netbios.len())
            && netbios
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !netbios_ok {
            return Err(invalid(
                "netbiosName",
                "must be 1-15 chars of [A-Za-z0-9-]",
            ));
        }
        let forest_mode = param(ctx, "forestMode").unwrap_or("WinThreshold");
        if !FOREST_MODES.contains(&forest_mode) {
            return Err(invalid(
                "forestMode",
                "must be 'Default', 'WinThreshold' or 'Win2025'",
            ));
        }
        let dsrm_password = required(ctx, "safeModePassword")?;
        if !valid_secret(dsrm_password) {
            return Err(invalid(
                "safeModePassword",
                "must be non-empty and not begin with '-'",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "installing AD DS forest",
            10.0,
        ));

        let script = "param([string]$DomainName,[string]$Netbios,[string]$ForestMode,[string]$SafeModePassword) \
            $ErrorActionPreference = 'Stop'; \
            Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null; \
            $secure = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force; \
            Import-Module ADDSDeployment; \
            Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $Netbios \
                -ForestMode $ForestMode -DomainMode $ForestMode -InstallDns \
                -SafeModeAdministratorPassword $secure \
                -NoRebootOnCompletion -Force | Out-Null";
        let args = [
            domain.to_string(),
            netbios.to_string(),
            forest_mode.to_string(),
            dsrm_password.to_string(),
        ];
        let output = require_success(ctx.shell.run(script, &args)?)?;
        drop(output);

        let result = json!({
            "domain": domain,
            "netbios": netbios,
            "forest_mode": forest_mode,
            "reboot_required": true
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// `Get-ADDomain -Server $env:COMPUTERNAME` — proves the local forest is up
/// and the local ADWS endpoint is answering without depending on default DC
/// discovery (or on the cloned guest's pre-promotion DNS client settings).
pub struct DcVerify;

impl CommandHandler for DcVerify {
    fn name(&self) -> &'static str {
        "dc.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "verifying directory",
            50.0,
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            Import-Module ActiveDirectory; \
            Get-ADDomain -Server $env:COMPUTERNAME | \
                Select-Object DNSRoot, NetBIOSName, DomainMode | ConvertTo-Json";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let domain = parse_json(&output.stdout);
        let result = json!({ "domain": domain, "raw": output.stdout });
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

    fn forest_params() -> HashMap<String, String> {
        ctx_params(&[
            ("domainName", "EncryptionConsulting.com"),
            ("netbiosName", "ENCRYPTIONCONSU"),
            ("forestMode", "WinThreshold"),
            ("safeModePassword", "S0me-DSRM-secret!"),
        ])
    }

    #[test]
    fn install_forest_reports_reboot_required() {
        let params = forest_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DcInstallForest.execute(&ctx).unwrap();
        assert_eq!(result["domain"], "EncryptionConsulting.com");
        assert_eq!(result["reboot_required"], true);
    }

    #[test]
    fn install_forest_never_leaks_the_dsrm_password() {
        let params = forest_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::clone(&shell) as _,
        };
        let result = DcInstallForest.execute(&ctx).unwrap();
        // Not in the result JSON, and not interpolated into the script text
        // (it must travel only through the positional args array).
        assert!(!result.to_string().contains("S0me-DSRM-secret!"));
        for script in shell.calls.lock().unwrap().iter() {
            assert!(!script.contains("S0me-DSRM-secret!"));
        }
    }

    #[test]
    fn install_forest_rejects_undotted_domain() {
        let mut params = forest_params();
        params.insert("domainName".into(), "corp".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DcInstallForest.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_forest_rejects_overlong_netbios() {
        let mut params = forest_params();
        params.insert("netbiosName".into(), "EncryptionConsulting".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DcInstallForest.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_forest_rejects_unknown_forest_mode() {
        let mut params = forest_params();
        params.insert("forestMode".into(), "Win2003".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DcInstallForest.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_forest_rejects_dash_leading_password() {
        // A leading '-' would bind as a parameter name under -File.
        let mut params = forest_params();
        params.insert("safeModePassword".into(), "-StartsWithDash1!".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DcInstallForest.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn verify_parses_domain_facts() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"DNSRoot":"EncryptionConsulting.com","NetBIOSName":"ENCRYPTIONCONSU","DomainMode":"Windows2016Domain"}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::clone(&shell) as _,
        };
        let result = DcVerify.execute(&ctx).unwrap();
        assert_eq!(result["domain"]["DNSRoot"], "EncryptionConsulting.com");
        assert_eq!(result["domain"]["NetBIOSName"], "ENCRYPTIONCONSU");
        assert!(
            shell.calls.lock().unwrap()[0]
                .contains("Get-ADDomain -Server $env:COMPUTERNAME")
        );
    }

    #[test]
    fn verify_fails_while_adws_is_still_down() {
        // Backend engine treats this as "retry later", not a fault.
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(
            1,
            "Unable to contact the server. This may be because this server does not exist"
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            DcVerify.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    #[test]
    fn verify_keeps_raw_output_when_unparseable() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("not json");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DcVerify.execute(&ctx).unwrap();
        assert!(result["domain"].is_null());
        assert_eq!(result["raw"], "not json");
    }
}
