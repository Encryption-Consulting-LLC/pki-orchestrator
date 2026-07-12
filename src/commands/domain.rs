//! Domain-membership commands (Phase L).
//!
//! `domain.join` never self-reboots (`Add-Computer` without `-Restart`): the
//! backend sequence engine follows it with an explicit `system.reboot` step,
//! then polls `domain.verify` — the post-join probe
//! (`Win32_ComputerSystem.PartOfDomain`). The probe reports facts —
//! `part_of_domain: false` is a successful read of an unjoined machine, and
//! the engine's per-step predicate decides whether that means "retry".

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, parse_json, require_success, required, valid_dns_name,
        valid_secret, valid_username,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `Add-Computer -DomainName -Credential` (no `-Restart`). The domain-admin
/// credential arrives as secret params and is never echoed back.
pub struct DomainJoin;

impl CommandHandler for DomainJoin {
    fn name(&self) -> &'static str {
        "domain.join"
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
        let username = required(ctx, "username")?;
        if !valid_username(username) {
            return Err(invalid(
                "username",
                "must be a plain, domain\\user or user@domain account name",
            ));
        }
        let password = required(ctx, "password")?;
        if !valid_secret(password) {
            return Err(invalid(
                "password",
                "must be non-empty and not begin with '-'",
            ));
        }

        ctx.progress
            .report(crate::report::OpRunState::running("joining domain", 20.0));

        let script = "param([string]$DomainName,[string]$Username,[string]$Password) \
            $ErrorActionPreference = 'Stop'; \
            $secure = ConvertTo-SecureString $Password -AsPlainText -Force; \
            $cred = New-Object System.Management.Automation.PSCredential($Username, $secure); \
            Add-Computer -DomainName $DomainName -Credential $cred";
        let args = [
            domain.to_string(),
            username.to_string(),
            password.to_string(),
        ];
        let output = require_success(ctx.shell.run(script, &args)?)?;
        drop(output);

        let result = json!({
            "domain": domain,
            "reboot_required": true
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// `Win32_ComputerSystem` — domain membership, domain name, hostname.
pub struct DomainVerify;

impl CommandHandler for DomainVerify {
    fn name(&self) -> &'static str {
        "domain.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "verifying membership",
            50.0,
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            Get-CimInstance Win32_ComputerSystem | Select-Object PartOfDomain, Domain, DNSHostName | ConvertTo-Json";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let system = parse_json(&output.stdout);
        let result = json!({
            "part_of_domain": system["PartOfDomain"] == true,
            "domain": system["Domain"],
            "raw": output.stdout
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

    fn join_params() -> HashMap<String, String> {
        ctx_params(&[
            ("domainName", "EncryptionConsulting.com"),
            ("username", "ENCRYPTIONCONSU\\Administrator"),
            ("password", "Sup3r-Secret-Pw!"),
        ])
    }

    #[test]
    fn join_reports_reboot_required() {
        let params = join_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DomainJoin.execute(&ctx).unwrap();
        assert_eq!(result["domain"], "EncryptionConsulting.com");
        assert_eq!(result["reboot_required"], true);
    }

    #[test]
    fn join_never_leaks_the_password() {
        let params = join_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::clone(&shell) as _,
        };
        let result = DomainJoin.execute(&ctx).unwrap();
        assert!(!result.to_string().contains("Sup3r-Secret-Pw!"));
        for script in shell.calls.lock().unwrap().iter() {
            assert!(!script.contains("Sup3r-Secret-Pw!"));
        }
    }

    #[test]
    fn join_rejects_injection_shaped_username() {
        let mut params = join_params();
        params
            .insert("username".into(), "Administrator'; Remove-Item C:".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DomainJoin.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn join_rejects_dash_leading_password() {
        let mut params = join_params();
        params.insert("password".into(), "-StartsWithDash1!".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DomainJoin.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn join_propagates_bad_credential_failure() {
        let params = join_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "The user name or password is incorrect.");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            DomainJoin.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    #[test]
    fn verify_reports_joined_machine() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"PartOfDomain":true,"Domain":"EncryptionConsulting.com","DNSHostName":"ca02"}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DomainVerify.execute(&ctx).unwrap();
        assert_eq!(result["part_of_domain"], true);
        assert_eq!(result["domain"], "EncryptionConsulting.com");
    }

    #[test]
    fn verify_reports_workgroup_machine_as_not_joined() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"PartOfDomain":false,"Domain":"WORKGROUP","DNSHostName":"win11"}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DomainVerify.execute(&ctx).unwrap();
        assert_eq!(result["part_of_domain"], false);
        assert_eq!(result["domain"], "WORKGROUP");
    }

    #[test]
    fn verify_treats_unparseable_output_as_not_joined() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("garbage");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DomainVerify.execute(&ctx).unwrap();
        assert_eq!(result["part_of_domain"], false);
        assert_eq!(result["raw"], "garbage");
    }
}
