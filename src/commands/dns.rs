//! DNS client commands (Phase L).
//!
//! `dns.set_client` points a NIC's DNS resolvers at caller-supplied servers —
//! the pre-join step on every domain-joining machine (aim at the DC's pool
//! IP), and the post-promotion step on the DC itself (aim at self, replacing
//! the loopback default). Same conservative interface handling as `ip.write`:
//! an empty alias means the first Up adapter.

use std::net::Ipv4Addr;

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, require_success, required, valid_dns_name
    },
    registry::{CommandContext, CommandError, CommandHandler}
};

/// `Set-DnsClientServerAddress` — replace a NIC's DNS server list.
pub struct DnsSetClient;

impl CommandHandler for DnsSetClient {
    fn name(&self) -> &'static str {
        "dns.set_client"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext
    ) -> Result<serde_json::Value, CommandError> {
        let servers = required(ctx, "servers")?;
        let parsed: Vec<&str> = servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if parsed.is_empty()
            || parsed.iter().any(|s| s.parse::<Ipv4Addr>().is_err())
        {
            return Err(invalid(
                "servers",
                "must be a comma-separated list of dotted-quad IPv4 addresses"
            ));
        }
        let servers = parsed.join(",");

        // Empty alias → the script picks the first Up adapter itself.
        let alias = param(ctx, "interface").unwrap_or_default().to_string();

        ctx.progress.report(crate::report::OpRunState::running(
            "configuring DNS client",
            30.0
        ));

        // Echo the applied list back (readback) so the caller verifies the
        // change from the same run.
        let script = "param([string]$Servers,[string]$Alias) \
            $ErrorActionPreference = 'Stop'; \
            if (-not $Alias) { $Alias = Get-NetAdapter | Where-Object Status -eq 'Up' | Sort-Object ifIndex | Select-Object -First 1 -ExpandProperty Name }; \
            Set-DnsClientServerAddress -InterfaceAlias $Alias -ServerAddresses ($Servers -split ','); \
            (Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv4).ServerAddresses -join ','";
        let args = [servers.clone(), alias.clone()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "servers": parsed,
            "applied": output.stdout.trim(),
            "interface": if alias.is_empty() { serde_json::Value::Null } else { json!(alias) }
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// `Add-DnsServerResourceRecordCName` — the lab's `pki` alias on DC01
/// (`pki.<domain>` → the web host actually serving CertEnroll). Idempotent:
/// an existing CNAME of the same name is replaced, so re-running a plan
/// converges instead of erroring on the duplicate.
pub struct DnsCreateRecord;

impl CommandHandler for DnsCreateRecord {
    fn name(&self) -> &'static str {
        "dns.create_record"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext
    ) -> Result<serde_json::Value, CommandError> {
        let zone = required(ctx, "zone")?;
        if !valid_dns_name(zone) {
            return Err(invalid("zone", "must be a DNS zone name"));
        }
        let name = required(ctx, "name")?;
        if !valid_dns_name(name) || name.contains('.') {
            return Err(invalid("name", "must be a single DNS label"));
        }
        let target = required(ctx, "target")?;
        if !valid_dns_name(target) {
            return Err(invalid("target", "must be a DNS host name"));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "creating DNS record",
            30.0
        ));

        let script = "param([string]$Zone,[string]$Name,[string]$Target) \
            $ErrorActionPreference = 'Stop'; \
            $existing = Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType CName -ErrorAction SilentlyContinue; \
            if ($existing) { $existing | Remove-DnsServerResourceRecord -ZoneName $Zone -Force }; \
            Add-DnsServerResourceRecordCName -ZoneName $Zone -Name $Name -HostNameAlias $Target; \
            (Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType CName).RecordData.HostNameAlias";
        let args = [zone.to_string(), name.to_string(), target.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "zone": zone,
            "name": name,
            "target": target,
            "applied": output.stdout.trim()
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
    fn set_client_requires_servers() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            DnsSetClient.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn set_client_rejects_malformed_server() {
        let params = ctx_params(&[("servers", "192.168.1.90,not-an-ip")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            DnsSetClient.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn set_client_rejects_empty_list() {
        let params = ctx_params(&[("servers", " , ")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            DnsSetClient.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn set_client_applies_and_echoes_readback() {
        let params = ctx_params(&[("servers", "192.168.1.90, 192.168.1.91")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("192.168.1.90,192.168.1.91");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = DnsSetClient.execute(&ctx).unwrap();
        assert_eq!(result["servers"][0], "192.168.1.90");
        assert_eq!(result["servers"][1], "192.168.1.91");
        assert_eq!(result["applied"], "192.168.1.90,192.168.1.91");
        assert!(result["interface"].is_null());
    }

    #[test]
    fn create_record_requires_all_params() {
        let params = ctx_params(&[("zone", "EncryptionConsulting.com")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            DnsCreateRecord.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn create_record_rejects_dotted_name() {
        let params = ctx_params(&[
            ("zone", "EncryptionConsulting.com"),
            ("name", "pki.extra"),
            ("target", "srv1.EncryptionConsulting.com.")
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            DnsCreateRecord.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn create_record_rejects_injection_shaped_target() {
        let params = ctx_params(&[
            ("zone", "EncryptionConsulting.com"),
            ("name", "pki"),
            ("target", "srv1; Remove-Item -Recurse C:\\")
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            DnsCreateRecord.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn create_record_echoes_the_applied_alias() {
        let params = ctx_params(&[
            ("zone", "EncryptionConsulting.com"),
            ("name", "pki"),
            ("target", "srv1.EncryptionConsulting.com.")
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("srv1.EncryptionConsulting.com.");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = DnsCreateRecord.execute(&ctx).unwrap();
        assert_eq!(result["name"], "pki");
        assert_eq!(result["applied"], "srv1.EncryptionConsulting.com.");
    }
}
