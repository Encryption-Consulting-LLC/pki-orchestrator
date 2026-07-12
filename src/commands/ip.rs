use std::net::Ipv4Addr;

use serde_json::json;

use crate::{
    authz::Capability,
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `Get-NetIPAddress` — enumerate the machine's non-loopback IPv4 addresses.
/// Guest-eligible (`Capability::VmRead`) like `cert.verify`: the read half of
/// the hostname/IP parity set every template machine needs.
pub struct IpRead;

impl CommandHandler for IpRead {
    fn name(&self) -> &'static str {
        "ip.read"
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

        // `ConvertTo-Json @(...)` (InputObject form, not piped) so a single
        // address still serializes as a one-element array, never a bare
        // object.
        let script = "ConvertTo-Json @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | Select-Object InterfaceAlias, IPAddress, PrefixLength)";
        let output = ctx.shell.run(script, &[])?;
        if !output.succeeded() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: output.exit_code,
                    stderr: output.stderr,
                },
            ));
        }

        // Best-effort structured + raw, same convention as `cert.verify`.
        let addresses: serde_json::Value =
            serde_json::from_str(output.stdout.trim())
                .unwrap_or(serde_json::Value::Null);
        let result = json!({ "addresses": addresses, "raw": output.stdout });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Static IPv4 assignment (`Set-NetIPInterface -Dhcp Disabled` +
/// `New-NetIPAddress`) — the `vm-building.md` first-boot pattern
/// (CA01/CA02/SRV1 all pin a static address). Like `hostname.rename`, v0
/// never restarts and defaults conservatively: DHCP is disabled only on the
/// one target interface, and the default route is replaced only when a
/// gateway is supplied.
pub struct IpWrite;

impl CommandHandler for IpWrite {
    fn name(&self) -> &'static str {
        "ip.write"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmUpdate
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let address = ctx
            .params
            .get("address")
            .ok_or_else(|| CommandError::MissingParam("address".into()))?;
        if address.parse::<Ipv4Addr>().is_err() {
            return Err(CommandError::InvalidParam {
                name: "address".into(),
                reason: "must be a dotted-quad IPv4 address".into(),
            });
        }

        let prefix = ctx
            .params
            .get("prefixLength")
            .map(String::as_str)
            .unwrap_or("24");
        match prefix.parse::<u8>() {
            Ok(p) if p <= 32 => {}
            _ => {
                return Err(CommandError::InvalidParam {
                    name: "prefixLength".into(),
                    reason: "must be an integer in 0-32".into(),
                });
            }
        }

        let gateway = ctx.params.get("gateway").cloned().unwrap_or_default();
        if !gateway.is_empty() && gateway.parse::<Ipv4Addr>().is_err() {
            return Err(CommandError::InvalidParam {
                name: "gateway".into(),
                reason: "must be a dotted-quad IPv4 address".into(),
            });
        }

        // Empty alias → the script picks the first Up adapter itself.
        let alias = ctx.params.get("interface").cloned().unwrap_or_default();

        ctx.progress
            .report(crate::report::OpRunState::running("configuring", 10.0));

        let script = "param([string]$Address,[string]$Prefix,[string]$Gateway,[string]$Alias) \
            if (-not $Alias) { $Alias = Get-NetAdapter | Where-Object Status -eq 'Up' | Sort-Object ifIndex | Select-Object -First 1 -ExpandProperty Name }; \
            Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -Dhcp Disabled; \
            Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; \
            if ($Gateway) { \
                Remove-NetRoute -InterfaceAlias $Alias -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue; \
                New-NetIPAddress -InterfaceAlias $Alias -IPAddress $Address -PrefixLength $Prefix -DefaultGateway $Gateway \
            } else { \
                New-NetIPAddress -InterfaceAlias $Alias -IPAddress $Address -PrefixLength $Prefix \
            }";
        let args = [
            address.clone(),
            prefix.to_string(),
            gateway.clone(),
            alias.clone(),
        ];
        let output = ctx.shell.run(script, &args)?;
        if !output.succeeded() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: output.exit_code,
                    stderr: output.stderr,
                },
            ));
        }

        let result = json!({
            "address": address,
            "prefix_length": prefix,
            "gateway": if gateway.is_empty() { serde_json::Value::Null } else { json!(gateway) },
            "interface": if alias.is_empty() { serde_json::Value::Null } else { json!(alias) }
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
    fn read_parses_address_array() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"[{"InterfaceAlias":"Ethernet0","IPAddress":"192.168.1.10","PrefixLength":24}]"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = IpRead.execute(&ctx).unwrap();
        assert_eq!(result["addresses"][0]["IPAddress"], "192.168.1.10");
    }

    #[test]
    fn read_falls_back_to_raw_on_unparseable_output() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("not json");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = IpRead.execute(&ctx).unwrap();
        assert!(result["addresses"].is_null());
        assert_eq!(result["raw"], "not json");
    }

    #[test]
    fn write_rejects_malformed_address() {
        let params = ctx_params(&[("address", "999.1.2.3")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            IpWrite.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn write_rejects_out_of_range_prefix() {
        let params =
            ctx_params(&[("address", "10.0.0.5"), ("prefixLength", "33")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            IpWrite.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn write_rejects_malformed_gateway() {
        let params =
            ctx_params(&[("address", "10.0.0.5"), ("gateway", "not-an-ip")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            IpWrite.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn write_missing_address_param_is_reported() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            IpWrite.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn write_succeeds_with_defaults_and_reports_them() {
        let params = ctx_params(&[("address", "192.168.1.20")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = IpWrite.execute(&ctx).unwrap();
        assert_eq!(result["address"], "192.168.1.20");
        assert_eq!(result["prefix_length"], "24");
        assert!(result["gateway"].is_null());
        assert!(result["interface"].is_null());
    }
}
