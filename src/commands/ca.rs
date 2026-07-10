//! ADCS Certificate Authority provisioning commands (Phase F).
//!
//! These are the first per-template *write* commands: they take the CA inputs
//! a user chose in the console Inspector (algorithm, key length, common name,
//! validity) and stand up a Standalone Root CA. All inputs arrive as dispatch
//! params — the backend sends them, both for an operator's ad-hoc dispatch and
//! for post-phone-home provisioning (where the backend dispatches the command
//! with the VM's stored template config as params; see the Phase F
//! backend-driven provisioning model). The agent holds no template state.
//!
//! Gated on `Capability::VmProvision` (both roles): a guest provisioning *its
//! own* throwaway CA is the product's point; the backend enforces per-VM
//! ownership on the dispatch route so it can't target someone else's VM.
//!
//! Like every handler, all user values reach PowerShell through a `param()`
//! block + args array, never string-interpolated into the script text.

use serde_json::json;

use crate::{
    authz::Capability,
    registry::{CommandContext, CommandError, CommandHandler}
};

const CA_TYPES: &[&str] = &["Root", "Issuing"];
const KEY_ALGORITHMS: &[&str] = &["RSA", "ECDSA", "ML-DSA-87"];
const KEY_LENGTHS: &[&str] = &["2048", "4096"];
const HASH_ALGORITHMS: &[&str] = &["SHA256", "SHA384", "SHA512"];

/// Post-quantum algorithm identifier as exposed by the Windows Server 2025 CNG
/// software KSP. UNVERIFIED against a real golden image — the exact provider
/// string may differ; treated as a canary (see the Phase F plan's risk list).
const MLDSA_PROVIDER: &str =
    "ML-DSA-87#Microsoft Software Key Storage Provider";

fn cng_provider(algorithm: &str) -> &'static str {
    match algorithm {
        "ECDSA" => "ECDSA_P384#Microsoft Software Key Storage Provider",
        "ML-DSA-87" => MLDSA_PROVIDER,
        // RSA (and any future default)
        _ => "RSA#Microsoft Software Key Storage Provider"
    }
}

fn invalid(name: &str, reason: &str) -> CommandError {
    CommandError::InvalidParam {
        name: name.into(),
        reason: reason.into()
    }
}

/// Read one dispatch param as `&str`. The backend supplies these — for
/// self-apply it dispatches the command with the VM's stored template config
/// as params, so a handler never reads config directly (see the Phase F
/// backend-driven provisioning model).
fn param<'a>(ctx: &'a CommandContext, key: &str) -> Option<&'a str> {
    ctx.params.get(key).map(String::as_str)
}

/// `Install-AdcsCertificationAuthority` for a Standalone Root CA.
pub struct CaInstall;

impl CommandHandler for CaInstall {
    fn name(&self) -> &'static str {
        "ca.install"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext
    ) -> Result<serde_json::Value, CommandError> {
        let ca_type = param(ctx, "caType").unwrap_or("Root");
        if !CA_TYPES.contains(&ca_type) {
            return Err(invalid("caType", "must be 'Root' or 'Issuing'"));
        }
        if ca_type == "Issuing" {
            // Issuing CAs need an enrolled subordinate cert from a parent CA —
            // a multi-VM flow the plan runner doesn't orchestrate yet.
            return Err(invalid(
                "caType",
                "Issuing CA install is not yet supported (Root only in this phase)"
            ));
        }

        let common_name = param(ctx, "commonName")
            .ok_or_else(|| CommandError::MissingParam("commonName".into()))?;
        let cn_ok = (1..=64).contains(&common_name.len())
            && common_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " ._-".contains(c));
        if !cn_ok {
            return Err(invalid(
                "commonName",
                "must be 1-64 chars of [A-Za-z0-9 ._-]"
            ));
        }

        let algorithm = param(ctx, "keyAlgorithm").unwrap_or("RSA");
        if !KEY_ALGORITHMS.contains(&algorithm) {
            return Err(invalid(
                "keyAlgorithm",
                "must be 'RSA', 'ECDSA' or 'ML-DSA-87'"
            ));
        }
        let is_pqc = algorithm == "ML-DSA-87";

        // Key length applies to RSA only; ECDSA is fixed by the curve and
        // ML-DSA-87 has a fixed parameter set.
        let key_length = if algorithm == "RSA" {
            let kl = param(ctx, "keyLength").unwrap_or("4096");
            if !KEY_LENGTHS.contains(&kl) {
                return Err(invalid("keyLength", "must be '2048' or '4096'"));
            }
            Some(kl)
        } else {
            None
        };

        // Hash algorithm is meaningless for ML-DSA-87 (the scheme fixes it).
        let hash_algorithm = if is_pqc {
            None
        } else {
            let ha = param(ctx, "hashAlgorithm").unwrap_or("SHA256");
            if !HASH_ALGORITHMS.contains(&ha) {
                return Err(invalid(
                    "hashAlgorithm",
                    "must be 'SHA256', 'SHA384' or 'SHA512'"
                ));
            }
            Some(ha)
        };

        let validity_years = param(ctx, "validityYears").unwrap_or("5");
        match validity_years.parse::<u32>() {
            Ok(y) if (1..=50).contains(&y) => {}
            _ => {
                return Err(invalid(
                    "validityYears",
                    "must be an integer in 1-50"
                ));
            }
        }

        let provider = cng_provider(algorithm);

        ctx.progress
            .report(crate::report::OpRunState::running("installing CA", 20.0));

        // CAPolicy.inf is built line-by-line (not a here-string) to sidestep
        // PowerShell's column-zero `"@` rule; single-quoted lines keep the
        // literal `$Windows NT$` marker from interpolating.
        let script = "param([string]$CommonName,[string]$Provider,[string]$KeyLength,[string]$HashAlgorithm,[string]$ValidityYears) \
            $ErrorActionPreference = 'Stop'; \
            $capolicy = @( \
                '[Version]', \
                'Signature=\"$Windows NT$\"', \
                '', \
                '[Certsrv_Server]', \
                'RenewalValidityPeriod=Years', \
                \"RenewalValidityPeriodUnits=$ValidityYears\" \
            ) -join \"`r`n\"; \
            Set-Content -Path (Join-Path $env:SystemRoot 'CAPolicy.inf') -Value $capolicy -Encoding ASCII; \
            Import-Module ADCSDeployment; \
            $caParams = @{ \
                CAType = 'StandaloneRootCA'; \
                CACommonName = $CommonName; \
                CryptoProviderName = $Provider; \
                ValidityPeriod = 'Years'; \
                ValidityPeriodUnits = [int]$ValidityYears; \
                Force = $true \
            }; \
            if ($KeyLength) { $caParams['KeyLength'] = [int]$KeyLength }; \
            if ($HashAlgorithm) { $caParams['HashAlgorithmName'] = $HashAlgorithm }; \
            Install-AdcsCertificationAuthority @caParams";
        let args = [
            common_name.to_string(),
            provider.to_string(),
            key_length.unwrap_or("").to_string(),
            hash_algorithm.unwrap_or("").to_string(),
            validity_years.to_string()
        ];
        let output = ctx.shell.run(script, &args)?;
        if !output.succeeded() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: output.exit_code,
                    stderr: output.stderr
                }
            ));
        }

        let result = json!({
            "caType": "StandaloneRootCA",
            "commonName": common_name,
            "keyAlgorithm": algorithm,
            "keyLength": key_length,
            "hashAlgorithm": hash_algorithm,
            "validityYears": validity_years
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

fn valid_publication_url(url: &str) -> bool {
    ["http://", "https://", "ldap://", "file://"]
        .iter()
        .any(|scheme| url.starts_with(scheme))
}

/// Point the CA's CRL (CDP) and issuer-cert (AIA) publication URLs at
/// caller-supplied locations, then restart `certsvc` to apply.
pub struct CaConfigureCdpAia;

impl CommandHandler for CaConfigureCdpAia {
    fn name(&self) -> &'static str {
        "ca.configure_cdp_aia"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext
    ) -> Result<serde_json::Value, CommandError> {
        let cdp_url = param(ctx, "cdpUrl").unwrap_or_default();
        let aia_url = param(ctx, "aiaUrl").unwrap_or_default();
        if cdp_url.is_empty() && aia_url.is_empty() {
            return Err(CommandError::MissingParam("cdpUrl or aiaUrl".into()));
        }
        if !cdp_url.is_empty() && !valid_publication_url(cdp_url) {
            return Err(invalid(
                "cdpUrl",
                "must start with http://, https://, ldap:// or file://"
            ));
        }
        if !aia_url.is_empty() && !valid_publication_url(aia_url) {
            return Err(invalid(
                "aiaUrl",
                "must start with http://, https://, ldap:// or file://"
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "configuring CDP/AIA",
            40.0
        ));

        let script = "param([string]$CdpUrl,[string]$AiaUrl) \
            $ErrorActionPreference = 'Stop'; \
            if ($CdpUrl) { certutil -setreg CA\\CRLPublicationURLs (\"65:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8%9.crl`n6:\" + $CdpUrl) }; \
            if ($AiaUrl) { certutil -setreg CA\\CACertPublicationURLs (\"1:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%1_%3%4.crt`n2:\" + $AiaUrl) }; \
            Restart-Service certsvc";
        let args = [cdp_url.to_string(), aia_url.to_string()];
        let output = ctx.shell.run(script, &args)?;
        if !output.succeeded() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: output.exit_code,
                    stderr: output.stderr
                }
            ));
        }

        let result = json!({
            "cdpUrl": if cdp_url.is_empty() { serde_json::Value::Null } else { json!(cdp_url) },
            "aiaUrl": if aia_url.is_empty() { serde_json::Value::Null } else { json!(aia_url) }
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
    fn install_rejects_issuing_ca() {
        let params = ctx_params(&[("caType", "Issuing"), ("commonName", "X")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_requires_common_name() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn install_rejects_bad_common_name() {
        let params = ctx_params(&[("commonName", "bad;name`$injection")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_rejects_unknown_algorithm() {
        let params = ctx_params(&[
            ("commonName", "EC-Root-CA"),
            ("keyAlgorithm", "Dilithium")
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_rejects_bad_key_length_for_rsa() {
        let params = ctx_params(&[
            ("commonName", "EC-Root-CA"),
            ("keyAlgorithm", "RSA"),
            ("keyLength", "1024")
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_rejects_out_of_range_validity() {
        let params = ctx_params(&[
            ("commonName", "EC-Root-CA"),
            ("validityYears", "99")
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_succeeds_and_reports_rsa_defaults() {
        let params = ctx_params(&[
            ("commonName", "EC-Root-CA"),
            ("validityYears", "20")
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = CaInstall.execute(&ctx).unwrap();
        assert_eq!(result["commonName"], "EC-Root-CA");
        assert_eq!(result["keyAlgorithm"], "RSA");
        assert_eq!(result["keyLength"], "4096");
        assert_eq!(result["hashAlgorithm"], "SHA256");
        assert_eq!(result["validityYears"], "20");
    }

    #[test]
    fn install_pqc_omits_key_length_and_hash() {
        let params = ctx_params(&[
            ("commonName", "EC-PQC-Root"),
            ("keyAlgorithm", "ML-DSA-87")
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = CaInstall.execute(&ctx).unwrap();
        assert_eq!(result["keyAlgorithm"], "ML-DSA-87");
        assert!(result["keyLength"].is_null());
        assert!(result["hashAlgorithm"].is_null());
    }

    #[test]
    fn install_uses_ecdsa_provider_without_key_length() {
        let params = ctx_params(&[
            ("commonName", "EC-ECDSA-Root"),
            ("keyAlgorithm", "ECDSA")
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = CaInstall.execute(&ctx).unwrap();
        assert_eq!(result["keyAlgorithm"], "ECDSA");
        // ECDSA: key length is curve-fixed, not reported.
        assert!(result["keyLength"].is_null());
    }

    #[test]
    fn configure_requires_at_least_one_url() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            CaConfigureCdpAia.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn configure_rejects_bad_url_scheme() {
        let params = ctx_params(&[("cdpUrl", "javascript:alert(1)")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new())
        };
        assert!(matches!(
            CaConfigureCdpAia.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_succeeds_with_http_cdp() {
        let params = ctx_params(&[("cdpUrl", "http://pki.example/root.crl")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = CaConfigureCdpAia.execute(&ctx).unwrap();
        assert_eq!(result["cdpUrl"], "http://pki.example/root.crl");
        assert!(result["aiaUrl"].is_null());
    }
}
