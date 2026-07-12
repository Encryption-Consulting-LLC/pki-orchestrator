//! Artifact relay commands (Phase L) — the "sneakernet" that carries the
//! cross-signing handshake (CSR out of CA02, signed cert back, root
//! cert/CRL to CA02+SRV1) through the backend instead of removable media or
//! SMB. Content rides base64 in params/results with a 256 KiB cap (CA
//! certs/CRLs are 1–5 KB; the cap is generous headroom, and the backend
//! stores artifacts inline in the `plan_runs` doc).
//!
//! Both commands enforce a path-prefix allowlist: `C:\Transfer\` (the
//! relay scratch dir), the CertEnroll publication dir, and the web host's
//! served `C:\CertEnroll\`. A VM whose operator configured a nonstandard
//! `certEnrollPath` is simply not relay-reachable there — the plan
//! sequences use these defaults.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, parse_json, require_success, required, valid_windows_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

/// 256 KiB decoded; the base64 param cap is the encoded equivalent (~4/3).
const RELAY_CAP_BYTES: usize = 256 * 1024;
const RELAY_CAP_B64: usize = RELAY_CAP_BYTES / 3 * 4 + 4;

const ALLOWED_PREFIXES: &[&str] = &[
    "C:\\Transfer\\",
    "C:\\Windows\\System32\\CertSrv\\CertEnroll\\",
    "C:\\CertEnroll\\",
];

fn relay_path_ok(path: &str) -> bool {
    valid_windows_path(path)
        && !path.contains("..")
        && ALLOWED_PREFIXES.iter().any(|prefix| {
            path.len() > prefix.len()
                && path[..prefix.len()].eq_ignore_ascii_case(prefix)
        })
}

fn invalid_relay_path() -> CommandError {
    invalid(
        "path",
        "must be an absolute path under C:\\Transfer\\, the CertSrv \
         CertEnroll dir, or C:\\CertEnroll\\",
    )
}

/// Read one relay-eligible file as base64 (+ sha256 for the digest check).
pub struct FileRead;

impl CommandHandler for FileRead {
    fn name(&self) -> &'static str {
        "file.read"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let path = required(ctx, "path")?;
        if !relay_path_ok(path) {
            return Err(invalid_relay_path());
        }

        ctx.progress
            .report(crate::report::OpRunState::running("reading file", 30.0));

        let script = "param([string]$Path,[string]$Cap) \
            $ErrorActionPreference = 'Stop'; \
            $bytes = [System.IO.File]::ReadAllBytes($Path); \
            if ($bytes.Length -gt [int]$Cap) { throw \"file exceeds the relay cap\" }; \
            $sha = [System.Security.Cryptography.SHA256]::Create(); \
            $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''; \
            @{ contentB64 = [Convert]::ToBase64String($bytes); sha256 = $hash; size = $bytes.Length } | ConvertTo-Json";
        let args = [path.to_string(), RELAY_CAP_BYTES.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let payload = parse_json(&output.stdout);
        if payload["contentB64"].as_str().is_none() {
            return Err(invalid("path", "file could not be read"));
        }
        let result = json!({
            "path": path,
            "contentB64": payload["contentB64"],
            "sha256": payload["sha256"],
            "size": payload["size"]
        });
        // The done frame carries the content; progress stays content-free.
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Write one relay-carried file from base64 (+ sha256 readback).
pub struct FileWrite;

impl CommandHandler for FileWrite {
    fn name(&self) -> &'static str {
        "file.write"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let path = required(ctx, "path")?;
        if !relay_path_ok(path) {
            return Err(invalid_relay_path());
        }
        let content = required(ctx, "contentB64")?;
        if content.len() > RELAY_CAP_B64 {
            return Err(invalid("contentB64", "exceeds the 256 KiB relay cap"));
        }
        let b64_ok = !content.is_empty()
            && content
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c));
        if !b64_ok {
            return Err(invalid("contentB64", "must be base64"));
        }

        ctx.progress
            .report(crate::report::OpRunState::running("writing file", 30.0));

        let script = "param([string]$Path,[string]$ContentB64) \
            $ErrorActionPreference = 'Stop'; \
            $bytes = [Convert]::FromBase64String($ContentB64); \
            New-Item -ItemType Directory -Force -Path (Split-Path $Path) | Out-Null; \
            [System.IO.File]::WriteAllBytes($Path, $bytes); \
            $sha = [System.Security.Cryptography.SHA256]::Create(); \
            ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''";
        let args = [path.to_string(), content.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "path": path,
            "sha256": output.stdout.trim()
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
    fn read_rejects_paths_outside_the_allowlist() {
        for path in [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Users\\Administrator\\secret.txt",
            "C:\\Transfer\\..\\Windows\\evil.dll",
            "D:\\Transfer\\x.crt",
        ] {
            let params = ctx_params(&[("path", path)]);
            let sink = NullProgressSink;
            let ctx = CommandContext {
                params: &params,
                progress: &sink,
                shell: Arc::new(MockPowerShell::new()),
            };
            assert!(
                matches!(
                    FileRead.execute(&ctx),
                    Err(CommandError::InvalidParam { .. })
                ),
                "path should have been rejected: {path}"
            );
        }
    }

    #[test]
    fn read_accepts_all_three_relay_prefixes() {
        for path in [
            "C:\\Transfer\\EC-Root-CA.crt",
            "C:\\Windows\\System32\\CertSrv\\CertEnroll\\root.crl",
            "C:\\CertEnroll\\issuing.crt",
        ] {
            let params = ctx_params(&[("path", path)]);
            let sink = NullProgressSink;
            let shell = Arc::new(MockPowerShell::new());
            shell.push_success(
                r#"{"contentB64":"aGVsbG8=","sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","size":5}"#
            );
            let ctx = CommandContext {
                params: &params,
                progress: &sink,
                shell,
            };
            let result = FileRead.execute(&ctx).unwrap();
            assert_eq!(result["contentB64"], "aGVsbG8=");
            assert_eq!(result["size"], 5);
        }
    }

    #[test]
    fn read_fails_cleanly_on_unreadable_file() {
        let params = ctx_params(&[("path", "C:\\Transfer\\missing.crt")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "Could not find file");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            FileRead.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    #[test]
    fn write_rejects_paths_outside_the_allowlist() {
        let params = ctx_params(&[
            ("path", "C:\\Windows\\System32\\evil.exe"),
            ("contentB64", "aGVsbG8="),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            FileWrite.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn write_rejects_non_base64_content() {
        let params = ctx_params(&[
            ("path", "C:\\Transfer\\EC-Root-CA.crt"),
            ("contentB64", "not base64!!"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            FileWrite.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn write_rejects_oversized_content() {
        let big = "A".repeat(RELAY_CAP_B64 + 1);
        let params = ctx_params(&[
            ("path", "C:\\Transfer\\big.bin"),
            ("contentB64", &big),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            FileWrite.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn write_reports_the_digest_readback() {
        let params = ctx_params(&[
            ("path", "C:\\Transfer\\EC-Root-CA.crt"),
            ("contentB64", "aGVsbG8="),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = FileWrite.execute(&ctx).unwrap();
        assert_eq!(
            result["sha256"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
