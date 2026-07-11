//! Helpers shared by command handlers: dispatch-param access, validation
//! errors, and the non-zero-exit check every shell-backed handler performs.
//! Extracted once the Phase L catalog grew past a handful of files — the
//! per-file copies in the original handlers (`ca.rs`, `ip.rs`) predate this.

use crate::{
    powershell::{PowerShellError, PowerShellOutput},
    registry::{CommandContext, CommandError}
};

/// Read one dispatch param as `&str`. The backend supplies these — for
/// plan-driven provisioning it dispatches each command with resolved params,
/// so a handler never reads config directly (backend-driven provisioning).
pub fn param<'a>(ctx: &'a CommandContext, key: &str) -> Option<&'a str> {
    ctx.params.get(key).map(String::as_str)
}

/// Like [`param`], but a missing key is a `MissingParam` error.
pub fn required<'a>(
    ctx: &'a CommandContext,
    key: &str
) -> Result<&'a str, CommandError> {
    param(ctx, key).ok_or_else(|| CommandError::MissingParam(key.into()))
}

pub fn invalid(name: &str, reason: &str) -> CommandError {
    CommandError::InvalidParam {
        name: name.into(),
        reason: reason.into()
    }
}

/// Pass a successful shell run through; map a non-zero exit to
/// `CommandError::Shell` carrying the exit code and stderr.
pub fn require_success(
    output: PowerShellOutput
) -> Result<PowerShellOutput, CommandError> {
    if output.succeeded() {
        Ok(output)
    } else {
        Err(CommandError::Shell(PowerShellError::NonZeroExit {
            exit_code: output.exit_code,
            stderr: output.stderr
        }))
    }
}

/// Best-effort JSON parse of `ConvertTo-Json` output — `Null` when the
/// output isn't valid JSON (callers keep the raw text alongside).
pub fn parse_json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap_or(serde_json::Value::Null)
}

/// A plain absolute Windows path (`C:\...`) with a conservative character
/// set — same shape the backend's `_CERT_PATH` validator enforces. Defence
/// in depth on top of the `param()`-block quoting: path params reach
/// PowerShell as literal strings either way.
pub fn valid_windows_path(path: &str) -> bool {
    let mut chars = path.chars();
    let (Some(drive), Some(':'), Some('\\')) =
        (chars.next(), chars.next(), chars.next())
    else {
        return false;
    };
    drive.is_ascii_alphabetic()
        && path.len() <= 200
        && chars.all(|c| c.is_ascii_alphanumeric() || " ._-\\()".contains(c))
}

/// One DNS name label or dotted name (`pki`, `srv1.example.com.`), max 253
/// chars — mirrors the backend's `_DNS` validator, plus an optional
/// trailing dot (FQDN form used by CNAME targets).
pub fn valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}
