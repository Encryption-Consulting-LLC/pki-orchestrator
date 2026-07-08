mod cert_verify;
mod exec_arbitrary;
mod hostname_read;
mod hostname_rename;

use crate::registry::CommandRegistry;

/// The command surface: the 3 v0 handlers chosen to exercise every point on
/// the role spectrum (guest-eligible read, operator-only write,
/// guest-forbidden escape hatch), plus the hostname/IP read-write parity set
/// every template machine needs. See the README's command-catalog table for
/// the planned ADCS catalog this will grow into.
pub fn build_default_registry() -> CommandRegistry {
    let mut registry = CommandRegistry::new();
    registry.register(Box::new(hostname_rename::HostnameRename));
    registry.register(Box::new(hostname_read::HostnameRead));
    registry.register(Box::new(cert_verify::CertVerify));
    registry.register(Box::new(exec_arbitrary::ExecArbitrary));
    registry
}
