mod ca;
mod cert_verify;
mod exec_arbitrary;
mod hostname_read;
mod hostname_rename;
mod ip;

use crate::registry::CommandRegistry;

/// The command surface: the 3 v0 handlers chosen to exercise every point on
/// the role spectrum (guest-eligible read, operator-only write,
/// guest-forbidden escape hatch), the hostname/IP read-write parity set every
/// template machine needs, and (Phase F) the per-template CA provisioning
/// commands that self-apply from the ISO-baked config. See the README's
/// command-catalog table for the planned ADCS catalog this grows into.
pub fn build_default_registry() -> CommandRegistry {
    let mut registry = CommandRegistry::new();
    registry.register(Box::new(hostname_rename::HostnameRename));
    registry.register(Box::new(hostname_read::HostnameRead));
    registry.register(Box::new(cert_verify::CertVerify));
    registry.register(Box::new(exec_arbitrary::ExecArbitrary));
    registry.register(Box::new(ip::IpRead));
    registry.register(Box::new(ip::IpWrite));
    registry.register(Box::new(ca::CaInstall));
    registry.register(Box::new(ca::CaConfigureCdpAia));
    registry
}
