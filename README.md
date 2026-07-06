# pki-orchestrator

A VM-resident agent that mediates post-boot control of a deployed VM on behalf
of [EC-PKI-Playground](https://github.com/Arnesh-EC/EC-PKI-Playground).

## Vision

`configgen` generates this agent's first-boot configuration, `isokit` packs it
into the VM's boot ISO, and `vmkit` deploys the VM. Once the VM boots, the
orchestrator runs as a persistent Windows Service, phones home to the
EC-PKI-Playground backend to establish two-way communication, and then
executes a **role-differentiated command surface**: guests get a narrow,
allowlisted set of commands; operators get the broad/arbitrary set, gated by
the backend's already-reserved `Capability.VM_EXEC_ARBITRARY`
(`backend/src/app/core/authz.py`). The end goal is to compose an entire PKI
topology on the EC-PKI-Playground dashboard, hit deploy, and have this agent
carry out the build (AD DS forest promotion, ADCS install, CDP/AIA
configuration, domain join, cert enrollment — see
`pki-lab-guides/vm-building.md` for the manual reference process) behind the
scenes, streaming progress back to the frontend.

Windows Server is the only target for now; Linux support is a stated future
goal.

## Out of scope for v0

This is the first commit of a new repo. It proves the core architecture —
role-gated command dispatch, PowerShell execution, Windows Service
lifecycle — with a small, real, testable slice. It deliberately does **not**
yet include:

- Any network connection to the EC-PKI-Playground backend ("phone home").
  `backend.url` exists in the config schema but nothing reads it yet.
- The full ADCS command catalog from `vm-building.md` (AD DS forest
  promotion, CA install, template publishing, OCSP configuration, etc.) —
  only 3 commands are implemented, chosen to exercise every point on the role
  spectrum (see below).
- Packaging/deployment integration with `configgen`/`isokit`/`vmkit`.

## Future integration points

Gaps identified in the sibling repos while designing this one, so they don't
need rediscovering later:

- **isokit** (`build_script_iso`) only accepts text scripts, force-decoded as
  UTF-8 with rewritten line endings — it cannot embed a compiled binary today.
  Shipping this orchestrator's binary via the boot ISO will need a new
  binary-embedding API there.
- **vmkit** has no guest-level communication (no VMware Tools/VIX guest-exec,
  no IP/hostname readback) — there is no existing way for the backend to
  correlate an inbound "phone home" call to a specific VM record. This is why
  `identity.vm_id` exists in the config schema now: it's a placeholder for a
  shared correlation token baked into the config ISO and echoed back on
  phone-home.
- **configgen** has no plugin/extension point for emitting an "install the
  orchestrator" first-boot step — only hostname/network/local-password
  renderers exist today.

## Command surface (v0)

| Command | Capability | Guest-eligible? | Source |
|---|---|---|---|
| `hostname.rename` | `VmUpdate` | No | `Rename-Computer` pattern, used repeatedly across `vm-building.md` |
| `cert.verify` | `VmRead` | **Yes** | `certutil -verify -urlfetch`, the guide's own health-check command |
| `powershell.exec_arbitrary` | `VmExecArbitrary` | **No** (by construction) | Reserved escape hatch — must never reach a guest |

`cert.verify` is deliberately guest-eligible to prove the *allowed* path
through the registry, not just the forbidden one. `powershell.exec_arbitrary`
is the load-bearing negative case: `CommandRegistry::dispatch` must reject it
for `Role::Guest` before the handler ever runs.

### Planned (not yet implemented)

The full catalog this orchestrator will eventually need, drawn from
`pki-lab-guides/vm-building.md`'s two-tier ADCS lab (DC01/CA01/CA02/SRV1/WIN11).
Each will be added as its own command handler once the v0 pattern above is
validated:

| Planned command | Capability | Notes |
|---|---|---|
| `ad.promote_forest` | `VmExecArbitrary` | AD DS forest promotion + DNS |
| `ca.install_standalone_root` | `VmExecArbitrary` | CAPolicy.inf + standalone root CA install |
| `ca.configure_registry` | `VmExecArbitrary` | `certutil -setreg` cluster (CRL periods, auditing) |
| `ca.configure_cdp_aia` | `VmExecArbitrary` | AIA/CDP publication URLs |
| `ca.sign_request` / `ca.install_subordinate` | `VmExecArbitrary` | Cross-CA CSR signing pass |
| `ca.publish_template` | `VmExecArbitrary` | `Add-CATemplate` |
| `iis.configure_cert_enroll_share` | `VmExecArbitrary` | Web CDP/AIA hosting |
| `ocsp.configure_revocation` | `VmExecArbitrary` | **COM-only** (`CertAdm.OCSPAdmin`) — no clean PowerShell path per the guide; will need a distinct `windows-rs`-based executor, not the `.ps1` shell-out path used everywhere else |
| `domain.join` | `VmExecArbitrary` | `Add-Computer` |

## Architecture

- `authz.rs` — local mirror of the backend's `Role`/`Capability`/
  `ROLE_CAPABILITIES`. Wire values must match `authz.py`'s `.value` strings
  exactly; there is no automated sync between the two languages.
- `report.rs` — `OpRunState`/`OpStatus` mirror the backend's
  `app/core/jobs/models.py::OpRunState` shape, so a future backend adapter is
  a serializer, not a redesign.
- `registry.rs` — `CommandRegistry::dispatch` checks the caller's role against
  a handler's required capability *before* calling into it — structurally
  impossible for a new handler to forget its own gate.
- `powershell.rs` — `PowerShellExecutor` trait, with a real
  `std::process::Command`-based implementation and a mock for tests. Shells
  out rather than binding COM, since every v0 command has a plain PowerShell
  equivalent and this is what's testable from a non-Windows dev machine.
- `commands/` — the 3 v0 handlers.
- `service/` — dual-mode binary: `run` (works on any OS, the dev/CI path) and
  `service {install,uninstall,run}` (Windows Service Control Manager
  integration via the `windows-service` crate, Windows-only).

## Usage

```sh
cp orchestrator.example.toml orchestrator.toml
cargo run -- run --command cert.verify --param path=C:\win11.cer
```

On Windows, to install as a service:

```powershell
pki-orchestrator.exe service install
```

## Testing

`cargo test` runs everything that doesn't require a real Windows box or a
live shell: config parsing, capability/role gating (including the guest ↔
`VmExecArbitrary` invariant), and all 3 command handlers driven through a
mock PowerShell executor. Real `powershell.exe` invocation and Windows
Service Control Manager lifecycle are exercised only in CI's `windows-latest`
job / manual testing — see the CI workflow for what actually runs where.
