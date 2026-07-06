//! Phone-home client: connects outbound to the EC-PKI-Playground backend
//! over a long-lived WebSocket (`ws /api/orchestrator/connect`), receives
//! dispatched commands, and streams their `OpRunState` progress back.
//!
//! The backend is the authoritative capability gate — it checks the calling
//! human's role via `require_capability` before ever forwarding a command,
//! and includes that role in every dispatched frame (see `InboundCommand`).
//! `CommandRegistry::dispatch` re-checks that *forwarded* role locally: a
//! second, structural gate, not the primary one — `identity.role` in the
//! local config is not consulted here at all.
//!
//! The framing/dispatch translation (`handle_command`) is a plain sync
//! function so it's unit-testable with an in-memory channel, without a real
//! socket — the actual connect/reconnect I/O loop below it is verified
//! manually (same tier as `powershell::RealPowerShell`, `service::scm`).

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::{
    authz::Role,
    config::OrchestratorConfig,
    powershell::PowerShellExecutor,
    registry::CommandRegistry,
    report::{OpRunState, ProgressSink}
};

/// One command dispatched by the backend, tagged with the job id its
/// progress should be reported under and the role the backend authenticated
/// the calling human as.
#[derive(Debug, Clone, Deserialize)]
pub struct InboundCommand {
    pub job_id: String,
    pub command: String,
    #[serde(default)]
    pub params: std::collections::HashMap<String, String>,
    pub role: Role
}

/// One progress frame sent back to the backend, tagged with the job id it
/// belongs to so the backend can relay it onto the matching
/// `/api/ws/jobs/{job_id}` channel.
#[derive(Debug, Clone, Serialize)]
pub struct OutboundProgress {
    pub job_id: String,
    pub state: OpRunState
}

struct TaggedProgressSink {
    job_id: String,
    sender: mpsc::UnboundedSender<OutboundProgress>
}

impl ProgressSink for TaggedProgressSink {
    fn report(&self, state: OpRunState) {
        let _ = self.sender.send(OutboundProgress {
            job_id: self.job_id.clone(),
            state
        });
    }
}

/// Dispatches one inbound command and forwards its progress. Handlers
/// already report their own terminal `done` state via the sink on success
/// (see `commands/*.rs`), so this only synthesizes a terminal `error` frame
/// when dispatch itself fails (unknown command, forbidden role, or a
/// `CommandError` a handler never got the chance to report itself).
pub fn handle_command(
    registry: &CommandRegistry,
    shell: Arc<dyn PowerShellExecutor>,
    cmd: InboundCommand,
    sender: &mpsc::UnboundedSender<OutboundProgress>
) {
    let sink = TaggedProgressSink {
        job_id: cmd.job_id.clone(),
        sender: sender.clone()
    };

    if let Err(err) =
        registry.dispatch(&cmd.command, cmd.role, cmd.params, &sink, shell)
    {
        let _ = sender.send(OutboundProgress {
            job_id: cmd.job_id,
            state: OpRunState::error(err.to_string())
        });
    }
}

fn connect_url(config: &OrchestratorConfig) -> Result<Url> {
    let base = config
        .backend
        .url
        .as_deref()
        .context("backend.url is required to connect")?;
    let mut url = Url::parse(base).context("parsing backend.url")?;
    let ws_scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(ws_scheme).map_err(|()| {
        anyhow::anyhow!("backend.url has an unsupported scheme")
    })?;
    url.set_path("/api/orchestrator/connect");
    url.query_pairs_mut()
        .append_pair("vm_id", &config.identity.vm_id)
        .append_pair("token", &config.identity.agent_token);
    Ok(url)
}

async fn connect_once(
    config: &OrchestratorConfig,
    registry: &Arc<CommandRegistry>,
    shell: &Arc<dyn PowerShellExecutor>
) -> Result<()> {
    let url = connect_url(config)?;
    let (stream, _) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .context("connecting to backend")?;
    tracing::info!(vm_id = %config.identity.vm_id, "connected to backend");

    let (mut write, mut read) = stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<OutboundProgress>();

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Ok(text) = serde_json::to_string(&msg) else {
                continue;
            };
            if write.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    });

    while let Some(frame) = read.next().await {
        let frame = frame.context("reading from backend")?;
        let Message::Text(text) = frame else { continue };

        let cmd: InboundCommand = match serde_json::from_str(&text) {
            Ok(cmd) => cmd,
            Err(err) => {
                tracing::warn!(?err, "received malformed command frame");
                continue;
            }
        };

        let registry = Arc::clone(registry);
        let shell = Arc::clone(shell);
        let tx = tx.clone();
        tokio::task::spawn_blocking(move || {
            handle_command(&registry, shell, cmd, &tx);
        });
    }

    drop(tx);
    let _ = writer.await;
    Ok(())
}

const RECONNECT_DELAYS_SECS: [u64; 5] = [1, 2, 5, 10, 30];

/// Connects, dispatches, and reconnects with capped backoff forever. Only
/// returns if the config itself is unusable (e.g. no `backend.url`) — a
/// dropped connection is retried, never treated as fatal.
pub async fn run_forever(
    config: &OrchestratorConfig,
    registry: Arc<CommandRegistry>,
    shell: Arc<dyn PowerShellExecutor>
) -> Result<()> {
    connect_url(config)?; // fail fast on bad config, before the first attempt

    let mut attempt = 0usize;
    loop {
        match connect_once(config, &registry, &shell).await {
            Ok(()) => {
                tracing::warn!("backend closed the connection; reconnecting")
            }
            Err(err) => tracing::warn!(
                ?err,
                "phone-home connection failed; reconnecting"
            )
        }

        let delay =
            RECONNECT_DELAYS_SECS[attempt.min(RECONNECT_DELAYS_SECS.len() - 1)];
        attempt += 1;
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commands::build_default_registry, powershell::MockPowerShell};
    use std::collections::HashMap;

    fn recv_all(
        rx: &mut mpsc::UnboundedReceiver<OutboundProgress>
    ) -> Vec<OutboundProgress> {
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            out.push(msg);
        }
        out
    }

    #[test]
    fn guest_forbidden_command_reports_a_terminal_error_frame() {
        let registry = build_default_registry();
        let shell: Arc<dyn PowerShellExecutor> =
            Arc::new(MockPowerShell::new());
        let (tx, mut rx) = mpsc::unbounded_channel();

        handle_command(
            &registry,
            shell,
            InboundCommand {
                job_id: "job-1".into(),
                command: "powershell.exec_arbitrary".into(),
                params: HashMap::from([("script".into(), "echo hi".into())]),
                role: Role::Guest
            },
            &tx
        );

        let frames = recv_all(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].job_id, "job-1");
        assert_eq!(frames[0].state.status, crate::report::OpStatus::Error);
    }

    #[test]
    fn allowed_command_forwards_the_handlers_own_progress_and_done_frames() {
        let registry = build_default_registry();
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            "...\nCertUtil: -verify command completed successfully.\n"
        );
        let shell: Arc<dyn PowerShellExecutor> = shell;
        let (tx, mut rx) = mpsc::unbounded_channel();

        handle_command(
            &registry,
            shell,
            InboundCommand {
                job_id: "job-2".into(),
                command: "cert.verify".into(),
                params: HashMap::from([(
                    "path".into(),
                    "C:\\win11.cer".into()
                )]),
                role: Role::Guest
            },
            &tx
        );

        let frames = recv_all(&mut rx);
        assert!(frames.iter().all(|f| f.job_id == "job-2"));
        assert!(
            frames
                .iter()
                .any(|f| f.state.status == crate::report::OpStatus::Running)
        );
        let done = frames
            .iter()
            .find(|f| f.state.status == crate::report::OpStatus::Done)
            .expect("expected a done frame");
        assert_eq!(done.state.result.as_ref().unwrap()["chain_ok"], true);
    }

    #[test]
    fn unknown_command_reports_a_terminal_error_frame() {
        let registry = build_default_registry();
        let shell: Arc<dyn PowerShellExecutor> =
            Arc::new(MockPowerShell::new());
        let (tx, mut rx) = mpsc::unbounded_channel();

        handle_command(
            &registry,
            shell,
            InboundCommand {
                job_id: "job-3".into(),
                command: "does.not_exist".into(),
                params: HashMap::new(),
                role: Role::Operator
            },
            &tx
        );

        let frames = recv_all(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].state.status, crate::report::OpStatus::Error);
    }

    #[test]
    fn connect_url_rejects_missing_backend_url() {
        let config = OrchestratorConfig {
            identity: crate::config::IdentityConfig {
                vm_id: "dev".into(),
                agent_token: "tok".into(),
                role: Role::Operator
            },
            backend: crate::config::BackendConfig { url: None },
            execution: Default::default(),
            service: Default::default()
        };
        assert!(connect_url(&config).is_err());
    }

    #[test]
    fn connect_url_builds_a_ws_url_with_vm_id_and_token() {
        let config = OrchestratorConfig {
            identity: crate::config::IdentityConfig {
                vm_id: "vm-42".into(),
                agent_token: "secret".into(),
                role: Role::Operator
            },
            backend: crate::config::BackendConfig {
                url: Some("http://127.0.0.1:8000".into())
            },
            execution: Default::default(),
            service: Default::default()
        };
        let url = connect_url(&config).unwrap();
        assert_eq!(url.scheme(), "ws");
        assert_eq!(url.path(), "/api/orchestrator/connect");
        assert!(url.query().unwrap().contains("vm_id=vm-42"));
        assert!(url.query().unwrap().contains("token=secret"));
    }
}
