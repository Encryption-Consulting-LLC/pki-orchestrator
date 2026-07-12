//! Mirrors `EC-PKI-Playground/backend/src/app/core/jobs/models.py::OpRunState`.
//!
//! Keeping this shape identical means a future backend adapter is a
//! serializer onto the existing WS job transport, not a redesign.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpStatus {
    Pending,
    Running,
    Done,
    Error,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpRunState {
    pub status: OpStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

impl OpRunState {
    pub fn running(phase: impl Into<String>, percent: f64) -> Self {
        Self {
            status: OpStatus::Running,
            percent: Some(percent),
            phase: Some(phase.into()),
            detail: None,
            result: None,
        }
    }

    pub fn done(result: serde_json::Value) -> Self {
        Self {
            status: OpStatus::Done,
            percent: Some(100.0),
            phase: None,
            detail: None,
            result: Some(result),
        }
    }

    pub fn error(detail: impl Into<String>) -> Self {
        Self {
            status: OpStatus::Error,
            percent: None,
            phase: None,
            detail: Some(detail.into()),
            result: None,
        }
    }
}

/// Thin sink so handlers don't know whether progress goes to stdout, a
/// channel, or (future) a WebSocket frame to the backend.
pub trait ProgressSink: Send + Sync {
    fn report(&self, state: OpRunState);
}

/// Discards all progress — useful in tests where only the final result
/// matters.
pub struct NullProgressSink;

impl ProgressSink for NullProgressSink {
    fn report(&self, _state: OpRunState) {}
}

/// Records every reported state, in order — used by tests to assert
/// phase/percent sequencing.
#[derive(Default)]
pub struct RecordingProgressSink {
    pub states: std::sync::Mutex<Vec<OpRunState>>,
}

impl ProgressSink for RecordingProgressSink {
    fn report(&self, state: OpRunState) {
        self.states.lock().unwrap().push(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_without_null_fields() {
        let state = OpRunState::done(serde_json::json!({ "ok": true }));
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["status"], "done");
        assert_eq!(json["percent"], 100.0);
        assert!(json.get("phase").is_none());
    }

    #[test]
    fn recording_sink_preserves_order() {
        let sink = RecordingProgressSink::default();
        sink.report(OpRunState::running("first", 10.0));
        sink.report(OpRunState::running("second", 50.0));
        let states = sink.states.lock().unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].phase.as_deref(), Some("first"));
        assert_eq!(states[1].phase.as_deref(), Some("second"));
    }
}
