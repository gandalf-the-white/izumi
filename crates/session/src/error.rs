use crate::SessionPhase;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("unexpected protocol message while session is in phase {phase:?}")]
    UnexpectedMessage { phase: SessionPhase },

    #[error("session id mismatch: expected {expected}, received {received}")]
    SessionIdMismatch { expected: String, received: String },

    #[error("transport error: {0}")]
    Transport(String),

    #[error("session is already closed")]
    Closed,

    #[error("remote capabilities are not available")]
    MissingRemoteCapabilities,

    #[error("remote recommendation is not available")]
    MissingRemoteRecommendation,

    #[error("negotiation was rejected")]
    NegotiationRejected,
}
