use crate::state::SessionPhase;

use thiserror::Error;

// #[derive(Debug, Error)]
// pub enum SessionError {
//     #[error("unexpected protocol message while session is in phase {phase:?}")]
//     UnexpectedMessage { phase: SessionPhase },

//     #[error("session id mismatch: expected {expected}, received {received}")]
//     SessionIdMismatch { expected: String, received: String },

//     #[error("peer identity mismatch")]
//     PeerMismatch,

//     #[error("transport error: {0}")]
//     Transport(String),

//     #[error("session is already closed")]
//     Closed,

//     #[error(
//         "recommendation contains a suite \
//      that is not common to both peers"
//     )]
//     InvalidRecommendation,

//     #[error("remote capabilities are not available")]
//     MissingRemoteCapabilities,
// }

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("unexpected protocol message while session is in phase {phase:?}")]
    UnexpectedMessage { phase: SessionPhase },

    #[error("session id mismatch: expected {expected}, received {received}")]
    SessionIdMismatch { expected: String, received: String },

    #[error("peer identity mismatch")]
    PeerMismatch,

    #[error(
        "recommendation contains a cryptographic suite \
         that is not supported by both peers"
    )]
    InvalidRecommendation,

    #[error(
        "negotiated cryptographic suite is not supported \
         by both peers"
    )]
    InvalidNegotiatedSuite,

    #[error(
        "local and remote peers selected different \
         cryptographic suites"
    )]
    NegotiationMismatch,

    #[error("transport error: {0}")]
    Transport(String),

    #[error("session is already closed")]
    Closed,
}
