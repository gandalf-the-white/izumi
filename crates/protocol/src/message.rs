use domain::{CryptoRecommendation, CryptoSuiteId, PeerId, SessionId};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub session_id: SessionId,

    /// Identity claimed by the remote peer.
    /// It MUST NOT be trusted until cryptographic
    /// authentication succeeds.
    pub claimed_peer_id: PeerId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub session_id: SessionId,
    pub supported_suites: Vec<CryptoSuiteId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub session_id: SessionId,
    pub recommendation: CryptoRecommendation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiationAccept {
    pub session_id: SessionId,
    pub selected_suite: CryptoSuiteId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectionReason {
    UnsupportedProtocolVersion,
    NoCommonCryptoSuite,
    PolicyRejected,
    InvalidRecommendation,
    ProtocolViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiationReject {
    pub session_id: SessionId,
    pub reason: RejectionReason,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolMessage {
    ClientHello(ClientHello),

    Capabilities(Capabilities),

    Recommendation(Recommendation),

    NegotiationAccept(NegotiationAccept),

    NegotiationReject(NegotiationReject),
}
