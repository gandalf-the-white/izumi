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

    AuthenticationAck(AuthenticationAck),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationAck {
    pub session_id: SessionId,
}

impl ProtocolMessage {
    pub fn session_id(&self) -> &SessionId {
        match self {
            Self::ClientHello(message) => &message.session_id,

            Self::AuthenticationAck(message) => &message.session_id,

            Self::Capabilities(message) => &message.session_id,

            Self::Recommendation(message) => &message.session_id,

            Self::NegotiationAccept(message) => &message.session_id,

            Self::NegotiationReject(message) => &message.session_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_message_exposes_session_id() {
        let message = ProtocolMessage::AuthenticationAck(AuthenticationAck {
            session_id: SessionId::new("session-42"),
        });

        assert_eq!(message.session_id().as_str(), "session-42");
    }
}
