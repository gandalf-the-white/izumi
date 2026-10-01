use domain::{CryptoRecommendation, CryptoSuiteId, PeerId, SessionId};

use protocol::{
    AuthenticationAck, Capabilities, ClientHello, JsonCodec, NegotiationAccept, NegotiationReject,
    PROTOCOL_VERSION, ProtocolCodec, ProtocolMessage, Recommendation, RejectionReason,
};

fn roundtrip(message: ProtocolMessage) {
    let codec = JsonCodec;

    let encoded = codec.encode(&message).expect("Message should encode");

    let decode = codec.decode(&encoded).expect("Message should decode");

    assert_eq!(decode, message);
}

#[test]
fn all_protocol_message_roundtrip() {
    let session_id = SessionId::new("session-123");

    roundtrip(ProtocolMessage::ClientHello(ClientHello {
        protocol_version: PROTOCOL_VERSION,

        session_id: session_id.clone(),

        claimed_peer_id: PeerId::new("proxy-a"),
    }));

    roundtrip(ProtocolMessage::Capabilities(Capabilities {
        session_id: session_id.clone(),

        supported_suites: vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
    }));

    roundtrip(ProtocolMessage::Recommendation(Recommendation {
        session_id: session_id.clone(),

        recommendation: CryptoRecommendation::new(
            CryptoSuiteId::ChaCha20Poly1305,
            "Preferred suite",
            0.95,
        ),
    }));

    roundtrip(ProtocolMessage::NegotiationAccept(NegotiationAccept {
        session_id: session_id.clone(),

        selected_suite: CryptoSuiteId::ChaCha20Poly1305,
    }));

    roundtrip(ProtocolMessage::NegotiationReject(NegotiationReject {
        session_id: session_id.clone(),

        reason: RejectionReason::NoCommonCryptoSuite,
    }));
}

#[test]
fn protocol_message_exposes_session_id() {
    let message = ProtocolMessage::AuthenticationAck(AuthenticationAck {
        session_id: SessionId::new("session-42"),
    });

    assert_eq!(message.session_id().as_str(), "session-42");
}
