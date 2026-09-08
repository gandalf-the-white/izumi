use domain::{CryptoRecommendation, CryptoSuiteId, PeerId, SessionId};

use protocol::{
    Capabilities, ClientHello, JsonCodec, NegotiationAccept, NegotiationReject, PROTOCOL_VERSION,
    ProtocolCodec, ProtocolMessage, Recommendation, RejectionReason,
};

fn roundtrip(message: ProtocolMessage) {
    let codec = JsonCodec;

    let encoded = codec.encode(&message).expect("message should encode");

    let decoded = codec.decode(&encoded).expect("message should decode");

    assert_eq!(decoded, message);
}

#[test]
fn all_protocol_messages_roundtrip() {
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
        session_id,

        reason: RejectionReason::NoCommonCryptoSuite,
    }));
}
