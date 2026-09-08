use crate::ProtocolMessage;

use thiserror::Error;

pub trait ProtocolCodec {
    type Error;

    fn encode(&self, message: &ProtocolMessage) -> Result<Vec<u8>, Self::Error>;

    fn decode(&self, data: &[u8]) -> Result<ProtocolMessage, Self::Error>;
}

#[derive(Debug, Error)]
pub enum JsonCodecError {
    #[error("JSON protocol encoding failed: {0}")]
    Encode(serde_json::Error),

    #[error("JSON protocol decoding failed: {0}")]
    Decode(serde_json::Error),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct JsonCodec;

impl ProtocolCodec for JsonCodec {
    type Error = JsonCodecError;

    fn encode(&self, message: &ProtocolMessage) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(message).map_err(JsonCodecError::Encode)
    }

    fn decode(&self, data: &[u8]) -> Result<ProtocolMessage, Self::Error> {
        serde_json::from_slice(data).map_err(JsonCodecError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{ClientHello, PROTOCOL_VERSION, ProtocolMessage};

    use domain::{PeerId, SessionId};

    #[test]
    fn client_hello_roundtrip() {
        let message = ProtocolMessage::ClientHello(ClientHello {
            protocol_version: PROTOCOL_VERSION,

            session_id: SessionId::new("session-1"),

            peer_id: PeerId::new("proxy-a"),
        });

        let codec = JsonCodec;

        let encoded = codec.encode(&message).expect("message should encode");

        let decoded = codec.decode(&encoded).expect("message should decode");

        assert_eq!(decoded, message);
    }

    #[test]
    fn capabilities_roundtrip() {
        let message = ProtocolMessage::Capabilities(crate::Capabilities {
            session_id: SessionId::new("session-1"),

            supported_suites: vec![
                domain::CryptoSuiteId::Aes256Gcm,
                domain::CryptoSuiteId::ChaCha20Poly1305,
            ],
        });

        let codec = JsonCodec;

        let encoded = codec.encode(&message).unwrap();

        let decoded = codec.decode(&encoded).unwrap();

        assert_eq!(decoded, message);
    }

    #[test]
    fn crypto_suite_uses_stable_wire_name() {
        let message = ProtocolMessage::Capabilities(crate::Capabilities {
            session_id: SessionId::new("session-1"),

            supported_suites: vec![domain::CryptoSuiteId::Aes256Gcm],
        });

        let codec = JsonCodec;

        let encoded = codec.encode(&message).unwrap();

        let json = String::from_utf8(encoded).unwrap();

        assert!(json.contains("\"AES_256_GCM\""));
    }

    #[test]
    fn malformed_json_is_rejected() {
        let codec = JsonCodec;

        let result = codec.decode(br#"{"type":"INVALID""#);

        assert!(result.is_err());
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        let codec = JsonCodec;

        let data = br#"
    {
        "type": "DESTROY_THE_WORLD",
        "payload": {}
    }
    "#;

        let result = codec.decode(data);

        assert!(result.is_err());
    }
}
