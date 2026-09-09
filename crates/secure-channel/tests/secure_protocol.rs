use domain::PeerId;

use identity::{TrustStore, generate_keypair};

use secure_channel::{SecureChannelPair, establish_in_memory};

use domain::{CryptoSuiteId, SessionId};

use protocol::{Capabilities, ProtocolMessage};

fn build_test_channel_pair() -> SecureChannelPair {
    // Create identities
    // Generate keys
    // Build TrustStores
    // Noise handshake
    // Mutual authentication
    // Transition to TransportState

    let proxy_a_id = PeerId::new("proxy-a");

    let proxy_b_id = PeerId::new("proxy-b");

    let proxy_a = generate_keypair().expect("proxy A keypair should be generated");

    let proxy_b = generate_keypair().expect("proxy B keypair should be generated");

    let mut trust_a = TrustStore::new();

    let mut trust_b = TrustStore::new();

    trust_a.trust(proxy_b_id.clone(), proxy_b.public_key().clone());

    trust_b.trust(proxy_a_id.clone(), proxy_a.public_key().clone());

    establish_in_memory(
        proxy_a_id, &proxy_a, &trust_a, proxy_b_id, &proxy_b, &trust_b,
    )
    .expect("secure channel pair should be established")
}

#[test]
fn encrypted_payload_roundtrip_works() {
    let proxy_a_id = PeerId::new("proxy-a");

    let proxy_b_id = PeerId::new("proxy-b");

    let proxy_a = generate_keypair().unwrap();

    let proxy_b = generate_keypair().unwrap();

    let mut trust_a = TrustStore::new();

    let mut trust_b = TrustStore::new();

    trust_a.trust(proxy_b_id.clone(), proxy_b.public_key().clone());

    trust_b.trust(proxy_a_id.clone(), proxy_a.public_key().clone());

    let mut pair = establish_in_memory(
        proxy_a_id, &proxy_a, &trust_a, proxy_b_id, &proxy_b, &trust_b,
    )
    .expect("secure channel should establish");

    let frame = pair
        .initiator
        .seal(b"hello proxy-b")
        .expect("message should encrypt");

    let plaintext = pair.responder.open(&frame).expect("message should decrypt");

    assert_eq!(plaintext, b"hello proxy-b");

    let response = pair.responder.seal(b"hello proxy-a").unwrap();

    let plaintext = pair.initiator.open(&response).unwrap();

    assert_eq!(plaintext, b"hello proxy-a");
}

#[test]
fn modified_ciphertext_is_rejected() {
    let mut pair = build_test_channel_pair();

    let mut frame = pair.initiator.seal(b"sensitive negotiation").unwrap();

    let last = frame.len() - 1;

    frame[last] ^= 0x01;

    let result = pair.responder.open(&frame);

    assert!(result.is_err());
}

#[test]
fn multiple_messages_can_be_exchanged_in_order() {
    let mut pair = build_test_channel_pair();

    for index in 0..100 {
        let message = format!("message-{index}");

        let frame = pair.initiator.seal(message.as_bytes()).unwrap();

        let received = pair.responder.open(&frame).unwrap();

        assert_eq!(received, message.as_bytes());
    }
}

#[test]
fn replayed_transport_message_is_rejected() {
    let mut pair = build_test_channel_pair();

    let frame = pair.initiator.seal(b"message").unwrap();

    pair.responder
        .open(&frame)
        .expect("first delivery should succeed");

    let replay = pair.responder.open(&frame);

    assert!(replay.is_err());
}

#[test]
fn capabilities_can_travel_through_secure_channel() {
    let mut pair = build_test_channel_pair();

    let message = ProtocolMessage::Capabilities(Capabilities {
        session_id: SessionId::new("session-123"),

        supported_suites: vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
    });

    let frame = pair
        .initiator
        .seal_protocol_message(&message)
        .expect("protocol message should encrypt");

    let received = pair
        .responder
        .open_protocol_message(&frame)
        .expect("protocol message should decrypt");

    assert_eq!(received, message);
}
