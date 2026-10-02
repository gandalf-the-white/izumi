use crypto::{ChaCha20Poly1305DataCipher, DataCipher};

use data_plane::{DataDirection, DataPlaneChannel, DataPlaneConfig, DataPlaneError};

use domain::SessionId;

fn cipher(key: &[u8; 32]) -> Box<dyn DataCipher> {
    Box::new(ChaCha20Poly1305DataCipher::new(key))
}

fn make_channels(
    session_id: SessionId,
) -> (
    DataPlaneChannel<tokio::io::DuplexStream>,
    DataPlaneChannel<tokio::io::DuplexStream>,
) {
    let (stream_a, stream_b) = tokio::io::duplex(128 * 1024);

    let initiator_to_responder = [0x11_u8; 32];

    let responder_to_initiator = [0x22_u8; 32];

    let config_a = DataPlaneConfig::new(
        session_id.clone(),
        cipher(&initiator_to_responder),
        cipher(&responder_to_initiator),
        DataDirection::InitiatorToResponder,
        DataDirection::ResponderToInitiator,
    );
    let channel_a = DataPlaneChannel::new(
        stream_a,
        config_a,
        // session_id.clone(),
        // cipher(&initiator_to_responder),
        // cipher(&responder_to_initiator),
        // DataDirection::InitiatorToResponder,
        // DataDirection::ResponderToInitiator,
    );

    let config_b = DataPlaneConfig::new(
        session_id,
        cipher(&responder_to_initiator),
        cipher(&initiator_to_responder),
        DataDirection::ResponderToInitiator,
        DataDirection::InitiatorToResponder,
    );
    let channel_b = DataPlaneChannel::new(
        stream_b,
        config_b,
        // session_id,
        // cipher(&responder_to_initiator),
        // cipher(&initiator_to_responder),
        // DataDirection::ResponderToInitiator,
        // DataDirection::InitiatorToResponder,
    );

    (channel_a, channel_b)
}

#[tokio::test]
async fn initiator_can_send_to_responder() {
    let session_id = SessionId::new("channel-a-to-b");

    let (mut channel_a, mut channel_b) = make_channels(session_id);

    channel_a
        .send(b"hello from A")
        .await
        .expect("A should send data");

    let plaintext = channel_b.receive().await.expect("B should receive data");

    assert_eq!(plaintext, b"hello from A");

    assert_eq!(channel_a.send_sequence(), 1);

    assert_eq!(channel_b.receive_sequence(), 1);
}

#[tokio::test]
async fn responder_can_send_to_initiator() {
    let session_id = SessionId::new("channel-b-to-a");

    let (mut channel_a, mut channel_b) = make_channels(session_id);

    channel_b
        .send(b"hello from B")
        .await
        .expect("B should send data");

    let plaintext = channel_a.receive().await.expect("A should receive data");

    assert_eq!(plaintext, b"hello from B");

    assert_eq!(channel_b.send_sequence(), 1);

    assert_eq!(channel_a.receive_sequence(), 1);
}

#[tokio::test]
async fn channel_is_bidirectional() {
    let session_id = SessionId::new("bidirectional");

    let (mut channel_a, mut channel_b) = make_channels(session_id);

    channel_a.send(b"request").await.unwrap();

    let request = channel_b.receive().await.unwrap();

    assert_eq!(request, b"request");

    channel_b.send(b"response").await.unwrap();

    let response = channel_a.receive().await.unwrap();

    assert_eq!(response, b"response");
}

#[tokio::test]
async fn multiple_records_are_transferred() {
    let session_id = SessionId::new("multiple-records");

    let (mut channel_a, mut channel_b) = make_channels(session_id);

    for sequence in 0..100_u64 {
        let message = format!("message-{sequence}");

        channel_a.send(message.as_bytes()).await.unwrap();

        let received = channel_b.receive().await.unwrap();

        assert_eq!(received, message.as_bytes());

        assert_eq!(channel_a.send_sequence(), sequence + 1);

        assert_eq!(channel_b.receive_sequence(), sequence + 1);
    }
}

#[tokio::test]
async fn different_session_ids_are_rejected() {
    let (stream_a, stream_b) = tokio::io::duplex(4096);

    let i2r = [0x11_u8; 32];

    let r2i = [0x22_u8; 32];

    let config_a = DataPlaneConfig::new(
        SessionId::new("session-A"),
        cipher(&i2r),
        cipher(&r2i),
        DataDirection::InitiatorToResponder,
        DataDirection::ResponderToInitiator,
    );
    let mut channel_a = DataPlaneChannel::new(
        stream_a,
        config_a,
        // SessionId::new("session-A"),
        // cipher(&i2r),
        // cipher(&r2i),
        // DataDirection::InitiatorToResponder,
        // DataDirection::ResponderToInitiator,
    );

    let config_b = DataPlaneConfig::new(
        SessionId::new("session-B"),
        cipher(&r2i),
        cipher(&i2r),
        DataDirection::ResponderToInitiator,
        DataDirection::InitiatorToResponder,
    );
    let mut channel_b = DataPlaneChannel::new(
        stream_b,
        config_b,
        // SessionId::new("session-B"),
        // cipher(&r2i),
        // cipher(&i2r),
        // DataDirection::ResponderToInitiator,
        // DataDirection::InitiatorToResponder,
    );

    channel_a.send(b"secret").await.unwrap();

    let result = channel_b.receive().await;

    assert!(matches!(result, Err(DataPlaneError::Crypto(_))));
}

#[tokio::test]
async fn wrong_direction_is_rejected() {
    let (stream_a, stream_b) = tokio::io::duplex(4096);

    let i2r = [0x11_u8; 32];

    let r2i = [0x22_u8; 32];

    let session = SessionId::new("direction-test");

    let config_a = DataPlaneConfig::new(
        session.clone(),
        cipher(&i2r),
        cipher(&r2i),
        DataDirection::InitiatorToResponder,
        DataDirection::ResponderToInitiator,
    );
    let mut channel_a = DataPlaneChannel::new(
        stream_a,
        config_a,
        // session.clone(),
        // cipher(&i2r),
        // cipher(&r2i),
        // DataDirection::InitiatorToResponder,
        // DataDirection::ResponderToInitiator,
    );

    let config_b = DataPlaneConfig::new(
        session,
        cipher(&r2i),
        cipher(&i2r),
        DataDirection::ResponderToInitiator,
        // volontairement faux
        DataDirection::ResponderToInitiator,
    );
    let mut channel_b = DataPlaneChannel::new(
        stream_b,
        config_b,
        // session,
        // cipher(&r2i),
        // cipher(&i2r),
        // DataDirection::ResponderToInitiator,
        // volontairement faux
        // DataDirection::ResponderToInitiator,
    );

    channel_a.send(b"secret").await.unwrap();

    let result = channel_b.receive().await;

    assert!(matches!(result, Err(DataPlaneError::Crypto(_))));
}
