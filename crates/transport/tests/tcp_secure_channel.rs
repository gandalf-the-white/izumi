use domain::{CryptoSuiteId, PeerId, SessionId};

use identity::{TrustStore, generate_keypair};

use protocol::{Capabilities, ProtocolMessage};

use secure_channel::{MAX_ENCRYPTED_FRAME_SIZE, establish_in_memory};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

use transport::{FramedIo, PeerConnection, TransportError};

fn build_secure_channels() -> (secure_channel::SecureChannel, secure_channel::SecureChannel) {
    let proxy_a_id = PeerId::new("proxy-a");

    let proxy_b_id = PeerId::new("proxy-b");

    let proxy_a = generate_keypair().unwrap();

    let proxy_b = generate_keypair().unwrap();

    let mut trust_a = TrustStore::new();

    let mut trust_b = TrustStore::new();

    trust_a.trust(proxy_b_id.clone(), proxy_b.public_key().clone());

    trust_b.trust(proxy_a_id.clone(), proxy_a.public_key().clone());

    let pair = establish_in_memory(
        proxy_a_id, &proxy_a, &trust_a, proxy_b_id, &proxy_b, &trust_b,
    )
    .unwrap();

    (pair.initiator, pair.responder)
}

#[tokio::test]
async fn capabilities_travel_over_real_tcp() {
    let (channel_a, channel_b) = build_secure_channels();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");

    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("server should accept");

        let mut connection = PeerConnection::new(stream, channel_b);

        connection.receive().await.expect("server should receive")
    });

    let stream = TcpStream::connect(address)
        .await
        .expect("client should connect");

    let mut connection = PeerConnection::new(stream, channel_a);

    let message = ProtocolMessage::Capabilities(Capabilities {
        session_id: SessionId::new("session-123"),

        supported_suites: vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
    });

    connection.send(&message).await.expect("client should send");

    let received = server.await.expect("server task should finish");

    assert_eq!(received, message);
}

#[tokio::test]
async fn secure_tcp_connection_is_bidirectional() {
    let (channel_a, channel_b) = build_secure_channels();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();

        let mut connection = PeerConnection::new(stream, channel_b);

        let received = connection.receive().await.unwrap();

        let response = ProtocolMessage::NegotiationAccept(protocol::NegotiationAccept {
            session_id: SessionId::new("session-123"),

            selected_suite: CryptoSuiteId::ChaCha20Poly1305,
        });

        connection.send(&response).await.unwrap();

        received
    });

    let stream = TcpStream::connect(address).await.unwrap();

    let mut client = PeerConnection::new(stream, channel_a);

    let capabilities = ProtocolMessage::Capabilities(Capabilities {
        session_id: SessionId::new("session-123"),

        supported_suites: vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
    });

    client.send(&capabilities).await.unwrap();

    let response = client.receive().await.unwrap();

    assert!(matches!(response, ProtocolMessage::NegotiationAccept(_)));

    let server_received = server.await.unwrap();

    assert_eq!(server_received, capabilities);
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_payload_read() {
    let (mut attacker, victim) = tokio::io::duplex(64);

    let malicious_length = (MAX_ENCRYPTED_FRAME_SIZE as u32) + 1;

    attacker
        .write_all(&malicious_length.to_be_bytes())
        .await
        .unwrap();

    let mut framed = FramedIo::new(victim);

    let result = framed.read_frame().await;

    assert!(matches!(result, Err(TransportError::FrameTooLarge { .. })));
}
