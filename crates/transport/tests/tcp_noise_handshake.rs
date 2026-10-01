use domain::{CryptoSuiteId, PeerId, SessionId};

use identity::{TrustStore, generate_keypair};

use protocol::{Capabilities, ProtocolMessage};
use tokio::net::{TcpListener, TcpStream};

use transport::{perform_initiator_handshake, perform_responder_handshake};

#[tokio::test]
async fn noise_xx_is_performed_over_real_tcp() {
    let proxy_a_id = PeerId::new("proxy-a");

    let proxy_b_id = PeerId::new("proxy-b");

    let proxy_a = generate_keypair().expect("proxy A keypair");

    let proxy_b = generate_keypair().expect("proxy B keypair");

    let mut trust_a = TrustStore::new();

    let mut trust_b = TrustStore::new();

    trust_a.trust(proxy_b_id.clone(), proxy_b.public_key().clone());

    trust_b.trust(proxy_a_id.clone(), proxy_a.public_key().clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();

        let mut connection = perform_responder_handshake(stream, &proxy_b, proxy_a_id, &trust_b)
            .await
            .expect("responder authentication");

        assert_eq!(connection.peer().peer_id().as_str(), "proxy-a");

        connection.receive().await.expect("secure message")
    });

    let stream = TcpStream::connect(address).await.unwrap();

    let mut connection = perform_initiator_handshake(stream, &proxy_a, proxy_b_id, &trust_a)
        .await
        .expect("initiator authentication");

    assert_eq!(connection.peer().peer_id().as_str(), "proxy-b");

    let message = ProtocolMessage::Capabilities(Capabilities {
        session_id: SessionId::new("session-123"),

        supported_suites: vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
    });

    connection
        .send(&message)
        .await
        .expect("message should send");

    let received = server.await.unwrap();

    assert_eq!(received, message);
}

#[tokio::test]
async fn untrusted_tcp_peer_is_rejected() {
    let proxy_a_id = PeerId::new("proxy-a");

    let proxy_b_id = PeerId::new("proxy-b");

    let real_proxy_a = generate_keypair().unwrap();

    let attacker = generate_keypair().unwrap();

    let proxy_b = generate_keypair().unwrap();

    let mut trust_b = TrustStore::new();

    trust_b.trust(proxy_a_id.clone(), real_proxy_a.public_key().clone());

    let mut trust_attacker = TrustStore::new();

    trust_attacker.trust(proxy_b_id.clone(), proxy_b.public_key().clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();

        perform_responder_handshake(stream, &proxy_b, proxy_a_id, &trust_b).await
    });

    let stream = TcpStream::connect(address).await.unwrap();

    let attacker_result =
        perform_initiator_handshake(stream, &attacker, proxy_b_id, &trust_attacker).await;

    assert!(attacker_result.is_ok());

    let server_result = server.await.unwrap();

    assert!(matches!(
        server_result,
        Err(transport::TransportError::Authentication(_))
    ));
}
