use crypto::CryptoRegistry;
use data_plane::{DataPlaneChannel, DataPlaneConfig};
use domain::{CryptoRecommendation, CryptoSuiteId, PeerCapabilities, PeerId, SessionId};

use identity::{TrustStore, generate_keypair};

use session::{PeerSession, SessionError, SessionPhase, SessionRole};

use tokio::net::{TcpListener, TcpStream};

use transport::{perform_initiator_handshake, perform_responder_handshake};

async fn create_session_pair(
    session_id: &str,
    capabilities_a: Vec<CryptoSuiteId>,
    capabilities_b: Vec<CryptoSuiteId>,
) -> (PeerSession, PeerSession) {
    let proxy_a_id = PeerId::new("proxy-a");

    let proxy_b_id = PeerId::new("proxy-b");

    let proxy_a = generate_keypair().expect("proxy A keypair");

    let proxy_b = generate_keypair().expect("proxy B keypair");

    let mut trust_a = TrustStore::new();

    trust_a.trust(proxy_b_id.clone(), proxy_b.public_key().clone());

    let mut trust_b = TrustStore::new();

    trust_b.trust(proxy_a_id.clone(), proxy_a.public_key().clone());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");

    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("server accept");

        perform_responder_handshake(stream, &proxy_b, proxy_a_id, &trust_b)
            .await
            .expect("responder handshake")
    });

    let stream = TcpStream::connect(address)
        .await
        .expect("client connection");

    let connection_a = perform_initiator_handshake(stream, &proxy_a, proxy_b_id, &trust_a)
        .await
        .expect("initiator handshake");

    let connection_b = server.await.expect("server task");

    let capabilities_a = PeerCapabilities::new(PeerId::new("proxy-a"), capabilities_a);

    let capabilities_b = PeerCapabilities::new(PeerId::new("proxy-b"), capabilities_b);

    let session_id = SessionId::new(session_id);

    let session_a = PeerSession::new(
        session_id.clone(),
        SessionRole::Initiator,
        connection_a,
        capabilities_a,
    );

    let session_b = PeerSession::new(
        session_id,
        SessionRole::Responder,
        connection_b,
        capabilities_b,
    );

    (session_a, session_b)
}

async fn confirm_peers(session_a: &mut PeerSession, session_b: &mut PeerSession) {
    session_a
        .send_authentication_ack()
        .await
        .expect("A should send authentication ack");

    session_b
        .receive_authentication_ack()
        .await
        .expect("B should receive authentication ack");

    session_b
        .send_authentication_ack()
        .await
        .expect("B should send authentication ack");

    session_a
        .receive_authentication_ack()
        .await
        .expect("A should receive authentication ack");

    assert_eq!(session_a.phase(), SessionPhase::PeerConfirmed);

    assert_eq!(session_b.phase(), SessionPhase::PeerConfirmed);
}

async fn exchange_capabilities(session_a: &mut PeerSession, session_b: &mut PeerSession) {
    session_a
        .send_capabilities()
        .await
        .expect("A should send capabilities");

    session_b
        .receive_capabilities()
        .await
        .expect("B should receive capabilities");

    session_b
        .send_capabilities()
        .await
        .expect("B should send capabilities");

    session_a
        .receive_capabilities()
        .await
        .expect("A should receive capabilities");

    assert_eq!(session_a.phase(), SessionPhase::CapabilitiesExchanged);

    assert_eq!(session_b.phase(), SessionPhase::CapabilitiesExchanged);
}

fn recommendation(suite: CryptoSuiteId) -> CryptoRecommendation {
    CryptoRecommendation::new(suite, "test recommendation", 0.9)
}

async fn exchange_recommendations(
    session_a: &mut PeerSession,
    session_b: &mut PeerSession,
    suite: CryptoSuiteId,
) {
    session_a
        .send_recommendation(recommendation(suite))
        .await
        .expect("A should send recommendation");

    session_b
        .receive_recommendation()
        .await
        .expect("B should receive recommendation");

    session_b
        .send_recommendation(recommendation(suite))
        .await
        .expect("B should send recommendation");

    session_a
        .receive_recommendation()
        .await
        .expect("A should receive recommendation");

    assert_eq!(session_a.phase(), SessionPhase::RecommendationsExchanged);

    assert_eq!(session_b.phase(), SessionPhase::RecommendationsExchanged);
}

async fn initialize_data_plane_configs(
    session_a: &mut PeerSession,
    session_b: &mut PeerSession,
) -> (DataPlaneConfig, DataPlaneConfig) {
    let registry = CryptoRegistry::default();

    let config_a = session_a
        .initialize_data_plane(&registry)
        .expect("initiator data plane initialization");

    let config_b = session_b
        .initialize_data_plane(&registry)
        .expect("responder data plane initialization");

    (config_a, config_b)
}

async fn tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
    // Port 0 : le système choisit automatiquement un port TCP libre.
    let listener = TcpListener::bind("127.0.0.1:0").await?;

    let address = listener.local_addr()?;

    // Le futur initiateur se connecte au listener.
    let client = TcpStream::connect(address);

    // Le futur responder accepte la connexion.
    let server = listener.accept();

    // connect() et accept() doivent progresser simultanément.
    let (client_result, server_result) = tokio::join!(client, server);

    let client_stream = client_result?;

    let (server_stream, _peer_address) = server_result?;

    Ok((client_stream, server_stream))
}

#[tokio::test]
async fn session_starts_authenticated() {
    let (session_a, session_b) = create_session_pair(
        "session-001",
        vec![CryptoSuiteId::Aes256Gcm],
        vec![CryptoSuiteId::Aes256Gcm],
    )
    .await;

    assert_eq!(session_a.phase(), SessionPhase::Authenticated);

    assert_eq!(session_b.phase(), SessionPhase::Authenticated);

    assert_eq!(session_a.authenticated_peer_id().as_str(), "proxy-b");

    assert_eq!(session_b.authenticated_peer_id().as_str(), "proxy-a");
}

#[tokio::test]
async fn mutual_ack_confirms_peers() {
    let (mut session_a, mut session_b) = create_session_pair(
        "session-002",
        vec![CryptoSuiteId::Aes256Gcm],
        vec![CryptoSuiteId::Aes256Gcm],
    )
    .await;

    confirm_peers(&mut session_a, &mut session_b).await;

    assert_eq!(session_a.phase(), SessionPhase::PeerConfirmed);

    assert_eq!(session_b.phase(), SessionPhase::PeerConfirmed);
}

#[tokio::test]
async fn capabilities_are_exchanged() {
    let (mut session_a, mut session_b) = create_session_pair(
        "session-003",
        vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        vec![CryptoSuiteId::ChaCha20Poly1305],
    )
    .await;

    confirm_peers(&mut session_a, &mut session_b).await;

    exchange_capabilities(&mut session_a, &mut session_b).await;

    let remote_a = session_a
        .remote_capabilities()
        .expect("A should know B capabilities");

    assert_eq!(remote_a.peer_id().as_str(), "proxy-b");

    let remote_b = session_b
        .remote_capabilities()
        .expect("B should know A capabilities");

    assert_eq!(remote_b.peer_id().as_str(), "proxy-a");

    let context_a = session_a
        .negotiation_context()
        .expect("A negotiation context");

    assert_eq!(
        context_a.common_suites(),
        &[CryptoSuiteId::ChaCha20Poly1305]
    );
}

#[tokio::test]
async fn full_session_reaches_negotiated() {
    let (mut session_a, mut session_b) = create_session_pair(
        "session-full",
        vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        vec![CryptoSuiteId::ChaCha20Poly1305],
    )
    .await;

    confirm_peers(&mut session_a, &mut session_b).await;

    exchange_capabilities(&mut session_a, &mut session_b).await;

    exchange_recommendations(
        &mut session_a,
        &mut session_b,
        CryptoSuiteId::ChaCha20Poly1305,
    )
    .await;

    session_a
        .send_negotiation_accept(CryptoSuiteId::ChaCha20Poly1305)
        .await
        .expect("A should accept negotiation");

    session_b
        .send_negotiation_accept(CryptoSuiteId::ChaCha20Poly1305)
        .await
        .expect("B should accept negotiation");

    session_a
        .receive_negotiation_accept()
        .await
        .expect("A should receive B acceptance");

    session_b
        .receive_negotiation_accept()
        .await
        .expect("B should receive A acceptance");

    assert_eq!(session_a.phase(), SessionPhase::Negotiated);

    assert_eq!(session_b.phase(), SessionPhase::Negotiated);

    assert_eq!(
        session_a.selected_suite(),
        Some(CryptoSuiteId::ChaCha20Poly1305)
    );

    assert_eq!(
        session_b.selected_suite(),
        Some(CryptoSuiteId::ChaCha20Poly1305)
    );
}

#[tokio::test]
async fn capabilities_before_ack_are_rejected() {
    let (mut session_a, _session_b) = create_session_pair(
        "session-order",
        vec![CryptoSuiteId::Aes256Gcm],
        vec![CryptoSuiteId::Aes256Gcm],
    )
    .await;

    let result = session_a.send_capabilities().await;

    assert!(matches!(
        result,
        Err(SessionError::UnexpectedMessage {
            phase: SessionPhase::Authenticated
        })
    ));

    assert_eq!(session_a.phase(), SessionPhase::Authenticated);
}

#[tokio::test]
async fn duplicate_authentication_ack_is_rejected() {
    let (mut session_a, _session_b) = create_session_pair(
        "session-duplicate",
        vec![CryptoSuiteId::Aes256Gcm],
        vec![CryptoSuiteId::Aes256Gcm],
    )
    .await;

    session_a
        .send_authentication_ack()
        .await
        .expect("first ACK should succeed");

    let result = session_a.send_authentication_ack().await;

    assert!(matches!(
        result,
        Err(SessionError::UnexpectedMessage {
            phase: SessionPhase::Authenticated
        })
    ));
}

#[tokio::test]
async fn recommendation_outside_common_suites_is_rejected() {
    let (mut session_a, mut session_b) = create_session_pair(
        "session-invalid-recommendation",
        vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        vec![CryptoSuiteId::Aes256Gcm],
    )
    .await;

    confirm_peers(&mut session_a, &mut session_b).await;

    exchange_capabilities(&mut session_a, &mut session_b).await;

    let result = session_a
        .send_recommendation(recommendation(CryptoSuiteId::ChaCha20Poly1305))
        .await;

    assert!(matches!(result, Err(SessionError::InvalidRecommendation)));

    assert_eq!(session_a.phase(), SessionPhase::CapabilitiesExchanged);
}

#[tokio::test]
async fn different_selected_suites_are_rejected() {
    let (mut session_a, mut session_b) = create_session_pair(
        "session-mismatch",
        vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
    )
    .await;

    confirm_peers(&mut session_a, &mut session_b).await;

    exchange_capabilities(&mut session_a, &mut session_b).await;

    exchange_recommendations(&mut session_a, &mut session_b, CryptoSuiteId::Aes256Gcm).await;

    session_a
        .send_negotiation_accept(CryptoSuiteId::Aes256Gcm)
        .await
        .expect("A local decision");

    session_b
        .send_negotiation_accept(CryptoSuiteId::ChaCha20Poly1305)
        .await
        .expect("B local decision");

    let result_a = session_a.receive_negotiation_accept().await;

    let result_b = session_b.receive_negotiation_accept().await;

    assert!(matches!(result_a, Err(SessionError::NegotiationMismatch)));

    assert!(matches!(result_b, Err(SessionError::NegotiationMismatch)));
}

#[tokio::test]
async fn closed_session_rejects_operations() {
    let (mut session_a, _session_b) = create_session_pair(
        "session-closed",
        vec![CryptoSuiteId::Aes256Gcm],
        vec![CryptoSuiteId::Aes256Gcm],
    )
    .await;

    session_a.close();

    assert_eq!(session_a.phase(), SessionPhase::Closed);

    let result = session_a.send_authentication_ack().await;

    assert!(matches!(result, Err(SessionError::Closed)));
}

// =============================================================

async fn negotiate_suite(
    session_a: &mut PeerSession,
    session_b: &mut PeerSession,
    suite: CryptoSuiteId,
) {
    session_a
        .send_negotiation_accept(suite)
        .await
        .expect("A should send negotiation acceptance");

    session_b
        .send_negotiation_accept(suite)
        .await
        .expect("B should send negotiation acceptance");

    session_a
        .receive_negotiation_accept()
        .await
        .expect("A should receive B negotiation acceptance");

    session_b
        .receive_negotiation_accept()
        .await
        .expect("B should receive A negotiation acceptance");

    assert_eq!(session_a.phase(), SessionPhase::Negotiated);

    assert_eq!(session_b.phase(), SessionPhase::Negotiated);

    assert_eq!(session_a.selected_suite(), Some(suite));

    assert_eq!(session_b.selected_suite(), Some(suite));
}

async fn create_negotiated_session_pair(
    session_id: &str,
    suite: CryptoSuiteId,
) -> (PeerSession, PeerSession) {
    let (mut session_a, mut session_b) = create_session_pair(
        session_id,
        vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
    )
    .await;

    confirm_peers(&mut session_a, &mut session_b).await;

    exchange_capabilities(&mut session_a, &mut session_b).await;

    exchange_recommendations(&mut session_a, &mut session_b, suite).await;

    negotiate_suite(&mut session_a, &mut session_b, suite).await;

    (session_a, session_b)
}

async fn exchange_data_keys(session_a: &mut PeerSession, session_b: &mut PeerSession) {
    session_a
        .send_data_key()
        .await
        .expect("A should send its data-plane public key");

    session_b
        .receive_data_key()
        .await
        .expect("B should receive A data-plane public key");

    session_b
        .send_data_key()
        .await
        .expect("B should send its data-plane public key");

    session_a
        .receive_data_key()
        .await
        .expect("A should receive B data-plane public key");

    assert_eq!(session_a.phase(), SessionPhase::DataKeysEstablished);

    assert_eq!(session_b.phase(), SessionPhase::DataKeysEstablished);
}

fn initialize_data_planes(session_a: &mut PeerSession, session_b: &mut PeerSession) {
    let registry = CryptoRegistry::default();

    session_a
        .initialize_data_plane(&registry)
        .expect("A data plane should initialize");

    session_b
        .initialize_data_plane(&registry)
        .expect("B data plane should initialize");

    assert_eq!(session_a.phase(), SessionPhase::ReadyForData);

    assert_eq!(session_b.phase(), SessionPhase::ReadyForData);
}

// =============================================================

#[tokio::test]
async fn data_key_exchange_reaches_established() {
    let (mut session_a, mut session_b) =
        create_negotiated_session_pair("data-key-exchange", CryptoSuiteId::ChaCha20Poly1305).await;

    assert_eq!(session_a.phase(), SessionPhase::Negotiated);

    assert_eq!(session_b.phase(), SessionPhase::Negotiated);

    exchange_data_keys(&mut session_a, &mut session_b).await;

    assert_eq!(session_a.phase(), SessionPhase::DataKeysEstablished);

    assert_eq!(session_b.phase(), SessionPhase::DataKeysEstablished);
}

#[tokio::test]
async fn data_plane_reaches_ready() {
    let (mut session_a, mut session_b) =
        create_negotiated_session_pair("data-plane-ready", CryptoSuiteId::ChaCha20Poly1305).await;

    exchange_data_keys(&mut session_a, &mut session_b).await;

    initialize_data_planes(&mut session_a, &mut session_b);

    assert_eq!(session_a.phase(), SessionPhase::ReadyForData);

    assert_eq!(session_b.phase(), SessionPhase::ReadyForData);
}

#[tokio::test]
async fn negotiated_session_can_create_working_data_plane() {
    let (mut session_a, mut session_b) = create_negotiated_session_pair(
        SessionId::new("integrated-data-plane").as_str(),
        CryptoSuiteId::ChaCha20Poly1305,
    )
    .await;

    exchange_data_keys(&mut session_a, &mut session_b).await;

    let (config_a, config_b) = initialize_data_plane_configs(&mut session_a, &mut session_b).await;

    assert_eq!(session_a.phase(), SessionPhase::ReadyForData);

    assert_eq!(session_b.phase(), SessionPhase::ReadyForData);

    let (stream_a, stream_b) = tcp_pair().await.unwrap();

    let mut data_a = DataPlaneChannel::new(stream_a, config_a);

    let mut data_b = DataPlaneChannel::new(stream_b, config_b);

    data_a.send(b"hello negotiated data plane").await.unwrap();

    let plaintext = data_b.receive().await.unwrap();

    assert_eq!(plaintext, b"hello negotiated data plane");

    data_b.send(b"hello back").await.unwrap();

    let plaintext = data_a.receive().await.unwrap();

    assert_eq!(plaintext, b"hello back");
}
