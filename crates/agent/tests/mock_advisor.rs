use agent::{CryptoAdvisor, MockCryptoAdvisor};

use domain::{CryptoSuiteId, NegotiationContext, PeerCapabilities, PeerId};

#[tokio::test]
async fn mock_advisor_returns_configured_suite() {
    let context = NegotiationContext::new(
        PeerCapabilities::new(
            PeerId::new("proxy-a"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        ),
        PeerCapabilities::new(
            PeerId::new("proxy-b"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        ),
    );

    let advisor =
        MockCryptoAdvisor::new(CryptoSuiteId::ChaCha20Poly1305, "test recommendation", 0.95);

    let recommendation = advisor
        .recommend(&context)
        .await
        .expect("recommendation should succeed");

    assert_eq!(recommendation.suite(), CryptoSuiteId::ChaCha20Poly1305);

    assert_eq!(recommendation.reason(), "test recommendation");

    assert_eq!(recommendation.confidence(), 0.95);
}

#[tokio::test]
async fn mock_advisor_rejects_empty_intersection() {
    let context = NegotiationContext::new(
        PeerCapabilities::new(PeerId::new("proxy-a"), vec![CryptoSuiteId::Aes256Gcm]),
        PeerCapabilities::new(
            PeerId::new("proxy-b"),
            vec![CryptoSuiteId::ChaCha20Poly1305],
        ),
    );

    let advisor = MockCryptoAdvisor::new(CryptoSuiteId::Aes256Gcm, "test", 0.9);

    let result = advisor.recommend(&context).await;

    assert!(matches!(result, Err(agent::AdvisorError::NoCommonSuite)));
}
