use agent::{CryptoAdvisor, RigCryptoAdvisor};

use domain::{CryptoSuiteId, NegotiationContext, PeerCapabilities, PeerId};

#[tokio::test]
#[ignore = "requires a running Ollama instance and qwen3.8"]
async fn ollama_returns_common_crypto_suite() {
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

    let advisor = RigCryptoAdvisor::new().expect("advisor should be created");

    let recommendation = advisor.recommend(&context).await.expect(
        "Ollama should return \
                 a recommendation",
    );

    assert!(context.common_suites().contains(&recommendation.suite()));

    assert!((0.0..=1.0).contains(&recommendation.confidence()));
}
