use crypto::CryptoRegistry;

use domain::{CryptoSuiteId, PeerCapabilities, PeerId};

#[test]
fn registry_can_build_peer_capabilities() {
    let registry = CryptoRegistry::with_defaults();

    let capabilities = PeerCapabilities::new(PeerId::new("proxy-a"), registry.available_suites());

    assert!(capabilities.supports(CryptoSuiteId::Aes256Gcm));

    assert!(capabilities.supports(CryptoSuiteId::ChaCha20Poly1305));
}
