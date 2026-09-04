use serde::{Deserialize, Serialize};

use crate::crypto::{CryptoSuiteDescriptor, CryptoSuiteId};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(String);

impl PeerId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCapabilities {
    peer_id: PeerId,
    supported_suites: Vec<CryptoSuiteId>,
}

impl PeerCapabilities {
    pub fn new(peer_id: PeerId, supported_suites: Vec<CryptoSuiteId>) -> Self {
        Self {
            peer_id,
            supported_suites,
        }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn supported_suites(&self) -> &[CryptoSuiteId] {
        &self.supported_suites
    }

    pub fn supports(&self, suite: CryptoSuiteId) -> bool {
        self.supported_suites.contains(&suite)
    }

    pub fn supported_descriptors(&self) -> impl Iterator<Item = CryptoSuiteDescriptor> + '_ {
        self.supported_suites
            .iter()
            .copied()
            .map(CryptoSuiteId::descriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_can_be_created() {
        let peer_id = PeerId::new("proxy-a");

        assert_eq!(peer_id.as_str(), "proxy-a");
    }

    #[test]
    fn peer_capabilities_reports_supported_suite() {
        let capabilities = PeerCapabilities::new(
            PeerId::new("proxy-a"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        );

        assert!(capabilities.supports(CryptoSuiteId::ChaCha20Poly1305));
    }

    #[test]
    fn peer_capabilities_reports_unsupported_suite() {
        let capabilities =
            PeerCapabilities::new(PeerId::new("proxy-a"), vec![CryptoSuiteId::Aes256Gcm]);

        assert!(!capabilities.supports(CryptoSuiteId::ChaCha20Poly1305));
    }

    #[test]
    fn peer_can_expose_suite_descriptors() {
        let capabilities = PeerCapabilities::new(
            PeerId::new("proxy-a"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        );

        let descriptors: Vec<_> = capabilities.supported_descriptors().collect();

        assert_eq!(descriptors.len(), 2);

        assert!(descriptors.iter().all(|descriptor| descriptor.aead));
    }
}
