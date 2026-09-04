use serde::{Deserialize, Serialize};

use crate::{
    crypto::{CryptoSuiteDescriptor, CryptoSuiteId},
    peer::PeerCapabilities,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiationContext {
    local: PeerCapabilities,
    remote: PeerCapabilities,
}

impl NegotiationContext {
    pub fn new(local: PeerCapabilities, remote: PeerCapabilities) -> Self {
        Self { local, remote }
    }

    pub fn local(&self) -> &PeerCapabilities {
        &self.local
    }

    pub fn remote(&self) -> &PeerCapabilities {
        &self.remote
    }

    pub fn common_suites(&self) -> Vec<CryptoSuiteId> {
        self.local
            .supported_suites()
            .iter()
            .copied()
            .filter(|suite| self.remote.supports(*suite))
            .collect()
    }

    pub fn common_suite_descriptors(&self) -> Vec<CryptoSuiteDescriptor> {
        self.common_suites()
            .into_iter()
            .map(CryptoSuiteId::descriptor)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptoRecommendation {
    suite: CryptoSuiteId,
    reason: String,
    confidence: f32,
}

impl CryptoRecommendation {
    pub fn new(suite: CryptoSuiteId, reason: impl Into<String>, confidence: f32) -> Self {
        Self {
            suite,
            reason: reason.into(),
            confidence,
        }
    }

    pub fn suite(&self) -> CryptoSuiteId {
        self.suite
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn confidence(&self) -> f32 {
        self.confidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerId;

    #[test]
    fn common_suites_returns_shared_algorithms() {
        let local = PeerCapabilities::new(
            PeerId::new("proxy-a"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        );

        let remote = PeerCapabilities::new(
            PeerId::new("proxy-b"),
            vec![CryptoSuiteId::ChaCha20Poly1305],
        );

        let context = NegotiationContext::new(local, remote);

        assert_eq!(
            context.common_suites(),
            vec![CryptoSuiteId::ChaCha20Poly1305]
        );
    }

    #[test]
    fn common_suites_returns_empty_when_no_suite_matches() {
        let local = PeerCapabilities::new(PeerId::new("proxy-a"), vec![CryptoSuiteId::Aes256Gcm]);

        let remote = PeerCapabilities::new(
            PeerId::new("proxy-b"),
            vec![CryptoSuiteId::ChaCha20Poly1305],
        );

        let context = NegotiationContext::new(local, remote);

        assert!(context.common_suites().is_empty());
    }

    #[test]
    fn recommendation_exposes_selected_suite() {
        let recommendation = CryptoRecommendation::new(
            CryptoSuiteId::ChaCha20Poly1305,
            "Preferred for this peer",
            0.95,
        );

        assert_eq!(recommendation.suite(), CryptoSuiteId::ChaCha20Poly1305);

        assert_eq!(recommendation.reason(), "Preferred for this peer");

        assert_eq!(recommendation.confidence(), 0.95);
    }

    #[test]
    fn common_suite_descriptors_return_metadata() {
        let local = PeerCapabilities::new(
            PeerId::new("proxy-a"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        );

        let remote = PeerCapabilities::new(
            PeerId::new("proxy-b"),
            vec![CryptoSuiteId::ChaCha20Poly1305],
        );

        let context = NegotiationContext::new(local, remote);

        let descriptors = context.common_suite_descriptors();

        assert_eq!(descriptors.len(), 1);

        assert_eq!(descriptors[0].id, CryptoSuiteId::ChaCha20Poly1305);

        assert_eq!(descriptors[0].key_size_bits, 256);

        assert_eq!(descriptors[0].nonce_size_bits, 96);
    }
}
