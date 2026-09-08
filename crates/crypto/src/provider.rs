use domain::{CryptoSuiteDescriptor, CryptoSuiteId};

pub trait CryptoProvider: Send + Sync {
    fn suite_id(&self) -> CryptoSuiteId;

    fn descriptor(&self) -> CryptoSuiteDescriptor {
        self.suite_id().descriptor()
    }
}

#[derive(Debug, Default)]
pub struct Aes256GcmProvider;

impl CryptoProvider for Aes256GcmProvider {
    fn suite_id(&self) -> CryptoSuiteId {
        CryptoSuiteId::Aes256Gcm
    }
}

#[derive(Debug, Default)]
pub struct ChaCha20Poly1305Provider;

impl CryptoProvider for ChaCha20Poly1305Provider {
    fn suite_id(&self) -> CryptoSuiteId {
        CryptoSuiteId::ChaCha20Poly1305
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_provider_reports_correct_suite() {
        let provider = Aes256GcmProvider;

        assert_eq!(provider.suite_id(), CryptoSuiteId::Aes256Gcm);
    }

    #[test]
    fn chacha_provider_reports_correct_suite() {
        let provider = ChaCha20Poly1305Provider;

        assert_eq!(provider.suite_id(), CryptoSuiteId::ChaCha20Poly1305);
    }

    #[test]
    fn provider_can_expose_descriptor() {
        let provider = ChaCha20Poly1305Provider;

        let descriptor = provider.descriptor();

        assert_eq!(descriptor.id, CryptoSuiteId::ChaCha20Poly1305);

        assert_eq!(descriptor.key_size_bits, 256);
    }
}
