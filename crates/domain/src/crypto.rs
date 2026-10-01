use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CryptoSuiteId {
    #[serde(rename = "AES_256_GCM")]
    Aes256Gcm,

    #[serde(rename = "CHACHA20_POLY1305")]
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoFamily {
    Aes,
    ChaCha,
}

pub const SUPPORTED_CRYPTO_SUITES: &[CryptoSuiteId] =
    &[CryptoSuiteId::ChaCha20Poly1305, CryptoSuiteId::Aes256Gcm];

pub fn supported_crypto_suites() -> impl Iterator<Item = CryptoSuiteDescriptor> {
    SUPPORTED_CRYPTO_SUITES
        .iter()
        .copied()
        .map(CryptoSuiteId::descriptor)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSuiteDescriptor {
    pub id: CryptoSuiteId,
    pub family: CryptoFamily,
    pub key_size_bits: u16,
    pub nonce_size_bits: u16,
    pub security_bits: u16,
    pub aead: bool,
    pub priority: u16,
}

impl CryptoSuiteDescriptor {
    pub fn meets_security_level(&self, minimum_bits: u16) -> bool {
        self.security_bits >= minimum_bits
    }

    pub fn is_aead(&self) -> bool {
        self.aead
    }
}

impl CryptoSuiteId {
    pub fn descriptor(self) -> CryptoSuiteDescriptor {
        match self {
            Self::Aes256Gcm => CryptoSuiteDescriptor {
                id: self,
                family: CryptoFamily::Aes,
                key_size_bits: 256,
                nonce_size_bits: 96,
                security_bits: 128,
                aead: true,
                priority: 90,
            },
            Self::ChaCha20Poly1305 => CryptoSuiteDescriptor {
                id: self,
                family: CryptoFamily::ChaCha,
                key_size_bits: 256,
                nonce_size_bits: 96,
                security_bits: 128,
                aead: true,
                priority: 100,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_suite_ids_are_compatible() {
        assert_eq!(CryptoSuiteId::Aes256Gcm, CryptoSuiteId::Aes256Gcm);

        assert_ne!(CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305)
    }

    #[test]
    fn aes256_gcm_descriptor_is_correct() {
        let descriptor = CryptoSuiteId::Aes256Gcm.descriptor();

        assert_eq!(descriptor.id, CryptoSuiteId::Aes256Gcm);

        assert_eq!(descriptor.family, CryptoFamily::Aes);

        assert_eq!(descriptor.key_size_bits, 256);

        assert_eq!(descriptor.nonce_size_bits, 96);

        assert!(descriptor.aead);
    }

    #[test]
    fn chacha20_poly1305_descriptor_is_correct() {
        let descriptor = CryptoSuiteId::ChaCha20Poly1305.descriptor();

        assert_eq!(descriptor.id, CryptoSuiteId::ChaCha20Poly1305);

        assert_eq!(descriptor.family, CryptoFamily::ChaCha);

        assert_eq!(descriptor.key_size_bits, 256);

        assert_eq!(descriptor.nonce_size_bits, 96);

        assert!(descriptor.aead);
    }

    #[test]
    fn suite_meets_minimum_security_level() {
        let descriptor = CryptoSuiteId::ChaCha20Poly1305.descriptor();

        assert!(descriptor.meets_security_level(128));
    }

    #[test]
    fn catalog_contains_all_supported_suites() {
        let suites: Vec<_> = supported_crypto_suites().collect();

        assert_eq!(suites.len(), 2);

        assert!(
            suites
                .iter()
                .any(|suite| { suite.id == CryptoSuiteId::Aes256Gcm })
        );

        assert!(
            suites
                .iter()
                .any(|suite| { suite.id == CryptoSuiteId::ChaCha20Poly1305 })
        );
    }
}
