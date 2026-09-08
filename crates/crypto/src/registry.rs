use domain::CryptoSuiteId;
use thiserror::Error;

use std::collections::HashMap;

use crate::provider::CryptoProvider;

use crate::provider::{Aes256GcmProvider, ChaCha20Poly1305Provider};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoRegistryError {
    #[error("crypto suite {0:?} is not registered")]
    SuiteNotRegistered(CryptoSuiteId),

    #[error("crypto suite {0:?} is already registered")]
    SuiteAlreadyRegistered(CryptoSuiteId),
}

pub struct CryptoRegistry {
    providers: HashMap<CryptoSuiteId, Box<dyn CryptoProvider>>,
}

impl CryptoRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();

        registry.register(ChaCha20Poly1305Provider).expect(
            "default ChaCha20Poly1305 provider \
                 must register",
        );

        registry.register(Aes256GcmProvider).expect(
            "default AES256GCM provider \
                 must register",
        );

        registry
    }

    pub fn register<P>(&mut self, provider: P) -> Result<(), CryptoRegistryError>
    where
        P: CryptoProvider + 'static,
    {
        let suite_id = provider.suite_id();

        if self.providers.contains_key(&suite_id) {
            return Err(CryptoRegistryError::SuiteAlreadyRegistered(suite_id));
        }

        self.providers.insert(suite_id, Box::new(provider));

        Ok(())
    }

    pub fn contains(&self, suite_id: CryptoSuiteId) -> bool {
        self.providers.contains_key(&suite_id)
    }

    pub fn get(&self, suite_id: CryptoSuiteId) -> Result<&dyn CryptoProvider, CryptoRegistryError> {
        self.providers
            .get(&suite_id)
            .map(Box::as_ref)
            .ok_or(CryptoRegistryError::SuiteNotRegistered(suite_id))
    }

    pub fn available_suites(&self) -> Vec<CryptoSuiteId> {
        let mut suites: Vec<_> = self.providers.keys().copied().collect();

        suites.sort();

        suites
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

impl Default for CryptoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_registry_is_empty() {
        let registry = CryptoRegistry::new();

        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn provider_can_be_registered() {
        let mut registry = CryptoRegistry::new();

        registry
            .register(ChaCha20Poly1305Provider)
            .expect("provider should register");

        assert!(registry.contains(CryptoSuiteId::ChaCha20Poly1305));

        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registered_provider_can_be_retrieved() {
        let mut registry = CryptoRegistry::new();

        registry
            .register(Aes256GcmProvider)
            .expect("provider should register");

        let provider = registry
            .get(CryptoSuiteId::Aes256Gcm)
            .expect("provider should exist");

        assert_eq!(provider.suite_id(), CryptoSuiteId::Aes256Gcm);
    }

    #[test]
    fn duplicate_provider_is_rejected() {
        let mut registry = CryptoRegistry::new();

        registry.register(Aes256GcmProvider).expect(
            "first registration \
                 should succeed",
        );

        let result = registry.register(Aes256GcmProvider);

        assert_eq!(
            result,
            Err(CryptoRegistryError::SuiteAlreadyRegistered(
                CryptoSuiteId::Aes256Gcm
            ))
        );
    }

    #[test]
    fn unknown_suite_returns_error() {
        let registry = CryptoRegistry::new();

        let result = registry.get(CryptoSuiteId::ChaCha20Poly1305);

        assert!(matches!(
            result,
            Err(CryptoRegistryError::SuiteNotRegistered(
                CryptoSuiteId::ChaCha20Poly1305
            ))
        ));
    }

    #[test]
    fn default_registry_contains_all_providers() {
        let registry = CryptoRegistry::with_defaults();

        assert!(registry.contains(CryptoSuiteId::Aes256Gcm));

        assert!(registry.contains(CryptoSuiteId::ChaCha20Poly1305));

        assert_eq!(registry.len(), 2);
    }
}
