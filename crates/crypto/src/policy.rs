use std::collections::HashSet;

use domain::{CryptoRecommendation, CryptoSuiteId};

use crate::CryptoRegistry;

#[derive(Debug, Clone)]
pub struct CryptoPolicy {
    minimum_security_bits: u16,
    require_aead: bool,
    allowed_suites: HashSet<CryptoSuiteId>,
    denied_suites: HashSet<CryptoSuiteId>,
}

impl CryptoPolicy {
    pub fn new(
        minimum_security_bits: u16,
        require_aead: bool,
        allowed_suites: impl IntoIterator<Item = CryptoSuiteId>,
        denied_suites: impl IntoIterator<Item = CryptoSuiteId>,
    ) -> Self {
        Self {
            minimum_security_bits,
            require_aead,
            allowed_suites: allowed_suites.into_iter().collect(),
            denied_suites: denied_suites.into_iter().collect(),
        }
    }

    pub fn minimum_security_bits(&self) -> u16 {
        self.minimum_security_bits
    }

    pub fn require_aead(&self) -> bool {
        self.require_aead
    }

    pub fn allows(&self, suite: CryptoSuiteId) -> bool {
        self.allowed_suites.contains(&suite) && !self.denied_suites.contains(&suite)
    }
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self::new(
            128,
            true,
            [CryptoSuiteId::ChaCha20Poly1305, CryptoSuiteId::Aes256Gcm],
            [],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyViolation {
    SuiteNotAllowed(CryptoSuiteId),

    SuiteDenied(CryptoSuiteId),

    SecurityLevelTooLow {
        suite: CryptoSuiteId,
        actual_bits: u16,
        minimum_bits: u16,
    },

    AeadRequired {
        suite: CryptoSuiteId,
    },

    SuiteUnavailable {
        suite: CryptoSuiteId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Accepted { suite: CryptoSuiteId },

    Rejected { violation: PolicyViolation },
}

pub struct CryptoPolicyEngine {
    policy: CryptoPolicy,
}

impl CryptoPolicyEngine {
    pub fn new(policy: CryptoPolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &CryptoPolicy {
        &self.policy
    }

    pub fn evaluate(
        &self,
        recommendation: &CryptoRecommendation,
        registry: &CryptoRegistry,
    ) -> PolicyDecision {
        let suite = recommendation.suite();

        if self.policy.denied_suites.contains(&suite) {
            return PolicyDecision::Rejected {
                violation: PolicyViolation::SuiteDenied(suite),
            };
        }

        if !self.policy.allowed_suites.contains(&suite) {
            return PolicyDecision::Rejected {
                violation: PolicyViolation::SuiteNotAllowed(suite),
            };
        }

        let descriptor = suite.descriptor();

        if descriptor.security_bits < self.policy.minimum_security_bits {
            return PolicyDecision::Rejected {
                violation: PolicyViolation::SecurityLevelTooLow {
                    suite,
                    actual_bits: descriptor.security_bits,
                    minimum_bits: self.policy.minimum_security_bits,
                },
            };
        }

        if self.policy.require_aead && !descriptor.aead {
            return PolicyDecision::Rejected {
                violation: PolicyViolation::AeadRequired { suite },
            };
        }

        if !registry.contains(suite) {
            return PolicyDecision::Rejected {
                violation: PolicyViolation::SuiteUnavailable { suite },
            };
        }

        PolicyDecision::Accepted { suite }
    }
}
