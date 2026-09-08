use crypto::{CryptoPolicy, CryptoPolicyEngine, CryptoRegistry, PolicyDecision};

use crypto::PolicyViolation;

use domain::{CryptoRecommendation, CryptoSuiteId};

#[test]
fn valid_recommendation_is_accepted() {
    let registry = CryptoRegistry::with_defaults();

    let policy = CryptoPolicy::default();

    let engine = CryptoPolicyEngine::new(policy);

    let recommendation = CryptoRecommendation::new(
        CryptoSuiteId::ChaCha20Poly1305,
        "Recommended for this platform",
        0.95,
    );

    let decision = engine.evaluate(&recommendation, &registry);

    assert_eq!(
        decision,
        PolicyDecision::Accepted {
            suite: CryptoSuiteId::ChaCha20Poly1305,
        }
    );
}

#[test]
fn explicitly_denied_suite_is_rejected() {
    let registry = CryptoRegistry::with_defaults();

    let policy = CryptoPolicy::new(
        128,
        true,
        [CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        [CryptoSuiteId::Aes256Gcm],
    );

    let engine = CryptoPolicyEngine::new(policy);

    let recommendation =
        CryptoRecommendation::new(CryptoSuiteId::Aes256Gcm, "AES hardware available", 0.99);

    let decision = engine.evaluate(&recommendation, &registry);

    assert_eq!(
        decision,
        PolicyDecision::Rejected {
            violation: PolicyViolation::SuiteDenied(CryptoSuiteId::Aes256Gcm,),
        }
    );
}

#[test]
fn suite_outside_allow_list_is_rejected() {
    let registry = CryptoRegistry::with_defaults();

    let policy = CryptoPolicy::new(128, true, [CryptoSuiteId::ChaCha20Poly1305], []);

    let engine = CryptoPolicyEngine::new(policy);

    let recommendation = CryptoRecommendation::new(CryptoSuiteId::Aes256Gcm, "AES selected", 1.0);

    let decision = engine.evaluate(&recommendation, &registry);

    assert_eq!(
        decision,
        PolicyDecision::Rejected {
            violation: PolicyViolation::SuiteNotAllowed(CryptoSuiteId::Aes256Gcm,),
        }
    );
}

#[test]
fn insufficient_security_level_is_rejected() {
    let registry = CryptoRegistry::with_defaults();

    let policy = CryptoPolicy::new(256, true, [CryptoSuiteId::ChaCha20Poly1305], []);

    let engine = CryptoPolicyEngine::new(policy);

    let recommendation =
        CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "Preferred suite", 0.90);

    let decision = engine.evaluate(&recommendation, &registry);

    assert_eq!(
        decision,
        PolicyDecision::Rejected {
            violation: PolicyViolation::SecurityLevelTooLow {
                suite: CryptoSuiteId::ChaCha20Poly1305,
                actual_bits: 128,
                minimum_bits: 256,
            },
        }
    );
}

#[test]
fn unavailable_suite_is_rejected() {
    let registry = CryptoRegistry::new();

    let policy = CryptoPolicy::default();

    let engine = CryptoPolicyEngine::new(policy);

    let recommendation =
        CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "Preferred suite", 0.97);

    let decision = engine.evaluate(&recommendation, &registry);

    assert_eq!(
        decision,
        PolicyDecision::Rejected {
            violation: PolicyViolation::SuiteUnavailable {
                suite: CryptoSuiteId::ChaCha20Poly1305,
            },
        }
    );
}
