use crypto::{CryptoPolicy, CryptoPolicyEngine, CryptoRegistry};

use domain::{CryptoRecommendation, CryptoSuiteId, NegotiationContext, PeerCapabilities, PeerId};

use negotiation::{NegotiationFailure, NegotiationResolver, NegotiationResult};

fn context_with_both_suites() -> NegotiationContext {
    NegotiationContext::new(
        PeerCapabilities::new(
            PeerId::new("proxy-a"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        ),
        PeerCapabilities::new(
            PeerId::new("proxy-b"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        ),
    )
}

#[test]
fn negotiation_fails_when_no_common_suite_exists() {
    let context = NegotiationContext::new(
        PeerCapabilities::new(PeerId::new("proxy-a"), vec![CryptoSuiteId::Aes256Gcm]),
        PeerCapabilities::new(
            PeerId::new("proxy-b"),
            vec![CryptoSuiteId::ChaCha20Poly1305],
        ),
    );

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let resolver = NegotiationResolver::new(&policy_engine, &registry);

    let local = CryptoRecommendation::new(CryptoSuiteId::Aes256Gcm, "local", 0.9);

    let remote = CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "remote", 0.9);

    assert_eq!(
        resolver.resolve(&context, &local, &remote,),
        NegotiationResult::Rejected {
            reason: NegotiationFailure::NoCommonSuite,
        }
    );
}

#[test]
fn single_usable_suite_is_selected() {
    let context = NegotiationContext::new(
        PeerCapabilities::new(
            PeerId::new("proxy-a"),
            vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        ),
        PeerCapabilities::new(
            PeerId::new("proxy-b"),
            vec![CryptoSuiteId::ChaCha20Poly1305],
        ),
    );

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let resolver = NegotiationResolver::new(&policy_engine, &registry);

    let local = CryptoRecommendation::new(CryptoSuiteId::Aes256Gcm, "local", 0.9);

    let remote = CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "remote", 0.9);

    assert_eq!(
        resolver.resolve(&context, &local, &remote,),
        NegotiationResult::Agreed {
            suite: CryptoSuiteId::ChaCha20Poly1305,

            reason: negotiation::AgreementReason::SingleUsableSuite,
        }
    );
}

#[test]
fn identical_recommendations_are_accepted() {
    let context = context_with_both_suites();

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let resolver = NegotiationResolver::new(&policy_engine, &registry);

    let local = CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "local", 0.9);

    let remote = CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "remote", 0.8);

    assert_eq!(
        resolver.resolve(&context, &local, &remote,),
        NegotiationResult::Agreed {
            suite: CryptoSuiteId::ChaCha20Poly1305,

            reason: negotiation::AgreementReason::BothAgentsAgreed,
        }
    );
}

#[test]
fn divergent_recommendations_are_resolved_deterministically() {
    let context = context_with_both_suites();

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let resolver = NegotiationResolver::new(&policy_engine, &registry);

    let local = CryptoRecommendation::new(CryptoSuiteId::Aes256Gcm, "AES preferred", 0.99);

    let remote =
        CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "ChaCha preferred", 0.51);

    assert_eq!(
        resolver.resolve(&context, &local, &remote,),
        NegotiationResult::Agreed {
            suite: CryptoSuiteId::ChaCha20Poly1305,

            reason: negotiation::AgreementReason::DeterministicResolution,
        }
    );
}

#[test]
fn only_policy_valid_recommendation_is_selected() {
    let context = context_with_both_suites();

    let registry = CryptoRegistry::with_defaults();

    let policy = CryptoPolicy::new(
        128,
        true,
        [CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        [CryptoSuiteId::Aes256Gcm],
    );

    let policy_engine = CryptoPolicyEngine::new(policy);

    let resolver = NegotiationResolver::new(&policy_engine, &registry);

    let local = CryptoRecommendation::new(CryptoSuiteId::Aes256Gcm, "AES", 1.0);

    let remote = CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "ChaCha", 0.4);

    assert_eq!(
        resolver.resolve(&context, &local, &remote,),
        NegotiationResult::Agreed {
            suite: CryptoSuiteId::ChaCha20Poly1305,

            reason: negotiation::AgreementReason::SingleUsableSuite,
        }
    );
}

#[test]
fn resolver_is_symmetric() {
    let context_ab = context_with_both_suites();

    let context_ba =
        NegotiationContext::new(context_ab.remote().clone(), context_ab.local().clone());

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let resolver = NegotiationResolver::new(&policy_engine, &registry);

    let recommendation_a = CryptoRecommendation::new(CryptoSuiteId::Aes256Gcm, "A", 0.9);

    let recommendation_b = CryptoRecommendation::new(CryptoSuiteId::ChaCha20Poly1305, "B", 0.8);

    let result_a = resolver.resolve(&context_ab, &recommendation_a, &recommendation_b);

    let result_b = resolver.resolve(&context_ba, &recommendation_b, &recommendation_a);

    assert_eq!(result_a, result_b);
}
