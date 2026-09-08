use crypto::{CryptoPolicy, CryptoPolicyEngine, CryptoRegistry};

use domain::{CryptoSuiteId, NegotiationContext, PeerCapabilities, PeerId};

use negotiation::{AgreementReason, NegotiationResult};

use orchestrator::NegotiationCoordinator;

use agent::{FailingCryptoAdvisor, MockCryptoAdvisor};

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

#[tokio::test]
async fn two_matching_advisors_reach_agreement() {
    let context = context_with_both_suites();

    let local = MockCryptoAdvisor::new(CryptoSuiteId::ChaCha20Poly1305, "local choice", 0.9);

    let remote = MockCryptoAdvisor::new(CryptoSuiteId::ChaCha20Poly1305, "remote choice", 0.8);

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let coordinator = NegotiationCoordinator::new(&local, &remote, &policy_engine, &registry);

    let outcome = coordinator.negotiate(&context).await;

    assert_eq!(
        outcome.result,
        NegotiationResult::Agreed {
            suite: CryptoSuiteId::ChaCha20Poly1305,

            reason: AgreementReason::BothAgentsAgreed,
        }
    );
}

#[tokio::test]
async fn divergent_advisors_are_resolved_deterministically() {
    let context = context_with_both_suites();

    let local = MockCryptoAdvisor::new(CryptoSuiteId::Aes256Gcm, "AES preferred", 1.0);

    let remote = MockCryptoAdvisor::new(CryptoSuiteId::ChaCha20Poly1305, "ChaCha preferred", 0.4);

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let coordinator = NegotiationCoordinator::new(&local, &remote, &policy_engine, &registry);

    let outcome = coordinator.negotiate(&context).await;

    assert_eq!(
        outcome.result,
        NegotiationResult::Agreed {
            suite: CryptoSuiteId::ChaCha20Poly1305,

            reason: AgreementReason::DeterministicResolution,
        }
    );
}

#[tokio::test]
async fn one_failed_advisor_triggers_deterministic_fallback() {
    let context = context_with_both_suites();

    let local = MockCryptoAdvisor::new(CryptoSuiteId::Aes256Gcm, "AES", 1.0);

    let remote = FailingCryptoAdvisor;

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let coordinator = NegotiationCoordinator::new(&local, &remote, &policy_engine, &registry);

    let outcome = coordinator.negotiate(&context).await;

    assert_eq!(
        outcome.result,
        NegotiationResult::Agreed {
            suite: CryptoSuiteId::ChaCha20Poly1305,

            reason: AgreementReason::DeterministicFallback,
        }
    );
}

#[tokio::test]
async fn two_failed_advisors_still_allow_safe_fallback() {
    let context = context_with_both_suites();

    let local = FailingCryptoAdvisor;

    let remote = FailingCryptoAdvisor;

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let coordinator = NegotiationCoordinator::new(&local, &remote, &policy_engine, &registry);

    let outcome = coordinator.negotiate(&context).await;

    assert_eq!(
        outcome.result,
        NegotiationResult::Agreed {
            suite: CryptoSuiteId::ChaCha20Poly1305,

            reason: AgreementReason::DeterministicFallback,
        }
    );
}

#[tokio::test]
async fn fallback_cannot_bypass_policy() {
    let context = context_with_both_suites();

    let local = FailingCryptoAdvisor;

    let remote = FailingCryptoAdvisor;

    let registry = CryptoRegistry::with_defaults();

    let policy = CryptoPolicy::new(
        256,
        true,
        [CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
        [],
    );

    let policy_engine = CryptoPolicyEngine::new(policy);

    let coordinator = NegotiationCoordinator::new(&local, &remote, &policy_engine, &registry);

    let outcome = coordinator.negotiate(&context).await;

    assert_eq!(
        outcome.result,
        NegotiationResult::Rejected {
            reason: negotiation::NegotiationFailure::NoPolicyCompatibleSuite,
        }
    );
}

#[tokio::test]
async fn deterministic_fallback_is_symmetric() {
    let context_ab = context_with_both_suites();

    let context_ba =
        NegotiationContext::new(context_ab.remote().clone(), context_ab.local().clone());

    let local = FailingCryptoAdvisor;

    let remote = FailingCryptoAdvisor;

    let registry = CryptoRegistry::with_defaults();

    let policy_engine = CryptoPolicyEngine::new(CryptoPolicy::default());

    let coordinator = NegotiationCoordinator::new(&local, &remote, &policy_engine, &registry);

    let result_ab = coordinator.negotiate(&context_ab).await;

    let result_ba = coordinator.negotiate(&context_ba).await;

    assert_eq!(result_ab.result, result_ba.result);
}
