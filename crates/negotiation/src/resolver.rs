use crypto::{CryptoPolicyEngine, CryptoRegistry, PolicyDecision};

use domain::{CryptoRecommendation, CryptoSuiteId, NegotiationContext};

use crate::{AgreementReason, NegotiationFailure, NegotiationResult};

pub struct NegotiationResolver<'a> {
    policy_engine: &'a CryptoPolicyEngine,
    registry: &'a CryptoRegistry,
}

impl<'a> NegotiationResolver<'a> {
    pub fn new(policy_engine: &'a CryptoPolicyEngine, registry: &'a CryptoRegistry) -> Self {
        Self {
            policy_engine,
            registry,
        }
    }

    fn allowed_common_suites(&self, common: &[CryptoSuiteId]) -> Vec<CryptoSuiteId> {
        common
            .iter()
            .copied()
            .filter(|suite| {
                matches!(
                    self.policy_engine.evaluate_suite(*suite, self.registry,),
                    PolicyDecision::Accepted { .. }
                )
            })
            .collect()
    }

    fn select_by_priority(suites: &[CryptoSuiteId]) -> Option<CryptoSuiteId> {
        suites
            .iter()
            .copied()
            .max_by_key(|suite| (suite.descriptor().priority, *suite))
    }

    pub fn resolve(
        &self,
        context: &NegotiationContext,

        local_recommendation: &CryptoRecommendation,

        remote_recommendation: &CryptoRecommendation,
    ) -> NegotiationResult {
        let common = context.common_suites();

        if common.is_empty() {
            return NegotiationResult::Rejected {
                reason: NegotiationFailure::NoCommonSuite,
            };
        }

        let allowed_common = self.allowed_common_suites(&common);

        if allowed_common.is_empty() {
            return NegotiationResult::Rejected {
                reason: NegotiationFailure::NoPolicyCompatibleSuite,
            };
        }

        if allowed_common.len() == 1 {
            return NegotiationResult::Agreed {
                suite: allowed_common[0],

                reason: AgreementReason::SingleUsableSuite,
            };
        }

        let local_suite = local_recommendation.suite();

        let remote_suite = remote_recommendation.suite();

        let local_valid = allowed_common.contains(&local_suite);

        let remote_valid = allowed_common.contains(&remote_suite);

        match (local_valid, remote_valid) {
            (false, false) => NegotiationResult::Rejected {
                reason: NegotiationFailure::NoUsableRecommendation,
            },

            (true, false) => NegotiationResult::Agreed {
                suite: local_suite,

                reason: AgreementReason::SingleUsableRecommendation,
            },

            (false, true) => NegotiationResult::Agreed {
                suite: remote_suite,

                reason: AgreementReason::SingleUsableRecommendation,
            },

            (true, true) if local_suite == remote_suite => NegotiationResult::Agreed {
                suite: local_suite,

                reason: AgreementReason::BothAgentsAgreed,
            },

            (true, true) => {
                let selected = Self::select_by_priority(&[local_suite, remote_suite]).expect(
                    "two valid recommendations \
                         must produce a selection",
                );

                NegotiationResult::Agreed {
                    suite: selected,

                    reason: AgreementReason::DeterministicResolution,
                }
            }
        }
    }
}
