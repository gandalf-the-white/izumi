use agent::CryptoAdvisor;

use crypto::{CryptoPolicyEngine, CryptoRegistry};

use negotiation::NegotiationResolver;

use domain::NegotiationContext;

use agent::AdvisorError;

use crate::{AdvisorOutcome, NegotiationOutcome};

pub struct NegotiationCoordinator<'a, L, R>
where
    L: CryptoAdvisor,
    R: CryptoAdvisor,
{
    local_advisor: &'a L,
    remote_advisor: &'a R,
    resolver: NegotiationResolver<'a>,
}

impl<'a, L, R> NegotiationCoordinator<'a, L, R>
where
    L: CryptoAdvisor,
    R: CryptoAdvisor,
{
    pub fn new(
        local_advisor: &'a L,
        remote_advisor: &'a R,
        policy_engine: &'a CryptoPolicyEngine,
        registry: &'a CryptoRegistry,
    ) -> Self {
        Self {
            local_advisor,
            remote_advisor,
            resolver: NegotiationResolver::new(policy_engine, registry),
        }
    }

    fn advisor_outcome(
        result: &Result<domain::CryptoRecommendation, AdvisorError>,
    ) -> AdvisorOutcome {
        match result {
            Ok(recommendation) => AdvisorOutcome::Recommendation(recommendation.clone()),

            Err(error) => AdvisorOutcome::Failed {
                error: error.to_string(),
            },
        }
    }

    fn resolve_outcomes(
        &self,
        context: &NegotiationContext,
        local: Result<domain::CryptoRecommendation, AdvisorError>,
        remote: Result<domain::CryptoRecommendation, AdvisorError>,
    ) -> NegotiationOutcome {
        let local_outcome = Self::advisor_outcome(&local);

        let remote_outcome = Self::advisor_outcome(&remote);

        let result = match (&local, &remote) {
            (Ok(local), Ok(remote)) => self.resolver.resolve(context, local, remote),

            _ => self.resolver.resolve_without_recommendations(context),
        };

        NegotiationOutcome {
            local_advisor: local_outcome,

            remote_advisor: remote_outcome,

            result,
        }
    }

    pub async fn negotiate(&self, context: &NegotiationContext) -> NegotiationOutcome {
        let local = self.local_advisor.recommend(context).await;

        let remote = self.remote_advisor.recommend(context).await;

        self.resolve_outcomes(context, local, remote)
    }
}
