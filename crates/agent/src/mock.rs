use async_trait::async_trait;

use domain::{CryptoRecommendation, CryptoSuiteId, NegotiationContext};

use crate::{AdvisorError, CryptoAdvisor};

#[derive(Debug, Clone)]
pub struct MockCryptoAdvisor {
    suite: CryptoSuiteId,
    reason: String,
    confidence: f32,
}

impl MockCryptoAdvisor {
    pub fn new(suite: CryptoSuiteId, reason: impl Into<String>, confidence: f32) -> Self {
        Self {
            suite,
            reason: reason.into(),
            confidence,
        }
    }
}

#[async_trait]
impl CryptoAdvisor for MockCryptoAdvisor {
    async fn recommend(
        &self,
        context: &NegotiationContext,
    ) -> Result<CryptoRecommendation, AdvisorError> {
        let common = context.common_suites();

        if common.is_empty() {
            return Err(AdvisorError::NoCommonSuite);
        }

        Ok(CryptoRecommendation::new(
            self.suite,
            self.reason.clone(),
            self.confidence,
        ))
    }
}

#[derive(Debug, Clone, Default)]
pub struct FailingCryptoAdvisor;

#[async_trait]
impl CryptoAdvisor for FailingCryptoAdvisor {
    async fn recommend(
        &self,
        _context: &NegotiationContext,
    ) -> Result<CryptoRecommendation, AdvisorError> {
        Err(AdvisorError::Provider("simulated advisor failure".into()))
    }
}
