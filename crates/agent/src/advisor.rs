use async_trait::async_trait;
use domain::{CryptoRecommendation, NegotiationContext};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdvisorError {
    #[error("no common crypto suite is available")]
    NoCommonSuite,

    #[error("agent returned an invalid recommendation: {0}")]
    InvalidRecommendation(String),

    #[error("AI provider error: {0}")]
    Provider(String),
}

#[async_trait]
pub trait CryptoAdvisor: Send + Sync {
    async fn recommend(
        &self,
        context: &NegotiationContext,
    ) -> Result<CryptoRecommendation, AdvisorError>;
}
