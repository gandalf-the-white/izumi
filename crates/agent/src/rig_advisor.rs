use async_trait::async_trait;

use domain::{CryptoRecommendation, CryptoSuiteId, NegotiationContext};

use rig::{Agent, client::Nothing, prelude::*, providers::ollama};

use schemars::JsonSchema;
use serde::Deserialize;

use crate::{AdvisorError, CRYPTO_ADVISOR_PREAMBLE, CryptoAdvisor, build_crypto_advisor_prompt};

const MODEL: &str = "qwen3.8";

#[derive(Debug, Deserialize, JsonSchema)]
struct AgentRecommendationOutput {
    suite: AgentCryptoSuite,
    reason: String,
    confidence: f32,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
enum AgentCryptoSuite {
    #[serde(rename = "AES_256_GCM")]
    Aes256Gcm,

    #[serde(rename = "CHACHA20_POLY1305")]
    ChaCha20Poly1305,
}

impl From<AgentCryptoSuite> for CryptoSuiteId {
    fn from(value: AgentCryptoSuite) -> Self {
        match value {
            AgentCryptoSuite::Aes256Gcm => Self::Aes256Gcm,

            AgentCryptoSuite::ChaCha20Poly1305 => Self::ChaCha20Poly1305,
        }
    }
}

fn validate_output(
    output: AgentRecommendationOutput,
) -> Result<CryptoRecommendation, AdvisorError> {
    if !(0.0..=1.0).contains(&output.confidence) {
        return Err(AdvisorError::InvalidRecommendation(format!(
            "confidence {} is outside \
                         [0.0, 1.0]",
            output.confidence
        )));
    }

    Ok(CryptoRecommendation::new(
        output.suite.into(),
        output.reason,
        output.confidence,
    ))
}

pub struct RigCryptoAdvisor {
    agent: Agent,
}

impl RigCryptoAdvisor {
    pub fn new() -> Result<Self, AdvisorError> {
        let client = ollama::Client::new(Nothing)
            .map_err(|error| AdvisorError::Provider(error.to_string()))?;

        let agent = client
            .agent(MODEL)
            .preamble(CRYPTO_ADVISOR_PREAMBLE)
            .temperature(0.0)
            .build();

        Ok(Self { agent })
    }
}

// #[async_trait]
// impl CryptoAdvisor for RigCryptoAdvisor {
//     async fn recommend(
//         &self,
//         context: &NegotiationContext,
//     ) -> Result<CryptoRecommendation, AdvisorError> {
//         let prompt = build_crypto_advisor_prompt(context)?;

//         let output = self
//             .agent
//             .prompt_typed::<AgentRecommendationOutput>(prompt)
//             .max_turns(1)
//             .await
//             .map_err(|error| AdvisorError::Provider(error.to_string()))?;

//         validate_output(output)
//     }
// }

#[async_trait]
impl CryptoAdvisor for RigCryptoAdvisor {
    async fn recommend(
        &self,
        context: &NegotiationContext,
    ) -> Result<CryptoRecommendation, AdvisorError> {
        let prompt = build_crypto_advisor_prompt(context)?;

        let output = self
            .agent
            .prompt_typed::<AgentRecommendationOutput>(prompt)
            .max_turns(1)
            .await
            .map_err(|error| AdvisorError::Provider(error.to_string()))?;

        let recommendation = validate_output(output)?;

        if !context.common_suites().contains(&recommendation.suite()) {
            return Err(AdvisorError::InvalidRecommendation(format!(
                "suite {:?} is not \
                             common to both peers",
                recommendation.suite()
            )));
        }

        Ok(recommendation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_output_is_converted() {
        let output = AgentRecommendationOutput {
            suite: AgentCryptoSuite::ChaCha20Poly1305,

            reason: "preferred".into(),

            confidence: 0.9,
        };

        let recommendation = validate_output(output).expect("output should be valid");

        assert_eq!(recommendation.suite(), CryptoSuiteId::ChaCha20Poly1305);

        assert_eq!(recommendation.confidence(), 0.9);
    }

    #[test]
    fn invalid_confidence_is_rejected() {
        let output = AgentRecommendationOutput {
            suite: AgentCryptoSuite::Aes256Gcm,

            reason: "test".into(),

            confidence: 2.0,
        };

        let result = validate_output(output);

        assert!(matches!(
            result,
            Err(AdvisorError::InvalidRecommendation(_))
        ));
    }
}
