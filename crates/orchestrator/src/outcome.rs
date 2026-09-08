use domain::CryptoRecommendation;

use negotiation::NegotiationResult;

#[derive(Debug, Clone, PartialEq)]
pub enum AdvisorOutcome {
    Recommendation(CryptoRecommendation),

    Failed { error: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct NegotiationOutcome {
    pub local_advisor: AdvisorOutcome,

    pub remote_advisor: AdvisorOutcome,

    pub result: NegotiationResult,
}
