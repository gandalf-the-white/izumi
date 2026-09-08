use domain::CryptoSuiteId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationResult {
    Agreed {
        suite: CryptoSuiteId,
        reason: AgreementReason,
    },

    Rejected {
        reason: NegotiationFailure,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgreementReason {
    BothAgentsAgreed,

    SingleUsableRecommendation,

    DeterministicResolution,

    SingleUsableSuite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationFailure {
    NoCommonSuite,

    NoPolicyCompatibleSuite,

    NoUsableRecommendation,
}
