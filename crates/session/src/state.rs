// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum SessionPhase {
//     Authenticated,
//     PeerConfirmed,
//     CapabilitiesExchanged,
//     RecommendationsExchanged,
//     Negotiated,
//     ReadyForData,
//     Closed,
// }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    /// Noise XX has completed and the remote peer
    /// has been authenticated through the TrustStore.
    Authenticated,

    /// Both peers have confirmed that authentication
    /// was accepted.
    PeerConfirmed,

    /// Both peers have exchanged their cryptographic
    /// capabilities.
    CapabilitiesExchanged,

    /// Both peers have exchanged their agent-generated
    /// recommendations.
    RecommendationsExchanged,

    /// Both peers have confirmed the same cryptographic
    /// suite.
    Negotiated,

    /// The negotiated data-plane cipher has been
    /// initialized and application traffic may flow.
    ReadyForData,

    /// The session is no longer usable.
    Closed,
}
