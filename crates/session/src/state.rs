#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Authenticated,
    PeerConfirmed,
    CapabilitiesExchanged,
    RecommendationsExchanged,
    Negotiated,
    ReadyForData,
    Closed,
}
