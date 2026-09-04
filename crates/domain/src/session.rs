use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Connected,
    Authenticating,
    Authenticated,
    ExchangingCapabilities,
    Negotiating,
    Validating,
    EstablishingKeys,
    Secure,
    Forwarding,
    Closed,
}
