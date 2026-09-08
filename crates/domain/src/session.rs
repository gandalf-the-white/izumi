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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_can_be_created() {
        let session_id = SessionId::new("session-123");

        assert_eq!(session_id.as_str(), "session-123");
    }
}
