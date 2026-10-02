use crypto::{CryptoRegistry, DataCipher, EphemeralKeyExchange, derive_directional_keys};
use domain::{
    CryptoRecommendation, CryptoSuiteId, NegotiationContext, PeerCapabilities, PeerId, SessionId,
};

use protocol::{
    AuthenticationAck, Capabilities, DataKeyExchange, NegotiationAccept, ProtocolMessage,
    Recommendation,
};

use transport::AuthenticatedConnection;

use crate::{SessionError, SessionPhase};

// use crate::{SessionError, SessionPhase};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

pub struct PeerSession {
    session_id: SessionId,
    phase: SessionPhase,

    connection: AuthenticatedConnection,

    local_capabilities: PeerCapabilities,
    remote_capabilities: Option<PeerCapabilities>,

    local_ack_sent: bool,
    remote_ack_received: bool,

    local_capabilities_sent: bool,
    remote_capabilities_received: bool,

    local_recommendation: Option<CryptoRecommendation>,
    remote_recommendation: Option<CryptoRecommendation>,

    selected_suite: Option<CryptoSuiteId>,

    role: SessionRole,

    key_exchange: Option<EphemeralKeyExchange>,

    send_cipher: Option<Box<dyn DataCipher>>,

    receive_cipher: Option<Box<dyn DataCipher>>,

    remote_data_public_key: Option<[u8; 32]>,

    send_sequence: u64,
    receive_sequence: u64,
}

impl PeerSession {
    pub fn new(
        session_id: SessionId,
        role: SessionRole,
        connection: AuthenticatedConnection,
        local_capabilities: PeerCapabilities,
    ) -> Self {
        Self {
            session_id,
            phase: SessionPhase::Authenticated,

            connection,

            local_capabilities,
            remote_capabilities: None,

            local_ack_sent: false,
            remote_ack_received: false,

            local_capabilities_sent: false,
            remote_capabilities_received: false,

            local_recommendation: None,
            remote_recommendation: None,

            selected_suite: None,

            role,

            key_exchange: None,

            send_cipher: None,

            receive_cipher: None,

            remote_data_public_key: None,

            send_sequence: 0,
            receive_sequence: 0,
        }
    }

    // ---------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn authenticated_peer_id(&self) -> &PeerId {
        self.connection.peer().peer_id()
    }

    pub fn local_capabilities(&self) -> &PeerCapabilities {
        &self.local_capabilities
    }

    pub fn remote_capabilities(&self) -> Option<&PeerCapabilities> {
        self.remote_capabilities.as_ref()
    }

    pub fn selected_suite(&self) -> Option<CryptoSuiteId> {
        self.selected_suite
    }

    // ---------------------------------------------------------
    // Internal validation
    // ---------------------------------------------------------

    fn ensure_open(&self) -> Result<(), SessionError> {
        if self.phase == SessionPhase::Closed {
            return Err(SessionError::Closed);
        }

        Ok(())
    }

    fn ensure_phase(&self, expected: SessionPhase) -> Result<(), SessionError> {
        self.ensure_open()?;

        if self.phase != expected {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        Ok(())
    }

    // fn validate_session_id(&self, message: &ProtocolMessage) -> Result<(), SessionError> {
    //     if message.session_id() != &self.session_id {
    //         return Err(SessionError::SessionIdMismatch {
    //             expected: self.session_id.as_str().to_owned(),

    //             received: message.session_id().as_str().to_owned(),
    //         });
    //     }

    //     Ok(())
    // }

    fn validate_session_ids(
        expected: &SessionId,
        received: &SessionId,
    ) -> Result<(), SessionError> {
        if expected != received {
            return Err(SessionError::SessionIdMismatch {
                expected: expected.as_str().to_owned(),

                received: received.as_str().to_owned(),
            });
        }

        Ok(())
    }

    fn validate_session_id(&self, message: &ProtocolMessage) -> Result<(), SessionError> {
        Self::validate_session_ids(&self.session_id, message.session_id())
    }

    fn transport_error(error: impl std::fmt::Display) -> SessionError {
        SessionError::Transport(error.to_string())
    }

    // ---------------------------------------------------------
    // Phase refresh helpers
    // ---------------------------------------------------------

    fn refresh_authentication_phase(&mut self) {
        if self.phase == SessionPhase::Authenticated
            && self.local_ack_sent
            && self.remote_ack_received
        {
            self.phase = SessionPhase::PeerConfirmed;
        }
    }

    fn refresh_capabilities_phase(&mut self) {
        if self.phase == SessionPhase::PeerConfirmed
            && self.local_capabilities_sent
            && self.remote_capabilities_received
        {
            self.phase = SessionPhase::CapabilitiesExchanged;
        }
    }

    fn refresh_recommendation_phase(&mut self) {
        if self.phase == SessionPhase::CapabilitiesExchanged
            && self.local_recommendation.is_some()
            && self.remote_recommendation.is_some()
        {
            self.phase = SessionPhase::RecommendationsExchanged;
        }
    }

    // ---------------------------------------------------------
    // Authentication confirmation
    // ---------------------------------------------------------

    pub async fn send_authentication_ack(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::Authenticated)?;

        if self.local_ack_sent {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let message = ProtocolMessage::AuthenticationAck(AuthenticationAck {
            session_id: self.session_id.clone(),
        });

        self.connection
            .send(&message)
            .await
            .map_err(Self::transport_error)?;

        self.local_ack_sent = true;

        self.refresh_authentication_phase();

        Ok(())
    }

    pub async fn receive_authentication_ack(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::Authenticated)?;

        if self.remote_ack_received {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let message = self
            .connection
            .receive()
            .await
            .map_err(Self::transport_error)?;

        self.validate_session_id(&message)?;

        match message {
            ProtocolMessage::AuthenticationAck(_) => {
                self.remote_ack_received = true;

                self.refresh_authentication_phase();

                Ok(())
            }

            _ => Err(SessionError::UnexpectedMessage { phase: self.phase }),
        }
    }

    // ---------------------------------------------------------
    // Capabilities exchange
    // ---------------------------------------------------------

    pub async fn send_capabilities(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::PeerConfirmed)?;

        if self.local_capabilities_sent {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let message = ProtocolMessage::Capabilities(Capabilities {
            session_id: self.session_id.clone(),

            supported_suites: self.local_capabilities.supported_suites().to_vec(),
        });

        self.connection
            .send(&message)
            .await
            .map_err(Self::transport_error)?;

        self.local_capabilities_sent = true;

        self.refresh_capabilities_phase();

        Ok(())
    }

    pub async fn receive_capabilities(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::PeerConfirmed)?;

        if self.remote_capabilities_received {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let message = self
            .connection
            .receive()
            .await
            .map_err(Self::transport_error)?;

        self.validate_session_id(&message)?;

        match message {
            ProtocolMessage::Capabilities(capabilities) => {
                let peer_id = self.connection.peer().peer_id().clone();

                let remote = PeerCapabilities::new(peer_id, capabilities.supported_suites);

                self.remote_capabilities = Some(remote);

                self.remote_capabilities_received = true;

                self.refresh_capabilities_phase();

                Ok(())
            }

            _ => Err(SessionError::UnexpectedMessage { phase: self.phase }),
        }
    }

    // ---------------------------------------------------------
    // Negotiation context
    // ---------------------------------------------------------

    pub fn negotiation_context(&self) -> Option<NegotiationContext> {
        let remote = self.remote_capabilities.as_ref()?;

        Some(NegotiationContext::new(
            self.local_capabilities.clone(),
            remote.clone(),
        ))
    }

    // ---------------------------------------------------------
    // Recommendation exchange
    // ---------------------------------------------------------

    pub async fn send_recommendation(
        &mut self,
        recommendation: CryptoRecommendation,
    ) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::CapabilitiesExchanged)?;

        if self.local_recommendation.is_some() {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let context = self
            .negotiation_context()
            .ok_or(SessionError::UnexpectedMessage { phase: self.phase })?;

        if !context.common_suites().contains(&recommendation.suite()) {
            return Err(SessionError::InvalidRecommendation);
        }

        let message = ProtocolMessage::Recommendation(Recommendation {
            session_id: self.session_id.clone(),

            recommendation: recommendation.clone(),
        });

        self.connection
            .send(&message)
            .await
            .map_err(Self::transport_error)?;

        self.local_recommendation = Some(recommendation);

        self.refresh_recommendation_phase();

        Ok(())
    }

    pub async fn receive_recommendation(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::CapabilitiesExchanged)?;

        if self.remote_recommendation.is_some() {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let message = self
            .connection
            .receive()
            .await
            .map_err(Self::transport_error)?;

        self.validate_session_id(&message)?;

        match message {
            ProtocolMessage::Recommendation(recommendation) => {
                let context = self
                    .negotiation_context()
                    .ok_or(SessionError::UnexpectedMessage { phase: self.phase })?;

                if !context
                    .common_suites()
                    .contains(&recommendation.recommendation.suite())
                {
                    return Err(SessionError::InvalidRecommendation);
                }

                self.remote_recommendation = Some(recommendation.recommendation);

                self.refresh_recommendation_phase();

                Ok(())
            }

            _ => Err(SessionError::UnexpectedMessage { phase: self.phase }),
        }
    }

    pub fn recommendations(&self) -> Option<(&CryptoRecommendation, &CryptoRecommendation)> {
        Some((
            self.local_recommendation.as_ref()?,
            self.remote_recommendation.as_ref()?,
        ))
    }

    // ---------------------------------------------------------
    // Negotiation confirmation
    // ---------------------------------------------------------

    pub async fn send_negotiation_accept(
        &mut self,
        suite: CryptoSuiteId,
    ) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::RecommendationsExchanged)?;

        if self.selected_suite.is_some() {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let context = self
            .negotiation_context()
            .ok_or(SessionError::UnexpectedMessage { phase: self.phase })?;

        if !context.common_suites().contains(&suite) {
            return Err(SessionError::InvalidNegotiatedSuite);
        }

        let message = ProtocolMessage::NegotiationAccept(NegotiationAccept {
            session_id: self.session_id.clone(),

            selected_suite: suite,
        });

        self.connection
            .send(&message)
            .await
            .map_err(Self::transport_error)?;

        self.selected_suite = Some(suite);

        Ok(())
    }

    pub async fn receive_negotiation_accept(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::RecommendationsExchanged)?;

        let local_suite = self
            .selected_suite
            .ok_or(SessionError::UnexpectedMessage { phase: self.phase })?;

        let message = self
            .connection
            .receive()
            .await
            .map_err(Self::transport_error)?;

        self.validate_session_id(&message)?;

        match message {
            ProtocolMessage::NegotiationAccept(accept) => {
                if accept.selected_suite != local_suite {
                    return Err(SessionError::NegotiationMismatch);
                }

                self.phase = SessionPhase::Negotiated;

                Ok(())
            }

            _ => Err(SessionError::UnexpectedMessage { phase: self.phase }),
        }
    }

    // ---------------------------------------------------------
    // Session lifecycle
    // ---------------------------------------------------------

    pub fn close(&mut self) {
        self.phase = SessionPhase::Closed;
    }

    pub async fn send_data_key(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::Negotiated)?;

        if self.key_exchange.is_some() {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let exchange = EphemeralKeyExchange::generate();

        let public_key = exchange.public_key();

        let message = ProtocolMessage::DataKeyExchange(DataKeyExchange {
            session_id: self.session_id.clone(),

            public_key,
        });

        self.connection
            .send(&message)
            .await
            .map_err(Self::transport_error)?;

        self.key_exchange = Some(exchange);

        self.refresh_data_key_phase();

        Ok(())
    }

    pub async fn receive_data_key(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::Negotiated)?;

        if self.remote_data_public_key.is_some() {
            return Err(SessionError::UnexpectedMessage { phase: self.phase });
        }

        let message = self
            .connection
            .receive()
            .await
            .map_err(Self::transport_error)?;

        self.validate_session_id(&message)?;

        match message {
            ProtocolMessage::DataKeyExchange(exchange) => {
                self.remote_data_public_key = Some(exchange.public_key);

                self.refresh_data_key_phase();

                Ok(())
            }

            _ => Err(SessionError::UnexpectedMessage { phase: self.phase }),
        }
    }

    fn refresh_data_key_phase(&mut self) {
        if self.phase == SessionPhase::Negotiated
            && self.key_exchange.is_some()
            && self.remote_data_public_key.is_some()
        {
            self.phase = SessionPhase::DataKeysEstablished;
        }
    }

    pub fn initialize_data_plane(&mut self, registry: &CryptoRegistry) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::DataKeysEstablished)?;

        let exchange = self
            .key_exchange
            .take()
            .ok_or(SessionError::DataKeysUnavailable)?;

        let remote_public = self
            .remote_data_public_key
            .take()
            .ok_or(SessionError::DataKeysUnavailable)?;

        let shared_secret = exchange.shared_secret(remote_public);

        let suite = self
            .selected_suite
            .ok_or(SessionError::DataKeysUnavailable)?;

        let keys = derive_directional_keys(&shared_secret, self.session_id.as_str(), suite.label())
            .map_err(|error| SessionError::DataCrypto(error.to_string()))?;

        let (send_key, receive_key) = match self.role {
            SessionRole::Initiator => (keys.initiator_to_responder, keys.responder_to_initiator),

            SessionRole::Responder => (keys.responder_to_initiator, keys.initiator_to_responder),
        };

        let send_cipher = registry
            .create_data_cipher(suite, &send_key)
            .map_err(|error| SessionError::DataCrypto(error.to_string()))?;

        let receive_cipher = registry
            .create_data_cipher(suite, &receive_key)
            .map_err(|error| SessionError::DataCrypto(error.to_string()))?;

        self.send_cipher = Some(send_cipher);

        self.receive_cipher = Some(receive_cipher);

        self.phase = SessionPhase::ReadyForData;

        Ok(())
    }

    // pub fn encrypt_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
    //     self.ensure_phase(SessionPhase::ReadyForData)?;

    //     let aad = self.session_id.as_str().as_bytes();

    //     self.send_cipher
    //         .as_mut()
    //         .ok_or(SessionError::DataKeysUnavailable)?
    //         .encrypt(plaintext, aad)
    //         .map_err(|error| SessionError::DataCrypto(error.to_string()))
    // }

    pub fn encrypt_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.ensure_phase(SessionPhase::ReadyForData)?;

        let sequence = self.send_sequence;

        let aad = self.session_id.as_str().as_bytes();

        let ciphertext = self
            .send_cipher
            .as_ref()
            .ok_or(SessionError::DataKeysUnavailable)?
            .encrypt(sequence, plaintext, aad)
            .map_err(|error| SessionError::DataCrypto(error.to_string()))?;

        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or_else(|| SessionError::DataCrypto("send sequence exhausted".to_owned()))?;

        Ok(ciphertext)
    }

    // pub fn decrypt_data(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
    //     self.ensure_phase(SessionPhase::ReadyForData)?;

    //     let aad = self.session_id.as_str().as_bytes();

    //     self.receive_cipher
    //         .as_mut()
    //         .ok_or(SessionError::DataKeysUnavailable)?
    //         .decrypt(ciphertext, aad)
    //         .map_err(|error| SessionError::DataCrypto(error.to_string()))
    // }

    pub fn decrypt_data(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.ensure_phase(SessionPhase::ReadyForData)?;

        let sequence = self.receive_sequence;

        let aad = self.session_id.as_str().as_bytes();

        let plaintext = self
            .receive_cipher
            .as_ref()
            .ok_or(SessionError::DataKeysUnavailable)?
            .decrypt(sequence, ciphertext, aad)
            .map_err(|error| SessionError::DataCrypto(error.to_string()))?;

        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or_else(|| SessionError::DataCrypto("receive sequence exhausted".to_owned()))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_session_ids_are_accepted() {
        let expected = SessionId::new("session-123");

        let received = SessionId::new("session-123");

        let result = PeerSession::validate_session_ids(&expected, &received);

        assert!(result.is_ok());
    }

    #[test]
    fn different_session_ids_are_rejected() {
        let expected = SessionId::new("session-123");

        let received = SessionId::new("session-999");

        let result = PeerSession::validate_session_ids(&expected, &received);

        assert!(matches!(
            result,
            Err(SessionError::SessionIdMismatch { .. })
        ));
    }
}
