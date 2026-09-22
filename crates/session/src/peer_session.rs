use domain::{
    CryptoRecommendation, CryptoSuiteId, NegotiationContext, PeerCapabilities, PeerId, SessionId,
};

use negotiation::{NegotiationResolver, NegotiationResult};

use protocol::{
    AuthenticationAck, Capabilities, NegotiationAccept, ProtocolMessage, Recommendation,
};

use transport::AuthenticatedConnection;

use crate::{SessionError, SessionPhase};

pub struct PeerSession {
    session_id: SessionId,
    phase: SessionPhase,
    connection: AuthenticatedConnection,
    local_capabilities: PeerCapabilities,
    remote_capabilities: Option<PeerCapabilities>,
    local_recommendation: Option<CryptoRecommendation>,
    remote_recommendation: Option<CryptoRecommendation>,
    selected_suite: Option<CryptoSuiteId>,
    local_ack_sent: bool,
    remote_ack_received: bool,
    local_capabilities_sent: bool,
    remote_capabilities_received: bool,
    local_recommendation_sent: bool,
    remote_recommendation_received: bool,
}

impl PeerSession {
    pub fn new(
        session_id: SessionId,
        connection: AuthenticatedConnection,
        local_capabilities: PeerCapabilities,
    ) -> Self {
        Self {
            session_id,
            phase: SessionPhase::Authenticated,
            connection,
            local_capabilities,
            remote_capabilities: None,
            local_recommendation: None,
            remote_recommendation: None,
            selected_suite: None,
            local_ack_sent: false,
            remote_ack_received: false,
            local_capabilities_sent: false,
            remote_capabilities_received: false,
            local_recommendation_sent: false,
            remote_recommendation_received: false,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn remote_capabilities(&self) -> Option<&PeerCapabilities> {
        self.remote_capabilities.as_ref()
    }

    pub fn remote_recommendation(&self) -> Option<&CryptoRecommendation> {
        self.remote_recommendation.as_ref()
    }

    pub fn selected_suite(&self) -> Option<CryptoSuiteId> {
        self.selected_suite
    }

    pub fn authenticated_peer_id(&self) -> &PeerId {
        self.connection.peer().peer_id()
    }

    pub fn negotiation_context(&self) -> Result<NegotiationContext, SessionError> {
        let remote = self
            .remote_capabilities
            .clone()
            .ok_or(SessionError::MissingRemoteCapabilities)?;

        Ok(NegotiationContext::new(
            self.local_capabilities.clone(),
            remote,
        ))
    }

    pub async fn send_authentication_ack(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::Authenticated)?;

        let message = ProtocolMessage::AuthenticationAck(AuthenticationAck {
            session_id: self.session_id.clone(),
        });

        self.send_message(&message).await?;

        self.local_ack_sent = true;
        self.refresh_authentication_phase();

        Ok(())
    }

    pub async fn receive_authentication_ack(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::Authenticated)?;

        let message = self.receive_message().await?;
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

    pub async fn send_capabilities(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::PeerConfirmed)?;

        let message = ProtocolMessage::Capabilities(Capabilities {
            session_id: self.session_id.clone(),
            supported_suites: self.local_capabilities.supported_suites().to_vec(),
        });

        self.send_message(&message).await?;

        self.local_capabilities_sent = true;
        self.refresh_capabilities_phase();

        Ok(())
    }

    pub async fn receive_capabilities(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::PeerConfirmed)?;

        let message = self.receive_message().await?;
        self.validate_session_id(&message)?;

        match message {
            ProtocolMessage::Capabilities(capabilities) => {
                let remote = PeerCapabilities::new(
                    self.authenticated_peer_id().clone(),
                    capabilities.supported_suites,
                );

                self.remote_capabilities = Some(remote);
                self.remote_capabilities_received = true;
                self.refresh_capabilities_phase();

                Ok(())
            }
            _ => Err(SessionError::UnexpectedMessage { phase: self.phase }),
        }
    }

    pub async fn send_recommendation(
        &mut self,
        recommendation: CryptoRecommendation,
    ) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::CapabilitiesExchanged)?;

        let message = ProtocolMessage::Recommendation(Recommendation {
            session_id: self.session_id.clone(),
            recommendation: recommendation.clone(),
        });

        self.send_message(&message).await?;

        self.local_recommendation = Some(recommendation);
        self.local_recommendation_sent = true;
        self.refresh_recommendations_phase();

        Ok(())
    }

    pub async fn receive_recommendation(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::CapabilitiesExchanged)?;

        let message = self.receive_message().await?;
        self.validate_session_id(&message)?;

        match message {
            ProtocolMessage::Recommendation(message) => {
                self.remote_recommendation = Some(message.recommendation);
                self.remote_recommendation_received = true;
                self.refresh_recommendations_phase();

                Ok(())
            }
            _ => Err(SessionError::UnexpectedMessage { phase: self.phase }),
        }
    }

    pub async fn resolve_and_send_accept(
        &mut self,
        resolver: &NegotiationResolver<'_>,
    ) -> Result<CryptoSuiteId, SessionError> {
        self.ensure_phase(SessionPhase::RecommendationsExchanged)?;

        let context = self.negotiation_context()?;

        let local = self
            .local_recommendation
            .as_ref()
            .ok_or(SessionError::MissingRemoteRecommendation)?;

        let remote = self
            .remote_recommendation
            .as_ref()
            .ok_or(SessionError::MissingRemoteRecommendation)?;

        let result = resolver.resolve(&context, local, remote);

        match result {
            NegotiationResult::Agreed { suite, .. } => {
                let message = ProtocolMessage::NegotiationAccept(NegotiationAccept {
                    session_id: self.session_id.clone(),
                    selected_suite: suite,
                });

                self.send_message(&message).await?;

                self.selected_suite = Some(suite);
                self.phase = SessionPhase::Negotiated;

                Ok(suite)
            }
            NegotiationResult::Rejected { .. } => Err(SessionError::NegotiationRejected),
        }
    }

    pub async fn receive_accept(&mut self) -> Result<CryptoSuiteId, SessionError> {
        self.ensure_phase(SessionPhase::RecommendationsExchanged)?;

        let message = self.receive_message().await?;
        self.validate_session_id(&message)?;

        match message {
            ProtocolMessage::NegotiationAccept(message) => {
                self.selected_suite = Some(message.selected_suite);
                self.phase = SessionPhase::Negotiated;

                Ok(message.selected_suite)
            }
            _ => Err(SessionError::UnexpectedMessage { phase: self.phase }),
        }
    }

    pub fn confirm_ready_for_data(&mut self) -> Result<(), SessionError> {
        self.ensure_phase(SessionPhase::Negotiated)?;
        self.phase = SessionPhase::ReadyForData;
        Ok(())
    }

    pub fn close(&mut self) {
        self.phase = SessionPhase::Closed;
    }

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

    fn validate_session_id(&self, message: &ProtocolMessage) -> Result<(), SessionError> {
        if message.session_id() != &self.session_id {
            return Err(SessionError::SessionIdMismatch {
                expected: self.session_id.as_str().to_owned(),
                received: message.session_id().as_str().to_owned(),
            });
        }

        Ok(())
    }

    fn refresh_authentication_phase(&mut self) {
        if self.local_ack_sent && self.remote_ack_received {
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

    fn refresh_recommendations_phase(&mut self) {
        if self.phase == SessionPhase::CapabilitiesExchanged
            && self.local_recommendation_sent
            && self.remote_recommendation_received
        {
            self.phase = SessionPhase::RecommendationsExchanged;
        }
    }

    async fn send_message(&mut self, message: &ProtocolMessage) -> Result<(), SessionError> {
        self.connection
            .send(message)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))
    }

    async fn receive_message(&mut self) -> Result<ProtocolMessage, SessionError> {
        self.connection
            .receive()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))
    }
}
