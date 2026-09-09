use protocol::ProtocolMessage;

use secure_channel::SecureChannel;

use tokio::net::TcpStream;

use crate::{FramedIo, TransportError};

use identity::AuthenticatedPeer;

pub struct AuthenticatedConnection {
    peer: AuthenticatedPeer,
    io: FramedIo<TcpStream>,
    channel: SecureChannel,
}

impl AuthenticatedConnection {
    pub(crate) fn new(stream: TcpStream, channel: SecureChannel, peer: AuthenticatedPeer) -> Self {
        Self {
            peer,
            io: FramedIo::new(stream),
            channel,
        }
    }

    pub fn peer(&self) -> &AuthenticatedPeer {
        &self.peer
    }

    pub async fn send(&mut self, message: &ProtocolMessage) -> Result<(), TransportError> {
        let ciphertext = self
            .channel
            .seal_protocol_message(message)
            .map_err(|error| TransportError::SecureChannel(error.to_string()))?;

        self.io.write_payload(&ciphertext).await
    }

    pub async fn receive(&mut self) -> Result<ProtocolMessage, TransportError> {
        let ciphertext = self.io.read_payload().await?;

        self.channel
            .open_protocol_message(&ciphertext)
            .map_err(|error| TransportError::SecureChannel(error.to_string()))
    }
}
