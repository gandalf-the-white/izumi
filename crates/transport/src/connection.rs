use identity::AuthenticatedPeer;
use protocol::ProtocolMessage;
use secure_channel::SecureChannel;
use tokio::net::TcpStream;

use crate::{error::TransportError, framed_io::FramedIo};

pub struct PeerConnection {
    io: FramedIo<TcpStream>,
    channel: SecureChannel,
}

pub struct AuthenticatedConnection {
    peer: AuthenticatedPeer,
    io: FramedIo<TcpStream>,
    channel: SecureChannel,
}

impl PeerConnection {
    pub fn new(stream: TcpStream, channel: SecureChannel) -> Self {
        Self {
            io: FramedIo::new(stream),

            channel,
        }
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
