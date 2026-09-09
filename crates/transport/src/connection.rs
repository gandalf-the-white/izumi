use protocol::ProtocolMessage;

use secure_channel::SecureChannel;

use tokio::net::TcpStream;

use crate::{FramedIo, TransportError};

pub struct PeerConnection {
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
        let frame = self
            .channel
            .seal_protocol_message(message)
            .map_err(|error| TransportError::SecureChannel(error.to_string()))?;

        self.io.write_frame(&frame).await
    }

    pub async fn receive(&mut self) -> Result<ProtocolMessage, TransportError> {
        let frame = self.io.read_frame().await?;

        self.channel
            .open_protocol_message(&frame)
            .map_err(|error| TransportError::SecureChannel(error.to_string()))
    }
}
