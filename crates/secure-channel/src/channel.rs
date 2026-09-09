use snow::TransportState;

use crate::{MAX_ENCRYPTED_FRAME_SIZE, MAX_PLAINTEXT_SIZE, SecureChannelError, encode_frame};

use crate::decode_frame;

use protocol::{JsonCodec, ProtocolCodec, ProtocolMessage};

pub struct SecureChannel {
    transport: TransportState,
}

impl SecureChannel {
    pub fn new(transport: TransportState) -> Self {
        Self { transport }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SecureChannelError> {
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(SecureChannelError::PlaintextTooLarge {
                actual: plaintext.len(),
                maximum: MAX_PLAINTEXT_SIZE,
            });
        }

        let mut ciphertext = vec![0_u8; MAX_ENCRYPTED_FRAME_SIZE];

        let written = self
            .transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|error| SecureChannelError::Noise(error.to_string()))?;

        ciphertext.truncate(written);

        encode_frame(&ciphertext)
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, SecureChannelError> {
        let ciphertext = decode_frame(frame)?;

        let mut plaintext = vec![0_u8; MAX_PLAINTEXT_SIZE];

        let written = self
            .transport
            .read_message(ciphertext, &mut plaintext)
            .map_err(|error| SecureChannelError::Noise(error.to_string()))?;

        plaintext.truncate(written);

        Ok(plaintext)
    }

    pub fn seal_protocol_message(
        &mut self,
        message: &ProtocolMessage,
    ) -> Result<Vec<u8>, SecureChannelError> {
        let codec = JsonCodec;

        let encoded = codec
            .encode(message)
            .map_err(|error| SecureChannelError::Protocol(error.to_string()))?;

        self.seal(&encoded)
    }

    pub fn open_protocol_message(
        &mut self,
        frame: &[u8],
    ) -> Result<ProtocolMessage, SecureChannelError> {
        let plaintext = self.open(frame)?;

        let codec = JsonCodec;

        codec
            .decode(&plaintext)
            .map_err(|error| SecureChannelError::Protocol(error.to_string()))
    }
}
