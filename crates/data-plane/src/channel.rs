use crypto::DataCipher;
use domain::SessionId;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    DataFrame, DataFrameCodec, DataPlaneConfig, DataPlaneError, aad::build_aad,
    frame::DataDirection,
};

pub struct DataPlaneChannel<T> {
    codec: DataFrameCodec<T>,

    send_cipher: Box<dyn DataCipher>,

    receive_cipher: Box<dyn DataCipher>,

    send_sequence: u64,
    receive_sequence: u64,

    session_id: SessionId,

    send_direction: DataDirection,

    receive_direction: DataDirection,
}

impl<T> DataPlaneChannel<T> {
    pub fn new(
        io: T,
        config: DataPlaneConfig,
        // session_id: SessionId,
        // send_cipher: Box<dyn DataCipher>,
        // receive_cipher: Box<dyn DataCipher>,
        // send_direction: DataDirection,
        // receive_direction: DataDirection,
    ) -> Self {
        let (session_id, send_cipher, receive_cipher, send_direction, receive_direction) =
            config.into_parts();
        Self {
            codec: DataFrameCodec::new(io),

            send_cipher,
            receive_cipher,

            send_sequence: 0,
            receive_sequence: 0,

            session_id,

            send_direction,
            receive_direction,
        }
    }

    pub fn send_sequence(&self) -> u64 {
        self.send_sequence
    }

    pub fn receive_sequence(&self) -> u64 {
        self.receive_sequence
    }

    pub fn into_inner(self) -> T {
        self.codec.into_inner()
    }
}

impl<T> DataPlaneChannel<T>
where
    T: AsyncWrite + Unpin,
{
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), DataPlaneError> {
        let sequence = self.send_sequence;

        let aad = build_aad(&self.session_id, self.send_direction, sequence);

        let ciphertext = self
            .send_cipher
            .encrypt(sequence, plaintext, &aad)
            .map_err(|error| DataPlaneError::Crypto(error.to_string()))?;

        let frame = DataFrame::new(sequence, ciphertext);

        self.codec.write_frame(&frame).await?;

        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(DataPlaneError::SequenceExhausted)?;

        Ok(())
    }
}

impl<T> DataPlaneChannel<T>
where
    T: AsyncRead + Unpin,
{
    pub async fn receive(&mut self) -> Result<Vec<u8>, DataPlaneError> {
        let frame = self.codec.read_frame().await?;

        let expected = self.receive_sequence;

        if frame.sequence() != expected {
            return Err(DataPlaneError::UnexpectedSequence {
                expected,
                received: frame.sequence(),
            });
        }

        let aad = build_aad(&self.session_id, self.receive_direction, expected);

        let plaintext = self
            .receive_cipher
            .decrypt(expected, frame.ciphertext(), &aad)
            .map_err(|error| DataPlaneError::Crypto(error.to_string()))?;

        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(DataPlaneError::SequenceExhausted)?;

        Ok(plaintext)
    }
}
