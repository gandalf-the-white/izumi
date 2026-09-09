use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use secure_channel::MAX_ENCRYPTED_FRAME_SIZE;

use crate::TransportError;

const FRAME_HEADER_SIZE: usize = 4;

pub struct FramedIo<S> {
    stream: S,
}

impl<S> FramedIo<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> FramedIo<S>
where
    S: AsyncWrite + Unpin,
{
    pub async fn write_payload(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if payload.is_empty() {
            return Err(TransportError::EmptyFrame);
        }

        if payload.len() > MAX_ENCRYPTED_FRAME_SIZE {
            return Err(TransportError::FrameTooLarge {
                actual: payload.len(),
                maximum: MAX_ENCRYPTED_FRAME_SIZE,
            });
        }

        let length = u32::try_from(payload.len()).map_err(|_| TransportError::FrameTooLarge {
            actual: payload.len(),
            maximum: MAX_ENCRYPTED_FRAME_SIZE,
        })?;

        self.stream.write_all(&length.to_be_bytes()).await?;

        self.stream.write_all(payload).await?;

        self.stream.flush().await?;

        Ok(())
    }
}

impl<S> FramedIo<S>
where
    S: AsyncRead + Unpin,
{
    pub async fn read_payload(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut header = [0_u8; FRAME_HEADER_SIZE];

        self.stream.read_exact(&mut header).await?;

        let payload_len = u32::from_be_bytes(header) as usize;

        if payload_len == 0 {
            return Err(TransportError::EmptyFrame);
        }

        if payload_len > MAX_ENCRYPTED_FRAME_SIZE {
            return Err(TransportError::FrameTooLarge {
                actual: payload_len,
                maximum: MAX_ENCRYPTED_FRAME_SIZE,
            });
        }

        let mut payload = vec![0_u8; payload_len];

        self.stream.read_exact(&mut payload).await?;

        Ok(payload)
    }
}
