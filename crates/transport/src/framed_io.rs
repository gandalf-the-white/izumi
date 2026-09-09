use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use secure_channel::{FRAME_HEADER_SIZE, MAX_ENCRYPTED_FRAME_SIZE};

use crate::TransportError;

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
    pub async fn write_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        self.stream.write_all(frame).await?;

        self.stream.flush().await?;

        Ok(())
    }
}

impl<S> FramedIo<S>
where
    S: AsyncRead + Unpin,
{
    pub async fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut header = [0_u8; FRAME_HEADER_SIZE];

        self.stream.read_exact(&mut header).await?;

        let payload_len = u32::from_be_bytes(header) as usize;

        if payload_len > MAX_ENCRYPTED_FRAME_SIZE {
            return Err(TransportError::FrameTooLarge {
                actual: payload_len,
                maximum: MAX_ENCRYPTED_FRAME_SIZE,
            });
        }

        let mut payload = vec![0_u8; payload_len];

        self.stream.read_exact(&mut payload).await?;

        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload_len);

        frame.extend_from_slice(&header);

        frame.extend_from_slice(&payload);

        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip_works() {
        let (stream_a, stream_b) = tokio::io::duplex(1024);

        let mut writer = FramedIo::new(stream_a);

        let mut reader = FramedIo::new(stream_b);

        let payload = b"hello";

        let mut frame = Vec::new();

        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());

        frame.extend_from_slice(payload);

        writer.write_frame(&frame).await.unwrap();

        let received = reader.read_frame().await.unwrap();

        assert_eq!(received, frame);
    }

    #[tokio::test]
    async fn fragmented_frame_is_reassembled() {
        let (mut writer, reader) = tokio::io::duplex(1024);

        let payload = b"fragmented-message";

        let header = (payload.len() as u32).to_be_bytes();

        let task = tokio::spawn(async move {
            writer.write_all(&header[..2]).await.unwrap();

            writer.write_all(&header[2..]).await.unwrap();

            writer.write_all(&payload[..5]).await.unwrap();

            writer.write_all(&payload[5..]).await.unwrap();
        });

        let mut framed = FramedIo::new(reader);

        let frame = framed.read_frame().await.unwrap();

        task.await.unwrap();

        assert_eq!(&frame[FRAME_HEADER_SIZE..], payload);
    }
}
