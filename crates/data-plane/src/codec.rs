use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{DataFrame, DataPlaneError, MAX_DATA_FRAME_SIZE};

pub struct DataFrameCodec<T> {
    io: T,
}

impl<T> DataFrameCodec<T> {
    pub fn new(io: T) -> Self {
        Self { io }
    }

    pub fn into_inner(self) -> T {
        self.io
    }
}

impl<T> DataFrameCodec<T>
where
    T: AsyncWrite + Unpin,
{
    pub async fn write_frame(&mut self, frame: &DataFrame) -> Result<(), DataPlaneError> {
        let ciphertext = frame.ciphertext();

        if ciphertext.is_empty() {
            return Err(DataPlaneError::EmptyFrame);
        }

        if ciphertext.len() > MAX_DATA_FRAME_SIZE {
            return Err(DataPlaneError::FrameTooLarge {
                actual: ciphertext.len(),

                maximum: MAX_DATA_FRAME_SIZE,
            });
        }

        let length =
            u32::try_from(ciphertext.len()).map_err(|_| DataPlaneError::FrameTooLarge {
                actual: ciphertext.len(),

                maximum: MAX_DATA_FRAME_SIZE,
            })?;

        self.io.write_all(&frame.sequence().to_be_bytes()).await?;

        self.io.write_all(&length.to_be_bytes()).await?;

        self.io.write_all(ciphertext).await?;

        self.io.flush().await?;

        Ok(())
    }
}

impl<T> DataFrameCodec<T>
where
    T: AsyncRead + Unpin,
{
    pub async fn read_frame(&mut self) -> Result<DataFrame, DataPlaneError> {
        let mut sequence_bytes = [0_u8; 8];

        self.io.read_exact(&mut sequence_bytes).await?;

        let sequence = u64::from_be_bytes(sequence_bytes);

        let mut length_bytes = [0_u8; 4];

        self.io.read_exact(&mut length_bytes).await?;

        let length = u32::from_be_bytes(length_bytes) as usize;

        if length == 0 {
            return Err(DataPlaneError::EmptyFrame);
        }

        if length > MAX_DATA_FRAME_SIZE {
            return Err(DataPlaneError::FrameTooLarge {
                actual: length,
                maximum: MAX_DATA_FRAME_SIZE,
            });
        }

        let mut ciphertext = vec![0_u8; length];

        self.io.read_exact(&mut ciphertext).await?;

        Ok(DataFrame::new(sequence, ciphertext))
    }
}
