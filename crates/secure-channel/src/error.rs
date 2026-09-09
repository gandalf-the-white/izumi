use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecureChannelError {
    #[error("plaintext is too large: {actual} bytes, maximum is {maximum}")]
    PlaintextTooLarge { actual: usize, maximum: usize },

    #[error("encrypted frame is too large: {actual} bytes, maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },

    #[error("frame header is incomplete")]
    IncompleteFrameHeader,

    #[error("incomplete frame: expected {expected} bytes, got {actual}")]
    IncompleteFrame { expected: usize, actual: usize },

    #[error("frame contains trailing bytes: expected {expected}, got {actual}")]
    TrailingFrameData { expected: usize, actual: usize },

    #[error("Noise transport error: {0}")]
    Noise(String),

    #[error("protocol codec error: {0}")]
    Protocol(String),

    #[error("identity error: {0}")]
    Identity(String),
}
