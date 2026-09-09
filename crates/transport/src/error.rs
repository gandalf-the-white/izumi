use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "received frame is too large: \
         {actual} bytes, maximum is {maximum}"
    )]
    FrameTooLarge { actual: usize, maximum: usize },

    #[error("empty frame is not allowed")]
    EmptyFrame,

    #[error("secure channel error: {0}")]
    SecureChannel(String),

    #[error("authentication error: {0}")]
    Authentication(String),

    #[error("Noise handshake error: {0}")]
    Handshake(String),
}
