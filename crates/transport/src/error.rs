use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("received frame is too large: {actual} bytes, maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },

    #[error("secure channel error: {0}")]
    SecureChannel(String),
}
