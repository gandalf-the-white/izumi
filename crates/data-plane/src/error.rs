use thiserror::Error;

// #[derive(Debug, Error)]
// pub enum DataPlaneError {
//     #[error("I/O error: {0}")]
//     Io(#[from] std::io::Error),

//     #[error("data frame too large: {actual} bytes, maximum is {maximum}")]
//     FrameTooLarge { actual: usize, maximum: usize },

//     #[error("unexpected sequence: expected {expected}, received {received}")]
//     UnexpectedSequence { expected: u64, received: u64 },

//     #[error("sequence number exhausted")]
//     SequenceExhausted,

//     #[error("cryptographic error: {0}")]
//     Crypto(String),

//     #[error("data plane is closed")]
//     Closed,
// }

#[derive(Debug, Error)]
pub enum DataPlaneError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("data frame too large: {actual} bytes, maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },

    #[error("empty data frame")]
    EmptyFrame,
}
