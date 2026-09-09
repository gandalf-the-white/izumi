mod channel;
mod error;
mod frame;

pub mod test_support;

pub use channel::SecureChannel;

pub use error::SecureChannelError;

pub use frame::{
    FRAME_HEADER_SIZE, MAX_ENCRYPTED_FRAME_SIZE, MAX_PLAINTEXT_SIZE, decode_frame, encode_frame,
};

pub use test_support::{SecureChannelPair, establish_in_memory};
