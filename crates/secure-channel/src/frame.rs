use crate::SecureChannelError;

pub const MAX_PLAINTEXT_SIZE: usize = 60 * 1024;

pub const MAX_ENCRYPTED_FRAME_SIZE: usize = 65_535;

pub const FRAME_HEADER_SIZE: usize = 4;

pub fn encode_frame(ciphertext: &[u8]) -> Result<Vec<u8>, SecureChannelError> {
    if ciphertext.len() > MAX_ENCRYPTED_FRAME_SIZE {
        return Err(SecureChannelError::FrameTooLarge {
            actual: ciphertext.len(),
            maximum: MAX_ENCRYPTED_FRAME_SIZE,
        });
    }

    let length =
        u32::try_from(ciphertext.len()).map_err(|_| SecureChannelError::FrameTooLarge {
            actual: ciphertext.len(),
            maximum: MAX_ENCRYPTED_FRAME_SIZE,
        })?;

    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + ciphertext.len());

    frame.extend_from_slice(&length.to_be_bytes());

    frame.extend_from_slice(ciphertext);

    Ok(frame)
}

pub fn decode_frame(frame: &[u8]) -> Result<&[u8], SecureChannelError> {
    if frame.len() < FRAME_HEADER_SIZE {
        return Err(SecureChannelError::IncompleteFrameHeader);
    }

    let length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;

    if length > MAX_ENCRYPTED_FRAME_SIZE {
        return Err(SecureChannelError::FrameTooLarge {
            actual: length,
            maximum: MAX_ENCRYPTED_FRAME_SIZE,
        });
    }

    let expected = FRAME_HEADER_SIZE + length;

    if frame.len() < expected {
        return Err(SecureChannelError::IncompleteFrame {
            expected,
            actual: frame.len(),
        });
    }

    if frame.len() > expected {
        return Err(SecureChannelError::TrailingFrameData {
            expected,
            actual: frame.len(),
        });
    }

    Ok(&frame[FRAME_HEADER_SIZE..expected])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_preserves_payload() {
        let ciphertext = b"encrypted-data";

        let frame = encode_frame(ciphertext).expect("frame should encode");

        let decoded = decode_frame(&frame).expect("frame should decode");

        assert_eq!(decoded, ciphertext);
    }

    #[test]
    fn incomplete_header_is_rejected() {
        let frame = [0_u8; 3];

        assert!(matches!(
            decode_frame(&frame),
            Err(SecureChannelError::IncompleteFrameHeader)
        ));
    }

    #[test]
    fn oversized_declared_frame_is_rejected() {
        let length = (MAX_ENCRYPTED_FRAME_SIZE as u32) + 1;

        let frame = length.to_be_bytes().to_vec();

        assert!(matches!(
            decode_frame(&frame),
            Err(SecureChannelError::FrameTooLarge { .. })
        ));
    }
}
