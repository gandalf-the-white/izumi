use domain::SessionId;

use crate::frame::DataDirection;

const DATA_PROTOCOL_VERSION: u8 = 1;

pub(crate) fn build_aad(
    session_id: &SessionId,
    direction: DataDirection,
    sequence: u64,
) -> Vec<u8> {
    let session = session_id.as_str().as_bytes();

    let session_length = u32::try_from(session.len()).expect("session id length must fit in u32");

    let mut aad = Vec::with_capacity(1 + 1 + 8 + 4 + session.len());

    aad.push(DATA_PROTOCOL_VERSION);

    aad.push(direction.as_byte());

    aad.extend_from_slice(&sequence.to_be_bytes());

    aad.extend_from_slice(&session_length.to_be_bytes());

    aad.extend_from_slice(session);

    aad
}
