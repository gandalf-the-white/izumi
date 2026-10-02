pub const MAX_DATA_FRAME_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    sequence: u64,
    ciphertext: Vec<u8>,
}

impl DataFrame {
    pub fn new(sequence: u64, ciphertext: Vec<u8>) -> Self {
        Self {
            sequence,
            ciphertext,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn into_ciphertext(self) -> Vec<u8> {
        self.ciphertext
    }
}

// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum DataDirection {
//     InitiatorToResponder,
//     ResponderToInitiator,
// }

// impl DataDirection {
//     pub fn as_byte(self) -> u8 {
//         match self {
//             Self::InitiatorToResponder => 0x01,

//             Self::ResponderToInitiator => 0x02,
//         }
//     }
// }

// fn build_aad(session_id: &SessionId, direction: DataDirection, sequence: u64) -> Vec<u8> {
//     let session = session_id.as_str().as_bytes();

//     let mut aad = Vec::with_capacity(1 + 1 + 8 + session.len());

//     aad.push(1);

//     aad.push(direction.as_byte());

//     aad.extend_from_slice(&sequence.to_be_bytes());

//     aad.extend_from_slice(session);

//     aad
// }
