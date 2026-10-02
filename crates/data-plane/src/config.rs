use crypto::DataCipher;
use domain::SessionId;

use crate::DataDirection;

pub struct DataPlaneConfig {
    session_id: SessionId,

    send_cipher: Box<dyn DataCipher>,
    receive_cipher: Box<dyn DataCipher>,

    send_direction: DataDirection,
    receive_direction: DataDirection,
}

impl DataPlaneConfig {
    pub fn new(
        session_id: SessionId,
        send_cipher: Box<dyn DataCipher>,
        receive_cipher: Box<dyn DataCipher>,
        send_direction: DataDirection,
        receive_direction: DataDirection,
    ) -> Self {
        Self {
            session_id,
            send_cipher,
            receive_cipher,
            send_direction,
            receive_direction,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SessionId,
        Box<dyn DataCipher>,
        Box<dyn DataCipher>,
        DataDirection,
        DataDirection,
    ) {
        (
            self.session_id,
            self.send_cipher,
            self.receive_cipher,
            self.send_direction,
            self.receive_direction,
        )
    }
}
