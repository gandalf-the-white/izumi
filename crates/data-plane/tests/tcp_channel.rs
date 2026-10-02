use crypto::{ChaCha20Poly1305DataCipher, DataCipher};

use data_plane::{DataDirection, DataFrameCodec, DataPlaneChannel, DataPlaneConfig};

use domain::SessionId;

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

fn cipher(key: &[u8; 32]) -> Box<dyn DataCipher> {
    Box::new(ChaCha20Poly1305DataCipher::new(key))
}

fn initiator_channel(
    stream: TcpStream,
    session_id: SessionId,
    i2r_key: &[u8; 32],
    r2i_key: &[u8; 32],
) -> DataPlaneChannel<TcpStream> {
    let config = DataPlaneConfig::new(
        session_id,
        cipher(i2r_key),
        cipher(r2i_key),
        DataDirection::InitiatorToResponder,
        DataDirection::ResponderToInitiator,
    );
    DataPlaneChannel::new(
        stream,
        config,
        // session_id,
        // cipher(i2r_key),
        // cipher(r2i_key),
        // DataDirection::InitiatorToResponder,
        // DataDirection::ResponderToInitiator,
    )
}

fn responder_channel(
    stream: TcpStream,
    session_id: SessionId,
    i2r_key: &[u8; 32],
    r2i_key: &[u8; 32],
) -> DataPlaneChannel<TcpStream> {
    let config = DataPlaneConfig::new(
        session_id,
        cipher(r2i_key),
        cipher(i2r_key),
        DataDirection::ResponderToInitiator,
        DataDirection::InitiatorToResponder,
    );
    DataPlaneChannel::new(
        stream,
        config,
        // session_id,
        // cipher(r2i_key),
        // cipher(i2r_key),
        // DataDirection::ResponderToInitiator,
        // DataDirection::InitiatorToResponder,
    )
}

async fn tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;

    let address = listener.local_addr()?;

    let client = TcpStream::connect(address);

    let server = listener.accept();

    let (client_result, server_result) = tokio::join!(client, server);

    let client_stream = client_result?;

    let (server_stream, _peer_address) = server_result?;

    Ok((client_stream, server_stream))
}

#[tokio::test]
async fn initiator_sends_over_real_tcp() {
    let (initiator_stream, responder_stream) =
        tcp_pair().await.expect("TCP pair should be created");

    let session_id = SessionId::new("tcp-a-to-b");

    let i2r = [0x11_u8; 32];

    let r2i = [0x22_u8; 32];

    let mut initiator = initiator_channel(initiator_stream, session_id.clone(), &i2r, &r2i);

    let mut responder = responder_channel(responder_stream, session_id, &i2r, &r2i);

    initiator
        .send(b"hello over TCP")
        .await
        .expect("initiator should send");

    let received = responder.receive().await.expect("responder should receive");

    assert_eq!(received, b"hello over TCP");

    assert_eq!(initiator.send_sequence(), 1);

    assert_eq!(responder.receive_sequence(), 1);
}

#[tokio::test]
async fn responder_sends_over_real_tcp() {
    let (initiator_stream, responder_stream) = tcp_pair().await.unwrap();

    let session_id = SessionId::new("tcp-b-to-a");

    let i2r = [0x11_u8; 32];

    let r2i = [0x22_u8; 32];

    let mut initiator = initiator_channel(initiator_stream, session_id.clone(), &i2r, &r2i);

    let mut responder = responder_channel(responder_stream, session_id, &i2r, &r2i);

    responder.send(b"response from responder").await.unwrap();

    let received = initiator.receive().await.unwrap();

    assert_eq!(received, b"response from responder");
}

#[tokio::test]
async fn tcp_channel_is_bidirectional() {
    let (initiator_stream, responder_stream) = tcp_pair().await.unwrap();

    let session_id = SessionId::new("tcp-bidirectional");

    let i2r = [0x11_u8; 32];

    let r2i = [0x22_u8; 32];

    let mut initiator = initiator_channel(initiator_stream, session_id.clone(), &i2r, &r2i);

    let mut responder = responder_channel(responder_stream, session_id, &i2r, &r2i);

    initiator.send(b"request").await.unwrap();

    let request = responder.receive().await.unwrap();

    assert_eq!(request, b"request");

    responder.send(b"response").await.unwrap();

    let response = initiator.receive().await.unwrap();

    assert_eq!(response, b"response");

    assert_eq!(initiator.send_sequence(), 1);

    assert_eq!(initiator.receive_sequence(), 1);

    assert_eq!(responder.send_sequence(), 1);

    assert_eq!(responder.receive_sequence(), 1);
}

#[tokio::test]
async fn multiple_frames_are_preserved_over_tcp() {
    let (initiator_stream, responder_stream) = tcp_pair().await.unwrap();

    let session_id = SessionId::new("tcp-many-frames");

    let i2r = [0x11_u8; 32];

    let r2i = [0x22_u8; 32];

    let mut initiator = initiator_channel(initiator_stream, session_id.clone(), &i2r, &r2i);

    let mut responder = responder_channel(responder_stream, session_id, &i2r, &r2i);

    for sequence in 0..100_u64 {
        let message = format!("tcp-message-{sequence}");

        initiator.send(message.as_bytes()).await.unwrap();

        let received = responder.receive().await.unwrap();

        assert_eq!(received, message.as_bytes());
    }

    assert_eq!(initiator.send_sequence(), 100);

    assert_eq!(responder.receive_sequence(), 100);
}

#[tokio::test]
async fn fragmented_tcp_frame_is_reassembled() {
    let (mut sender, receiver) = tcp_pair().await.unwrap();

    let sequence = 42_u64;

    let payload = b"fragmented ciphertext";

    let length = u32::try_from(payload.len()).unwrap();

    let sequence_bytes = sequence.to_be_bytes();

    let length_bytes = length.to_be_bytes();

    sender.write_all(&sequence_bytes[..3]).await.unwrap();

    tokio::task::yield_now().await;

    sender.write_all(&sequence_bytes[3..]).await.unwrap();

    tokio::task::yield_now().await;

    sender.write_all(&length_bytes[..2]).await.unwrap();

    tokio::task::yield_now().await;

    sender.write_all(&length_bytes[2..]).await.unwrap();

    for chunk in payload.chunks(3) {
        sender.write_all(chunk).await.unwrap();

        tokio::task::yield_now().await;
    }

    let mut codec = DataFrameCodec::new(receiver);

    let frame = codec
        .read_frame()
        .await
        .expect("fragmented frame should be reconstructed");

    assert_eq!(frame.sequence(), 42);

    assert_eq!(frame.ciphertext(), payload);
}

#[tokio::test]
async fn concatenated_tcp_frames_are_separated() {
    let (mut sender, receiver) = tcp_pair().await.unwrap();

    let first = b"first";

    let second = b"second";

    let mut bytes = Vec::new();

    bytes.extend_from_slice(&0_u64.to_be_bytes());

    bytes.extend_from_slice(&u32::try_from(first.len()).unwrap().to_be_bytes());

    bytes.extend_from_slice(first);

    bytes.extend_from_slice(&1_u64.to_be_bytes());

    bytes.extend_from_slice(&u32::try_from(second.len()).unwrap().to_be_bytes());

    bytes.extend_from_slice(second);

    sender.write_all(&bytes).await.unwrap();

    let mut codec = DataFrameCodec::new(receiver);

    let first_frame = codec.read_frame().await.unwrap();

    let second_frame = codec.read_frame().await.unwrap();

    assert_eq!(first_frame.sequence(), 0);

    assert_eq!(first_frame.ciphertext(), first);

    assert_eq!(second_frame.sequence(), 1);

    assert_eq!(second_frame.ciphertext(), second);
}

#[tokio::test]
async fn tcp_disconnect_during_frame_is_detected() {
    let (mut sender, receiver) = tcp_pair().await.unwrap();

    sender.write_all(&0_u64.to_be_bytes()).await.unwrap();

    sender.write_all(&100_u32.to_be_bytes()).await.unwrap();

    sender.write_all(b"only-a-few-bytes").await.unwrap();

    drop(sender);

    let mut codec = DataFrameCodec::new(receiver);

    let result = codec.read_frame().await;

    assert!(result.is_err(), "disconnect during frame must be detected");
}

#[tokio::test]
async fn large_payload_is_transferred_over_tcp() {
    let (initiator_stream, responder_stream) = tcp_pair().await.unwrap();

    let session_id = SessionId::new("tcp-large");

    let i2r = [0x11_u8; 32];

    let r2i = [0x22_u8; 32];

    let mut initiator = initiator_channel(initiator_stream, session_id.clone(), &i2r, &r2i);

    let mut responder = responder_channel(responder_stream, session_id, &i2r, &r2i);

    let plaintext = vec![0xAB_u8; 32 * 1024];

    initiator.send(&plaintext).await.unwrap();

    let received = responder.receive().await.unwrap();

    assert_eq!(received, plaintext);
}
