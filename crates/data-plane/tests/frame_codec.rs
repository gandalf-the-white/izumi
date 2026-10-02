use data_plane::{DataFrame, DataFrameCodec, DataPlaneError, MAX_DATA_FRAME_SIZE};

use tokio::io::AsyncWriteExt;

#[test]
fn data_frame_preserves_values() {
    let frame = DataFrame::new(42, vec![1, 2, 3, 4]);

    assert_eq!(frame.sequence(), 42);

    assert_eq!(frame.ciphertext(), &[1, 2, 3, 4]);
}

#[tokio::test]
async fn frame_can_be_written_and_read() {
    let (stream_a, stream_b) = tokio::io::duplex(1024);

    let mut writer = DataFrameCodec::new(stream_a);

    let mut reader = DataFrameCodec::new(stream_b);

    let expected = DataFrame::new(42, b"encrypted payload".to_vec());

    writer
        .write_frame(&expected)
        .await
        .expect("frame should be written");

    let received = reader.read_frame().await.expect("frame should be read");

    assert_eq!(received.sequence(), 42);

    assert_eq!(received.ciphertext(), b"encrypted payload");
}

#[tokio::test]
async fn multiple_frames_preserve_order() {
    let (stream_a, stream_b) = tokio::io::duplex(4096);

    let mut writer = DataFrameCodec::new(stream_a);

    let mut reader = DataFrameCodec::new(stream_b);

    for sequence in 0..10_u64 {
        let payload = format!("ciphertext-{sequence}");

        let frame = DataFrame::new(sequence, payload.as_bytes().to_vec());

        writer.write_frame(&frame).await.expect("frame write");

        let received = reader.read_frame().await.expect("frame read");

        assert_eq!(received.sequence(), sequence);

        assert_eq!(received.ciphertext(), payload.as_bytes());
    }
}

#[tokio::test]
async fn empty_frame_is_rejected_on_write() {
    let (stream, _peer) = tokio::io::duplex(1024);

    let mut codec = DataFrameCodec::new(stream);

    let frame = DataFrame::new(0, Vec::new());

    let result = codec.write_frame(&frame).await;

    assert!(matches!(result, Err(DataPlaneError::EmptyFrame)));
}

#[tokio::test]
async fn oversized_frame_is_rejected_on_write() {
    let (stream, _peer) = tokio::io::duplex(1024);

    let mut codec = DataFrameCodec::new(stream);

    let frame = DataFrame::new(0, vec![0_u8; MAX_DATA_FRAME_SIZE + 1]);

    let result = codec.write_frame(&frame).await;

    assert!(matches!(
        result,
        Err(
            DataPlaneError::
                FrameTooLarge {
                    actual,
                    maximum,
                }
        )
        if actual
            == MAX_DATA_FRAME_SIZE + 1
            && maximum
                == MAX_DATA_FRAME_SIZE
    ));
}

#[tokio::test]
async fn zero_length_frame_is_rejected_on_read() {
    let (mut sender, receiver) = tokio::io::duplex(1024);

    sender.write_all(&42_u64.to_be_bytes()).await.unwrap();

    sender.write_all(&0_u32.to_be_bytes()).await.unwrap();

    let mut codec = DataFrameCodec::new(receiver);

    let result = codec.read_frame().await;

    assert!(matches!(result, Err(DataPlaneError::EmptyFrame)));
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_payload_allocation() {
    let (mut sender, receiver) = tokio::io::duplex(1024);

    sender.write_all(&7_u64.to_be_bytes()).await.unwrap();

    let malicious_length = u32::try_from(MAX_DATA_FRAME_SIZE + 1).unwrap();

    sender
        .write_all(&malicious_length.to_be_bytes())
        .await
        .unwrap();

    let mut codec = DataFrameCodec::new(receiver);

    let result = codec.read_frame().await;

    assert!(matches!(
        result,
        Err(
            DataPlaneError::
                FrameTooLarge {
                    actual,
                    maximum,
                }
        )
        if actual
            == MAX_DATA_FRAME_SIZE + 1
            && maximum
                == MAX_DATA_FRAME_SIZE
    ));
}

#[tokio::test]
async fn truncated_header_is_rejected() {
    let (mut sender, receiver) = tokio::io::duplex(1024);

    sender.write_all(&[0_u8; 5]).await.unwrap();

    drop(sender);

    let mut codec = DataFrameCodec::new(receiver);

    let result = codec.read_frame().await;

    assert!(matches!(result, Err(DataPlaneError::Io(_))));
}

#[tokio::test]
async fn truncated_ciphertext_is_rejected() {
    let (mut sender, receiver) = tokio::io::duplex(1024);

    sender.write_all(&1_u64.to_be_bytes()).await.unwrap();

    sender.write_all(&10_u32.to_be_bytes()).await.unwrap();

    sender.write_all(&[1_u8, 2, 3]).await.unwrap();

    drop(sender);

    let mut codec = DataFrameCodec::new(receiver);

    let result = codec.read_frame().await;

    assert!(matches!(result, Err(DataPlaneError::Io(_))));
}

#[tokio::test]
async fn maximum_sized_frame_is_accepted() {
    let (stream_a, stream_b) = tokio::io::duplex(MAX_DATA_FRAME_SIZE + 1024);

    let mut writer = DataFrameCodec::new(stream_a);

    let mut reader = DataFrameCodec::new(stream_b);

    let frame = DataFrame::new(123, vec![0xAA; MAX_DATA_FRAME_SIZE]);

    writer
        .write_frame(&frame)
        .await
        .expect("maximum frame should be accepted");

    let received = reader
        .read_frame()
        .await
        .expect("maximum frame should be readable");

    assert_eq!(received.sequence(), 123);

    assert_eq!(received.ciphertext().len(), MAX_DATA_FRAME_SIZE);
}
