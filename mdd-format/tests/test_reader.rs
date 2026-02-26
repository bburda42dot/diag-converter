use mdd_format::reader::{read_mdd_bytes, MddReadError, FILE_MAGIC};

#[test]
fn test_invalid_magic_header() {
    let result = read_mdd_bytes(b"NOT AN MDD FILE AT ALL!!");
    assert!(matches!(result, Err(MddReadError::InvalidMagic)));
}

#[test]
fn test_empty_after_magic() {
    let result = read_mdd_bytes(FILE_MAGIC);
    // Should fail - no protobuf data after magic, but prost decodes empty as default
    // MddFile with empty chunks, so we get NoDescriptionChunk
    assert!(result.is_err());
}

#[test]
fn test_too_short() {
    let result = read_mdd_bytes(b"MDD");
    assert!(matches!(result, Err(MddReadError::InvalidMagic)));
}

#[test]
fn test_uncompressed_data_without_algorithm_field() {
    use mdd_format::compression::Compression;
    use mdd_format::writer::{write_mdd_bytes, WriteOptions};

    let fake_fbs = b"uncompressed fbs data for testing the reader path";
    let options = WriteOptions {
        compression: Compression::None,
        ecu_name: "NOCOMP_ECU".into(),
        ..Default::default()
    };
    let mdd_bytes = write_mdd_bytes(fake_fbs.as_slice(), &options).unwrap();

    // Read should succeed: LZMA fails on non-LZMA data, falls back to raw
    let (meta, recovered) = read_mdd_bytes(&mdd_bytes).unwrap();
    assert_eq!(meta.ecu_name, "NOCOMP_ECU");
    assert_eq!(&recovered[..], &fake_fbs[..]);
}

#[test]
fn test_no_algorithm_with_garbage_data_returns_error() {
    use prost::Message;

    // Build a valid MDD container with garbage data and NO compression_algorithm.
    let mut mdd_file = mdd_format::fileformat::MddFile::default();
    mdd_file.ecu_name = "BAD".into();
    let chunk = mdd_format::fileformat::Chunk {
        r#type: 0, // DIAGNOSTIC_DESCRIPTION
        data: Some(vec![0xFF; 3]), // too short for valid FlatBuffers (< 4 bytes)
        compression_algorithm: None, // hits the _ => branch
        ..Default::default()
    };
    mdd_file.chunks.push(chunk);

    let mut buf = FILE_MAGIC.to_vec();
    mdd_file.encode(&mut buf).unwrap();

    let result = read_mdd_bytes(&buf);
    assert!(result.is_err(), "tiny garbage data with no algorithm should error, not silently fallback");
}
