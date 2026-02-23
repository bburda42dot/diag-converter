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
