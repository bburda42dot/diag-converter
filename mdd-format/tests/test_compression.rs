use mdd_format::compression::{compress, decompress, Compression};

#[test]
fn test_lzma_roundtrip() {
    let original = b"Hello diagnostic world! This is test data for LZMA compression.";
    let compressed = compress(original, &Compression::Lzma).unwrap();
    assert_ne!(compressed, original.as_slice());
    let decompressed = decompress(&compressed, "lzma").unwrap();
    assert_eq!(decompressed, original);
}

#[test]
fn test_gzip_roundtrip() {
    let original = b"Hello diagnostic world!";
    let compressed = compress(original, &Compression::Gzip).unwrap();
    let decompressed = decompress(&compressed, "gzip").unwrap();
    assert_eq!(decompressed, original);
}

#[test]
fn test_zstd_roundtrip() {
    let original = b"Hello diagnostic world!";
    let compressed = compress(original, &Compression::Zstd).unwrap();
    let decompressed = decompress(&compressed, "zstd").unwrap();
    assert_eq!(decompressed, original);
}

#[test]
fn test_none_passthrough() {
    let original = b"no compression";
    let result = compress(original, &Compression::None).unwrap();
    assert_eq!(result, original);
}
