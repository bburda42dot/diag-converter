use mdd_format::compression::{Compression, compress, decompress, decompress_bounded};

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

#[test]
fn test_decompress_bounded_rejects_oversized_output() {
    // Compress data that is larger than the limit we'll set
    let original = vec![0u8; 1024]; // 1 KiB of zeros (compresses well)
    for algo in [Compression::Lzma, Compression::Gzip, Compression::Zstd] {
        let compressed = compress(&original, &algo).unwrap();
        let algo_name = algo.algorithm_name().unwrap();

        // Limit to 512 bytes - decompressed output is 1024, should fail
        let result = decompress_bounded(&compressed, algo_name, 512);
        assert!(
            result.is_err(),
            "decompress_bounded should reject output exceeding limit for {:?}",
            algo
        );

        // Limit to 2048 bytes - decompressed output is 1024, should succeed
        let result = decompress_bounded(&compressed, algo_name, 2048).unwrap();
        assert_eq!(result, original, "roundtrip failed for {:?}", algo);
    }
}

#[test]
fn test_decompress_bounded_exact_limit() {
    let original = vec![42u8; 256];
    for algo in [Compression::Lzma, Compression::Gzip, Compression::Zstd] {
        let compressed = compress(&original, &algo).unwrap();
        let algo_name = algo.algorithm_name().unwrap();

        // Limit exactly equal to output size should succeed
        let result = decompress_bounded(&compressed, algo_name, 256).unwrap();
        assert_eq!(
            result, original,
            "exact-limit roundtrip failed for {:?}",
            algo
        );
    }
}
