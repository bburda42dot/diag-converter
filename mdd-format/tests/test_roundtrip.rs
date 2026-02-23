use mdd_format::compression::Compression;
use mdd_format::reader::read_mdd_bytes;
use mdd_format::writer::{write_mdd_bytes, WriteOptions};

#[test]
fn test_write_then_read_no_compression() {
    let fake_fbs_data = b"this is fake flatbuffers data for testing";
    let options = WriteOptions {
        version: "1.0.0".into(),
        ecu_name: "TEST_ECU".into(),
        revision: "0.1".into(),
        compression: Compression::None,
        ..Default::default()
    };

    let mdd_bytes = write_mdd_bytes(fake_fbs_data, &options).unwrap();
    let (metadata, recovered_fbs) = read_mdd_bytes(&mdd_bytes).unwrap();

    assert_eq!(metadata.ecu_name, "TEST_ECU");
    assert_eq!(metadata.version, "1.0.0");
    assert_eq!(metadata.revision, "0.1");
    assert_eq!(recovered_fbs, fake_fbs_data);
}

#[test]
fn test_write_then_read_lzma() {
    let fake_fbs_data = b"test data for LZMA compression roundtrip - needs some length";
    let options = WriteOptions {
        compression: Compression::Lzma,
        ecu_name: "LZMA_ECU".into(),
        ..Default::default()
    };

    let mdd_bytes = write_mdd_bytes(fake_fbs_data, &options).unwrap();
    let (metadata, recovered_fbs) = read_mdd_bytes(&mdd_bytes).unwrap();

    assert_eq!(metadata.ecu_name, "LZMA_ECU");
    assert_eq!(recovered_fbs, fake_fbs_data);
}

#[test]
fn test_write_then_read_all_compressions() {
    let data = b"test data repeated enough times to actually compress well \
                  test data repeated enough times to actually compress well";

    for compression in [
        Compression::None,
        Compression::Lzma,
        Compression::Gzip,
        Compression::Zstd,
    ] {
        let options = WriteOptions {
            compression,
            ecu_name: "TEST".into(),
            ..Default::default()
        };

        let mdd_bytes = write_mdd_bytes(data, &options).unwrap();
        let (_, recovered) = read_mdd_bytes(&mdd_bytes).unwrap();
        assert_eq!(recovered, data, "failed for compression {:?}", compression);
    }
}
