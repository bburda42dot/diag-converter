use mdd_format::compression::Compression;
use mdd_format::reader::{FILE_MAGIC, read_mdd_bytes};
use mdd_format::writer::{ExtraChunk, ExtraChunkType, WriteOptions, write_mdd_bytes};
use prost::Message;
use sha2::{Digest, Sha512};

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

#[test]
fn test_extra_chunks_included_in_output() {
    let fake_fbs_data = b"fake fbs data";
    let jar_data = b"jar file content";
    let jar_partial_data = b"partial jar content";

    let options = WriteOptions {
        compression: Compression::None,
        ecu_name: "CHUNK_TEST".into(),
        extra_chunks: vec![
            ExtraChunk {
                chunk_type: ExtraChunkType::JarFile,
                name: "my_job.jar".into(),
                data: jar_data.to_vec(),
            },
            ExtraChunk {
                chunk_type: ExtraChunkType::JarFilePartial,
                name: "my_job.jar::com/example/Main.class".into(),
                data: jar_partial_data.to_vec(),
            },
        ],
        ..Default::default()
    };

    let mdd_bytes = write_mdd_bytes(fake_fbs_data, &options).unwrap();

    // Reader should still extract the diagnostic description chunk normally
    let (meta, recovered_fbs) = read_mdd_bytes(&mdd_bytes).unwrap();
    assert_eq!(meta.ecu_name, "CHUNK_TEST");
    assert_eq!(recovered_fbs, fake_fbs_data);

    // Decode raw protobuf to verify all 3 chunks exist
    let mdd_file = mdd_format::fileformat::MddFile::decode(&mdd_bytes[FILE_MAGIC.len()..]).unwrap();
    assert_eq!(
        mdd_file.chunks.len(),
        3,
        "should have desc + 2 extra chunks"
    );

    let jar_chunk = &mdd_file.chunks[1];
    assert_eq!(jar_chunk.r#type, 1); // JAR_FILE
    assert_eq!(jar_chunk.name.as_deref(), Some("my_job.jar"));
    assert_eq!(jar_chunk.data.as_deref(), Some(jar_data.as_slice()));

    let partial_chunk = &mdd_file.chunks[2];
    assert_eq!(partial_chunk.r#type, 2); // JAR_FILE_PARTIAL
    assert_eq!(
        partial_chunk.name.as_deref(),
        Some("my_job.jar::com/example/Main.class")
    );
    assert_eq!(
        partial_chunk.data.as_deref(),
        Some(jar_partial_data.as_slice())
    );
}

#[test]
fn test_no_extra_chunks_by_default() {
    let fake_fbs_data = b"fake fbs";
    let options = WriteOptions {
        compression: Compression::None,
        ..Default::default()
    };

    let mdd_bytes = write_mdd_bytes(fake_fbs_data, &options).unwrap();
    let mdd_file = mdd_format::fileformat::MddFile::decode(&mdd_bytes[FILE_MAGIC.len()..]).unwrap();
    assert_eq!(
        mdd_file.chunks.len(),
        1,
        "only diagnostic description chunk"
    );
}

#[test]
fn test_sha512_signature_present() {
    let fake_fbs_data = b"data to hash for signature test";
    let options = WriteOptions {
        compression: Compression::None,
        ..Default::default()
    };

    let mdd_bytes = write_mdd_bytes(fake_fbs_data, &options).unwrap();
    let mdd_file = mdd_format::fileformat::MddFile::decode(&mdd_bytes[FILE_MAGIC.len()..]).unwrap();

    let desc_chunk = &mdd_file.chunks[0];
    assert_eq!(desc_chunk.signatures.len(), 1, "should have one signature");

    let sig = &desc_chunk.signatures[0];
    assert_eq!(sig.algorithm, "sha512_uncompressed");
    assert_eq!(sig.signature.len(), 64, "SHA-512 produces 64 bytes");

    // Verify the hash matches independently computed SHA-512
    let expected_hash = Sha512::digest(fake_fbs_data);
    assert_eq!(sig.signature, expected_hash.as_slice());
}

#[test]
fn test_sha512_signature_with_compression() {
    let fake_fbs_data = b"data to hash - the signature should be of uncompressed data";
    let options = WriteOptions {
        compression: Compression::Lzma,
        ..Default::default()
    };

    let mdd_bytes = write_mdd_bytes(fake_fbs_data, &options).unwrap();

    // Read back and verify the FBS data is recovered correctly
    let (_, recovered) = read_mdd_bytes(&mdd_bytes).unwrap();
    assert_eq!(recovered, fake_fbs_data);

    // Verify signature is of the uncompressed data
    let mdd_file = mdd_format::fileformat::MddFile::decode(&mdd_bytes[FILE_MAGIC.len()..]).unwrap();
    let sig = &mdd_file.chunks[0].signatures[0];
    let expected_hash = Sha512::digest(fake_fbs_data);
    assert_eq!(sig.signature, expected_hash.as_slice());
}

#[test]
fn test_no_signature_still_reads_successfully() {
    // MDD files without signatures (e.g. older CDA-generated files) must still be readable.
    let fake_fbs = b"data without signature for backward compat test";
    let options = WriteOptions {
        compression: Compression::None,
        ecu_name: "NOSIG".into(),
        ..Default::default()
    };
    let mdd_bytes = write_mdd_bytes(fake_fbs, &options).unwrap();

    // Strip signatures from the encoded MDD to simulate an old file
    let mut mdd_file =
        mdd_format::fileformat::MddFile::decode(&mdd_bytes[FILE_MAGIC.len()..]).unwrap();
    mdd_file.chunks[0].signatures.clear();
    let mut no_sig = FILE_MAGIC.to_vec();
    mdd_file.encode(&mut no_sig).unwrap();

    let (meta, recovered) = read_mdd_bytes(&no_sig).unwrap();
    assert_eq!(meta.ecu_name, "NOSIG");
    assert_eq!(recovered, fake_fbs);
}

#[test]
fn test_signature_verification_fails_on_tampered_data() {
    let fake_fbs = b"original fbs data that we will tamper with after writing";
    let options = WriteOptions {
        compression: Compression::None,
        ecu_name: "TAMPER".into(),
        ..Default::default()
    };
    let mdd_bytes = write_mdd_bytes(fake_fbs, &options).unwrap();

    // Decode, tamper with the FBS data payload directly, re-encode.
    let mut mdd_file =
        mdd_format::fileformat::MddFile::decode(&mdd_bytes[FILE_MAGIC.len()..]).unwrap();
    let chunk = &mut mdd_file.chunks[0];
    let data = chunk.data.as_mut().unwrap();
    data[0] ^= 0xFF; // corrupt first byte of FBS payload

    let mut tampered = FILE_MAGIC.to_vec();
    mdd_file.encode(&mut tampered).unwrap();

    let result = read_mdd_bytes(&tampered);
    assert!(
        result.is_err(),
        "tampered MDD data should fail signature verification"
    );
}
