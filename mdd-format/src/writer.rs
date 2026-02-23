use crate::compression::{self, Compression};
use crate::fileformat;
use crate::reader::FILE_MAGIC;
use prost::Message;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MddWriteError {
    #[error("protobuf encode error: {0}")]
    ProtobufEncode(#[from] prost::EncodeError),
    #[error("compression failed: {0}")]
    CompressionFailed(#[from] crate::compression::CompressionError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct WriteOptions {
    pub version: String,
    pub ecu_name: String,
    pub revision: String,
    pub compression: Compression,
    pub metadata: HashMap<String, String>,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            version: "1.0.0".into(),
            ecu_name: String::new(),
            revision: String::new(),
            compression: Compression::Lzma,
            metadata: HashMap::new(),
        }
    }
}

/// Write raw FlatBuffers data as MDD file.
pub fn write_mdd_file(
    fbs_data: &[u8],
    options: &WriteOptions,
    path: &Path,
) -> Result<(), MddWriteError> {
    let bytes = write_mdd_bytes(fbs_data, options)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Write raw FlatBuffers data as MDD bytes.
pub fn write_mdd_bytes(
    fbs_data: &[u8],
    options: &WriteOptions,
) -> Result<Vec<u8>, MddWriteError> {
    let uncompressed_size = fbs_data.len() as u64;
    let chunk_data = compression::compress(fbs_data, &options.compression)?;

    let chunk = fileformat::Chunk {
        r#type: fileformat::chunk::DataType::DiagnosticDescription as i32,
        name: Some("diagnostic_description".into()),
        metadata: HashMap::new(),
        signatures: vec![],
        compression_algorithm: options.compression.algorithm_name().map(String::from),
        uncompressed_size: if options.compression != Compression::None {
            Some(uncompressed_size)
        } else {
            None
        },
        encryption: None,
        mime_type: Some("application/x-flatbuffers".into()),
        data: Some(chunk_data),
    };

    let mdd_file = fileformat::MddFile {
        version: options.version.clone(),
        ecu_name: options.ecu_name.clone(),
        revision: options.revision.clone(),
        metadata: options.metadata.clone(),
        chunks: vec![chunk],
        feature_flags: vec![],
        chunks_signature: None,
    };

    let mut output = Vec::from(FILE_MAGIC.as_slice());
    mdd_file.encode(&mut output)?;
    Ok(output)
}
