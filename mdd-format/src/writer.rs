use crate::compression::{self, Compression};
use crate::fileformat;
use crate::reader::FILE_MAGIC;
use prost::Message;
use sha2::{Digest, Sha512};
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
    /// Additional chunks (e.g. JAR_FILE, JAR_FILE_PARTIAL) to include.
    pub extra_chunks: Vec<ExtraChunk>,
}

/// An additional chunk to embed in the MDD file.
#[derive(Debug, Clone)]
pub struct ExtraChunk {
    pub chunk_type: ExtraChunkType,
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum ExtraChunkType {
    JarFile,
    JarFilePartial,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            version: "1.0.0".into(),
            ecu_name: String::new(),
            revision: String::new(),
            compression: Compression::Lzma,
            metadata: HashMap::new(),
            extra_chunks: Vec::new(),
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
pub fn write_mdd_bytes(fbs_data: &[u8], options: &WriteOptions) -> Result<Vec<u8>, MddWriteError> {
    let uncompressed_size = fbs_data.len() as u64;

    // Compute SHA-512 of uncompressed data before compression
    let hash = Sha512::digest(fbs_data);
    let signature = fileformat::Signature {
        algorithm: "sha512_uncompressed".into(),
        key_identifier: None,
        metadata: HashMap::new(),
        signature: hash.to_vec(),
    };

    let chunk_data = compression::compress(fbs_data, &options.compression)?;

    let chunk = fileformat::Chunk {
        r#type: fileformat::chunk::DataType::DiagnosticDescription as i32,
        name: Some("diagnostic_description".into()),
        metadata: HashMap::new(),
        signatures: vec![signature],
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

    let mut chunks = vec![chunk];

    for extra in &options.extra_chunks {
        let data_type = match extra.chunk_type {
            ExtraChunkType::JarFile => fileformat::chunk::DataType::JarFile,
            ExtraChunkType::JarFilePartial => fileformat::chunk::DataType::JarFilePartial,
        };
        chunks.push(fileformat::Chunk {
            r#type: data_type as i32,
            name: Some(extra.name.clone()),
            metadata: HashMap::new(),
            signatures: vec![],
            compression_algorithm: None,
            uncompressed_size: None,
            encryption: None,
            mime_type: None,
            data: Some(extra.data.clone()),
        });
    }

    let mdd_file = fileformat::MddFile {
        version: options.version.clone(),
        ecu_name: options.ecu_name.clone(),
        revision: options.revision.clone(),
        metadata: options.metadata.clone(),
        chunks,
        feature_flags: vec![],
        chunks_signature: None,
    };

    let mut output = Vec::from(FILE_MAGIC.as_slice());
    mdd_file.encode(&mut output)?;
    Ok(output)
}
