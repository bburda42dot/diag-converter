use crate::compression;
use crate::fileformat;
use prost::Message;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Magic header bytes: "MDD version 0      \0" (20 bytes)
pub const FILE_MAGIC: &[u8; 20] = b"MDD version 0      \0";

#[derive(Debug, Error)]
pub enum MddReadError {
    #[error("invalid MDD magic header")]
    InvalidMagic,
    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),
    #[error("no diagnostic description chunk found")]
    NoDescriptionChunk,
    #[error("chunk has no data")]
    MissingChunkData,
    #[error("decompression failed: {0}")]
    DecompressionFailed(#[from] crate::compression::CompressionError),
    #[error("SHA-512 signature verification failed: data may be corrupted or tampered")]
    SignatureMismatch,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Metadata extracted from the MDD Protobuf container.
#[derive(Debug, Clone)]
pub struct MddMetadata {
    pub version: String,
    pub ecu_name: String,
    pub revision: String,
    pub metadata: HashMap<String, String>,
}

/// Read an MDD file and return metadata + raw FlatBuffers bytes.
pub fn read_mdd_file(path: &Path) -> Result<(MddMetadata, Vec<u8>), MddReadError> {
    let data = std::fs::read(path)?;
    read_mdd_bytes(&data)
}

/// Read MDD from bytes and return metadata + raw FlatBuffers bytes.
pub fn read_mdd_bytes(data: &[u8]) -> Result<(MddMetadata, Vec<u8>), MddReadError> {
    if data.len() < FILE_MAGIC.len() || &data[..FILE_MAGIC.len()] != FILE_MAGIC {
        return Err(MddReadError::InvalidMagic);
    }

    let mdd_file = fileformat::MddFile::decode(&data[FILE_MAGIC.len()..])?;

    let metadata = MddMetadata {
        version: mdd_file.version.clone(),
        ecu_name: mdd_file.ecu_name.clone(),
        revision: mdd_file.revision.clone(),
        metadata: mdd_file.metadata,
    };

    // Find DIAGNOSTIC_DESCRIPTION chunk (type = 0)
    let chunk = mdd_file
        .chunks
        .iter()
        .find(|c| c.r#type == fileformat::chunk::DataType::DiagnosticDescription as i32)
        .ok_or(MddReadError::NoDescriptionChunk)?;

    let raw_data = chunk.data.as_ref().ok_or(MddReadError::MissingChunkData)?;

    // CDA hardcodes LZMA decompression regardless of the compression_algorithm field.
    // We try LZMA first (matching CDA behavior). If LZMA fails, we allow raw data
    // only when it's at least 4 bytes (minimum FlatBuffers size - the root u32 offset).
    // Anything smaller is definitely invalid.
    let fbs_bytes = match &chunk.compression_algorithm {
        Some(algo) if !algo.is_empty() => compression::decompress(raw_data, algo)?,
        _ => match compression::decompress(raw_data, "lzma") {
            Ok(decompressed) => decompressed,
            Err(_) if raw_data.len() >= 4 => {
                log::warn!(
                    "no compression_algorithm specified and LZMA failed; \
                     treating {} bytes as uncompressed",
                    raw_data.len()
                );
                raw_data.clone()
            }
            Err(e) => return Err(MddReadError::DecompressionFailed(e)),
        },
    };

    // Verify SHA-512 signature if present.
    // Absent signatures are OK (backward compat with older MDD files / CDA output).
    if let Some(sig) = chunk
        .signatures
        .iter()
        .find(|s| s.algorithm == "sha512_uncompressed")
    {
        use sha2::{Digest, Sha512};
        let actual_hash = Sha512::digest(&fbs_bytes);
        if actual_hash.as_slice() != sig.signature.as_slice() {
            return Err(MddReadError::SignatureMismatch);
        }
    }

    Ok((metadata, fbs_bytes))
}
