use std::io::{Read, Write};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Compression {
    None,
    Lzma,
    Gzip,
    Zstd,
}

impl Compression {
    pub fn algorithm_name(&self) -> Option<&'static str> {
        match self {
            Compression::None => None,
            Compression::Lzma => Some("lzma"),
            Compression::Gzip => Some("gzip"),
            Compression::Zstd => Some("zstd"),
        }
    }

    pub fn from_name(name: &str) -> Result<Self, CompressionError> {
        match name {
            "lzma" => Ok(Compression::Lzma),
            "gzip" => Ok(Compression::Gzip),
            "zstd" => Ok(Compression::Zstd),
            other => Err(CompressionError::UnknownAlgorithm(other.into())),
        }
    }
}

#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("compression failed: {0}")]
    CompressFailed(String),
    #[error("decompression failed: {0}")]
    DecompressFailed(String),
    #[error("unknown compression algorithm: {0}")]
    UnknownAlgorithm(String),
}

pub fn compress(data: &[u8], algo: &Compression) -> Result<Vec<u8>, CompressionError> {
    match algo {
        Compression::None => Ok(data.to_vec()),
        Compression::Lzma => {
            // MUST use new_lzma_encoder (LZMA_ALONE format), NOT MtStreamBuilder/XzEncoder (XZ format).
            // CDA reads with: xz2::stream::Stream::new_lzma_decoder(u64::MAX)
            let opts = xz2::stream::LzmaOptions::new_preset(6)
                .map_err(|e| CompressionError::CompressFailed(e.to_string()))?;
            let stream = xz2::stream::Stream::new_lzma_encoder(&opts)
                .map_err(|e| CompressionError::CompressFailed(e.to_string()))?;
            let mut encoder = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
            encoder
                .write_all(data)
                .map_err(|e| CompressionError::CompressFailed(e.to_string()))?;
            encoder
                .finish()
                .map_err(|e| CompressionError::CompressFailed(e.to_string()))
        }
        Compression::Gzip => {
            use flate2::write::GzEncoder;
            let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(data)
                .map_err(|e| CompressionError::CompressFailed(e.to_string()))?;
            encoder
                .finish()
                .map_err(|e| CompressionError::CompressFailed(e.to_string()))
        }
        Compression::Zstd => zstd::encode_all(std::io::Cursor::new(data), 3)
            .map_err(|e| CompressionError::CompressFailed(e.to_string())),
    }
}

/// Maximum default decompression size (256 MB) - prevents OOM on malicious inputs.
pub const MAX_DECOMPRESSED_SIZE: u64 = 256 * 1024 * 1024;

/// Decompress with an upper bound on output size, enforced DURING streaming decompression.
/// This prevents decompression bombs from consuming all memory before we can check.
/// All codecs use `Read::take()` to cap output bytes.
pub fn decompress_bounded(
    data: &[u8],
    algorithm: &str,
    max_size: u64,
) -> Result<Vec<u8>, CompressionError> {
    match algorithm {
        "lzma" => {
            // NOTE: xz2's memlimit parameter controls decoder working memory (dictionary),
            // NOT output size. We use Read::take() to limit actual output bytes.
            const LZMA_MEMLIMIT: u64 = 256 * 1024 * 1024;
            let decompressor = xz2::stream::Stream::new_lzma_decoder(LZMA_MEMLIMIT)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            let decoder =
                xz2::bufread::XzDecoder::new_stream(std::io::BufReader::new(data), decompressor);
            let mut limited = decoder.take(max_size + 1);
            let mut out = Vec::new();
            limited
                .read_to_end(&mut out)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            if out.len() as u64 > max_size {
                return Err(CompressionError::DecompressFailed(format!(
                    "decompressed size {} exceeds limit {}",
                    out.len(),
                    max_size
                )));
            }
            Ok(out)
        }
        "gzip" => {
            use flate2::read::GzDecoder;
            let decoder = GzDecoder::new(data);
            let mut limited = decoder.take(max_size + 1);
            let mut out = Vec::new();
            limited
                .read_to_end(&mut out)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            if out.len() as u64 > max_size {
                return Err(CompressionError::DecompressFailed(format!(
                    "decompressed size exceeds limit {}",
                    max_size
                )));
            }
            Ok(out)
        }
        "zstd" => {
            let decoder = zstd::Decoder::new(std::io::Cursor::new(data))
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            let mut limited = decoder.take(max_size + 1);
            let mut out = Vec::new();
            limited
                .read_to_end(&mut out)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            if out.len() as u64 > max_size {
                return Err(CompressionError::DecompressFailed(format!(
                    "decompressed size exceeds limit {}",
                    max_size
                )));
            }
            Ok(out)
        }
        other => Err(CompressionError::UnknownAlgorithm(other.into())),
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub fn decompress(data: &[u8], algorithm: &str) -> Result<Vec<u8>, CompressionError> {
    match algorithm {
        "lzma" => {
            // Match CDA's decompression: xz2::stream::Stream::new_lzma_decoder(u64::MAX)
            let decompressor = xz2::stream::Stream::new_lzma_decoder(u64::MAX)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            let mut decoder =
                xz2::bufread::XzDecoder::new_stream(std::io::BufReader::new(data), decompressor);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            Ok(out)
        }
        "gzip" => {
            use flate2::read::GzDecoder;
            let mut decoder = GzDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            Ok(out)
        }
        "zstd" => zstd::decode_all(std::io::Cursor::new(data))
            .map_err(|e| CompressionError::DecompressFailed(e.to_string())),
        other => Err(CompressionError::UnknownAlgorithm(other.into())),
    }
}
