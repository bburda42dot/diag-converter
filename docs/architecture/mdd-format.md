# MDD Binary Format

## File structure

An MDD file consists of a fixed magic header followed by a length-delimited Protobuf message:

```
+----------------------------+
| Magic: "MDD version 0\0"  |  20 bytes
+----------------------------+
| Protobuf: MDDFile message  |  variable length
+----------------------------+
```

The magic bytes `MDD version 0      \0` (20 bytes, null-terminated, space-padded) identify the file format and allow quick rejection of non-MDD files before attempting Protobuf decoding.

## MDDFile message

The Protobuf envelope (`MDDFile` in `proto/file_format.proto`) contains metadata and an array of chunks:

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | ECU software version |
| `ecu_name` | string | ECU identifier |
| `revision` | string | Data revision |
| `metadata` | map\<string, string\> | Arbitrary key-value metadata |
| `feature_flags` | repeated FeatureFlag | Reserved for future use |
| `chunks` | repeated Chunk | Data chunks (see below) |
| `chunksSignature` | Signature (optional) | Signature over all chunks combined |

## Chunk types

Each `Chunk` in the `chunks` array has a `DataType` discriminator:

| Type | Value | Description |
|------|-------|-------------|
| `DIAGNOSTIC_DESCRIPTION` | 0 | Main payload - FlatBuffers-encoded diagnostic data |
| `JAR_FILE` | 1 | Java JAR file referenced by SingleEcuJob ProgCode entries |
| `JAR_FILE_PARTIAL` | 2 | Partial Java class extract. Name format: `<jar>::<path-in-jar>` |
| `EMBEDDED_FILE` | 3 | Generic embedded file (ODX-F, flashware, etc.) |
| `VENDOR_SPECIFIC` | 1024+ | Vendor-specific chunk types |

A typical MDD file has one `DIAGNOSTIC_DESCRIPTION` chunk and zero or more `JAR_FILE` chunks.

## Compression

Each chunk can be independently compressed. The `compression_algorithm` field names the algorithm, and `uncompressed_size` provides the original size for buffer pre-allocation.

| Algorithm | String value | Notes |
|-----------|-------------|-------|
| None | (field absent) | No compression |
| LZMA | `"lzma"` | Default. Compatible with CDA (classic-diagnostic-adapter) |
| Gzip | `"gzip"` | Standard deflate compression |
| Zstd | `"zstd"` | High compression ratio with fast decompression |

LZMA is the default because the original CDA implementation uses LZMA with `xz2` (liblzma bindings). Using the same algorithm ensures binary compatibility when reading MDD files produced by CDA.

## Signatures

Each chunk carries a `repeated Signature` field. The writer generates a SHA-512 hash of the uncompressed chunk data:

| Field | Value |
|-------|-------|
| `algorithm` | `"sha512_uncompressed"` |
| `signature` | SHA-512 digest bytes |
| `key_identifier` | (unused) |

The signature covers the data before compression, allowing integrity verification after decompression without needing the compressed form.

## FlatBuffers payload

The `DIAGNOSTIC_DESCRIPTION` chunk contains a FlatBuffers buffer whose root type is `EcuData` (defined in `schemas/diagnostic_description.fbs`). Key tables:

```
EcuData (root)
  +-- version, ecu_name, revision
  +-- metadata: [KeyValue]
  +-- variants: [Variant]
  |     +-- diag_layer: DiagLayer
  |     |     +-- diag_services: [DiagService]
  |     |     |     +-- request: Request -> [Param]
  |     |     |     +-- pos_responses, neg_responses: [Response]
  |     |     +-- single_ecu_jobs: [SingleEcuJob]
  |     |     +-- com_param_refs, state_charts, additional_audiences
  |     +-- variant_pattern: [VariantPattern]
  |     +-- parent_refs: [ParentRef]
  +-- functional_groups: [FunctionalGroup]
  +-- dtcs: [DTC]
```

The FlatBuffers schema uses `camelCase` field names to stay close to the original ODX descriptors. The `diag-ir` crate handles bidirectional conversion between the FlatBuffers representation and the Rust IR types.

## CDA compatibility

This project uses a fork of FlatBuffers (`alexmohr/flatbuffers` at revision `0ba3307d`) instead of upstream Google FlatBuffers. This fork is the same version used by the classic-diagnostic-adapter (CDA), ensuring that:

- MDD files written by diag-converter can be read by CDA
- MDD files written by CDA can be read by diag-converter
- The FlatBuffers binary encoding is identical (schema and compiler version match)

The fork revision is pinned in the workspace `Cargo.toml` via `[patch.crates-io]` and in the Bazel build via `http_archive` with a fixed SHA-256 hash.
