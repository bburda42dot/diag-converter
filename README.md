# diag-converter

Rust replacement for the `odx-converter` (Kotlin) and `yaml-to-mdd` (Python) diagnostic toolchains. Converts between automotive diagnostic formats through a canonical intermediate representation (IR).

## Supported formats

| Format | Read | Write |
|--------|------|-------|
| MDD (FlatBuffers + Protobuf) | Yes | Yes |
| YAML (diagnostic_yaml_proposal) | Yes | Yes |
| ODX (ISO 22901-1 XML) | Yes | Yes |

## Usage

```bash
# YAML to MDD
cargo run -- input.yml -o output.mdd

# ODX to MDD
cargo run -- input.odx -o output.mdd

# MDD to YAML
cargo run -- input.mdd -o output.yml

# MDD to ODX
cargo run -- input.mdd -o output.odx
```

## Crate structure

| Crate | Purpose |
|-------|---------|
| `mdd-format` | MDD file reader/writer (FlatBuffers + Protobuf container with compression) |
| `diag-ir` | Canonical IR types and FlatBuffers serialization |
| `diag-yaml` | YAML parser and writer |
| `diag-odx` | ODX XML parser and writer |
| `diag-cli` | CLI entry point |

## Building

```bash
cargo build --workspace
cargo test --workspace
```

## License

Apache-2.0
