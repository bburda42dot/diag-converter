# Extending diag-converter

## Adding a new input format

To add support for reading a new diagnostic format (e.g. "NewFormat"):

### 1. Create a new crate

```bash
cargo new diag-newformat --lib
```

Add it to the workspace `Cargo.toml`:

```toml
[workspace]
members = [
    "mdd-format",
    "diag-ir",
    "diag-yaml",
    "diag-odx",
    "diag-newformat",  # new
    "diag-cli",
]
```

Add `diag-ir` as a dependency in `diag-newformat/Cargo.toml`:

```toml
[dependencies]
diag-ir = { path = "../diag-ir" }
thiserror = { workspace = true }
log = { workspace = true }
```

### 2. Implement the parser

The parser must produce a `DiagDatabase` from the input:

```rust
use diag_ir::types::DiagDatabase;

pub fn parse_newformat(input: &str) -> Result<DiagDatabase, Error> {
    // Parse input into DiagDatabase
}
```

The IR types are defined in `diag-ir/src/types.rs`. The root type is `DiagDatabase` which contains variants, DTCs, and metadata. See `diag-yaml/src/parser.rs` or `diag-odx/src/odx_parser.rs` for examples.

### 3. Add format detection and dispatch to the CLI

In `diag-cli/src/main.rs`:

1. Add the extension to `detect_format()`:
   ```rust
   Some("nf") => Ok(Format::NewFormat),
   ```

2. Add the parsing case to `parse_input()`:
   ```rust
   Format::NewFormat => {
       let text = std::fs::read_to_string(input)?;
       diag_newformat::parse_newformat(&text)?
   }
   ```

3. Add `diag-newformat` as a dependency of `diag-cli`.

### 4. Add Bazel BUILD.bazel

Create `diag-newformat/BUILD.bazel`:

```python
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

rust_library(
    name = "diag_newformat",
    srcs = glob(["src/**/*.rs"]),
    crate_name = "diag_newformat",
    visibility = ["//visibility:public"],
    deps = [
        "//diag-ir:diag_ir",
        "@crates//:log",
        "@crates//:thiserror",
    ],
)
```

### 5. Add tests

Create integration tests in `diag-newformat/tests/` using test fixtures in `test-fixtures/newformat/`. Tests that use `include_str!("../../test-fixtures/...")` need `compile_data` in the BUILD.bazel target.

## Adding a new output format

To add support for writing a new format:

### 1. Implement the writer

In the format's crate (same crate as the parser):

```rust
pub fn write_newformat(db: &DiagDatabase) -> Result<String, Error> {
    // Serialize DiagDatabase to the output format
}
```

See `diag-yaml/src/writer.rs` or `diag-odx/src/odx_writer.rs` for examples.

### 2. Add to CLI dispatch

In `diag-cli/src/main.rs`, add the writing case in `run_convert()`:

```rust
Format::NewFormat => {
    let output = diag_newformat::write_newformat(&db)?;
    std::fs::write(output_path, &output)?;
}
```

## Modifying the IR

When the IR needs new fields (e.g. to support data that a new format carries):

### 1. Update Rust types

Edit `diag-ir/src/types.rs`. Add new fields with `Option<T>` or `Vec<T>` to maintain backward compatibility:

```rust
pub struct DiagService {
    // existing fields...
    pub new_field: Option<String>,  // new
}
```

### 2. Update FlatBuffers schema

Edit `mdd-format/schemas/diagnostic_description.fbs`. Add new fields at the end of the relevant table (FlatBuffers requires append-only changes for compatibility):

```fbs
table DiagService {
    // existing fields...
    new_field: string;  // new - must be at the end
}
```

### 3. Update FlatBuffers serialization

Update `diag-ir/src/to_fbs.rs` to serialize the new field, and `diag-ir/src/from_fbs.rs` to deserialize it. The `from_fbs` code must handle the field being absent (for files written before the change).

### 4. Update format parsers and writers

Each format parser/writer must handle the new IR field:
- Parsers: populate the new field from the source format (or leave as `None`/empty)
- Writers: write the new field if present

### 5. Find all breakage

```bash
cargo test --workspace
```

Rust's type system will catch most issues - any pattern match or struct literal missing the new field will fail to compile.

## Testing conventions

### Test fixtures

Test fixture files live in `test-fixtures/` organized by format:
- `test-fixtures/yaml/` - YAML diagnostic files
- `test-fixtures/odx/` - ODX XML files
- `test-fixtures/mdd/` - MDD binary files

### Include patterns

Integration tests typically use `include_str!` for text fixtures:

```rust
let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
```

For Bazel, these tests need `compile_data` pointing to the fixtures filegroup.

### Round-trip testing

The standard pattern for testing format correctness:

```rust
// Parse from format A
let db = parse_format_a(input);
// Write to format B
let output = write_format_b(&db);
// Parse back from format B
let db2 = parse_format_b(&output);
// Compare IR representations
assert_eq!(db, db2);
```

See `diag-cli/tests/test_integration.rs` and `diag-cli/tests/test_comparative.rs` for examples.
