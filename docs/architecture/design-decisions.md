# Design Decisions

## 1. IR-centric architecture over direct format-to-format converters

**Decision:** All format conversions go through a canonical intermediate representation (`DiagDatabase`) rather than direct format-pair converters.

**Context:** The legacy toolchain had separate tools: `odx-converter` (Kotlin, ODX->MDD) and `yaml-to-mdd` (Python, YAML->MDD). Adding a new format or direction required writing a new tool.

**Rationale:** With N formats, direct converters require up to N*(N-1) implementations. An IR-centric approach requires only N parsers + N writers. Validation logic is shared across all formats. Round-trip testing becomes straightforward (format A -> IR -> format B -> IR -> compare).

**Consequences:** Every format parser must produce a complete `DiagDatabase`. Information that exists in one format but not in the IR will be lost during conversion. The IR must be a superset of all formats' capabilities.

## 2. FlatBuffers fork (alexmohr/flatbuffers) over upstream

**Decision:** Use `alexmohr/flatbuffers` at revision `0ba3307d` instead of upstream Google FlatBuffers.

**Context:** The classic-diagnostic-adapter (CDA) uses this specific fork for its MDD binary format. MDD files must be readable by both CDA and diag-converter.

**Rationale:** FlatBuffers binary format depends on both the schema and the compiler version. Using the exact same fork and revision as CDA guarantees binary compatibility. Upstream FlatBuffers may produce different binary layouts for the same schema.

**Consequences:** The fork is pinned via `[patch.crates-io]` in Cargo.toml and via `http_archive` with SHA-256 in Bazel. Upgrading requires verifying binary compatibility with CDA. The fork must be built from source (cmake) during Cargo builds, or provided via FLATC env var for Bazel builds.

## 3. xz2 over lzma-rs for LZMA compression

**Decision:** Use `xz2` (liblzma C bindings) for LZMA compression instead of pure-Rust `lzma-rs`.

**Context:** CDA uses `xz2` for MDD compression. LZMA has multiple stream formats (raw, alone, xz) that are not interchangeable.

**Rationale:** Using the same library as CDA ensures identical LZMA stream format. The `xz2` crate statically links liblzma, avoiding runtime dependencies. Pure-Rust alternatives may use different LZMA stream framing.

**Consequences:** Requires a C compiler and cmake for building liblzma from source. The Bazel build handles this via `lzma-sys` build script. Build times are slightly longer than a pure-Rust dependency.

## 4. Protobuf container wrapping FlatBuffers payload

**Decision:** MDD files use a Protobuf envelope (`MDDFile` message) containing FlatBuffers-encoded diagnostic data as chunk payloads.

**Context:** The file format needs both flexible metadata (version, ECU name, compression info, signatures) and efficient zero-copy access to the diagnostic data.

**Rationale:** Protobuf is well-suited for the envelope - it handles optional fields, maps, and nested messages cleanly. FlatBuffers provides zero-copy deserialization for the large diagnostic payload, avoiding the cost of fully parsing the data when only metadata is needed. The two formats complement each other.

**Consequences:** Two code generation steps in `build.rs`: `prost-build` for Protobuf and `flatc` for FlatBuffers. Readers must handle both formats. The magic header allows quick format detection before Protobuf parsing.

## 5. Cargo + Bazel dual build system

**Decision:** Support both Cargo (primary development) and Bazel (integration) build systems.

**Context:** diag-converter is developed as a standalone tool (Cargo workflow) but needs to integrate into the Eclipse S-CORE build system (Bazel).

**Rationale:** Cargo provides the best Rust development experience (fast builds, `cargo test`, IDE integration). Bazel provides hermetic builds, cross-language integration, and caching for CI. `crate_universe` bridges both by generating Bazel targets from `Cargo.toml`/`Cargo.lock`.

**Consequences:** BUILD.bazel files must be maintained alongside Cargo.toml. The `build.rs` must handle both environments (FLATC env var for Bazel, git+cmake for Cargo). `Cargo.lock` is the source of truth for dependency versions in both systems.

## 6. Rust edition 2024

**Decision:** Use Rust edition 2024 with stable toolchain.

**Context:** The classic-diagnostic-adapter uses edition 2024. diag-converter was initially on edition 2021.

**Rationale:** Consistent edition across the CDA ecosystem. Edition 2024 provides improved ergonomics (`gen` keyword reserved, stricter unsafe checks). Stable toolchain ensures wider compatibility and reproducible builds.

**Consequences:** `gen` is a reserved keyword - any identifiers named `gen` must be renamed. `resolver = "3"` is required in workspace Cargo.toml. All workspace members inherit the edition from `[workspace.package]`.
