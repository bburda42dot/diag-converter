// Generated Protobuf types
#[allow(unsafe_code, clippy::all)]
pub mod proto_generated {
    include!(concat!(env!("OUT_DIR"), "/fileformat.rs"));
}

// Generated FlatBuffers types
#[allow(unsafe_code, unused_imports, clippy::all, dead_code, non_snake_case)]
pub mod fbs_generated {
    include!(concat!(
        env!("OUT_DIR"),
        "/fbs_generated/diagnostic_description.rs"
    ));
}

pub mod compression;
pub mod reader;
pub mod writer;

// Re-export generated types for consumers
pub use fbs_generated::dataformat;
pub use proto_generated as fileformat;
