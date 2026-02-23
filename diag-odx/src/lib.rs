pub mod inheritance;
pub mod odx_model;
pub mod parser;
pub mod ref_resolver;
pub mod writer;

pub use parser::{parse_odx, OdxParseError};
pub use writer::{write_odx, OdxWriteError};
