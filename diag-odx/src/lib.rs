pub mod inheritance;
pub mod odx_model;
pub mod parser;
pub mod ref_resolver;

pub use parser::{parse_odx, OdxParseError};
