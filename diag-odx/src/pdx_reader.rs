use crate::parser::parse_odx;
use diag_ir::types::DiagDatabase;
use std::io::Read;
use std::path::Path;

/// Errors that can occur reading a PDX file.
#[derive(Debug, thiserror::Error)]
pub enum PdxReadError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("no ODX files found in PDX archive")]
    NoOdxFiles,
    #[error("ODX parse error in '{file}': {source}")]
    OdxParse {
        file: String,
        source: crate::parser::OdxParseError,
    },
}

/// Read a PDX file (ZIP archive containing ODX files) and return a merged DiagDatabase.
///
/// Parses each .odx file inside the archive and merges the results.
pub fn read_pdx_file(path: &Path) -> Result<DiagDatabase, PdxReadError> {
    let file = std::fs::File::open(path)?;
    read_pdx_from_reader(file)
}

/// Read a PDX from any reader (for testing with in-memory data).
pub fn read_pdx_from_reader<R: Read + std::io::Seek>(reader: R) -> Result<DiagDatabase, PdxReadError> {
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut merged: Option<DiagDatabase> = None;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        if !name.to_lowercase().ends_with(".odx") {
            continue;
        }

        let mut xml = String::new();
        entry.read_to_string(&mut xml)?;

        log::info!("Parsing ODX from PDX entry: {}", name);
        let db = parse_odx(&xml).map_err(|e| PdxReadError::OdxParse {
            file: name.clone(),
            source: e,
        })?;

        merged = Some(match merged {
            None => db,
            Some(existing) => merge_databases(existing, db),
        });
    }

    merged.ok_or(PdxReadError::NoOdxFiles)
}

/// Merge two DiagDatabases. The first one's metadata takes precedence.
fn merge_databases(mut base: DiagDatabase, other: DiagDatabase) -> DiagDatabase {
    // Use the first ECU name if non-empty
    if base.ecu_name.is_empty() {
        base.ecu_name = other.ecu_name;
    }
    if base.version.is_empty() {
        base.version = other.version;
    }
    if base.revision.is_empty() {
        base.revision = other.revision;
    }

    // Merge variants (avoid duplicates by short_name)
    let existing_names: std::collections::HashSet<String> = base
        .variants
        .iter()
        .map(|v| v.diag_layer.short_name.clone())
        .collect();
    for v in other.variants {
        if !existing_names.contains(&v.diag_layer.short_name) {
            base.variants.push(v);
        }
    }

    // Merge DTCs
    let existing_dtcs: std::collections::HashSet<u32> =
        base.dtcs.iter().map(|d| d.trouble_code).collect();
    for dtc in other.dtcs {
        if !existing_dtcs.contains(&dtc.trouble_code) {
            base.dtcs.push(dtc);
        }
    }

    base
}
