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
pub fn read_pdx_from_reader<R: Read + std::io::Seek>(
    reader: R,
) -> Result<DiagDatabase, PdxReadError> {
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut merged: Option<DiagDatabase> = None;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        let lower = name.to_lowercase();
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if !lower.ends_with(".odx") && !lower.contains(".odx-") {
            continue;
        }

        let mut xml = String::new();
        entry.read_to_string(&mut xml)?;

        log::info!("Parsing ODX from PDX entry: {}", name);
        let db = match parse_odx(&xml) {
            Ok(db) => db,
            Err(crate::parser::OdxParseError::MissingElement(ref elem))
                if elem == "DIAG-LAYER-CONTAINER" =>
            {
                // Non-DLC ODX files (COMPARAM-SPEC, COMPARAM-SUBSET, etc.) lack
                // DIAG-LAYER-CONTAINER. Skip them instead of failing the entire import.
                log::info!(
                    "Skipping non-DLC ODX entry '{}' (no DIAG-LAYER-CONTAINER)",
                    name
                );
                continue;
            }
            Err(e) => {
                return Err(PdxReadError::OdxParse {
                    file: name.clone(),
                    source: e,
                });
            }
        };

        merged = Some(match merged {
            None => db,
            Some(existing) => merge_databases(existing, db),
        });
    }

    merged.ok_or(PdxReadError::NoOdxFiles)
}

/// Merge two DiagDatabases.
///
/// Prefer metadata (ECU name, version, revision) from the database that has
/// actual diagnostic content (variants), since protocol-layer ODX files also
/// have DIAG-LAYER-CONTAINER but contain no variants.
fn merge_databases(mut base: DiagDatabase, other: DiagDatabase) -> DiagDatabase {
    let base_has_variants = !base.variants.is_empty();
    let other_has_variants = !other.variants.is_empty();

    // Prefer ECU name from the database with variants
    if base.ecu_name.is_empty() || (!base_has_variants && other_has_variants) {
        base.ecu_name = other.ecu_name;
    }
    if base.version.is_empty() || (!base_has_variants && other_has_variants) {
        base.version = other.version;
    }
    if base.revision.is_empty() || (!base_has_variants && other_has_variants) {
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
