use diag_odx::pdx_reader::read_pdx_from_reader;
use std::io::{Cursor, Write};

fn minimal_odx() -> &'static str {
    include_str!("../../test-fixtures/odx/minimal.odx")
}

fn create_pdx_bytes(entries: &[(&str, &str)]) -> Vec<u8> {
    let buf = Vec::new();
    let cursor = Cursor::new(buf);
    let mut zip = zip::ZipWriter::new(cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    for (name, content) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(content.as_bytes()).unwrap();
    }

    let cursor = zip.finish().unwrap();
    cursor.into_inner()
}

#[test]
fn test_pdx_with_single_odx() {
    let bytes = create_pdx_bytes(&[("ECU.odx", minimal_odx())]);
    let db = read_pdx_from_reader(Cursor::new(bytes)).unwrap();
    assert!(!db.ecu_name.is_empty());
    assert!(!db.variants.is_empty());
}

#[test]
fn test_pdx_skips_non_odx_files() {
    let bytes = create_pdx_bytes(&[
        ("ECU.odx", minimal_odx()),
        ("README.txt", "not an ODX file"),
        ("data.xml", "<root/>"),
    ]);
    let db = read_pdx_from_reader(Cursor::new(bytes)).unwrap();
    assert!(!db.ecu_name.is_empty());
}

#[test]
fn test_pdx_with_no_odx_files_errors() {
    let bytes = create_pdx_bytes(&[("README.txt", "no ODX here")]);
    let result = read_pdx_from_reader(Cursor::new(bytes));
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("no ODX files"),
        "should report no ODX files found"
    );
}

#[test]
fn test_pdx_with_multiple_odx_merges() {
    // Same ODX twice - should deduplicate variants by name
    let bytes = create_pdx_bytes(&[("ECU1.odx", minimal_odx()), ("ECU2.odx", minimal_odx())]);
    let db = read_pdx_from_reader(Cursor::new(bytes)).unwrap();
    // Variants should not be duplicated
    let names: Vec<&str> = db
        .variants
        .iter()
        .map(|v| v.diag_layer.short_name.as_str())
        .collect();
    let unique: std::collections::HashSet<&&str> = names.iter().collect();
    assert_eq!(names.len(), unique.len(), "no duplicate variants");
}

#[test]
fn test_pdx_with_comparam_spec_skipped() {
    let comparam_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ODX version="2.2.0" model-version="2.2.0">
  <COMPARAM-SPEC><SHORT-NAME>CP_Spec</SHORT-NAME></COMPARAM-SPEC>
</ODX>"#;

    let bytes = create_pdx_bytes(&[("comparam.odx", comparam_xml), ("ECU.odx", minimal_odx())]);
    let result = read_pdx_from_reader(Cursor::new(bytes));
    assert!(
        result.is_ok(),
        "PDX with COMPARAM-SPEC should not fail: {:?}",
        result.err()
    );

    let db = result.unwrap();
    assert!(
        !db.variants.is_empty(),
        "should have at least one variant from ECU.odx"
    );
}
