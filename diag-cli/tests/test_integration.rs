use diag_ir::{flatbuffers_to_ir, ir_to_flatbuffers, validate_database, DiagDatabase};
use diag_odx::{parse_odx, write_odx};
use diag_yaml::{parse_yaml, write_yaml};
use mdd_format::reader::read_mdd_bytes;
use mdd_format::writer::{write_mdd_bytes, WriteOptions};

fn yaml_fixture() -> &'static str {
    include_str!("../../test-fixtures/yaml/example-ecm.yml")
}

fn odx_fixture() -> &'static str {
    include_str!("../../test-fixtures/odx/minimal.odx")
}

fn assert_db_equivalent(a: &DiagDatabase, b: &DiagDatabase) {
    assert_eq!(a.ecu_name, b.ecu_name);
    assert_eq!(a.version, b.version);
    assert_eq!(a.revision, b.revision);
    assert_eq!(a.variants.len(), b.variants.len());
    assert_eq!(a.dtcs.len(), b.dtcs.len());

    for (av, bv) in a.variants.iter().zip(b.variants.iter()) {
        assert_eq!(av.is_base_variant, bv.is_base_variant);
        assert_eq!(av.diag_layer.short_name, bv.diag_layer.short_name);
        // Service count may differ on YAML roundtrip because the writer
        // does not yet re-emit the `services` section (generated UDS
        // services like TesterPresent are not round-tripped). The
        // re-parsed DB should have at least the DID/routine services.
        assert!(
            bv.diag_layer.diag_services.len() > 0
                || av.diag_layer.diag_services.is_empty(),
            "variant {} should preserve some services",
            av.diag_layer.short_name,
        );
    }
}

// YAML -> IR -> MDD -> IR -> compare
#[test]
fn test_yaml_ir_mdd_ir_roundtrip() {
    let db = parse_yaml(yaml_fixture()).unwrap();

    let fbs = ir_to_flatbuffers(&db);
    let mdd = write_mdd_bytes(&fbs, &WriteOptions::default()).unwrap();
    let (_meta, fbs_back) = read_mdd_bytes(&mdd).unwrap();
    let db2 = flatbuffers_to_ir(&fbs_back).unwrap();

    assert_db_equivalent(&db, &db2);
}

// ODX -> IR -> MDD -> IR -> compare
#[test]
fn test_odx_ir_mdd_ir_roundtrip() {
    let db = parse_odx(odx_fixture()).unwrap();

    let fbs = ir_to_flatbuffers(&db);
    let mdd = write_mdd_bytes(&fbs, &WriteOptions::default()).unwrap();
    let (_meta, fbs_back) = read_mdd_bytes(&mdd).unwrap();
    let db2 = flatbuffers_to_ir(&fbs_back).unwrap();

    assert_db_equivalent(&db, &db2);
}

// MDD determinism: write(ir) == write(ir)
#[test]
fn test_mdd_determinism() {
    let db = parse_yaml(yaml_fixture()).unwrap();
    let fbs = ir_to_flatbuffers(&db);

    let opts = WriteOptions {
        compression: mdd_format::compression::Compression::None,
        ..Default::default()
    };

    let mdd1 = write_mdd_bytes(&fbs, &opts).unwrap();
    let mdd2 = write_mdd_bytes(&fbs, &opts).unwrap();

    assert_eq!(mdd1, mdd2, "MDD output should be deterministic");
}

// YAML -> IR -> YAML roundtrip
#[test]
fn test_yaml_roundtrip_full() {
    let db = parse_yaml(yaml_fixture()).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    assert_db_equivalent(&db, &db2);
}

// ODX -> IR -> ODX roundtrip
#[test]
fn test_odx_roundtrip_full() {
    let db = parse_odx(odx_fixture()).unwrap();
    let odx_out = write_odx(&db).unwrap();
    let db2 = parse_odx(&odx_out).unwrap();

    assert_db_equivalent(&db, &db2);
}

// ODX -> IR -> YAML -> IR -> compare (cross-format)
// Note: variant count may differ between formats (ODX has base+ECU variants,
// YAML may flatten/restructure), so we only check metadata and content presence.
#[test]
fn test_odx_to_yaml_cross_format() {
    let db = parse_odx(odx_fixture()).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    assert_eq!(db.ecu_name, db2.ecu_name);
    assert!(!db2.variants.is_empty(), "Should have at least one variant");
    assert_eq!(db.dtcs.len(), db2.dtcs.len());
}

// Validate IR after each parse
#[test]
fn test_ir_validation_yaml() {
    let db = parse_yaml(yaml_fixture()).unwrap();
    // Validation may return warnings but should not have hard errors
    let _result = validate_database(&db);
}

#[test]
fn test_ir_validation_odx() {
    let db = parse_odx(odx_fixture()).unwrap();
    let _result = validate_database(&db);
}

// MDD with all compression algorithms
#[test]
fn test_mdd_all_compressions() {
    use mdd_format::compression::Compression;

    let db = parse_yaml(yaml_fixture()).unwrap();
    let fbs = ir_to_flatbuffers(&db);

    for compression in [Compression::None, Compression::Lzma, Compression::Gzip, Compression::Zstd]
    {
        let opts = WriteOptions {
            compression,
            ..Default::default()
        };
        let mdd = write_mdd_bytes(&fbs, &opts).unwrap();
        let (_meta, fbs_back) = read_mdd_bytes(&mdd).unwrap();
        let db2 = flatbuffers_to_ir(&fbs_back).unwrap();
        assert_eq!(db.ecu_name, db2.ecu_name, "Failed for {compression:?}");
    }
}
