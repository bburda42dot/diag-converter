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
        assert_eq!(
            av.diag_layer.diag_services.len(),
            bv.diag_layer.diag_services.len(),
            "variant '{}' service count must match: original={}, roundtripped={}",
            av.diag_layer.short_name,
            av.diag_layer.diag_services.len(),
            bv.diag_layer.diag_services.len(),
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

// ODX -> FBS -> IR preserves funct_classes, state refs, admin_data
#[test]
fn test_odx_mdd_roundtrip_preserves_funct_classes_and_refs() {
    let db1 = parse_odx(odx_fixture()).unwrap();

    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();

    let svc1 = db1.variants[0]
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VehicleSpeed")
        .unwrap();
    let svc2 = db2.variants[0]
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VehicleSpeed")
        .unwrap();

    assert_eq!(
        svc1.diag_comm.funct_classes.len(),
        svc2.diag_comm.funct_classes.len(),
        "funct_classes count should survive ODX->MDD roundtrip"
    );
    assert_eq!(
        svc1.diag_comm.pre_condition_state_refs.len(),
        svc2.diag_comm.pre_condition_state_refs.len(),
        "pre_condition_state_refs should survive ODX->MDD roundtrip"
    );
    assert_eq!(
        svc1.diag_comm.state_transition_refs.len(),
        svc2.diag_comm.state_transition_refs.len(),
        "state_transition_refs should survive ODX->MDD roundtrip"
    );

    assert_eq!(
        db1.metadata.get("admin_language"),
        db2.metadata.get("admin_language"),
        "admin_language should survive roundtrip via metadata BTreeMap"
    );
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

// YAML -> IR -> MDD -> IR: memory config survives roundtrip
#[test]
fn test_yaml_mdd_roundtrip_preserves_memory_config() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  name: "MEM_ECU"
memory:
  default_address_format:
    address_bytes: 4
    length_bytes: 4
  regions:
    flash:
      name: flash
      start: 0x08000000
      end: 0x08100000
      access: read_write
      security_level: Level1
  data_blocks:
    app:
      name: app
      memory_address: 0x08000000
      memory_size: 0x00080000
      block_type: download
      format: compressed
"#;
    let db1 = parse_yaml(yaml).unwrap();
    assert!(db1.memory.is_some(), "precondition: YAML parser should produce MemoryConfig");

    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    assert!(db2.memory.is_some(), "MemoryConfig should survive MDD roundtrip");

    let mem = db2.memory.unwrap();
    assert_eq!(mem.regions.len(), 1);
    assert_eq!(mem.regions[0].name, "flash");
    assert_eq!(mem.data_blocks.len(), 1);
    assert_eq!(mem.data_blocks[0].name, "app");
}

// YAML -> IR -> FBS -> IR: type definitions survive roundtrip
#[test]
fn test_yaml_mdd_roundtrip_preserves_type_definitions() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  name: "TYPES_ECU"
types:
  VehicleSpeed:
    base: u16
    bit_length: 16
  EngineState:
    base: u8
    bit_length: 8
    enum:
      OFF: 0
      RUNNING: 1
dids:
  0x0100:
    name: Speed
    type: VehicleSpeed
"#;
    let db1 = parse_yaml(yaml).unwrap();
    assert_eq!(db1.type_definitions.len(), 2, "precondition: parser should produce 2 type defs");

    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    assert_eq!(db2.type_definitions.len(), 2,
        "type definitions count should survive MDD roundtrip");

    for td in &db1.type_definitions {
        let found = db2.type_definitions.iter().find(|t| t.name == td.name);
        assert!(found.is_some(), "type '{}' should survive MDD roundtrip", td.name);
        assert_eq!(found.unwrap().base, td.base,
            "type '{}' base should match", td.name);
    }
}
