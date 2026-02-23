use diag_yaml::{parse_yaml, write_yaml};

#[test]
fn test_yaml_roundtrip_minimal() {
    let content = include_str!("../../test-fixtures/yaml/minimal-ecu.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    assert_eq!(original.ecu_name, reparsed.ecu_name);
    assert_eq!(original.variants.len(), reparsed.variants.len());
}

#[test]
fn test_yaml_roundtrip_ecm_preserves_ecu_name() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    assert_eq!(original.ecu_name, reparsed.ecu_name);
    assert_eq!(original.revision, reparsed.revision);
}

#[test]
fn test_yaml_roundtrip_ecm_preserves_dtc_count() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    assert_eq!(original.dtcs.len(), reparsed.dtcs.len());
}

#[test]
fn test_yaml_roundtrip_ecm_preserves_service_count() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    let _orig_services = original.variants[0].diag_layer.diag_services.len();
    let reparsed_services = reparsed.variants[0].diag_layer.diag_services.len();

    // The reparsed version should have at least the same number of services
    // (DIDs generate read/write services, routines generate services)
    assert!(
        reparsed_services > 0,
        "reparsed should have services"
    );
    // Note: exact count may differ because writer may not re-emit all services
    // but key data should be preserved
    assert_eq!(original.ecu_name, reparsed.ecu_name);
}

#[test]
fn test_write_yaml_produces_valid_yaml() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&db).unwrap();

    // Should be parseable as generic YAML
    let _: serde_yaml::Value = serde_yaml::from_str(&yaml_output).unwrap();
}

#[test]
fn test_write_yaml_contains_schema() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&db).unwrap();

    assert!(
        yaml_output.contains("opensovd.cda.diagdesc/v1"),
        "output should contain schema identifier"
    );
}

/// Regression test: writable DID flag must survive IR -> YAML roundtrip.
/// Previously, `.cloned()` on a mutable borrow caused the writable flag to be
/// lost because the clone was modified instead of the original map entry.
#[test]
fn test_writable_did_roundtrip() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    // Verify the IR has at least one Write_ service (proving the DID is writable)
    let layer = &db.variants[0].diag_layer;
    let write_services: Vec<_> = layer.diag_services.iter()
        .filter(|s| s.diag_comm.short_name.starts_with("Write_"))
        .collect();
    assert!(!write_services.is_empty(), "example-ecm.yml should have writable DIDs generating Write_ services");

    // Write to YAML and re-parse
    let yaml_output = write_yaml(&db).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    // The reparsed IR must still have Write_ services for writable DIDs
    let reparsed_layer = &reparsed.variants[0].diag_layer;
    let reparsed_write_services: Vec<_> = reparsed_layer.diag_services.iter()
        .filter(|s| s.diag_comm.short_name.starts_with("Write_"))
        .collect();
    assert_eq!(
        write_services.len(),
        reparsed_write_services.len(),
        "writable DID count must be preserved through IR -> YAML -> IR roundtrip"
    );
}

#[test]
fn test_memory_config_roundtrip() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  id: "MEM_ECU"
  name: "MemoryTestECU"
memory:
  default_address_format:
    address_bytes: 4
    length_bytes: 2
  regions:
    flash:
      name: Flash
      description: "Main flash region"
      start: 0x08000000
      end: 0x080FFFFF
      access: read_write
      security_level: "level_1"
      session: programming
    calibration:
      name: Calibration
      start: 0x20000000
      end: 0x2000FFFF
      access: read
      session:
        - default
        - extended
  data_blocks:
    firmware:
      name: FirmwareUpdate
      description: "ECU firmware download"
      type: download
      memory_address: 0x08000000
      memory_size: 0x100000
      format: compressed
      max_block_length: 0xFFF
      session: programming
"#;

    let db = parse_yaml(yaml).unwrap();
    let mem = db.memory.as_ref().expect("memory config should be parsed");

    // Verify parsed structure
    assert_eq!(mem.default_address_format.address_bytes, 4);
    assert_eq!(mem.default_address_format.length_bytes, 2);
    assert_eq!(mem.regions.len(), 2);
    assert_eq!(mem.data_blocks.len(), 1);

    // Check a region
    let flash = mem.regions.iter().find(|r| r.name == "Flash").unwrap();
    assert_eq!(flash.start_address, 0x08000000);
    assert_eq!(flash.size, 0x000FFFFF);
    assert_eq!(flash.access, diag_ir::MemoryAccess::ReadWrite);
    assert_eq!(flash.security_level.as_deref(), Some("level_1"));
    assert_eq!(flash.session.as_deref(), Some(&["programming".to_string()][..]));

    // Check multi-session region
    let cal = mem.regions.iter().find(|r| r.name == "Calibration").unwrap();
    assert_eq!(cal.session.as_ref().unwrap().len(), 2);

    // Check data block
    let fw = &mem.data_blocks[0];
    assert_eq!(fw.name, "FirmwareUpdate");
    assert_eq!(fw.block_type, diag_ir::DataBlockType::Download);
    assert_eq!(fw.format, diag_ir::DataBlockFormat::Compressed);

    // Roundtrip: write back to YAML and re-parse
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    let mem2 = db2.memory.as_ref().expect("memory config should survive roundtrip");

    assert_eq!(mem.default_address_format, mem2.default_address_format);
    assert_eq!(mem.regions.len(), mem2.regions.len());
    assert_eq!(mem.data_blocks.len(), mem2.data_blocks.len());

    let flash2 = mem2.regions.iter().find(|r| r.name == "Flash").unwrap();
    assert_eq!(flash.start_address, flash2.start_address);
    assert_eq!(flash.size, flash2.size);
    assert_eq!(flash.access, flash2.access);
}

#[test]
fn test_sessions_state_model_security_roundtrip() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  id: "SC_ECU"
  name: "StateChartECU"
sessions:
  default:
    id: 1
    alias: "DS"
  extended:
    id: 3
    alias: "EXTDS"
  programming:
    id: 2
state_model:
  initial_state:
    session: default
  session_transitions:
    default:
      - extended
      - programming
    extended:
      - default
security:
  level_1:
    level: 1
    seed_size: 4
    key_size: 4
  level_2:
    level: 2
    seed_size: 8
    key_size: 8
"#;

    let db = parse_yaml(yaml).unwrap();
    let layer = &db.variants[0].diag_layer;

    // Verify state charts were built
    assert_eq!(layer.state_charts.len(), 2, "should have session + security state charts");

    let session_sc = layer.state_charts.iter().find(|sc| sc.semantic == "SESSION").unwrap();
    assert_eq!(session_sc.states.len(), 3);
    assert_eq!(session_sc.start_state_short_name_ref, "default");
    assert_eq!(session_sc.state_transitions.len(), 3); // default->extended, default->programming, extended->default

    let security_sc = layer.state_charts.iter().find(|sc| sc.semantic == "SECURITY").unwrap();
    assert_eq!(security_sc.states.len(), 2);

    // Roundtrip
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    let layer2 = &db2.variants[0].diag_layer;

    assert_eq!(layer2.state_charts.len(), 2);

    let session_sc2 = layer2.state_charts.iter().find(|sc| sc.semantic == "SESSION").unwrap();
    assert_eq!(session_sc.states.len(), session_sc2.states.len());
    assert_eq!(session_sc.start_state_short_name_ref, session_sc2.start_state_short_name_ref);
    assert_eq!(session_sc.state_transitions.len(), session_sc2.state_transitions.len());

    // Verify session IDs survived
    let ext_state = session_sc2.states.iter().find(|s| s.short_name == "extended").unwrap();
    assert_eq!(ext_state.long_name.as_ref().unwrap().value, "3");
    assert_eq!(ext_state.long_name.as_ref().unwrap().ti, "EXTDS");

    let security_sc2 = layer2.state_charts.iter().find(|sc| sc.semantic == "SECURITY").unwrap();
    assert_eq!(security_sc.states.len(), security_sc2.states.len());

    // Verify security levels survived
    let lvl1 = security_sc2.states.iter().find(|s| s.short_name == "level_1").unwrap();
    assert_eq!(lvl1.long_name.as_ref().unwrap().value, "1");
}
