use diag_yaml::parse_yaml;

#[test]
fn test_parse_minimal_yaml() {
    let content = include_str!("../../test-fixtures/yaml/minimal-ecu.yml");
    let db = parse_yaml(content).unwrap();
    assert_eq!(db.ecu_name, "Minimal ECU");
    assert!(!db.variants.is_empty(), "should have at least one variant");
    // Minimal ECU has 3 types defined: did_id_type, ascii_short, raw_bytes_fixed
    // No DIDs, so no services generated from DIDs
    // But services section enables some standard services
}

#[test]
fn test_parse_example_ecm() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    assert_eq!(db.ecu_name, "Engine Control Module");
    assert!(!db.variants.is_empty());

    // ECM has many DIDs which generate read services
    let services = &db.variants[0].diag_layer.diag_services;
    assert!(
        !services.is_empty(),
        "ECM should have generated services from DIDs"
    );

    // Check VIN read service exists
    let vin_svc = services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VIN");
    assert!(vin_svc.is_some(), "should have Read_VIN service");

    // Check that writable DIDs generate write services
    let write_svc = services
        .iter()
        .find(|s| s.diag_comm.short_name.starts_with("Write_"));
    assert!(write_svc.is_some(), "should have at least one write service");

    // Check routines are converted
    let routine_svc = services
        .iter()
        .find(|s| s.diag_comm.short_name == "ClearAdaptiveValues");
    assert!(
        routine_svc.is_some(),
        "should have ClearAdaptiveValues routine"
    );

    // Check DTCs
    assert!(
        !db.dtcs.is_empty(),
        "ECM should have DTCs"
    );
    let misfire = db.dtcs.iter().find(|d| d.short_name == "RandomMisfireDetected");
    assert!(misfire.is_some(), "should have RandomMisfireDetected DTC");

    // Check ECU jobs
    let jobs = &db.variants[0].diag_layer.single_ecu_jobs;
    assert!(!jobs.is_empty(), "ECM should have ECU jobs");
    let flash_job = jobs.iter().find(|j| j.diag_comm.short_name == "FlashECU");
    assert!(flash_job.is_some(), "should have FlashECU job");
}

#[test]
fn test_parse_preserves_metadata() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    assert_eq!(db.revision, "1.1.0");
    assert_eq!(db.metadata.get("author").map(|s| s.as_str()), Some("CDA Team"));
    assert_eq!(db.metadata.get("domain").map(|s| s.as_str()), Some("Variant"));
}

#[test]
fn test_parse_dtc_severity() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    let crankshaft = db
        .dtcs
        .iter()
        .find(|d| d.short_name == "CrankshaftPositionCorrelation")
        .unwrap();
    assert_eq!(crankshaft.level, Some(1));
    assert_eq!(crankshaft.display_trouble_code, "P0335");
}

#[test]
fn test_parse_type_with_enum() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    // The session_type uses an enum, which should result in TextTable CompuMethod
    let session_svc = db.variants[0]
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_ActiveDiagnosticSession");
    assert!(
        session_svc.is_some(),
        "should have service for ActiveDiagnosticSession DID"
    );

    if let Some(svc) = session_svc {
        if let Some(resp) = svc.pos_responses.first() {
            if let Some(param) = resp.params.first() {
                if let Some(diag_ir::ParamData::Value { dop, .. }) = &param.specific_data {
                    if let Some(diag_ir::DopData::NormalDop { compu_method, .. }) =
                        &dop.specific_data
                    {
                        let cm = compu_method.as_ref().unwrap();
                        assert_eq!(cm.category, diag_ir::CompuCategory::TextTable);
                    }
                }
            }
        }
    }
}

#[test]
fn test_parse_sdgs() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    let sdgs = &db.variants[0].diag_layer.sdgs;
    assert!(sdgs.is_some(), "ECM should have SDGs");
    let sdgs = sdgs.as_ref().unwrap();
    assert!(!sdgs.sdgs.is_empty(), "SDGs should not be empty");
}

#[test]
fn test_version_and_revision_are_independent() {
    let yaml = r#"
schema: "1.0"
meta:
  revision: "rev42"
  version: "2.0.0"
  author: "test"
  domain: "body"
  created: "2026-01-01"
  description: "test"
ecu:
  name: "TEST_ECU"
  id: "ECU001"
"#;
    let db = parse_yaml(yaml).unwrap();
    assert_eq!(db.revision, "rev42");
    assert_eq!(db.version, "2.0.0", "version should come from meta.version, not meta.revision");
}
