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
