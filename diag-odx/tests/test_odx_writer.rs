use diag_odx::{parse_odx, write_odx};

#[test]
fn test_odx_roundtrip_preserves_ecu_name() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    assert_eq!(original.ecu_name, reparsed.ecu_name);
}

#[test]
fn test_odx_roundtrip_preserves_version() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    assert_eq!(original.version, reparsed.version);
}

#[test]
fn test_odx_roundtrip_preserves_revision() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    assert_eq!(original.revision, reparsed.revision);
}

#[test]
fn test_odx_roundtrip_preserves_variant_count() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    assert_eq!(original.variants.len(), reparsed.variants.len());
}

#[test]
fn test_odx_roundtrip_preserves_dtc_count() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    assert_eq!(original.dtcs.len(), reparsed.dtcs.len());
}

#[test]
fn test_write_odx_produces_valid_xml() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let db = parse_odx(xml).unwrap();
    let odx_output = write_odx(&db).unwrap();

    // Should start with XML declaration
    assert!(odx_output.starts_with("<?xml"));
    // Should contain ODX root element
    assert!(odx_output.contains("<ODX"));
    assert!(odx_output.contains("DIAG-LAYER-CONTAINER"));
}

#[test]
fn test_odx_roundtrip_preserves_service_names() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    let orig_base = original.variants.iter().find(|v| v.is_base_variant).unwrap();
    let repr_base = reparsed.variants.iter().find(|v| v.is_base_variant).unwrap();

    // Should preserve diag service count
    assert_eq!(
        orig_base.diag_layer.diag_services.len(),
        repr_base.diag_layer.diag_services.len()
    );

    // Should preserve service name
    let orig_svc_names: Vec<_> = orig_base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| &s.diag_comm.short_name)
        .collect();
    let repr_svc_names: Vec<_> = repr_base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| &s.diag_comm.short_name)
        .collect();
    assert_eq!(orig_svc_names, repr_svc_names);
}

#[test]
fn test_odx_roundtrip_preserves_state_chart() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    let orig_base = original.variants.iter().find(|v| v.is_base_variant).unwrap();
    let repr_base = reparsed.variants.iter().find(|v| v.is_base_variant).unwrap();

    assert_eq!(
        orig_base.diag_layer.state_charts.len(),
        repr_base.diag_layer.state_charts.len()
    );

    if let (Some(orig_sc), Some(repr_sc)) = (
        orig_base.diag_layer.state_charts.first(),
        repr_base.diag_layer.state_charts.first(),
    ) {
        assert_eq!(orig_sc.short_name, repr_sc.short_name);
        assert_eq!(orig_sc.states.len(), repr_sc.states.len());
    }
}
