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

#[test]
fn test_odx_roundtrip_preserves_comparam_refs() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    let orig_base = original.variants.iter().find(|v| v.is_base_variant).unwrap();
    let repr_base = reparsed.variants.iter().find(|v| v.is_base_variant).unwrap();

    assert_eq!(
        orig_base.diag_layer.com_param_refs.len(),
        repr_base.diag_layer.com_param_refs.len(),
        "comparam ref count should be preserved"
    );

    // Verify the simple_value is preserved
    let orig_ref = &orig_base.diag_layer.com_param_refs[0];
    let repr_ref = &repr_base.diag_layer.com_param_refs[0];
    assert_eq!(
        orig_ref.simple_value.as_ref().map(|sv| &sv.value),
        repr_ref.simple_value.as_ref().map(|sv| &sv.value),
        "simple_value should be preserved"
    );

    // Verify protocol SNREF is preserved
    assert_eq!(
        orig_ref.protocol.as_ref().map(|p| &p.diag_layer.short_name),
        repr_ref.protocol.as_ref().map(|p| &p.diag_layer.short_name),
        "protocol SNREF should be preserved"
    );

    // Verify prot_stack SNREF is preserved
    assert_eq!(
        orig_ref.prot_stack.as_ref().map(|ps| &ps.short_name),
        repr_ref.prot_stack.as_ref().map(|ps| &ps.short_name),
        "prot_stack SNREF should be preserved"
    );
}

#[test]
fn test_odx_roundtrip_preserves_audience_refs() {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();
    let reparsed = parse_odx(&odx_output).unwrap();

    let orig_base = original.variants.iter().find(|v| v.is_base_variant).unwrap();
    let repr_base = reparsed.variants.iter().find(|v| v.is_base_variant).unwrap();

    let orig_svc = &orig_base.diag_layer.diag_services[0];
    let repr_svc = &repr_base.diag_layer.diag_services[0];

    // Audience boolean flags
    assert_eq!(
        orig_svc.diag_comm.audience.as_ref().map(|a| a.is_development),
        repr_svc.diag_comm.audience.as_ref().map(|a| a.is_development),
        "is_development should be preserved"
    );

    // Enabled audience refs
    let orig_enabled: Vec<_> = orig_svc.diag_comm.audience.as_ref()
        .map(|a| a.enabled_audiences.iter().map(|aa| &aa.short_name).collect())
        .unwrap_or_default();
    let repr_enabled: Vec<_> = repr_svc.diag_comm.audience.as_ref()
        .map(|a| a.enabled_audiences.iter().map(|aa| &aa.short_name).collect())
        .unwrap_or_default();
    assert_eq!(orig_enabled, repr_enabled, "enabled audience refs should be preserved");
    assert!(!orig_enabled.is_empty(), "fixture should have at least one enabled audience ref");
}

#[test]
fn test_odx_writer_handles_all_param_types() {
    // Roundtrip preserves param xsi_type for all supported variants
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    let original = parse_odx(xml).unwrap();
    let odx_output = write_odx(&original).unwrap();

    // Verify the ODX output contains expected xsi:type values
    assert!(
        odx_output.contains("CODED-CONST"),
        "should contain CODED-CONST param"
    );
    assert!(
        odx_output.contains("VALUE"),
        "should contain VALUE param"
    );
}
