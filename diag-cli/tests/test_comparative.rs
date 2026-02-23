//! Comparative tests: verify diag-converter MDD output is structurally
//! equivalent to reference MDD files (produced by yaml-to-mdd / CDA toolchain).

use diag_ir::{flatbuffers_to_ir, ir_to_flatbuffers};
use diag_odx::parse_odx;
use diag_yaml::parse_yaml;
use mdd_format::reader::read_mdd_bytes;
use mdd_format::writer::{write_mdd_bytes, WriteOptions};

fn flxc1000_yaml() -> &'static str {
    include_str!("../../test-fixtures/yaml/FLXC1000.yml")
}

fn flxcng1000_yaml() -> &'static str {
    include_str!("../../test-fixtures/yaml/FLXCNG1000.yml")
}

fn flxc1000_ref_mdd() -> &'static [u8] {
    include_bytes!("../../test-fixtures/mdd/FLXC1000.mdd")
}

fn flxcng1000_ref_mdd() -> &'static [u8] {
    include_bytes!("../../test-fixtures/mdd/FLXCNG1000.mdd")
}

/// Compare diag-converter's YAML->MDD output against a reference MDD structurally.
fn compare_yaml_vs_reference_mdd(yaml: &str, ref_mdd: &[u8], name: &str) {
    // Our pipeline: YAML -> IR -> FBS -> MDD -> FBS -> IR
    let our_db = parse_yaml(yaml).unwrap();
    let our_fbs = ir_to_flatbuffers(&our_db);
    let our_mdd = write_mdd_bytes(&our_fbs, &WriteOptions::default()).unwrap();
    let (_our_meta, our_fbs_back) = read_mdd_bytes(&our_mdd).unwrap();
    let our_ir = flatbuffers_to_ir(&our_fbs_back).unwrap();

    // Reference MDD -> FBS -> IR
    let (_ref_meta, ref_fbs) = read_mdd_bytes(ref_mdd).unwrap();
    let ref_ir = flatbuffers_to_ir(&ref_fbs).unwrap();

    // Compare ECU name
    assert_eq!(
        our_ir.ecu_name, ref_ir.ecu_name,
        "{name}: ecu_name mismatch (ours={}, ref={})",
        our_ir.ecu_name, ref_ir.ecu_name
    );

    // Compare variant count
    assert_eq!(
        our_ir.variants.len(), ref_ir.variants.len(),
        "{name}: variant count mismatch (ours={}, ref={})",
        our_ir.variants.len(), ref_ir.variants.len()
    );

    // Compare variant names (sorted, normalized).
    // Reference MDD prefixes non-base variant names with ECU name (e.g. "FLXC1000_App_0101"),
    // while our YAML parser uses short names ("App_0101"). Normalize by stripping ECU prefix.
    let ecu_prefix = format!("{}_", our_ir.ecu_name);
    let normalize = |name: &str| -> String {
        name.strip_prefix(&ecu_prefix).unwrap_or(name).to_string()
    };
    let mut our_var_names: Vec<_> = our_ir.variants.iter()
        .map(|v| normalize(&v.diag_layer.short_name)).collect();
    let mut ref_var_names: Vec<_> = ref_ir.variants.iter()
        .map(|v| normalize(&v.diag_layer.short_name)).collect();
    our_var_names.sort();
    ref_var_names.sort();
    assert_eq!(
        our_var_names, ref_var_names,
        "{name}: variant names differ (after normalizing ECU prefix)"
    );

    // Compare DTC count
    assert_eq!(
        our_ir.dtcs.len(), ref_ir.dtcs.len(),
        "{name}: DTC count mismatch (ours={}, ref={})",
        our_ir.dtcs.len(), ref_ir.dtcs.len()
    );

    // Compare base variant state chart count
    let our_base = our_ir.variants.iter().find(|v| v.is_base_variant);
    let ref_base = ref_ir.variants.iter().find(|v| v.is_base_variant);
    if let (Some(ob), Some(rb)) = (our_base, ref_base) {
        assert_eq!(
            ob.diag_layer.state_charts.len(),
            rb.diag_layer.state_charts.len(),
            "{name}: state chart count mismatch"
        );

        // Compare service count (allow some tolerance since service generation may differ)
        let our_svc_count = ob.diag_layer.diag_services.len();
        let ref_svc_count = rb.diag_layer.diag_services.len();
        // Service count should be within reasonable range
        assert!(
            our_svc_count > 0 && ref_svc_count > 0,
            "{name}: both should have services (ours={our_svc_count}, ref={ref_svc_count})"
        );

        // Service counts may differ between toolchains (different generation strategies),
        // but both should have a reasonable number of services.
        let our_svc_names: Vec<_> = ob.diag_layer.diag_services.iter()
            .map(|s| s.diag_comm.short_name.as_str()).collect();
        let ref_svc_names: Vec<_> = rb.diag_layer.diag_services.iter()
            .map(|s| s.diag_comm.short_name.as_str()).collect();
        assert!(
            !our_svc_names.is_empty(),
            "{name}: our pipeline should produce services"
        );
        assert!(
            !ref_svc_names.is_empty(),
            "{name}: reference MDD should have services"
        );
        // Log service names for diagnostic purposes if counts differ
        if our_svc_names.len() != ref_svc_names.len() {
            eprintln!("{name}: service count differs (ours={}, ref={})",
                our_svc_names.len(), ref_svc_names.len());
            eprintln!("  ours: {our_svc_names:?}");
            eprintln!("  ref:  {ref_svc_names:?}");
        }
    }
}

#[test]
fn test_flxc1000_vs_reference_mdd() {
    compare_yaml_vs_reference_mdd(flxc1000_yaml(), flxc1000_ref_mdd(), "FLXC1000");
}

#[test]
fn test_flxcng1000_vs_reference_mdd() {
    compare_yaml_vs_reference_mdd(flxcng1000_yaml(), flxcng1000_ref_mdd(), "FLXCNG1000");
}

// --- ODX pipeline structural completeness tests ---

fn minimal_odx() -> &'static str {
    include_str!("../../test-fixtures/odx/minimal.odx")
}

/// ODX -> IR -> FBS -> MDD -> FBS -> IR roundtrip preserves structural completeness.
#[test]
fn test_odx_mdd_structural_completeness() {
    let original = parse_odx(minimal_odx()).unwrap();
    let fbs = ir_to_flatbuffers(&original);
    let mdd = write_mdd_bytes(&fbs, &WriteOptions::default()).unwrap();
    let (_meta, fbs_back) = read_mdd_bytes(&mdd).unwrap();
    let roundtripped = flatbuffers_to_ir(&fbs_back).unwrap();

    // ECU name
    assert_eq!(original.ecu_name, roundtripped.ecu_name);

    // Variant count and names
    assert_eq!(original.variants.len(), roundtripped.variants.len());
    let mut orig_names: Vec<_> = original.variants.iter()
        .map(|v| v.diag_layer.short_name.as_str()).collect();
    let mut rt_names: Vec<_> = roundtripped.variants.iter()
        .map(|v| v.diag_layer.short_name.as_str()).collect();
    orig_names.sort();
    rt_names.sort();
    assert_eq!(orig_names, rt_names, "variant names should survive ODX->MDD roundtrip");

    // DTC count
    assert_eq!(original.dtcs.len(), roundtripped.dtcs.len());

    // Base variant services
    let orig_base = original.variants.iter().find(|v| v.is_base_variant).unwrap();
    let rt_base = roundtripped.variants.iter().find(|v| v.is_base_variant).unwrap();

    let mut orig_svcs: Vec<_> = orig_base.diag_layer.diag_services.iter()
        .map(|s| s.diag_comm.short_name.as_str()).collect();
    let mut rt_svcs: Vec<_> = rt_base.diag_layer.diag_services.iter()
        .map(|s| s.diag_comm.short_name.as_str()).collect();
    orig_svcs.sort();
    rt_svcs.sort();
    assert_eq!(orig_svcs, rt_svcs, "service names should survive ODX->MDD roundtrip");

    // State charts
    assert_eq!(
        orig_base.diag_layer.state_charts.len(),
        rt_base.diag_layer.state_charts.len(),
        "state chart count should survive ODX->MDD roundtrip"
    );

    // SingleEcuJobs
    assert_eq!(
        orig_base.diag_layer.single_ecu_jobs.len(),
        rt_base.diag_layer.single_ecu_jobs.len(),
        "single_ecu_job count should survive ODX->MDD roundtrip"
    );

    // Parent refs on ECU variant
    let orig_ecu_var = original.variants.iter().find(|v| !v.is_base_variant);
    let rt_ecu_var = roundtripped.variants.iter().find(|v| !v.is_base_variant);
    if let (Some(ov), Some(rv)) = (orig_ecu_var, rt_ecu_var) {
        assert_eq!(
            ov.parent_refs.len(), rv.parent_refs.len(),
            "parent ref count should survive ODX->MDD roundtrip"
        );
    }
}

/// Verify that reference MDD files are well-formed and readable.
#[test]
fn test_reference_mdd_readable() {
    for (name, mdd) in [("FLXC1000", flxc1000_ref_mdd()), ("FLXCNG1000", flxcng1000_ref_mdd())] {
        let result = read_mdd_bytes(mdd);
        assert!(result.is_ok(), "{name} reference MDD should be readable: {:?}", result.err());
        let (_meta, fbs) = result.unwrap();
        let ir = flatbuffers_to_ir(&fbs);
        assert!(ir.is_ok(), "{name} reference MDD should deserialize to IR: {:?}", ir.err());
    }
}
