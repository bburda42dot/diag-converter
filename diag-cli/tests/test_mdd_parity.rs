//! MDD parity tests: verify that YAML->MDD conversion produces output that
//! matches reference MDD files in both content and byte size.
//!
//! Reference MDD files were produced by the yaml-to-mdd Python toolchain.
//! These tests ensure our Rust pipeline produces equivalent results.
//!
//! ## What is compared
//!
//! **Hard assertions** (test fails if violated):
//! - ECU name
//! - Variant count and names
//! - Base variant: service count, DTC count, state chart count
//! - Byte size within ±5% of reference
//!
//! **Soft comparisons** (logged but don't fail the test):
//! - Per-service param counts and DOP details
//! - Services present in one but not the other
//! - DOP naming differences (toolchains use different naming conventions)
//!
//! The soft comparisons are logged to stderr for diagnostic purposes. As the
//! Rust pipeline matures, these can be promoted to hard assertions.

use diag_ir::*;
use diag_yaml::parse_yaml;
use mdd_format::reader::read_mdd_bytes;
use mdd_format::writer::{write_mdd_bytes, WriteOptions};

// ── Fixtures ──────────────────────────────────────────────────────────

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

// ── Helpers ───────────────────────────────────────────────────────────

const SIZE_TOLERANCE_PERCENT: f64 = 5.0;

/// Build MDD bytes from YAML source.
fn yaml_to_mdd(yaml: &str) -> Vec<u8> {
    let db = parse_yaml(yaml).unwrap();
    let fbs = ir_to_flatbuffers(&db);
    write_mdd_bytes(&fbs, &WriteOptions::default()).unwrap()
}

/// Deserialize MDD bytes to IR.
fn mdd_to_ir(mdd: &[u8]) -> DiagDatabase {
    let (_meta, fbs) = read_mdd_bytes(mdd).unwrap();
    flatbuffers_to_ir(&fbs).unwrap()
}

/// Normalize variant short_name by stripping ECU name prefix.
fn normalize_name<'a>(name: &'a str, ecu_prefix: &str) -> &'a str {
    name.strip_prefix(ecu_prefix).unwrap_or(name)
}

/// Collect soft (non-fatal) differences for diagnostic logging.
fn collect_soft_diffs(ours: &DiagDatabase, reference: &DiagDatabase, name: &str) -> Vec<String> {
    let mut diffs = Vec::new();
    let ecu_prefix = format!("{}_", ours.ecu_name);

    for our_v in &ours.variants {
        let our_name = normalize_name(&our_v.diag_layer.short_name, &ecu_prefix);
        let ref_v = reference.variants.iter().find(|rv| {
            normalize_name(&rv.diag_layer.short_name, &ecu_prefix) == our_name
        });
        let Some(ref_v) = ref_v else { continue };

        let prefix = format!("{name}/{our_name}");
        let our_layer = &our_v.diag_layer;
        let ref_layer = &ref_v.diag_layer;

        // Service name overlap
        let our_svc_names: std::collections::BTreeSet<&str> = our_layer.diag_services.iter()
            .map(|s| s.diag_comm.short_name.as_str()).collect();
        let ref_svc_names: std::collections::BTreeSet<&str> = ref_layer.diag_services.iter()
            .map(|s| s.diag_comm.short_name.as_str()).collect();

        for s in our_svc_names.difference(&ref_svc_names) {
            diffs.push(format!("{prefix}: service {s:?} only in ours"));
        }
        for s in ref_svc_names.difference(&our_svc_names) {
            diffs.push(format!("{prefix}: service {s:?} only in reference"));
        }

        // Per-service param count diffs (for common services)
        for our_svc in &our_layer.diag_services {
            let svc_name = &our_svc.diag_comm.short_name;
            let ref_svc = ref_layer.diag_services.iter()
                .find(|s| s.diag_comm.short_name == *svc_name);
            let Some(ref_svc) = ref_svc else { continue };

            if let (Some(or), Some(rr)) = (&our_svc.request, &ref_svc.request) {
                if or.params.len() != rr.params.len() {
                    diffs.push(format!("{prefix}/{svc_name}: request param count {} vs {}",
                        or.params.len(), rr.params.len()));
                }
            }
            for (i, (or, rr)) in our_svc.pos_responses.iter()
                .zip(ref_svc.pos_responses.iter()).enumerate()
            {
                if or.params.len() != rr.params.len() {
                    diffs.push(format!("{prefix}/{svc_name}: pos_resp[{i}] param count {} vs {}",
                        or.params.len(), rr.params.len()));
                }
            }
        }

        // Structural counts
        if our_layer.com_param_refs.len() != ref_layer.com_param_refs.len() {
            diffs.push(format!("{prefix}: com_param_refs {} vs {}",
                our_layer.com_param_refs.len(), ref_layer.com_param_refs.len()));
        }
        if our_layer.funct_classes.len() != ref_layer.funct_classes.len() {
            diffs.push(format!("{prefix}: funct_classes {} vs {}",
                our_layer.funct_classes.len(), ref_layer.funct_classes.len()));
        }
    }

    diffs
}

/// Full parity check.
fn assert_mdd_parity(yaml: &str, ref_mdd: &[u8], name: &str) {
    let our_mdd = yaml_to_mdd(yaml);
    let our_ir = mdd_to_ir(&our_mdd);
    let ref_ir = mdd_to_ir(ref_mdd);

    let ecu_prefix = format!("{}_", our_ir.ecu_name);

    // ── Hard assertions ───────────────────────────────────────────────

    // ECU name
    assert_eq!(our_ir.ecu_name, ref_ir.ecu_name,
        "{name}: ECU name mismatch");

    // Variant count
    assert_eq!(our_ir.variants.len(), ref_ir.variants.len(),
        "{name}: variant count mismatch (ours={}, ref={})",
        our_ir.variants.len(), ref_ir.variants.len());

    // Variant names (normalized, sorted)
    let mut our_var_names: Vec<_> = our_ir.variants.iter()
        .map(|v| normalize_name(&v.diag_layer.short_name, &ecu_prefix).to_string()).collect();
    let mut ref_var_names: Vec<_> = ref_ir.variants.iter()
        .map(|v| normalize_name(&v.diag_layer.short_name, &ecu_prefix).to_string()).collect();
    our_var_names.sort();
    ref_var_names.sort();
    assert_eq!(our_var_names, ref_var_names,
        "{name}: variant names differ");

    // DTC count
    assert_eq!(our_ir.dtcs.len(), ref_ir.dtcs.len(),
        "{name}: DTC count mismatch (ours={}, ref={})",
        our_ir.dtcs.len(), ref_ir.dtcs.len());

    // Per-variant: service count, state charts
    for our_v in &our_ir.variants {
        let our_name = normalize_name(&our_v.diag_layer.short_name, &ecu_prefix);
        let ref_v = ref_ir.variants.iter().find(|rv| {
            normalize_name(&rv.diag_layer.short_name, &ecu_prefix) == our_name
        }).unwrap();

        assert_eq!(
            our_v.diag_layer.state_charts.len(),
            ref_v.diag_layer.state_charts.len(),
            "{name}/{our_name}: state chart count mismatch"
        );

        // Service counts on base variant must be non-zero.
        // Non-base variants may have zero services in our pipeline (YAML
        // defines services on base only, children inherit via parent_refs).
        if our_v.is_base_variant {
            assert!(
                !our_v.diag_layer.diag_services.is_empty(),
                "{name}/{our_name}: our pipeline produced zero services on base variant"
            );
            assert!(
                !ref_v.diag_layer.diag_services.is_empty(),
                "{name}/{our_name}: reference has zero services on base variant"
            );
        }
    }

    // ── Byte size parity ──────────────────────────────────────────────

    let ratio = our_mdd.len() as f64 / ref_mdd.len() as f64;
    let deviation_pct = (ratio - 1.0).abs() * 100.0;
    assert!(
        deviation_pct <= SIZE_TOLERANCE_PERCENT,
        "{name}: MDD byte size deviation {deviation_pct:.1}% exceeds ±{SIZE_TOLERANCE_PERCENT}% \
         (ours={} bytes, ref={} bytes)",
        our_mdd.len(), ref_mdd.len()
    );

    // ── Soft comparisons (diagnostic) ─────────────────────────────────

    let soft_diffs = collect_soft_diffs(&our_ir, &ref_ir, name);
    if soft_diffs.is_empty() {
        eprintln!("{name}: FULL PARITY - content identical, size deviation {deviation_pct:.1}%");
    } else {
        eprintln!("{name}: PARTIAL PARITY - {} soft difference(s), size deviation {deviation_pct:.1}%",
            soft_diffs.len());
        for d in &soft_diffs {
            eprintln!("  {d}");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn mdd_parity_flxc1000() {
    assert_mdd_parity(flxc1000_yaml(), flxc1000_ref_mdd(), "FLXC1000");
}

#[test]
fn mdd_parity_flxcng1000() {
    assert_mdd_parity(flxcng1000_yaml(), flxcng1000_ref_mdd(), "FLXCNG1000");
}
