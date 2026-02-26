//! Lossless roundtrip tests for all supported format conversions.
//!
//! These tests verify **deep equality** (PartialEq on the full IR tree),
//! not just structural counts. Any field lost during conversion will fail.

use diag_ir::{flatbuffers_to_ir, ir_to_flatbuffers, DiagDatabase};
use diag_odx::{parse_odx, write_odx};
use diag_yaml::{parse_yaml, write_yaml};
use mdd_format::reader::read_mdd_bytes;
use mdd_format::writer::{write_mdd_bytes, WriteOptions};

// ── Fixtures ──────────────────────────────────────────────────────────

fn yaml_ecm() -> &'static str {
    include_str!("../../test-fixtures/yaml/example-ecm.yml")
}
fn yaml_minimal() -> &'static str {
    include_str!("../../test-fixtures/yaml/minimal-ecu.yml")
}
fn yaml_flxc1000() -> &'static str {
    include_str!("../../test-fixtures/yaml/FLXC1000.yml")
}
fn yaml_flxcng1000() -> &'static str {
    include_str!("../../test-fixtures/yaml/FLXCNG1000.yml")
}
fn odx_minimal() -> &'static str {
    include_str!("../../test-fixtures/odx/minimal.odx")
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Deep diff between two databases. Returns a list of differences found.
fn deep_diff(a: &DiagDatabase, b: &DiagDatabase) -> Vec<String> {
    let mut diffs = Vec::new();

    fn summary<T: std::fmt::Debug>(v: &T) -> String {
        let s = format!("{v:?}");
        if s.len() > 200 { format!("{}...", &s[..200]) } else { s }
    }

    macro_rules! cmp {
        ($a:expr, $b:expr, $label:expr) => {
            if $a != $b {
                diffs.push(format!("{}: {:?} != {:?}", $label, summary(&$a), summary(&$b)));
            }
        };
    }

    cmp!(a.ecu_name, b.ecu_name, "ecu_name");
    cmp!(a.version, b.version, "version");
    cmp!(a.revision, b.revision, "revision");
    cmp!(a.metadata, b.metadata, "metadata");
    cmp!(a.variants.len(), b.variants.len(), "variants.len");
    cmp!(a.functional_groups.len(), b.functional_groups.len(), "functional_groups.len");
    cmp!(a.dtcs.len(), b.dtcs.len(), "dtcs.len");
    cmp!(a.memory, b.memory, "memory");
    cmp!(a.type_definitions.len(), b.type_definitions.len(), "type_definitions.len");

    // Per-variant comparison
    for (i, (av, bv)) in a.variants.iter().zip(b.variants.iter()).enumerate() {
        let prefix = format!("variants[{i}]");
        if av.is_base_variant != bv.is_base_variant {
            diffs.push(format!("{prefix}.is_base_variant: {} != {}", av.is_base_variant, bv.is_base_variant));
        }
        if av.diag_layer.short_name != bv.diag_layer.short_name {
            diffs.push(format!("{prefix}.short_name: {:?} != {:?}", av.diag_layer.short_name, bv.diag_layer.short_name));
        }
        if av.diag_layer.diag_services.len() != bv.diag_layer.diag_services.len() {
            diffs.push(format!("{prefix}.diag_services.len: {} != {}", av.diag_layer.diag_services.len(), bv.diag_layer.diag_services.len()));
        }
        if av.diag_layer.state_charts != bv.diag_layer.state_charts {
            diffs.push(format!("{prefix}.state_charts differ"));
            for (k, (asc, bsc)) in av.diag_layer.state_charts.iter().zip(bv.diag_layer.state_charts.iter()).enumerate() {
                if asc != bsc {
                    diffs.push(format!("  state_charts[{k}] ({:?}): {:?} != {:?}", asc.short_name, asc, bsc));
                }
            }
        }
        if av.diag_layer.com_param_refs != bv.diag_layer.com_param_refs {
            diffs.push(format!("{prefix}.com_param_refs differ"));
        }
        if av.diag_layer.funct_classes != bv.diag_layer.funct_classes {
            diffs.push(format!("{prefix}.funct_classes differ"));
        }
        if av.diag_layer.additional_audiences != bv.diag_layer.additional_audiences {
            diffs.push(format!("{prefix}.additional_audiences differ"));
        }
        if av.diag_layer.single_ecu_jobs != bv.diag_layer.single_ecu_jobs {
            diffs.push(format!("{prefix}.single_ecu_jobs differ"));
            for (k, (aj, bj)) in av.diag_layer.single_ecu_jobs.iter().zip(bv.diag_layer.single_ecu_jobs.iter()).enumerate() {
                if aj != bj {
                    diffs.push(format!("  job[{k}] ({:?}): dc={} pc={} ip={} op={} np={}",
                        aj.diag_comm.short_name,
                        aj.diag_comm != bj.diag_comm,
                        aj.prog_codes != bj.prog_codes,
                        aj.input_params != bj.input_params,
                        aj.output_params != bj.output_params,
                        aj.neg_output_params != bj.neg_output_params,
                    ));
                    for (m, (ap, bp)) in aj.input_params.iter().zip(bj.input_params.iter()).enumerate() {
                        if ap != bp {
                            diffs.push(format!("    input[{m}] ({:?}): dop a={} b={}", ap.short_name, ap.dop_base.is_some(), bp.dop_base.is_some()));
                        }
                    }
                }
            }
        }
        if av.diag_layer.sdgs != bv.diag_layer.sdgs {
            let a_sdgs = av.diag_layer.sdgs.as_ref().map(|s| &s.sdgs[..]).unwrap_or(&[]);
            let b_sdgs = bv.diag_layer.sdgs.as_ref().map(|s| &s.sdgs[..]).unwrap_or(&[]);
            diffs.push(format!("{prefix}.sdgs differ (a={}, b={})", a_sdgs.len(), b_sdgs.len()));
            for s in a_sdgs {
                if !b_sdgs.iter().any(|bs| bs.caption_sn == s.caption_sn) {
                    diffs.push(format!("  only in a: {:?}", s.caption_sn));
                }
            }
            for s in b_sdgs {
                if !a_sdgs.iter().any(|as_| as_.caption_sn == s.caption_sn) {
                    diffs.push(format!("  only in b: {:?}", s.caption_sn));
                }
            }
            for (as_, bs) in a_sdgs.iter().zip(b_sdgs.iter()) {
                if as_ != bs {
                    diffs.push(format!("  sdg {:?} a: {:?}", as_.caption_sn, summary(as_)));
                    diffs.push(format!("  sdg {:?} b: {:?}", bs.caption_sn, summary(bs)));
                }
            }
        }

        // Per-service comparison
        for (j, (as_, bs)) in av.diag_layer.diag_services.iter().zip(bv.diag_layer.diag_services.iter()).enumerate() {
            if as_ != bs {
                let svc_prefix = format!("{prefix}.diag_services[{j}] ({:?})", as_.diag_comm.short_name);
                if as_.diag_comm != bs.diag_comm {
                    diffs.push(format!("{svc_prefix}.diag_comm differs"));
                    if as_.diag_comm.funct_classes != bs.diag_comm.funct_classes {
                        diffs.push(format!("  .funct_classes: {:?} != {:?}", as_.diag_comm.funct_classes, bs.diag_comm.funct_classes));
                    }
                    if as_.diag_comm.pre_condition_state_refs != bs.diag_comm.pre_condition_state_refs {
                        diffs.push(format!("  .pre_condition_state_refs differ"));
                    }
                    if as_.diag_comm.state_transition_refs != bs.diag_comm.state_transition_refs {
                        diffs.push(format!("  .state_transition_refs differ"));
                    }
                    if as_.diag_comm.sdgs != bs.diag_comm.sdgs {
                        diffs.push(format!("  .sdgs differ"));
                    }
                }
                if as_.request != bs.request {
                    diffs.push(format!("{svc_prefix}.request differs"));
                }
                if as_.pos_responses != bs.pos_responses {
                    diffs.push(format!("{svc_prefix}.pos_responses differ"));
                    for (r, (ar, br)) in as_.pos_responses.iter().zip(bs.pos_responses.iter()).enumerate() {
                        for (p, (ap, bp)) in ar.params.iter().zip(br.params.iter()).enumerate() {
                            if ap != bp {
                                diffs.push(format!("  resp[{r}].param[{p}] ({:?}) differs", ap.short_name));
                                if ap.specific_data != bp.specific_data {
                                    diffs.push(format!("    specific_data: a={:?}", summary(&ap.specific_data)));
                                    diffs.push(format!("    specific_data: b={:?}", summary(&bp.specific_data)));
                                }
                            }
                        }
                    }
                }
                if as_.neg_responses != bs.neg_responses {
                    diffs.push(format!("{svc_prefix}.neg_responses differ"));
                }
            }
        }
    }

    // DTCs comparison
    for (i, (ad, bd)) in a.dtcs.iter().zip(b.dtcs.iter()).enumerate() {
        if ad != bd {
            diffs.push(format!("dtcs[{i}] ({:?}) differs", ad.short_name));
        }
    }

    // Type definitions comparison
    for (i, (at, bt)) in a.type_definitions.iter().zip(b.type_definitions.iter()).enumerate() {
        if at != bt {
            diffs.push(format!("type_definitions[{i}] ({:?}): {:?} != {:?}", at.name, at, bt));
        }
    }

    diffs
}

/// Assert two databases are deeply equal, printing detailed diffs on failure.
fn assert_lossless(original: &DiagDatabase, roundtripped: &DiagDatabase, label: &str) {
    if original == roundtripped {
        return;
    }
    let diffs = deep_diff(original, roundtripped);
    panic!(
        "\n=== LOSSLESS ROUNDTRIP FAILED: {label} ===\n\
         Found {} difference(s):\n  {}\n\
         ===\n",
        diffs.len(),
        diffs.join("\n  ")
    );
}

// ── YAML -> IR -> YAML -> IR roundtrips ──────────────────────────────

#[test]
fn lossless_yaml_roundtrip_ecm() {
    let db1 = parse_yaml(yaml_ecm()).unwrap();
    let yaml_out = write_yaml(&db1).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    assert_lossless(&db1, &db2, "YAML roundtrip: example-ecm");
}

#[test]
fn lossless_yaml_roundtrip_minimal() {
    let db1 = parse_yaml(yaml_minimal()).unwrap();
    let yaml_out = write_yaml(&db1).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    assert_lossless(&db1, &db2, "YAML roundtrip: minimal-ecu");
}

#[test]
fn lossless_yaml_roundtrip_flxc1000() {
    let db1 = parse_yaml(yaml_flxc1000()).unwrap();
    let yaml_out = write_yaml(&db1).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    assert_lossless(&db1, &db2, "YAML roundtrip: FLXC1000");
}

#[test]
fn lossless_yaml_roundtrip_flxcng1000() {
    let db1 = parse_yaml(yaml_flxcng1000()).unwrap();
    let yaml_out = write_yaml(&db1).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    assert_lossless(&db1, &db2, "YAML roundtrip: FLXCNG1000");
}

// ── ODX -> IR -> ODX -> IR roundtrip ─────────────────────────────────

#[test]
fn lossless_odx_roundtrip_minimal() {
    let db1 = parse_odx(odx_minimal()).unwrap();
    let odx_out = write_odx(&db1).unwrap();
    let db2 = parse_odx(&odx_out).unwrap();
    assert_lossless(&db1, &db2, "ODX roundtrip: minimal");
}

// ── YAML -> IR -> MDD -> IR roundtrips ───────────────────────────────

#[test]
fn lossless_yaml_mdd_roundtrip_ecm() {
    let db1 = parse_yaml(yaml_ecm()).unwrap();
    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    assert_lossless(&db1, &db2, "YAML->MDD->IR: example-ecm");
}

#[test]
fn lossless_yaml_mdd_roundtrip_minimal() {
    let db1 = parse_yaml(yaml_minimal()).unwrap();
    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    assert_lossless(&db1, &db2, "YAML->MDD->IR: minimal-ecu");
}

#[test]
fn lossless_yaml_mdd_roundtrip_flxc1000() {
    let db1 = parse_yaml(yaml_flxc1000()).unwrap();
    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    assert_lossless(&db1, &db2, "YAML->MDD->IR: FLXC1000");
}

#[test]
fn lossless_yaml_mdd_roundtrip_flxcng1000() {
    let db1 = parse_yaml(yaml_flxcng1000()).unwrap();
    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    assert_lossless(&db1, &db2, "YAML->MDD->IR: FLXCNG1000");
}

// ── ODX -> IR -> MDD -> IR roundtrip ─────────────────────────────────

#[test]
fn lossless_odx_mdd_roundtrip_minimal() {
    let db1 = parse_odx(odx_minimal()).unwrap();
    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    assert_lossless(&db1, &db2, "ODX->MDD->IR: minimal");
}

// ── Full pipeline: YAML -> IR -> MDD (binary) -> IR ──────────────────

#[test]
fn lossless_yaml_full_mdd_binary_roundtrip_ecm() {
    let db1 = parse_yaml(yaml_ecm()).unwrap();
    let fbs = ir_to_flatbuffers(&db1);
    let mdd = write_mdd_bytes(&fbs, &WriteOptions::default()).unwrap();
    let (_meta, fbs_back) = read_mdd_bytes(&mdd).unwrap();
    let db2 = flatbuffers_to_ir(&fbs_back).unwrap();
    assert_lossless(&db1, &db2, "YAML->MDD binary->IR: example-ecm");
}

// ── YAML -> IR -> MDD -> IR -> YAML -> IR (double roundtrip) ─────────

#[test]
fn lossless_yaml_double_roundtrip_ecm() {
    let db1 = parse_yaml(yaml_ecm()).unwrap();

    // First roundtrip: YAML -> MDD -> IR
    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();

    // Second roundtrip: IR -> YAML -> IR
    let yaml_out = write_yaml(&db2).unwrap();
    let db3 = parse_yaml(&yaml_out).unwrap();

    assert_lossless(&db1, &db3, "YAML double roundtrip (MDD+YAML): example-ecm");
}

// ── ODX -> IR -> MDD -> IR -> ODX -> IR (double roundtrip) ───────────

#[test]
fn lossless_odx_double_roundtrip_minimal() {
    let db1 = parse_odx(odx_minimal()).unwrap();

    // First roundtrip: ODX -> MDD -> IR
    let fbs = ir_to_flatbuffers(&db1);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();

    // Second roundtrip: IR -> ODX -> IR
    let odx_out = write_odx(&db2).unwrap();
    let db3 = parse_odx(&odx_out).unwrap();

    assert_lossless(&db1, &db3, "ODX double roundtrip (MDD+ODX): minimal");
}

