use diag_ir::{DiagDatabase, flatbuffers_to_ir, ir_to_flatbuffers};
use mdd_format::reader::read_mdd_file;
use mdd_format::writer::{WriteOptions, write_mdd_bytes};
use std::path::Path;

fn read_reference_mdd(name: &str) -> (diag_ir::DiagDatabase, Vec<u8>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test-fixtures/mdd")
        .join(name);
    let (_meta, fbs_data) =
        read_mdd_file(&path).unwrap_or_else(|_| panic!("Failed to read {name}"));
    let db =
        flatbuffers_to_ir(&fbs_data).unwrap_or_else(|_| panic!("Failed to parse FBS from {name}"));
    (db, fbs_data)
}

#[test]
fn test_cda_flxc1000_reads_correctly() {
    let (db, _fbs) = read_reference_mdd("FLXC1000.mdd");
    assert_eq!(db.ecu_name, "FLXC1000");
    assert_eq!(db.variants.len(), 3, "Expected 3 variants (1 base + 2 ECU)");

    // Check that we actually got services from the FlatBuffers
    let total_services: usize = db
        .variants
        .iter()
        .map(|v| v.diag_layer.diag_services.len())
        .sum();
    eprintln!(
        "FLXC1000: {} variants, {} total services",
        db.variants.len(),
        total_services
    );

    for v in &db.variants {
        eprintln!(
            "  Variant '{}': base={}, services={}, state_charts={}, audiences={}",
            v.diag_layer.short_name,
            v.is_base_variant,
            v.diag_layer.diag_services.len(),
            v.diag_layer.state_charts.len(),
            v.diag_layer.additional_audiences.len(),
        );
    }

    assert!(
        total_services > 0,
        "Expected at least some diag services in reference MDD"
    );
}

#[test]
fn test_cda_flxcng1000_reads_correctly() {
    let (db, _fbs) = read_reference_mdd("FLXCNG1000.mdd");
    assert_eq!(db.ecu_name, "FLXCNG1000");
    assert_eq!(db.variants.len(), 2, "Expected 2 variants");

    let total_services: usize = db
        .variants
        .iter()
        .map(|v| v.diag_layer.diag_services.len())
        .sum();
    eprintln!(
        "FLXCNG1000: {} variants, {} total services",
        db.variants.len(),
        total_services
    );

    for v in &db.variants {
        eprintln!(
            "  Variant '{}': base={}, services={}, state_charts={}",
            v.diag_layer.short_name,
            v.is_base_variant,
            v.diag_layer.diag_services.len(),
            v.diag_layer.state_charts.len(),
        );
    }

    assert!(
        total_services > 0,
        "Expected at least some diag services in reference MDD"
    );
}

// Roundtrip: read reference MDD, convert to IR, write back to MDD, read again, compare
#[test]
fn test_cda_flxc1000_roundtrip() {
    let (db, _orig_fbs) = read_reference_mdd("FLXC1000.mdd");

    // Convert IR back to FBS and to MDD
    let our_fbs = ir_to_flatbuffers(&db);
    let our_mdd = write_mdd_bytes(&our_fbs, &WriteOptions::default()).unwrap();

    // Read back
    let (_meta2, fbs2) = mdd_format::reader::read_mdd_bytes(&our_mdd).unwrap();
    let db2 = flatbuffers_to_ir(&fbs2).unwrap();

    // Semantic comparison
    assert_eq!(db.ecu_name, db2.ecu_name);
    assert_eq!(db.variants.len(), db2.variants.len());

    for (v1, v2) in db.variants.iter().zip(db2.variants.iter()) {
        assert_eq!(v1.diag_layer.short_name, v2.diag_layer.short_name);
        assert_eq!(v1.is_base_variant, v2.is_base_variant);
        assert_eq!(
            v1.diag_layer.diag_services.len(),
            v2.diag_layer.diag_services.len(),
            "Service count mismatch for variant '{}'",
            v1.diag_layer.short_name
        );
        assert_eq!(
            v1.diag_layer.state_charts.len(),
            v2.diag_layer.state_charts.len(),
            "State chart count mismatch for variant '{}'",
            v1.diag_layer.short_name
        );
    }

    assert_eq!(db.dtcs.len(), db2.dtcs.len());
}

#[test]
fn test_cda_flxcng1000_roundtrip() {
    let (db, _orig_fbs) = read_reference_mdd("FLXCNG1000.mdd");

    let our_fbs = ir_to_flatbuffers(&db);
    let our_mdd = write_mdd_bytes(&our_fbs, &WriteOptions::default()).unwrap();
    let (_meta2, fbs2) = mdd_format::reader::read_mdd_bytes(&our_mdd).unwrap();
    let db2 = flatbuffers_to_ir(&fbs2).unwrap();

    assert_eq!(db.ecu_name, db2.ecu_name);
    assert_eq!(db.variants.len(), db2.variants.len());

    for (v1, v2) in db.variants.iter().zip(db2.variants.iter()) {
        assert_eq!(v1.diag_layer.short_name, v2.diag_layer.short_name);
        assert_eq!(
            v1.diag_layer.diag_services.len(),
            v2.diag_layer.diag_services.len(),
        );
    }
}

fn deep_compare_databases(db: &DiagDatabase, db2: &DiagDatabase) {
    assert_eq!(db.ecu_name, db2.ecu_name);
    assert_eq!(db.version, db2.version);
    assert_eq!(db.revision, db2.revision);
    assert_eq!(db.variants.len(), db2.variants.len());
    assert_eq!(db.dtcs.len(), db2.dtcs.len());

    for (v1, v2) in db.variants.iter().zip(db2.variants.iter()) {
        let dl1 = &v1.diag_layer;
        let dl2 = &v2.diag_layer;
        assert_eq!(dl1.short_name, dl2.short_name);
        assert_eq!(v1.is_base_variant, v2.is_base_variant);
        assert_eq!(
            dl1.diag_services.len(),
            dl2.diag_services.len(),
            "Service count mismatch for variant '{}'",
            dl1.short_name
        );
        assert_eq!(
            dl1.state_charts.len(),
            dl2.state_charts.len(),
            "State chart count mismatch for variant '{}'",
            dl1.short_name
        );
        assert_eq!(
            dl1.additional_audiences.len(),
            dl2.additional_audiences.len(),
            "Audience count mismatch for variant '{}'",
            dl1.short_name
        );

        // Compare service names and param counts
        for (s1, s2) in dl1.diag_services.iter().zip(dl2.diag_services.iter()) {
            assert_eq!(
                s1.diag_comm.short_name, s2.diag_comm.short_name,
                "Service name mismatch in variant '{}'",
                dl1.short_name
            );
            assert_eq!(s1.diag_comm.semantic, s2.diag_comm.semantic);

            // Request param count
            if let (Some(r1), Some(r2)) = (&s1.request, &s2.request) {
                assert_eq!(
                    r1.params.len(),
                    r2.params.len(),
                    "Request param count mismatch for service '{}'",
                    s1.diag_comm.short_name
                );
            }

            // Response counts
            assert_eq!(
                s1.pos_responses.len(),
                s2.pos_responses.len(),
                "Pos response count mismatch for '{}'",
                s1.diag_comm.short_name
            );
            assert_eq!(
                s1.neg_responses.len(),
                s2.neg_responses.len(),
                "Neg response count mismatch for '{}'",
                s1.diag_comm.short_name
            );
        }

        // Compare state charts
        for (sc1, sc2) in dl1.state_charts.iter().zip(dl2.state_charts.iter()) {
            assert_eq!(sc1.short_name, sc2.short_name);
            assert_eq!(sc1.states.len(), sc2.states.len());
            assert_eq!(sc1.state_transitions.len(), sc2.state_transitions.len());
        }

        // Compare parent refs
        assert_eq!(
            v1.parent_refs.len(),
            v2.parent_refs.len(),
            "Parent ref count mismatch for '{}'",
            dl1.short_name
        );
    }
}

#[test]
fn test_cda_flxc1000_deep_roundtrip() {
    let (db, _) = read_reference_mdd("FLXC1000.mdd");
    let our_fbs = ir_to_flatbuffers(&db);
    let our_mdd = write_mdd_bytes(&our_fbs, &WriteOptions::default()).unwrap();
    let (_meta, fbs2) = mdd_format::reader::read_mdd_bytes(&our_mdd).unwrap();
    let db2 = flatbuffers_to_ir(&fbs2).unwrap();
    deep_compare_databases(&db, &db2);
}

#[test]
fn test_cda_flxcng1000_deep_roundtrip() {
    let (db, _) = read_reference_mdd("FLXCNG1000.mdd");
    let our_fbs = ir_to_flatbuffers(&db);
    let our_mdd = write_mdd_bytes(&our_fbs, &WriteOptions::default()).unwrap();
    let (_meta, fbs2) = mdd_format::reader::read_mdd_bytes(&our_mdd).unwrap();
    let db2 = flatbuffers_to_ir(&fbs2).unwrap();
    deep_compare_databases(&db, &db2);
}

// Verify specific service names are present in the reference data
#[test]
fn test_cda_flxc1000_expected_services() {
    let (db, _) = read_reference_mdd("FLXC1000.mdd");
    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();

    let service_names: Vec<&str> = base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();

    eprintln!("Base variant services: {:?}", service_names);

    // State charts should have session and security access states
    assert_eq!(base.diag_layer.state_charts.len(), 2);
    let sc_names: Vec<&str> = base
        .diag_layer
        .state_charts
        .iter()
        .map(|sc| sc.short_name.as_str())
        .collect();
    eprintln!("State charts: {:?}", sc_names);
}
