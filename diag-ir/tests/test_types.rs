use diag_ir::*;

#[test]
fn test_empty_database_is_valid() {
    let db = DiagDatabase::default();
    assert!(validate_database(&db).is_ok());
}

#[test]
fn test_database_with_variant_validates() {
    let db = DiagDatabase {
        ecu_name: "TestECU".into(),
        version: "1.0".into(),
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "BaseVariant".into(),
                long_name: None,
                funct_classes: vec![],
                com_param_refs: vec![],
                diag_services: vec![],
                single_ecu_jobs: vec![],
                state_charts: vec![],
                additional_audiences: vec![],
                sdgs: None,
            },
            is_base_variant: true,
            variant_patterns: vec![],
            parent_refs: vec![],
        }],
        ..Default::default()
    };
    assert!(validate_database(&db).is_ok());
}

#[test]
fn test_duplicate_service_name_detected() {
    let svc = || DiagService {
        diag_comm: DiagComm {
            short_name: "ReadDID".into(),
            long_name: None,
            semantic: String::new(),
            funct_classes: vec![],
            sdgs: None,
            diag_class_type: DiagClassType::StartComm,
            pre_condition_state_refs: vec![],
            state_transition_refs: vec![],
            protocols: vec![],
            audience: None,
            is_mandatory: false,
            is_executable: true,
            is_final: false,
        },
        request: None,
        pos_responses: vec![],
        neg_responses: vec![],
        is_cyclic: false,
        is_multiple: false,
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        com_param_refs: vec![],
    };

    let db = DiagDatabase {
        ecu_name: "TestECU".into(),
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "Var1".into(),
                long_name: None,
                funct_classes: vec![],
                com_param_refs: vec![],
                diag_services: vec![svc(), svc()], // duplicate "ReadDID"
                single_ecu_jobs: vec![],
                state_charts: vec![],
                additional_audiences: vec![],
                sdgs: None,
            },
            is_base_variant: false,
            variant_patterns: vec![],
            parent_refs: vec![],
        }],
        ..Default::default()
    };
    let result = validate_database(&db);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].to_string().contains("ReadDID"),
        "error should mention the duplicate service name"
    );
}

#[test]
fn test_compu_method_constructs_correctly() {
    let cm = CompuMethod {
        category: CompuCategory::Linear,
        internal_to_phys: Some(CompuInternalToPhys {
            compu_scales: vec![CompuScale {
                short_label: None,
                lower_limit: Some(Limit {
                    value: "0".into(),
                    interval_type: IntervalType::Closed,
                }),
                upper_limit: Some(Limit {
                    value: "255".into(),
                    interval_type: IntervalType::Closed,
                }),
                inverse_values: None,
                consts: None,
                rational_co_effs: None,
            }],
            prog_code: None,
            compu_default_value: None,
        }),
        phys_to_internal: None,
    };
    assert_eq!(cm.category, CompuCategory::Linear);
    assert_eq!(cm.internal_to_phys.unwrap().compu_scales.len(), 1);
}

#[test]
fn test_empty_service_name_detected() {
    let db = DiagDatabase {
        ecu_name: "TEST".into(),
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "Base".into(),
                diag_services: vec![DiagService::default()], // empty short_name
                ..Default::default()
            },
            is_base_variant: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let errors = validate_database(&db).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.to_string().contains("empty service name")),
        "should detect empty service name: {:?}",
        errors
    );
}

#[test]
fn test_duplicate_dtc_id_detected() {
    let db = DiagDatabase {
        ecu_name: "TEST".into(),
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "Base".into(),
                diag_services: vec![DiagService {
                    diag_comm: DiagComm {
                        short_name: "Svc".into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            is_base_variant: true,
            ..Default::default()
        }],
        dtcs: vec![
            Dtc {
                short_name: "DTC_A".into(),
                trouble_code: 0x123456,
                ..Default::default()
            },
            Dtc {
                short_name: "DTC_B".into(),
                trouble_code: 0x123456,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let errors = validate_database(&db).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.to_string().contains("duplicate DTC")),
        "should detect duplicate DTC ID: {:?}",
        errors
    );
}

#[test]
fn test_empty_state_chart_detected() {
    let db = DiagDatabase {
        ecu_name: "TEST".into(),
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "Base".into(),
                diag_services: vec![DiagService {
                    diag_comm: DiagComm {
                        short_name: "Svc".into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                state_charts: vec![StateChart {
                    short_name: "EmptyChart".into(),
                    semantic: String::new(),
                    state_transitions: vec![],
                    start_state_short_name_ref: String::new(),
                    states: vec![],
                }],
                ..Default::default()
            },
            is_base_variant: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let errors = validate_database(&db).unwrap_err();
    assert!(
        errors.iter().any(|e| e.to_string().contains("EmptyChart")),
        "should detect empty state chart: {:?}",
        errors
    );
}

#[test]
fn test_duplicate_dtc_detected_without_base_variant() {
    let db = DiagDatabase {
        ecu_name: "TEST".into(),
        variants: vec![Variant {
            is_base_variant: false,
            diag_layer: DiagLayer {
                short_name: "EcuVar".into(),
                ..Default::default()
            },
            ..Default::default()
        }],
        dtcs: vec![
            Dtc {
                short_name: "P0001".into(),
                trouble_code: 1,
                ..Default::default()
            },
            Dtc {
                short_name: "P0001_dup".into(),
                trouble_code: 1, // same code = duplicate
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let result = validate_database(&db);
    assert!(
        result.is_err(),
        "duplicate DTC IDs should be caught even without base variants"
    );
}
