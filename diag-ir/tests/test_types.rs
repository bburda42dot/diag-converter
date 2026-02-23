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
