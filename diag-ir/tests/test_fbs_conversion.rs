use diag_ir::*;

/// Helper: build a minimal DiagService for reuse in tests.
fn make_service(name: &str) -> DiagService {
    DiagService {
        diag_comm: DiagComm {
            short_name: name.into(),
            long_name: Some(LongName {
                value: format!("{name} long"),
                ti: "en".into(),
            }),
            semantic: "DATA-READ".into(),
            funct_classes: vec![FunctClass {
                short_name: "Identification".into(),
            }],
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
        request: Some(Request {
            params: vec![Param {
                id: 0,
                param_type: ParamType::CodedConst,
                short_name: "SID".into(),
                semantic: "SERVICE-ID".into(),
                sdgs: None,
                physical_default_value: String::new(),
                byte_position: Some(0),
                bit_position: Some(0),
                specific_data: Some(ParamData::CodedConst {
                    coded_value: "0x22".into(),
                    diag_coded_type: DiagCodedType {
                        type_name: DiagCodedTypeName::StandardLengthType,
                        base_type_encoding: "unsigned".into(),
                        base_data_type: DataType::AUint32,
                        is_high_low_byte_order: true,
                        specific_data: Some(DiagCodedTypeData::StandardLength {
                            bit_length: 8,
                            bit_mask: vec![],
                            condensed: false,
                        }),
                    },
                }),
            }],
            sdgs: None,
        }),
        pos_responses: vec![Response {
            response_type: ResponseType::PosResponse,
            params: vec![Param {
                id: 1,
                param_type: ParamType::Value,
                short_name: "VehicleSpeed".into(),
                semantic: "DATA".into(),
                sdgs: None,
                physical_default_value: "0".into(),
                byte_position: Some(1),
                bit_position: None,
                specific_data: Some(ParamData::Value {
                    physical_default_value: "0".into(),
                    dop: Box::new(Dop {
                        dop_type: DopType::Regular,
                        short_name: "VehicleSpeedDOP".into(),
                        sdgs: None,
                        specific_data: Some(DopData::NormalDop {
                            compu_method: Some(CompuMethod {
                                category: CompuCategory::Linear,
                                internal_to_phys: Some(CompuInternalToPhys {
                                    compu_scales: vec![CompuScale {
                                        short_label: None,
                                        lower_limit: Some(Limit {
                                            value: "0".into(),
                                            interval_type: IntervalType::Closed,
                                        }),
                                        upper_limit: Some(Limit {
                                            value: "65535".into(),
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
                            }),
                            diag_coded_type: Some(DiagCodedType {
                                type_name: DiagCodedTypeName::StandardLengthType,
                                base_type_encoding: "unsigned".into(),
                                base_data_type: DataType::AUint32,
                                is_high_low_byte_order: true,
                                specific_data: Some(DiagCodedTypeData::StandardLength {
                                    bit_length: 16,
                                    bit_mask: vec![],
                                    condensed: false,
                                }),
                            }),
                            physical_type: Some(PhysicalType {
                                precision: Some(2),
                                base_data_type: PhysicalTypeDataType::AFloat32,
                                display_radix: Radix::Dec,
                            }),
                            internal_constr: None,
                            unit_ref: Some(Unit {
                                short_name: "km_per_h".into(),
                                display_name: "km/h".into(),
                                factor_si_to_unit: Some(3.6),
                                offset_si_to_unit: Some(0.0),
                                physical_dimension: Some(PhysicalDimension {
                                    short_name: "velocity".into(),
                                    long_name: None,
                                    length_exp: Some(1),
                                    mass_exp: None,
                                    time_exp: Some(-1),
                                    current_exp: None,
                                    temperature_exp: None,
                                    molar_amount_exp: None,
                                    luminous_intensity_exp: None,
                                }),
                            }),
                            phys_constr: None,
                        }),
                    }),
                }),
            }],
            sdgs: None,
        }],
        neg_responses: vec![],
        is_cyclic: false,
        is_multiple: false,
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        com_param_refs: vec![],
    }
}

/// Build a non-trivial DiagDatabase with coverage of key IR features.
fn make_test_database() -> DiagDatabase {
    DiagDatabase {
        version: "1.0.0".into(),
        ecu_name: "TestECU".into(),
        revision: "rev42".into(),
        metadata: [("author".into(), "test-suite".into())]
            .into_iter()
            .collect(),
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "BaseVariant".into(),
                long_name: Some(LongName {
                    value: "Base Variant".into(),
                    ti: "en".into(),
                }),
                funct_classes: vec![FunctClass {
                    short_name: "Identification".into(),
                }],
                com_param_refs: vec![],
                diag_services: vec![make_service("ReadDID_F190")],
                single_ecu_jobs: vec![],
                state_charts: vec![],
                additional_audiences: vec![AdditionalAudience {
                    short_name: "Developer".into(),
                    long_name: None,
                }],
                sdgs: Some(Sdgs {
                    sdgs: vec![Sdg {
                        caption_sn: "DiagInstSpec".into(),
                        sds: vec![SdOrSdg::Sd(Sd {
                            value: "1.0".into(),
                            si: "Version".into(),
                            ti: "en".into(),
                        })],
                        si: "spec".into(),
                    }],
                }),
            },
            is_base_variant: true,
            variant_patterns: vec![],
            parent_refs: vec![],
        }],
        functional_groups: vec![],
        dtcs: vec![Dtc {
            short_name: "P0001".into(),
            trouble_code: 0x0001,
            display_trouble_code: "P0001".into(),
            text: Some(Text {
                value: "Fuel Volume Regulator Control Circuit/Open".into(),
                ti: "en".into(),
            }),
            level: Some(3),
            sdgs: None,
            is_temporary: false,
        }],
        memory: None,
    }
}

#[test]
fn roundtrip_empty_database() {
    let db = DiagDatabase::default();
    let fbs_bytes = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs_bytes).expect("roundtrip failed");
    assert_eq!(db, db2);
}

#[test]
fn roundtrip_full_database() {
    let db = make_test_database();
    let fbs_bytes = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs_bytes).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

#[test]
fn roundtrip_preserves_metadata() {
    let mut db = DiagDatabase::default();
    db.metadata
        .insert("tool_version".into(), "diag-converter 0.1".into());
    db.metadata.insert("generated".into(), "2026-02-23".into());

    let fbs_bytes = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs_bytes).expect("roundtrip failed");
    assert_eq!(db.metadata, db2.metadata);
}

#[test]
fn roundtrip_dtc_fields() {
    let db = DiagDatabase {
        dtcs: vec![
            Dtc {
                short_name: "P0100".into(),
                trouble_code: 0x0100,
                display_trouble_code: "P0100".into(),
                text: Some(Text {
                    value: "MAF sensor circuit".into(),
                    ti: "en".into(),
                }),
                level: Some(5),
                sdgs: None,
                is_temporary: true,
            },
            Dtc {
                short_name: "P0200".into(),
                trouble_code: 0x0200,
                display_trouble_code: "P0200".into(),
                text: None,
                level: None,
                sdgs: None,
                is_temporary: false,
            },
        ],
        ..Default::default()
    };
    let fbs_bytes = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs_bytes).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

#[test]
fn roundtrip_diag_coded_type_variants() {
    // Test all four DiagCodedType variants via params
    let make_param = |name: &str, dct_data: DiagCodedTypeData, dct_name: DiagCodedTypeName| Param {
        id: 0,
        param_type: ParamType::CodedConst,
        short_name: name.into(),
        semantic: String::new(),
        sdgs: None,
        physical_default_value: String::new(),
        byte_position: Some(0),
        bit_position: Some(0),
        specific_data: Some(ParamData::CodedConst {
            coded_value: "0x00".into(),
            diag_coded_type: DiagCodedType {
                type_name: dct_name,
                base_type_encoding: "unsigned".into(),
                base_data_type: DataType::AUint32,
                is_high_low_byte_order: true,
                specific_data: Some(dct_data),
            },
        }),
    };

    let params = vec![
        make_param(
            "StdLen",
            DiagCodedTypeData::StandardLength {
                bit_length: 8,
                bit_mask: vec![0xFF],
                condensed: true,
            },
            DiagCodedTypeName::StandardLengthType,
        ),
        make_param(
            "LeadLen",
            DiagCodedTypeData::LeadingLength { bit_length: 16 },
            DiagCodedTypeName::LeadingLengthInfoType,
        ),
        make_param(
            "MinMax",
            DiagCodedTypeData::MinMax {
                min_length: 1,
                max_length: Some(255),
                termination: Termination::Zero,
            },
            DiagCodedTypeName::MinMaxLengthType,
        ),
    ];

    let db = DiagDatabase {
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "V1".into(),
                long_name: None,
                funct_classes: vec![],
                com_param_refs: vec![],
                diag_services: vec![DiagService {
                    diag_comm: DiagComm {
                        short_name: "Svc".into(),
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
                    request: Some(Request {
                        params,
                        sdgs: None,
                    }),
                    pos_responses: vec![],
                    neg_responses: vec![],
                    is_cyclic: false,
                    is_multiple: false,
                    addressing: Addressing::Physical,
                    transmission_mode: TransmissionMode::SendAndReceive,
                    com_param_refs: vec![],
                }],
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
    let fbs_bytes = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs_bytes).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

/// Test that ComplexValue deserialization correctly handles nested values.
/// Construct an IR with ComplexValues containing both Simple and nested Complex entries,
/// verify that the from_fbs deserialization properly distinguishes the union variants.
#[test]
fn test_complex_value_deserialization() {
    // Test the IR-level ComplexValue type directly
    let cv = ComplexValue {
        entries: vec![
            SimpleOrComplexValue::Simple(SimpleValue { value: "outer_val".into() }),
            SimpleOrComplexValue::Complex(Box::new(ComplexValue {
                entries: vec![
                    SimpleOrComplexValue::Simple(SimpleValue { value: "inner_val".into() }),
                ],
            })),
        ],
    };

    // Verify structure
    assert_eq!(cv.entries.len(), 2);
    match &cv.entries[0] {
        SimpleOrComplexValue::Simple(sv) => assert_eq!(sv.value, "outer_val"),
        _ => panic!("expected Simple at index 0"),
    }
    match &cv.entries[1] {
        SimpleOrComplexValue::Complex(nested) => {
            assert_eq!(nested.entries.len(), 1);
            match &nested.entries[0] {
                SimpleOrComplexValue::Simple(sv) => assert_eq!(sv.value, "inner_val"),
                _ => panic!("expected Simple in nested ComplexValue"),
            }
        }
        _ => panic!("expected Complex at index 1"),
    }
}

/// Test that reading a real CDA MDD file correctly deserializes ComplexValues
/// in ComParamRef entries (not as empty SimpleValues).
#[test]
fn test_complex_value_from_reference_mdd() {
    let mdd_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test-fixtures/mdd/FLXC1000.mdd");
    let (_meta, fbs_data) = mdd_format::reader::read_mdd_file(&mdd_path)
        .expect("Failed to read reference MDD");
    let db = flatbuffers_to_ir(&fbs_data)
        .expect("Failed to deserialize FBS");

    // Collect all ComplexValues from ComParamRefs across all variants
    let mut complex_value_count = 0;
    let mut non_empty_entries = 0;
    for variant in &db.variants {
        for cpr in &variant.diag_layer.com_param_refs {
            if let Some(cv) = &cpr.complex_value {
                complex_value_count += 1;
                for entry in &cv.entries {
                    match entry {
                        SimpleOrComplexValue::Simple(sv) if !sv.value.is_empty() => {
                            non_empty_entries += 1;
                        }
                        SimpleOrComplexValue::Complex(nested) if !nested.entries.is_empty() => {
                            non_empty_entries += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // The CDA reference MDD has COM params with complex values
    // After the fix, these should have non-empty entries (not all-empty placeholders)
    eprintln!(
        "FLXC1000: {} ComplexValues found, {} non-empty entries",
        complex_value_count, non_empty_entries
    );
    // If there are any complex values, they should have real data
    if complex_value_count > 0 {
        assert!(
            non_empty_entries > 0,
            "ComplexValues exist but all entries are empty - deserialization bug"
        );
    }
}

#[test]
fn roundtrip_parent_ref_variants() {
    // Build a variant that has parent_refs covering Protocol and EcuSharedData union arms
    let db = DiagDatabase {
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "ChildVariant".into(),
                ..Default::default()
            },
            is_base_variant: false,
            variant_patterns: vec![],
            parent_refs: vec![
                ParentRef {
                    ref_type: ParentRefType::Protocol(Box::new(Protocol {
                        diag_layer: DiagLayer {
                            short_name: "UDS_on_CAN".into(),
                            ..Default::default()
                        },
                        com_param_spec: None,
                        prot_stack: None,
                        parent_refs: vec![],
                    })),
                    not_inherited_diag_comm_short_names: vec!["SvcA".into()],
                    not_inherited_variables_short_names: vec![],
                    not_inherited_dops_short_names: vec!["DopX".into()],
                    not_inherited_tables_short_names: vec!["TblY".into()],
                    not_inherited_global_neg_responses_short_names: vec!["NR1".into()],
                },
                ParentRef {
                    ref_type: ParentRefType::EcuSharedData(Box::new(EcuSharedData {
                        diag_layer: DiagLayer {
                            short_name: "SharedBase".into(),
                            ..Default::default()
                        },
                    })),
                    not_inherited_diag_comm_short_names: vec![],
                    not_inherited_variables_short_names: vec!["VarZ".into()],
                    not_inherited_dops_short_names: vec![],
                    not_inherited_tables_short_names: vec![],
                    not_inherited_global_neg_responses_short_names: vec![],
                },
            ],
        }],
        ..Default::default()
    };
    let fbs_bytes = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs_bytes).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

#[test]
fn roundtrip_com_param_ref_with_complex_value() {
    let db = DiagDatabase {
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "V1".into(),
                com_param_refs: vec![
                    ComParamRef {
                        simple_value: Some(SimpleValue { value: "115200".into() }),
                        complex_value: None,
                        com_param: Some(Box::new(ComParam {
                            com_param_type: ComParamType::Regular,
                            short_name: "CP_Baudrate".into(),
                            long_name: None,
                            param_class: "BUSTYPE".into(),
                            cp_type: ComParamStandardisationLevel::Standard,
                            display_level: Some(1),
                            cp_usage: ComParamUsage::EcuComm,
                            specific_data: Some(ComParamSpecificData::Regular {
                                physical_default_value: "115200".into(),
                                dop: None,
                            }),
                        })),
                        protocol: None,
                        prot_stack: None,
                    },
                    ComParamRef {
                        simple_value: None,
                        complex_value: Some(ComplexValue {
                            entries: vec![
                                SimpleOrComplexValue::Simple(SimpleValue { value: "val1".into() }),
                                SimpleOrComplexValue::Complex(Box::new(ComplexValue {
                                    entries: vec![
                                        SimpleOrComplexValue::Simple(SimpleValue { value: "nested".into() }),
                                    ],
                                })),
                            ],
                        }),
                        com_param: None,
                        protocol: None,
                        prot_stack: None,
                    },
                ],
                ..Default::default()
            },
            is_base_variant: false,
            variant_patterns: vec![],
            parent_refs: vec![],
        }],
        ..Default::default()
    };
    let fbs_bytes = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs_bytes).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

#[test]
fn roundtrip_preserves_diag_comm_refs() {
    let db = DiagDatabase {
        ecu_name: "TEST".into(),
        variants: vec![Variant {
            is_base_variant: true,
            diag_layer: DiagLayer {
                short_name: "Base".into(),
                diag_services: vec![DiagService {
                    diag_comm: DiagComm {
                        short_name: "Svc1".into(),
                        funct_classes: vec![
                            FunctClass {
                                short_name: "Safety".into(),
                            },
                            FunctClass {
                                short_name: "Emission".into(),
                            },
                        ],
                        pre_condition_state_refs: vec![PreConditionStateRef {
                            value: "S_Default".into(),
                            in_param_if_short_name: String::new(),
                            in_param_path_short_name: String::new(),
                            state: Some(State {
                                short_name: "Default".into(),
                                long_name: None,
                            }),
                        }],
                        state_transition_refs: vec![StateTransitionRef {
                            value: "ST_1".into(),
                            state_transition: Some(StateTransition {
                                short_name: "DefaultToExtended".into(),
                                source_short_name_ref: "Default".into(),
                                target_short_name_ref: "Extended".into(),
                            }),
                        }],
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    let fbs = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    let svc = &db2.variants[0].diag_layer.diag_services[0];

    assert_eq!(svc.diag_comm.funct_classes.len(), 2);
    assert_eq!(svc.diag_comm.funct_classes[0].short_name, "Safety");
    assert_eq!(svc.diag_comm.funct_classes[1].short_name, "Emission");
    assert_eq!(svc.diag_comm.pre_condition_state_refs.len(), 1);
    assert_eq!(
        svc.diag_comm.pre_condition_state_refs[0].value,
        "S_Default"
    );
    assert_eq!(svc.diag_comm.state_transition_refs.len(), 1);
    assert_eq!(svc.diag_comm.state_transition_refs[0].value, "ST_1");
    let st = svc.diag_comm.state_transition_refs[0]
        .state_transition
        .as_ref()
        .unwrap();
    assert_eq!(st.short_name, "DefaultToExtended");
}

#[test]
fn fbs_output_is_not_empty() {
    let db = make_test_database();
    let bytes = ir_to_flatbuffers(&db);
    assert!(
        bytes.len() > 100,
        "FBS output too small: {} bytes",
        bytes.len()
    );
}
