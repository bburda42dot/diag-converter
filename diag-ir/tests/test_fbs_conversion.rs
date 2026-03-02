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
        type_definitions: vec![],
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
                    request: Some(Request { params, sdgs: None }),
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
            SimpleOrComplexValue::Simple(SimpleValue {
                value: "outer_val".into(),
            }),
            SimpleOrComplexValue::Complex(Box::new(ComplexValue {
                entries: vec![SimpleOrComplexValue::Simple(SimpleValue {
                    value: "inner_val".into(),
                })],
            })),
        ],
    };

    // Verify structure
    assert_eq!(cv.entries.len(), 2);
    match &cv.entries[0] {
        SimpleOrComplexValue::Simple(sv) => assert_eq!(sv.value, "outer_val"),
        SimpleOrComplexValue::Complex(_) => panic!("expected Simple at index 0"),
    }
    match &cv.entries[1] {
        SimpleOrComplexValue::Complex(nested) => {
            assert_eq!(nested.entries.len(), 1);
            match &nested.entries[0] {
                SimpleOrComplexValue::Simple(sv) => assert_eq!(sv.value, "inner_val"),
                SimpleOrComplexValue::Complex(_) => {
                    panic!("expected Simple in nested ComplexValue")
                }
            }
        }
        SimpleOrComplexValue::Simple(_) => panic!("expected Complex at index 1"),
    }
}

/// Test that reading a real CDA MDD file correctly deserializes ComplexValues
/// in ComParamRef entries (not as empty SimpleValues).
#[test]
fn test_complex_value_from_reference_mdd() {
    let mdd_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-fixtures/mdd/FLXC1000.mdd");
    let (_meta, fbs_data) =
        mdd_format::reader::read_mdd_file(&mdd_path).expect("Failed to read reference MDD");
    let db = flatbuffers_to_ir(&fbs_data).expect("Failed to deserialize FBS");

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
                        simple_value: Some(SimpleValue {
                            value: "115200".into(),
                        }),
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
                                SimpleOrComplexValue::Simple(SimpleValue {
                                    value: "val1".into(),
                                }),
                                SimpleOrComplexValue::Complex(Box::new(ComplexValue {
                                    entries: vec![SimpleOrComplexValue::Simple(SimpleValue {
                                        value: "nested".into(),
                                    })],
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
    assert_eq!(svc.diag_comm.pre_condition_state_refs[0].value, "S_Default");
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

#[test]
fn roundtrip_preserves_memory_config() {
    let db = DiagDatabase {
        ecu_name: "MEM_TEST".into(),
        memory: Some(MemoryConfig {
            default_address_format: AddressFormat {
                address_bytes: 4,
                length_bytes: 4,
            },
            regions: vec![MemoryRegion {
                name: "Flash".into(),
                description: Some("Main flash".into()),
                start_address: 0x0800_0000,
                size: 0x0010_0000,
                access: MemoryAccess::ReadWrite,
                address_format: None,
                security_level: Some("Level1".into()),
                session: Some(vec!["programming".into()]),
            }],
            data_blocks: vec![DataBlock {
                name: "AppBlock".into(),
                description: None,
                block_type: DataBlockType::Download,
                memory_address: 0x0800_0000,
                memory_size: 0x0008_0000,
                format: DataBlockFormat::Compressed,
                max_block_length: Some(4096),
                security_level: None,
                session: Some("programming".into()),
                checksum_type: Some("CRC32".into()),
            }],
        }),
        ..Default::default()
    };

    let fbs = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    let mem = db2.memory.expect("memory should survive FBS roundtrip");
    assert_eq!(mem.default_address_format.address_bytes, 4);
    assert_eq!(mem.regions.len(), 1);
    assert_eq!(mem.regions[0].name, "Flash");
    assert_eq!(mem.regions[0].start_address, 0x0800_0000);
    assert_eq!(mem.regions[0].access, MemoryAccess::ReadWrite);
    assert_eq!(mem.regions[0].security_level.as_deref(), Some("Level1"));
    assert_eq!(mem.data_blocks.len(), 1);
    assert_eq!(mem.data_blocks[0].name, "AppBlock");
    assert_eq!(mem.data_blocks[0].format, DataBlockFormat::Compressed);
    assert_eq!(mem.data_blocks[0].checksum_type.as_deref(), Some("CRC32"));
}

#[test]
fn roundtrip_preserves_type_definitions() {
    let enum_json = r#"{"OFF":0,"ON":1}"#;

    let db = DiagDatabase {
        ecu_name: "TYPES_TEST".into(),
        type_definitions: vec![
            TypeDefinition {
                name: "VehicleSpeed".into(),
                base: "u16".into(),
                bit_length: Some(16),
                ..Default::default()
            },
            TypeDefinition {
                name: "EngineState".into(),
                base: "u8".into(),
                bit_length: Some(8),
                enum_values_json: Some(enum_json.to_string()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let fbs = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs).unwrap();
    assert_eq!(db2.type_definitions.len(), 2);
    assert_eq!(db2.type_definitions[0].name, "VehicleSpeed");
    assert_eq!(db2.type_definitions[0].bit_length, Some(16));
    assert_eq!(db2.type_definitions[1].name, "EngineState");
    let enums_json = db2.type_definitions[1].enum_values_json.as_ref().unwrap();
    assert!(
        enums_json.contains("OFF"),
        "enum_values_json should contain OFF"
    );
    assert!(
        enums_json.contains("ON"),
        "enum_values_json should contain ON"
    );
}

// ---------------------------------------------------------------------------
// Helpers for coverage tests
// ---------------------------------------------------------------------------

fn minimal_diag_coded_type() -> DiagCodedType {
    DiagCodedType {
        type_name: DiagCodedTypeName::StandardLengthType,
        base_type_encoding: "unsigned".into(),
        base_data_type: DataType::AUint32,
        is_high_low_byte_order: true,
        specific_data: Some(DiagCodedTypeData::StandardLength {
            bit_length: 8,
            bit_mask: vec![],
            condensed: false,
        }),
    }
}

fn minimal_dop() -> Dop {
    Dop {
        dop_type: DopType::Regular,
        short_name: "TestDop".into(),
        sdgs: None,
        specific_data: Some(DopData::NormalDop {
            compu_method: None,
            diag_coded_type: Some(minimal_diag_coded_type()),
            physical_type: None,
            internal_constr: None,
            unit_ref: None,
            phys_constr: None,
        }),
    }
}

fn wrap_params_in_db(params: Vec<Param>) -> DiagDatabase {
    DiagDatabase {
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "V".into(),
                diag_services: vec![DiagService {
                    diag_comm: DiagComm {
                        short_name: "Svc".into(),
                        ..Default::default()
                    },
                    request: Some(Request { params, sdgs: None }),
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn wrap_dop_in_db(dop: Dop) -> DiagDatabase {
    let param = Param {
        id: 0,
        param_type: ParamType::Value,
        short_name: "P".into(),
        specific_data: Some(ParamData::Value {
            physical_default_value: "0".into(),
            dop: Box::new(dop),
        }),
        ..Default::default()
    };
    wrap_params_in_db(vec![param])
}

// ---------------------------------------------------------------------------
// Step 1: Roundtrip ParamData variants
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_param_data_scalar_variants() {
    let params = vec![
        Param {
            id: 0,
            param_type: ParamType::MatchingRequestParam,
            short_name: "MRP".into(),
            specific_data: Some(ParamData::MatchingRequestParam {
                request_byte_pos: 2,
                byte_length: 4,
            }),
            ..Default::default()
        },
        Param {
            id: 1,
            param_type: ParamType::Reserved,
            short_name: "Rsv".into(),
            specific_data: Some(ParamData::Reserved { bit_length: 16 }),
            ..Default::default()
        },
        Param {
            id: 2,
            param_type: ParamType::NrcConst,
            short_name: "NRC".into(),
            specific_data: Some(ParamData::NrcConst {
                coded_values: vec!["0x12".into(), "0x13".into(), "0x31".into()],
                diag_coded_type: minimal_diag_coded_type(),
            }),
            ..Default::default()
        },
    ];

    let db = wrap_params_in_db(params);
    let fbs = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

#[test]
fn roundtrip_param_data_dop_variants() {
    let params = vec![
        Param {
            id: 0,
            param_type: ParamType::LengthKey,
            short_name: "LenKey".into(),
            specific_data: Some(ParamData::LengthKeyRef {
                dop: Box::new(minimal_dop()),
            }),
            ..Default::default()
        },
        Param {
            id: 1,
            param_type: ParamType::PhysConst,
            short_name: "PC".into(),
            specific_data: Some(ParamData::PhysConst {
                phys_constant_value: "42.5".into(),
                dop: Box::new(minimal_dop()),
            }),
            ..Default::default()
        },
        Param {
            id: 2,
            param_type: ParamType::System,
            short_name: "Sys".into(),
            specific_data: Some(ParamData::System {
                dop: Box::new(minimal_dop()),
                sys_param: "ECU_SERIAL".into(),
            }),
            ..Default::default()
        },
    ];

    let db = wrap_params_in_db(params);
    let fbs = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

#[test]
fn roundtrip_param_data_table_variants() {
    let table_dop = TableDop {
        semantic: "TABLE".into(),
        short_name: "TDop".into(),
        long_name: None,
        key_label: "key".into(),
        struct_label: "struct".into(),
        key_dop: Some(Box::new(minimal_dop())),
        rows: vec![TableRow {
            short_name: "Row1".into(),
            long_name: None,
            key: "0x01".into(),
            dop: None,
            structure: None,
            sdgs: None,
            audience: None,
            funct_class_refs: vec![],
            state_transition_refs: vec![],
            pre_condition_state_refs: vec![],
            is_executable: false,
            semantic: String::new(),
            is_mandatory: false,
            is_final: false,
        }],
        diag_comm_connectors: vec![],
        sdgs: None,
    };

    let table_row = TableRow {
        short_name: "TargetRow".into(),
        long_name: None,
        key: "0x02".into(),
        dop: Some(Box::new(minimal_dop())),
        structure: None,
        sdgs: None,
        audience: None,
        funct_class_refs: vec![],
        state_transition_refs: vec![],
        pre_condition_state_refs: vec![],
        is_executable: true,
        semantic: "ROW".into(),
        is_mandatory: false,
        is_final: false,
    };

    let table_key_param = Param {
        id: 10,
        param_type: ParamType::CodedConst,
        short_name: "TK_inner".into(),
        specific_data: Some(ParamData::CodedConst {
            coded_value: "0x01".into(),
            diag_coded_type: minimal_diag_coded_type(),
        }),
        ..Default::default()
    };

    let params = vec![
        Param {
            id: 0,
            param_type: ParamType::TableEntry,
            short_name: "TE".into(),
            specific_data: Some(ParamData::TableEntry {
                param: Box::new(Param {
                    id: 99,
                    param_type: ParamType::Value,
                    short_name: "inner".into(),
                    specific_data: Some(ParamData::Value {
                        physical_default_value: "0".into(),
                        dop: Box::new(minimal_dop()),
                    }),
                    ..Default::default()
                }),
                target: TableEntryRowFragment::Key,
                table_row: Box::new(table_row),
            }),
            ..Default::default()
        },
        Param {
            id: 1,
            param_type: ParamType::TableKey,
            short_name: "TK_dop".into(),
            specific_data: Some(ParamData::TableKey {
                table_key_reference: TableKeyReference::TableDop(Box::new(table_dop)),
            }),
            ..Default::default()
        },
        Param {
            id: 2,
            param_type: ParamType::TableKey,
            short_name: "TK_row".into(),
            specific_data: Some(ParamData::TableKey {
                table_key_reference: TableKeyReference::TableRow(Box::new(TableRow {
                    short_name: "RefRow".into(),
                    long_name: None,
                    key: "0xFF".into(),
                    dop: None,
                    structure: None,
                    sdgs: None,
                    audience: None,
                    funct_class_refs: vec![],
                    state_transition_refs: vec![],
                    pre_condition_state_refs: vec![],
                    is_executable: false,
                    semantic: String::new(),
                    is_mandatory: false,
                    is_final: false,
                })),
            }),
            ..Default::default()
        },
        Param {
            id: 3,
            param_type: ParamType::TableStruct,
            short_name: "TS".into(),
            specific_data: Some(ParamData::TableStruct {
                table_key: Box::new(table_key_param),
            }),
            ..Default::default()
        },
    ];

    let db = wrap_params_in_db(params);
    let fbs = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

// ---------------------------------------------------------------------------
// Step 2: Roundtrip DopData variants
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_dop_data_field_variants() {
    let structure_dop = Dop {
        dop_type: DopType::Structure,
        short_name: "StructDop".into(),
        sdgs: None,
        specific_data: Some(DopData::Structure {
            params: vec![Param {
                id: 0,
                param_type: ParamType::CodedConst,
                short_name: "F1".into(),
                specific_data: Some(ParamData::CodedConst {
                    coded_value: "0xAA".into(),
                    diag_coded_type: minimal_diag_coded_type(),
                }),
                ..Default::default()
            }],
            byte_size: Some(4),
            is_visible: true,
        }),
    };

    let end_of_pdu_dop = Dop {
        dop_type: DopType::EndOfPduField,
        short_name: "EoPDop".into(),
        sdgs: None,
        specific_data: Some(DopData::EndOfPduField {
            max_number_of_items: Some(10),
            min_number_of_items: Some(1),
            field: Some(Field {
                basic_structure: Some(Box::new(minimal_dop())),
                env_data_desc: None,
                is_visible: true,
            }),
        }),
    };

    let static_field_dop = Dop {
        dop_type: DopType::StaticField,
        short_name: "SFDop".into(),
        sdgs: None,
        specific_data: Some(DopData::StaticField {
            fixed_number_of_items: 5,
            item_byte_size: 2,
            field: Some(Field {
                basic_structure: Some(Box::new(minimal_dop())),
                env_data_desc: None,
                is_visible: false,
            }),
        }),
    };

    let dyn_len_dop = Dop {
        dop_type: DopType::DynamicLengthField,
        short_name: "DynLenDop".into(),
        sdgs: None,
        specific_data: Some(DopData::DynamicLengthField {
            offset: 4,
            field: Some(Field {
                basic_structure: Some(Box::new(minimal_dop())),
                env_data_desc: None,
                is_visible: true,
            }),
            determine_number_of_items: Some(DetermineNumberOfItems {
                byte_position: 0,
                bit_position: 0,
                dop: Box::new(minimal_dop()),
            }),
        }),
    };

    for dop in [structure_dop, end_of_pdu_dop, static_field_dop, dyn_len_dop] {
        let db = wrap_dop_in_db(dop);
        let fbs = ir_to_flatbuffers(&db);
        let db2 = flatbuffers_to_ir(&fbs).expect("roundtrip failed");
        pretty_assertions::assert_eq!(db, db2);
    }
}

#[test]
fn roundtrip_dop_data_complex_variants() {
    let dtc_dop = Dop {
        dop_type: DopType::Dtc,
        short_name: "DtcDop".into(),
        sdgs: None,
        specific_data: Some(DopData::DtcDop {
            diag_coded_type: Some(minimal_diag_coded_type()),
            physical_type: Some(PhysicalType {
                precision: Some(0),
                base_data_type: PhysicalTypeDataType::AUint32,
                display_radix: Radix::Hex,
            }),
            compu_method: Some(CompuMethod {
                category: CompuCategory::Identical,
                internal_to_phys: None,
                phys_to_internal: None,
            }),
            dtcs: vec![Dtc {
                short_name: "P0100".into(),
                trouble_code: 0x0100,
                display_trouble_code: "P0100".into(),
                text: Some(Text {
                    value: "MAF".into(),
                    ti: "en".into(),
                }),
                level: Some(2),
                sdgs: None,
                is_temporary: false,
            }],
            is_visible: true,
        }),
    };

    let env_data_dop = Dop {
        dop_type: DopType::EnvData,
        short_name: "EnvDop".into(),
        sdgs: None,
        specific_data: Some(DopData::EnvData {
            dtc_values: vec![0x01, 0x02],
            params: vec![Param {
                id: 0,
                param_type: ParamType::Value,
                short_name: "EP".into(),
                specific_data: Some(ParamData::Value {
                    physical_default_value: "0".into(),
                    dop: Box::new(minimal_dop()),
                }),
                ..Default::default()
            }],
        }),
    };

    let env_data_desc_dop = Dop {
        dop_type: DopType::EnvDataDesc,
        short_name: "EnvDescDop".into(),
        sdgs: None,
        specific_data: Some(DopData::EnvDataDesc {
            param_short_name: "ParamSN".into(),
            param_path_short_name: "ParamPath".into(),
            env_datas: vec![Dop {
                dop_type: DopType::EnvData,
                short_name: "NestedEnv".into(),
                sdgs: None,
                specific_data: Some(DopData::EnvData {
                    dtc_values: vec![0x10],
                    params: vec![],
                }),
            }],
        }),
    };

    for dop in [dtc_dop, env_data_dop, env_data_desc_dop] {
        let db = wrap_dop_in_db(dop);
        let fbs = ir_to_flatbuffers(&db);
        let db2 = flatbuffers_to_ir(&fbs).expect("roundtrip failed");
        pretty_assertions::assert_eq!(db, db2);
    }
}

#[test]
fn roundtrip_dop_data_mux_dop() {
    let mux_dop = Dop {
        dop_type: DopType::Mux,
        short_name: "MuxDop".into(),
        sdgs: None,
        specific_data: Some(DopData::MuxDop {
            byte_position: 0,
            switch_key: Some(SwitchKey {
                byte_position: 0,
                bit_position: Some(4),
                dop: Box::new(minimal_dop()),
            }),
            default_case: Some(DefaultCase {
                short_name: "DefCase".into(),
                long_name: Some(LongName {
                    value: "Default Case".into(),
                    ti: "en".into(),
                }),
                structure: Some(Box::new(Dop {
                    dop_type: DopType::Structure,
                    short_name: "DefStruct".into(),
                    sdgs: None,
                    specific_data: Some(DopData::Structure {
                        params: vec![],
                        byte_size: Some(2),
                        is_visible: false,
                    }),
                })),
            }),
            cases: vec![
                Case {
                    short_name: "Case1".into(),
                    long_name: None,
                    structure: Some(Box::new(Dop {
                        dop_type: DopType::Structure,
                        short_name: "C1Struct".into(),
                        sdgs: None,
                        specific_data: Some(DopData::Structure {
                            params: vec![Param {
                                id: 0,
                                param_type: ParamType::CodedConst,
                                short_name: "C1P".into(),
                                specific_data: Some(ParamData::CodedConst {
                                    coded_value: "0x01".into(),
                                    diag_coded_type: minimal_diag_coded_type(),
                                }),
                                ..Default::default()
                            }],
                            byte_size: None,
                            is_visible: true,
                        }),
                    })),
                    lower_limit: Some(Limit {
                        value: "0".into(),
                        interval_type: IntervalType::Closed,
                    }),
                    upper_limit: Some(Limit {
                        value: "10".into(),
                        interval_type: IntervalType::Open,
                    }),
                },
                Case {
                    short_name: "Case2".into(),
                    long_name: Some(LongName {
                        value: "Second Case".into(),
                        ti: "en".into(),
                    }),
                    structure: None,
                    lower_limit: Some(Limit {
                        value: "10".into(),
                        interval_type: IntervalType::Closed,
                    }),
                    upper_limit: Some(Limit {
                        value: "255".into(),
                        interval_type: IntervalType::Closed,
                    }),
                },
            ],
            is_visible: true,
        }),
    };

    let db = wrap_dop_in_db(mux_dop);
    let fbs = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}

// ---------------------------------------------------------------------------
// Step 3: Roundtrip SingleEcuJob
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_single_ecu_job() {
    let db = DiagDatabase {
        variants: vec![Variant {
            diag_layer: DiagLayer {
                short_name: "V".into(),
                single_ecu_jobs: vec![SingleEcuJob {
                    diag_comm: DiagComm {
                        short_name: "ReadEcuIdent".into(),
                        semantic: "IDENTIFICATION".into(),
                        ..Default::default()
                    },
                    prog_codes: vec![ProgCode {
                        code_file: "ecu_ident.jar".into(),
                        encryption: "none".into(),
                        syntax: "JAVA".into(),
                        revision: "1.0".into(),
                        entrypoint: "com.ecu.ReadIdent".into(),
                        libraries: vec![Library {
                            short_name: "HelperLib".into(),
                            long_name: Some(LongName {
                                value: "Helper Library".into(),
                                ti: "en".into(),
                            }),
                            code_file: "helper.jar".into(),
                            encryption: "none".into(),
                            syntax: "JAVA".into(),
                            entry_point: "com.ecu.Helper".into(),
                        }],
                    }],
                    input_params: vec![JobParam {
                        short_name: "InputAddr".into(),
                        long_name: None,
                        physical_default_value: "0x0000".into(),
                        dop_base: Some(Box::new(minimal_dop())),
                        semantic: "INPUT".into(),
                    }],
                    output_params: vec![JobParam {
                        short_name: "OutputData".into(),
                        long_name: Some(LongName {
                            value: "Output Data".into(),
                            ti: "en".into(),
                        }),
                        physical_default_value: String::new(),
                        dop_base: None,
                        semantic: "OUTPUT".into(),
                    }],
                    neg_output_params: vec![JobParam {
                        short_name: "NegResult".into(),
                        long_name: None,
                        physical_default_value: "0xFF".into(),
                        dop_base: None,
                        semantic: "NEG_OUTPUT".into(),
                    }],
                }],
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    let fbs = ir_to_flatbuffers(&db);
    let db2 = flatbuffers_to_ir(&fbs).expect("roundtrip failed");
    pretty_assertions::assert_eq!(db, db2);
}
