//! YAML document -> canonical IR transformation.
//!
//! Parses a YAML string into the YAML model, then transforms it into the
//! canonical DiagDatabase IR used by all other converters.

use crate::yaml_model::*;
use diag_ir::*;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum YamlParseError {
    #[error("YAML deserialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

/// Parse a YAML string into a DiagDatabase IR.
pub fn parse_yaml(yaml: &str) -> Result<DiagDatabase, YamlParseError> {
    let doc: YamlDocument = serde_yaml::from_str(yaml)?;
    yaml_to_ir(&doc)
}

/// Transform a parsed YAML document into the canonical IR.
fn yaml_to_ir(doc: &YamlDocument) -> Result<DiagDatabase, YamlParseError> {
    let ecu = doc.ecu.as_ref();
    let ecu_name = ecu.map(|e| e.name.clone()).unwrap_or_default();
    let ecu_id = ecu.map(|e| e.id.clone()).unwrap_or_default();

    let revision = doc
        .meta
        .as_ref()
        .map(|m| m.revision.clone())
        .unwrap_or_default();

    let version = doc
        .meta
        .as_ref()
        .map(|m| m.revision.clone())
        .unwrap_or_default();

    // Build metadata from meta section
    let mut metadata = BTreeMap::new();
    if let Some(meta) = &doc.meta {
        if !meta.author.is_empty() {
            metadata.insert("author".into(), meta.author.clone());
        }
        if !meta.domain.is_empty() {
            metadata.insert("domain".into(), meta.domain.clone());
        }
        if !meta.created.is_empty() {
            metadata.insert("created".into(), meta.created.clone());
        }
        if !meta.description.is_empty() {
            metadata.insert("description".into(), meta.description.clone());
        }
    }
    if !ecu_id.is_empty() {
        metadata.insert("ecu_id".into(), ecu_id);
    }
    metadata.insert("schema".into(), doc.schema.clone());

    // Build named type registry for resolving type references in DIDs
    let type_registry = build_type_registry(doc.types.as_ref());

    // Build services from DID definitions + enabled standard services
    let mut diag_services = Vec::new();

    // Generate ReadDataByIdentifier services from DIDs
    if let Some(serde_yaml::Value::Mapping(dids)) = &doc.dids {
        for (key, val) in dids {
            let did_id = parse_hex_key(key);
            if let Ok(did) = serde_yaml::from_value::<Did>(val.clone()) {
                if did.readable.unwrap_or(true) {
                    diag_services.push(did_to_read_service(did_id, &did, &type_registry));
                }
                if did.writable.unwrap_or(false) {
                    diag_services.push(did_to_write_service(did_id, &did, &type_registry));
                }
            }
        }
    }

    // Generate RoutineControl services from routines
    if let Some(serde_yaml::Value::Mapping(routines)) = &doc.routines {
        for (key, val) in routines {
            let rid = parse_hex_key(key);
            if let Ok(routine) = serde_yaml::from_value::<Routine>(val.clone()) {
                diag_services.push(routine_to_service(rid, &routine, &type_registry));
            }
        }
    }

    // Build ECU jobs from ecu_jobs section
    let mut single_ecu_jobs = Vec::new();
    if let Some(jobs) = &doc.ecu_jobs {
        for (_key, job) in jobs {
            single_ecu_jobs.push(ecu_job_to_ir(job, &type_registry));
        }
    }

    // Build SDGs from sdgs section
    let sdgs = doc.sdgs.as_ref().map(|sdg_map| convert_sdgs(sdg_map));

    // Build DTCs
    let dtcs = if let Some(serde_yaml::Value::Mapping(dtc_map)) = &doc.dtcs {
        dtc_map
            .iter()
            .filter_map(|(key, val)| {
                let code = parse_hex_key(key);
                serde_yaml::from_value::<YamlDtc>(val.clone())
                    .ok()
                    .map(|dtc| convert_dtc(code, &dtc))
            })
            .collect()
    } else {
        vec![]
    };

    // Build the main variant containing all services
    let variant = Variant {
        diag_layer: DiagLayer {
            short_name: ecu_name.clone(),
            long_name: doc.meta.as_ref().map(|m| LongName {
                value: m.description.clone(),
                ti: String::new(),
            }),
            funct_classes: vec![],
            com_param_refs: vec![],
            diag_services,
            single_ecu_jobs,
            state_charts: vec![],
            additional_audiences: vec![],
            sdgs,
        },
        is_base_variant: true,
        variant_patterns: vec![],
        parent_refs: vec![],
    };

    Ok(DiagDatabase {
        version,
        ecu_name,
        revision,
        metadata,
        variants: vec![variant],
        functional_groups: vec![],
        dtcs,
    })
}

/// Registry of named types for resolving type references in DIDs.
struct TypeRegistry {
    types: BTreeMap<String, YamlType>,
}

fn build_type_registry(types: Option<&BTreeMap<String, YamlType>>) -> TypeRegistry {
    TypeRegistry {
        types: types.cloned().unwrap_or_default(),
    }
}

/// Resolve a DID type which can be either a string reference or inline type definition.
fn resolve_did_type<'a>(
    type_value: &'a serde_yaml::Value,
    registry: &'a TypeRegistry,
) -> Option<YamlType> {
    match type_value {
        serde_yaml::Value::String(name) => registry.types.get(name).cloned(),
        serde_yaml::Value::Mapping(_) => serde_yaml::from_value(type_value.clone()).ok(),
        _ => None,
    }
}

/// Convert a YAML type definition to IR DOP.
fn yaml_type_to_dop(name: &str, yaml_type: &YamlType) -> Dop {
    let (base_data_type, phys_data_type) = base_type_to_data_type(&yaml_type.base);

    let is_high_low = yaml_type
        .endian
        .as_deref()
        .map(|e| e == "big")
        .unwrap_or(true);

    let bit_length = yaml_type
        .bit_length
        .or_else(|| yaml_type.length.map(|l| l * 8))
        .or_else(|| default_bit_length(&yaml_type.base));

    // Build CompuMethod from scale/offset or enum
    let compu_method = build_compu_method(yaml_type);

    let diag_coded_type = DiagCodedType {
        type_name: if yaml_type.min_length.is_some() || yaml_type.max_length.is_some() {
            DiagCodedTypeName::MinMaxLengthType
        } else {
            DiagCodedTypeName::StandardLengthType
        },
        base_type_encoding: if yaml_type.base.starts_with('s') || yaml_type.base.starts_with("i") {
            "signed".into()
        } else {
            "unsigned".into()
        },
        base_data_type,
        is_high_low_byte_order: is_high_low,
        specific_data: if yaml_type.min_length.is_some() || yaml_type.max_length.is_some() {
            let termination = match yaml_type.termination.as_deref() {
                Some("zero") => Termination::Zero,
                Some("hex_ff") | Some("hexff") => Termination::HexFf,
                _ => Termination::EndOfPdu,
            };
            Some(DiagCodedTypeData::MinMax {
                min_length: yaml_type.min_length.unwrap_or(0),
                max_length: yaml_type.max_length,
                termination,
            })
        } else {
            bit_length.map(|bl| DiagCodedTypeData::StandardLength {
                bit_length: bl,
                bit_mask: vec![],
                condensed: false,
            })
        },
    };

    // Build unit if present
    let unit_ref = yaml_type.unit.as_ref().map(|u| Unit {
        short_name: u.clone(),
        display_name: u.clone(),
        factor_si_to_unit: None,
        offset_si_to_unit: None,
        physical_dimension: None,
    });

    // Build constraints
    let internal_constr = yaml_type
        .constraints
        .as_ref()
        .and_then(|c| c.internal.as_ref())
        .and_then(|vals| {
            if vals.len() == 2 {
                Some(InternalConstr {
                    lower_limit: Some(Limit {
                        value: yaml_value_to_string(&vals[0]),
                        interval_type: IntervalType::Closed,
                    }),
                    upper_limit: Some(Limit {
                        value: yaml_value_to_string(&vals[1]),
                        interval_type: IntervalType::Closed,
                    }),
                    scale_constrs: vec![],
                })
            } else {
                None
            }
        });

    Dop {
        dop_type: DopType::Regular,
        short_name: name.into(),
        sdgs: None,
        specific_data: Some(DopData::NormalDop {
            compu_method,
            diag_coded_type: Some(diag_coded_type),
            physical_type: Some(PhysicalType {
                precision: None,
                base_data_type: phys_data_type,
                display_radix: Radix::Dec,
            }),
            internal_constr,
            unit_ref,
            phys_constr: None,
        }),
    }
}

fn build_compu_method(yaml_type: &YamlType) -> Option<CompuMethod> {
    // Text table / enum
    if let Some(serde_yaml::Value::Mapping(enum_values)) = &yaml_type.enum_values {
        let scales: Vec<CompuScale> = enum_values
            .iter()
            .map(|(k, v)| {
                let v_str = yaml_value_to_string(v);
                CompuScale {
                    short_label: Some(Text {
                        value: v_str.clone(),
                        ti: String::new(),
                    }),
                    lower_limit: Some(Limit {
                        value: yaml_value_to_string(k),
                        interval_type: IntervalType::Closed,
                    }),
                    upper_limit: Some(Limit {
                        value: yaml_value_to_string(k),
                        interval_type: IntervalType::Closed,
                    }),
                    inverse_values: None,
                    consts: Some(CompuValues {
                        v: None,
                        vt: v_str,
                        vt_ti: String::new(),
                    }),
                    rational_co_effs: None,
                }
            })
            .collect();
        return Some(CompuMethod {
            category: CompuCategory::TextTable,
            internal_to_phys: Some(CompuInternalToPhys {
                compu_scales: scales,
                prog_code: None,
                compu_default_value: None,
            }),
            phys_to_internal: None,
        });
    }

    // Linear scale/offset
    if yaml_type.scale.is_some() || yaml_type.offset.is_some() {
        let scale = yaml_type.scale.unwrap_or(1.0);
        let offset = yaml_type.offset.unwrap_or(0.0);
        return Some(CompuMethod {
            category: CompuCategory::Linear,
            internal_to_phys: Some(CompuInternalToPhys {
                compu_scales: vec![CompuScale {
                    short_label: None,
                    lower_limit: None,
                    upper_limit: None,
                    inverse_values: None,
                    consts: None,
                    rational_co_effs: Some(CompuRationalCoEffs {
                        numerator: vec![offset, scale],
                        denominator: vec![1.0],
                    }),
                }],
                prog_code: None,
                compu_default_value: None,
            }),
            phys_to_internal: None,
        });
    }

    // Identical (no conversion)
    Some(CompuMethod {
        category: CompuCategory::Identical,
        internal_to_phys: None,
        phys_to_internal: None,
    })
}

/// Create a ReadDataByIdentifier (0x22) service from a DID definition.
fn did_to_read_service(did_id: u32, did: &Did, registry: &TypeRegistry) -> DiagService {
    let yaml_type = resolve_did_type(&did.did_type, registry);
    let dop = yaml_type
        .as_ref()
        .map(|t| yaml_type_to_dop(&did.name, t))
        .unwrap_or_else(|| Dop {
            dop_type: DopType::Regular,
            short_name: did.name.clone(),
            sdgs: None,
            specific_data: None,
        });

    DiagService {
        diag_comm: DiagComm {
            short_name: format!("Read_{}", did.name),
            long_name: did.description.as_ref().map(|d| LongName {
                value: d.clone(),
                ti: String::new(),
            }),
            semantic: "DATA-READ".into(),
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
            params: vec![
                // SID = 0x22
                Param {
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
                        diag_coded_type: uint8_coded_type(),
                    }),
                },
                // DID ID
                Param {
                    id: 1,
                    param_type: ParamType::CodedConst,
                    short_name: "DID".into(),
                    semantic: "ID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(1),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: format!("0x{did_id:04X}"),
                        diag_coded_type: uint16_coded_type(),
                    }),
                },
            ],
            sdgs: None,
        }),
        pos_responses: vec![Response {
            response_type: ResponseType::PosResponse,
            params: vec![Param {
                id: 2,
                param_type: ParamType::Value,
                short_name: did.name.clone(),
                semantic: "DATA".into(),
                sdgs: None,
                physical_default_value: String::new(),
                byte_position: Some(3),
                bit_position: None,
                specific_data: Some(ParamData::Value {
                    physical_default_value: String::new(),
                    dop: Box::new(dop),
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

/// Create a WriteDataByIdentifier (0x2E) service from a DID definition.
fn did_to_write_service(did_id: u32, did: &Did, registry: &TypeRegistry) -> DiagService {
    let yaml_type = resolve_did_type(&did.did_type, registry);
    let dop = yaml_type
        .as_ref()
        .map(|t| yaml_type_to_dop(&did.name, t))
        .unwrap_or_else(|| Dop {
            dop_type: DopType::Regular,
            short_name: did.name.clone(),
            sdgs: None,
            specific_data: None,
        });

    DiagService {
        diag_comm: DiagComm {
            short_name: format!("Write_{}", did.name),
            long_name: did.description.as_ref().map(|d| LongName {
                value: d.clone(),
                ti: String::new(),
            }),
            semantic: "DATA-WRITE".into(),
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
            params: vec![
                Param {
                    id: 0,
                    param_type: ParamType::CodedConst,
                    short_name: "SID".into(),
                    semantic: "SERVICE-ID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(0),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: "0x2E".into(),
                        diag_coded_type: uint8_coded_type(),
                    }),
                },
                Param {
                    id: 1,
                    param_type: ParamType::CodedConst,
                    short_name: "DID".into(),
                    semantic: "ID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(1),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: format!("0x{did_id:04X}"),
                        diag_coded_type: uint16_coded_type(),
                    }),
                },
                Param {
                    id: 2,
                    param_type: ParamType::Value,
                    short_name: did.name.clone(),
                    semantic: "DATA".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(3),
                    bit_position: None,
                    specific_data: Some(ParamData::Value {
                        physical_default_value: String::new(),
                        dop: Box::new(dop),
                    }),
                },
            ],
            sdgs: None,
        }),
        pos_responses: vec![],
        neg_responses: vec![],
        is_cyclic: false,
        is_multiple: false,
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        com_param_refs: vec![],
    }
}

/// Convert a routine definition to a RoutineControl (0x31) service.
fn routine_to_service(rid: u32, routine: &Routine, _registry: &TypeRegistry) -> DiagService {
    let mut request_params = vec![
        Param {
            id: 0,
            param_type: ParamType::CodedConst,
            short_name: "SID".into(),
            semantic: "SERVICE-ID".into(),
            sdgs: None,
            physical_default_value: String::new(),
            byte_position: Some(0),
            bit_position: Some(0),
            specific_data: Some(ParamData::CodedConst {
                coded_value: "0x31".into(),
                diag_coded_type: uint8_coded_type(),
            }),
        },
        Param {
            id: 1,
            param_type: ParamType::CodedConst,
            short_name: "RID".into(),
            semantic: "ID".into(),
            sdgs: None,
            physical_default_value: String::new(),
            byte_position: Some(2),
            bit_position: Some(0),
            specific_data: Some(ParamData::CodedConst {
                coded_value: format!("0x{rid:04X}"),
                diag_coded_type: uint16_coded_type(),
            }),
        },
    ];

    // Add start input params if present
    if let Some(params) = &routine.parameters {
        if let Some(start) = params.get("start") {
            if let Some(inputs) = &start.input {
                let mut id = 2u32;
                for input in inputs {
                    let yaml_type: Option<YamlType> =
                        serde_yaml::from_value(input.param_type.clone()).ok();
                    let dop = yaml_type
                        .as_ref()
                        .map(|t| yaml_type_to_dop(&input.name, t))
                        .unwrap_or_else(|| Dop {
                            dop_type: DopType::Regular,
                            short_name: input.name.clone(),
                            sdgs: None,
                            specific_data: None,
                        });
                    request_params.push(Param {
                        id,
                        param_type: ParamType::Value,
                        short_name: input.name.clone(),
                        semantic: input
                            .semantic
                            .clone()
                            .unwrap_or_else(|| "DATA".into()),
                        sdgs: None,
                        physical_default_value: String::new(),
                        byte_position: None,
                        bit_position: None,
                        specific_data: Some(ParamData::Value {
                            physical_default_value: String::new(),
                            dop: Box::new(dop),
                        }),
                    });
                    id += 1;
                }
            }
        }
    }

    // Build positive response from result output params
    let mut pos_responses = Vec::new();
    if let Some(params) = &routine.parameters {
        if let Some(result) = params.get("result") {
            if let Some(outputs) = &result.output {
                let mut resp_params = Vec::new();
                let mut id = 0u32;
                for output in outputs {
                    let yaml_type: Option<YamlType> =
                        serde_yaml::from_value(output.param_type.clone()).ok();
                    let dop = yaml_type
                        .as_ref()
                        .map(|t| yaml_type_to_dop(&output.name, t))
                        .unwrap_or_else(|| Dop {
                            dop_type: DopType::Regular,
                            short_name: output.name.clone(),
                            sdgs: None,
                            specific_data: None,
                        });
                    resp_params.push(Param {
                        id,
                        param_type: ParamType::Value,
                        short_name: output.name.clone(),
                        semantic: "DATA".into(),
                        sdgs: None,
                        physical_default_value: String::new(),
                        byte_position: None,
                        bit_position: None,
                        specific_data: Some(ParamData::Value {
                            physical_default_value: String::new(),
                            dop: Box::new(dop),
                        }),
                    });
                    id += 1;
                }
                if !resp_params.is_empty() {
                    pos_responses.push(Response {
                        response_type: ResponseType::PosResponse,
                        params: resp_params,
                        sdgs: None,
                    });
                }
            }
        }
    }

    DiagService {
        diag_comm: DiagComm {
            short_name: routine.name.clone(),
            long_name: routine.description.as_ref().map(|d| LongName {
                value: d.clone(),
                ti: String::new(),
            }),
            semantic: "ROUTINE".into(),
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
            params: request_params,
            sdgs: None,
        }),
        pos_responses,
        neg_responses: vec![],
        is_cyclic: false,
        is_multiple: false,
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        com_param_refs: vec![],
    }
}

/// Convert an ECU job definition to IR SingleEcuJob.
fn ecu_job_to_ir(job: &EcuJob, _registry: &TypeRegistry) -> SingleEcuJob {
    let convert_job_params = |params: &Option<Vec<JobParamDef>>| -> Vec<JobParam> {
        params
            .as_ref()
            .map(|ps| {
                ps.iter()
                    .map(|p| {
                        let yaml_type: Option<YamlType> =
                            serde_yaml::from_value(p.param_type.clone()).ok();
                        let dop_base = yaml_type
                            .as_ref()
                            .map(|t| Box::new(yaml_type_to_dop(&p.name, t)));
                        JobParam {
                            short_name: p.name.clone(),
                            long_name: p.description.as_ref().map(|d| LongName {
                                value: d.clone(),
                                ti: String::new(),
                            }),
                            physical_default_value: p
                                .default_value
                                .as_ref()
                                .map(|v| yaml_value_to_string(v))
                                .unwrap_or_default(),
                            dop_base,
                            semantic: p.semantic.clone().unwrap_or_default(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    SingleEcuJob {
        diag_comm: DiagComm {
            short_name: job.name.clone(),
            long_name: job.description.as_ref().map(|d| LongName {
                value: d.clone(),
                ti: String::new(),
            }),
            semantic: "ECU-JOB".into(),
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
        prog_codes: job
            .prog_code
            .as_ref()
            .map(|pc| {
                vec![ProgCode {
                    code_file: pc.clone(),
                    encryption: String::new(),
                    syntax: String::new(),
                    revision: String::new(),
                    entrypoint: String::new(),
                    libraries: vec![],
                }]
            })
            .unwrap_or_default(),
        input_params: convert_job_params(&job.input_params),
        output_params: convert_job_params(&job.output_params),
        neg_output_params: convert_job_params(&job.neg_output_params),
    }
}

/// Convert YAML SDGs to IR SDGs.
fn convert_sdgs(sdg_map: &BTreeMap<String, YamlSdg>) -> Sdgs {
    Sdgs {
        sdgs: sdg_map
            .iter()
            .map(|(_key, yaml_sdg)| convert_single_sdg(yaml_sdg))
            .collect(),
    }
}

fn convert_single_sdg(yaml_sdg: &YamlSdg) -> Sdg {
    let sds = yaml_sdg
        .values
        .iter()
        .map(|v| {
            if v.values.is_some() {
                // Nested SDG
                let nested = YamlSdg {
                    si: v.si.clone(),
                    caption: v.caption.clone().unwrap_or_default(),
                    values: v.values.clone().unwrap_or_default(),
                };
                SdOrSdg::Sdg(convert_single_sdg(&nested))
            } else {
                SdOrSdg::Sd(Sd {
                    value: v.value.clone().unwrap_or_default(),
                    si: v.si.clone(),
                    ti: v.ti.clone().unwrap_or_default(),
                })
            }
        })
        .collect();

    Sdg {
        caption_sn: yaml_sdg.caption.clone(),
        sds,
        si: yaml_sdg.si.clone(),
    }
}

/// Convert a YAML DTC to IR DTC.
fn convert_dtc(trouble_code: u32, yaml_dtc: &YamlDtc) -> Dtc {
    Dtc {
        short_name: yaml_dtc.name.clone(),
        trouble_code,
        display_trouble_code: yaml_dtc.sae.clone(),
        text: yaml_dtc.description.as_ref().map(|d| Text {
            value: d.clone(),
            ti: String::new(),
        }),
        level: yaml_dtc.severity,
        sdgs: None,
        is_temporary: false,
    }
}

// --- Helpers ---

fn parse_hex_key(key: &serde_yaml::Value) -> u32 {
    match key {
        serde_yaml::Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
        serde_yaml::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).unwrap_or(0)
            } else {
                s.parse::<u32>().unwrap_or(0)
            }
        }
        _ => 0,
    }
}

fn yaml_value_to_string(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => format!("{v:?}"),
    }
}

fn base_type_to_data_type(base: &str) -> (DataType, PhysicalTypeDataType) {
    match base {
        "u8" | "s8" => (DataType::AUint32, PhysicalTypeDataType::AUint32),
        "u16" | "s16" => (DataType::AUint32, PhysicalTypeDataType::AUint32),
        "u32" | "s32" | "u64" | "s64" => (DataType::AUint32, PhysicalTypeDataType::AUint32),
        "f32" => (DataType::AFloat32, PhysicalTypeDataType::AFloat32),
        "f64" => (DataType::AFloat64, PhysicalTypeDataType::AFloat64),
        "ascii" => (DataType::AAsciiString, PhysicalTypeDataType::AAsciiString),
        "bytes" => (DataType::ABytefield, PhysicalTypeDataType::ABytefield),
        "struct" => (DataType::ABytefield, PhysicalTypeDataType::ABytefield),
        _ => (DataType::AUint32, PhysicalTypeDataType::AUint32),
    }
}

fn default_bit_length(base: &str) -> Option<u32> {
    match base {
        "u8" | "s8" => Some(8),
        "u16" | "s16" => Some(16),
        "u32" | "s32" | "f32" => Some(32),
        "u64" | "s64" | "f64" => Some(64),
        _ => None,
    }
}

fn uint8_coded_type() -> DiagCodedType {
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

fn uint16_coded_type() -> DiagCodedType {
    DiagCodedType {
        type_name: DiagCodedTypeName::StandardLengthType,
        base_type_encoding: "unsigned".into(),
        base_data_type: DataType::AUint32,
        is_high_low_byte_order: true,
        specific_data: Some(DiagCodedTypeData::StandardLength {
            bit_length: 16,
            bit_mask: vec![],
            condensed: false,
        }),
    }
}
