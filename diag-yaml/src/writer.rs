//! IR -> YAML writer.
//!
//! Converts the canonical DiagDatabase IR back to a YAML string using the
//! OpenSOVD CDA diagnostic YAML schema format.

use crate::yaml_model::*;
use diag_ir::*;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum YamlWriteError {
    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Write a DiagDatabase IR to a YAML string.
pub fn write_yaml(db: &DiagDatabase) -> Result<String, YamlWriteError> {
    let doc = ir_to_yaml(db);
    let yaml = serde_yaml::to_string(&doc)?;
    Ok(yaml)
}

/// Transform the canonical IR into a YAML document model.
fn ir_to_yaml(db: &DiagDatabase) -> YamlDocument {
    let layer = db
        .variants
        .first()
        .map(|v| &v.diag_layer);

    // Build meta from metadata map
    let meta = Some(Meta {
        author: db.metadata.get("author").cloned().unwrap_or_default(),
        domain: db.metadata.get("domain").cloned().unwrap_or_default(),
        created: db.metadata.get("created").cloned().unwrap_or_default(),
        revision: db.revision.clone(),
        description: db.metadata.get("description").cloned().unwrap_or_default(),
        tags: vec![],
        revisions: vec![],
    });

    let ecu = Some(Ecu {
        id: db.metadata.get("ecu_id").cloned().unwrap_or_default(),
        name: db.ecu_name.clone(),
        protocols: None,
        default_addressing_mode: None,
        addressing: None,
        annotations: None,
    });

    // Extract DIDs and routines from services
    let mut dids_map = serde_yaml::Mapping::new();
    let mut routines_map = serde_yaml::Mapping::new();
    let mut types_map: BTreeMap<String, YamlType> = BTreeMap::new();

    if let Some(layer) = layer {
        for svc in &layer.diag_services {
            if svc.diag_comm.semantic == "ROUTINE" {
                let rid = extract_routine_id(svc);
                let routine = service_to_routine(svc);
                let key = serde_yaml::Value::Number(serde_yaml::Number::from(rid as u64));
                routines_map.insert(key, serde_yaml::to_value(&routine).unwrap_or_default());
            } else if svc.diag_comm.short_name.starts_with("Read_") {
                let did_id = extract_did_id(svc);
                let did_name = svc.diag_comm.short_name.strip_prefix("Read_").unwrap_or(&svc.diag_comm.short_name);

                // Extract type info from DOP if available
                let (did_type_val, type_name) = extract_did_type(svc, did_name);

                // Register named type if we extracted one
                if let Some((name, yaml_type)) = type_name {
                    types_map.insert(name, yaml_type);
                }

                let did = Did {
                    name: did_name.to_string(),
                    description: svc.diag_comm.long_name.as_ref().map(|ln| ln.value.clone()),
                    did_type: did_type_val,
                    access: "public".into(),
                    readable: Some(true),
                    writable: None, // Check if there's a matching write service
                    snapshot: Some(false),
                    io_control: None,
                    annotations: None,
                    audience: None,
                };

                let key = serde_yaml::Value::Number(serde_yaml::Number::from(did_id as u64));
                dids_map.insert(key, serde_yaml::to_value(&did).unwrap_or_default());
            }
        }

        // Mark DIDs that also have write services
        for svc in &layer.diag_services {
            if svc.diag_comm.short_name.starts_with("Write_") {
                let did_id = extract_did_id(svc);
                let key = serde_yaml::Value::Number(serde_yaml::Number::from(did_id as u64));
                if let Some(serde_yaml::Value::Mapping(did_mapping)) = dids_map.get_mut(&key) {
                    did_mapping.insert(
                        serde_yaml::Value::String("writable".into()),
                        serde_yaml::Value::Bool(true),
                    );
                }
            }
        }
    }

    // Convert SDGs
    let sdgs = layer
        .and_then(|l| l.sdgs.as_ref())
        .map(|s| ir_sdgs_to_yaml(s));

    // Convert DTCs
    let dtcs = if !db.dtcs.is_empty() {
        let mut dtc_map = serde_yaml::Mapping::new();
        for dtc in &db.dtcs {
            let key = serde_yaml::Value::Number(serde_yaml::Number::from(dtc.trouble_code as u64));
            let yaml_dtc = YamlDtc {
                name: dtc.short_name.clone(),
                sae: dtc.display_trouble_code.clone(),
                description: dtc.text.as_ref().map(|t| t.value.clone()),
                severity: dtc.level,
                snapshots: None,
                extended_data: None,
                x_oem: None,
            };
            dtc_map.insert(key, serde_yaml::to_value(&yaml_dtc).unwrap_or_default());
        }
        Some(serde_yaml::Value::Mapping(dtc_map))
    } else {
        None
    };

    // Convert ECU jobs
    let ecu_jobs = layer.map(|l| {
        let mut jobs = BTreeMap::new();
        for job in &l.single_ecu_jobs {
            let key = job.diag_comm.short_name.to_lowercase().replace(' ', "_");
            jobs.insert(key, ir_job_to_yaml(job));
        }
        jobs
    }).filter(|j| !j.is_empty());

    YamlDocument {
        schema: db.metadata.get("schema").cloned().unwrap_or_else(|| "opensovd.cda.diagdesc/v1".into()),
        meta,
        ecu,
        audience: None,
        sdgs,
        comparams: None,
        sessions: None,
        state_model: None,
        security: None,
        authentication: None,
        identification: None,
        variants: None,
        services: None,
        access_patterns: None,
        types: if types_map.is_empty() { None } else { Some(types_map) },
        dids: if dids_map.is_empty() { None } else { Some(serde_yaml::Value::Mapping(dids_map)) },
        routines: if routines_map.is_empty() { None } else { Some(serde_yaml::Value::Mapping(routines_map)) },
        dtc_config: None,
        dtcs,
        annotations: None,
        x_oem: None,
        ecu_jobs,
    }
}

/// Extract the DID ID from the request's coded const param.
fn extract_did_id(svc: &DiagService) -> u32 {
    if let Some(req) = &svc.request {
        for param in &req.params {
            if param.short_name == "DID" {
                if let Some(ParamData::CodedConst { coded_value, .. }) = &param.specific_data {
                    return parse_coded_value(coded_value);
                }
            }
        }
    }
    0
}

/// Extract the Routine ID from the request's coded const param.
fn extract_routine_id(svc: &DiagService) -> u32 {
    if let Some(req) = &svc.request {
        for param in &req.params {
            if param.short_name == "RID" {
                if let Some(ParamData::CodedConst { coded_value, .. }) = &param.specific_data {
                    return parse_coded_value(coded_value);
                }
            }
        }
    }
    0
}

fn parse_coded_value(s: &str) -> u32 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

/// Extract DID type info from the service's response DOP.
fn extract_did_type(svc: &DiagService, did_name: &str) -> (serde_yaml::Value, Option<(String, YamlType)>) {
    if let Some(resp) = svc.pos_responses.first() {
        if let Some(param) = resp.params.first() {
            if let Some(ParamData::Value { dop, .. }) = &param.specific_data {
                if let Some(DopData::NormalDop { diag_coded_type, compu_method, unit_ref, internal_constr, .. }) = &dop.specific_data {
                    let mut yaml_type = YamlType {
                        base: String::new(),
                        endian: None,
                        bit_length: None,
                        length: None,
                        min_length: None,
                        max_length: None,
                        encoding: None,
                        termination: None,
                        scale: None,
                        offset: None,
                        unit: unit_ref.as_ref().map(|u| u.display_name.clone()),
                        pattern: None,
                        constraints: None,
                        validation: None,
                        enum_values: None,
                        entries: None,
                        default_text: None,
                        conversion: None,
                        bitmask: None,
                        size: None,
                        fields: None,
                    };

                    if let Some(dct) = diag_coded_type {
                        yaml_type.base = data_type_to_base(&dct.base_data_type);
                        if !dct.is_high_low_byte_order {
                            yaml_type.endian = Some("little".into());
                        } else if matches!(dct.base_data_type, DataType::AUint32 | DataType::AFloat32 | DataType::AFloat64) {
                            yaml_type.endian = Some("big".into());
                        }

                        match &dct.specific_data {
                            Some(DiagCodedTypeData::StandardLength { bit_length, .. }) => {
                                yaml_type.bit_length = Some(*bit_length);
                                yaml_type.base = bit_length_to_base(*bit_length, &yaml_type.base);
                            }
                            Some(DiagCodedTypeData::MinMax { min_length, max_length, termination }) => {
                                yaml_type.min_length = Some(*min_length);
                                yaml_type.max_length = *max_length;
                                yaml_type.termination = Some(match termination {
                                    Termination::Zero => "zero".into(),
                                    Termination::HexFf => "hex_ff".into(),
                                    Termination::EndOfPdu => "end_of_pdu".into(),
                                });
                            }
                            _ => {}
                        }
                    }

                    // Extract scale/offset from CompuMethod
                    if let Some(cm) = compu_method {
                        match cm.category {
                            CompuCategory::Linear => {
                                if let Some(itp) = &cm.internal_to_phys {
                                    if let Some(scale) = itp.compu_scales.first() {
                                        if let Some(rc) = &scale.rational_co_effs {
                                            if rc.numerator.len() >= 2 {
                                                yaml_type.offset = Some(rc.numerator[0]);
                                                yaml_type.scale = Some(rc.numerator[1]);
                                            }
                                        }
                                    }
                                }
                            }
                            CompuCategory::TextTable => {
                                if let Some(itp) = &cm.internal_to_phys {
                                    let mut enum_map = serde_yaml::Mapping::new();
                                    for scale in &itp.compu_scales {
                                        if let (Some(ll), Some(consts)) = (&scale.lower_limit, &scale.consts) {
                                            let key = serde_yaml::Value::String(ll.value.clone());
                                            let val = serde_yaml::Value::String(consts.vt.clone());
                                            enum_map.insert(key, val);
                                        }
                                    }
                                    if !enum_map.is_empty() {
                                        yaml_type.enum_values = Some(serde_yaml::Value::Mapping(enum_map));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }

                    // Extract constraints
                    if let Some(ic) = internal_constr {
                        let mut internal = Vec::new();
                        if let Some(ll) = &ic.lower_limit {
                            internal.push(serde_yaml::Value::String(ll.value.clone()));
                        }
                        if let Some(ul) = &ic.upper_limit {
                            internal.push(serde_yaml::Value::String(ul.value.clone()));
                        }
                        if !internal.is_empty() {
                            yaml_type.constraints = Some(TypeConstraints {
                                internal: Some(internal),
                                physical: None,
                            });
                        }
                    }

                    let type_name = format!("{did_name}_type").to_lowercase();
                    let type_ref = serde_yaml::Value::String(type_name.clone());
                    return (type_ref, Some((type_name, yaml_type)));
                }
            }
        }
    }

    // Fallback: unknown type
    (serde_yaml::Value::Mapping(serde_yaml::Mapping::new()), None)
}

fn data_type_to_base(dt: &DataType) -> String {
    match dt {
        DataType::AUint32 => "u32".into(),
        DataType::AInt32 => "s32".into(),
        DataType::AFloat32 => "f32".into(),
        DataType::AFloat64 => "f64".into(),
        DataType::AAsciiString => "ascii".into(),
        DataType::AUtf8String => "ascii".into(),
        DataType::AUnicode2String => "ascii".into(),
        DataType::ABytefield => "bytes".into(),
    }
}

fn bit_length_to_base(bit_length: u32, current: &str) -> String {
    if current == "ascii" || current == "bytes" {
        return current.to_string();
    }
    let signed = current.starts_with('s') || current.starts_with('i');
    match bit_length {
        1..=8 => if signed { "s8" } else { "u8" }.into(),
        9..=16 => if signed { "s16" } else { "u16" }.into(),
        17..=32 => if signed { "s32" } else { "u32" }.into(),
        33..=64 => if signed { "s64" } else { "u64" }.into(),
        _ => current.to_string(),
    }
}

/// Convert a DiagService back to a Routine YAML model.
fn service_to_routine(svc: &DiagService) -> Routine {
    let mut operations = vec![];
    if svc.request.is_some() {
        operations.push("start".into());
    }
    if !svc.pos_responses.is_empty() {
        operations.push("result".into());
    }

    Routine {
        name: svc.diag_comm.short_name.clone(),
        description: svc.diag_comm.long_name.as_ref().map(|ln| ln.value.clone()),
        access: "public".into(),
        operations,
        parameters: None, // Simplified - could reconstruct from params
        audience: None,
        annotations: None,
    }
}

/// Convert IR SDGs to YAML SDGs.
fn ir_sdgs_to_yaml(sdgs: &Sdgs) -> BTreeMap<String, YamlSdg> {
    let mut map = BTreeMap::new();
    for (i, sdg) in sdgs.sdgs.iter().enumerate() {
        let key = if sdg.caption_sn.is_empty() {
            format!("sdg_{i}")
        } else {
            sdg.caption_sn.to_lowercase().replace(' ', "_")
        };
        map.insert(key, ir_sdg_to_yaml(sdg));
    }
    map
}

fn ir_sdg_to_yaml(sdg: &Sdg) -> YamlSdg {
    let values = sdg.sds.iter().map(|sd_or_sdg| match sd_or_sdg {
        SdOrSdg::Sd(sd) => YamlSdValue {
            si: sd.si.clone(),
            ti: if sd.ti.is_empty() { None } else { Some(sd.ti.clone()) },
            value: Some(sd.value.clone()),
            caption: None,
            values: None,
        },
        SdOrSdg::Sdg(nested) => {
            let nested_yaml = ir_sdg_to_yaml(nested);
            YamlSdValue {
                si: nested.si.clone(),
                ti: None,
                value: None,
                caption: Some(nested.caption_sn.clone()),
                values: Some(nested_yaml.values),
            }
        }
    }).collect();

    YamlSdg {
        si: sdg.si.clone(),
        caption: sdg.caption_sn.clone(),
        values,
    }
}

/// Convert IR SingleEcuJob to YAML EcuJob.
fn ir_job_to_yaml(job: &SingleEcuJob) -> EcuJob {
    let convert_params = |params: &[JobParam]| -> Option<Vec<JobParamDef>> {
        if params.is_empty() {
            return None;
        }
        Some(params.iter().map(|p| JobParamDef {
            name: p.short_name.clone(),
            description: p.long_name.as_ref().map(|ln| ln.value.clone()),
            param_type: serde_yaml::Value::Null,
            semantic: if p.semantic.is_empty() { None } else { Some(p.semantic.clone()) },
            default_value: if p.physical_default_value.is_empty() {
                None
            } else {
                Some(serde_yaml::Value::String(p.physical_default_value.clone()))
            },
        }).collect())
    };

    EcuJob {
        name: job.diag_comm.short_name.clone(),
        description: job.diag_comm.long_name.as_ref().map(|ln| ln.value.clone()),
        prog_code: job.prog_codes.first().map(|pc| pc.code_file.clone()),
        input_params: convert_params(&job.input_params),
        output_params: convert_params(&job.output_params),
        neg_output_params: convert_params(&job.neg_output_params),
        access: None,
        audience: None,
        annotations: None,
    }
}
