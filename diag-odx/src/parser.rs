//! ODX parser: XML string -> DiagDatabase IR.
//!
//! Orchestrates all 4 phases:
//! 1. XML deserialization (odx_model)
//! 2. Reference resolution (ref_resolver)
//! 3. Inheritance merge (inheritance)
//! 4. ODX -> IR mapping (this module)

use std::collections::HashMap;

use diag_ir::*;
use thiserror::Error;

use crate::inheritance::MergedLayer;
use crate::odx_model::{self, Odx};
use crate::ref_resolver::OdxIndex;

#[derive(Debug, Error)]
pub enum OdxParseError {
    #[error("XML deserialization failed: {0}")]
    XmlError(#[from] quick_xml::DeError),
    #[error("Missing required element: {0}")]
    MissingElement(String),
}

/// Parse an ODX XML string into an IR DiagDatabase.
pub fn parse_odx(xml: &str) -> Result<DiagDatabase, OdxParseError> {
    // Phase 1: XML deserialization
    let odx: Odx = quick_xml::de::from_str(xml)?;

    // Phase 2: Build reference index
    let index = OdxIndex::build(&odx);

    // Phase 3 + 4: Merge inheritance and map to IR
    odx_to_ir(&odx, &index)
}

fn odx_to_ir(odx: &Odx, index: &OdxIndex) -> Result<DiagDatabase, OdxParseError> {
    let dlc = odx
        .diag_layer_container
        .as_ref()
        .ok_or_else(|| OdxParseError::MissingElement("DIAG-LAYER-CONTAINER".into()))?;

    let ecu_name = dlc.short_name.clone().unwrap_or_default();
    let revision = extract_revision(&dlc.admin_data);
    let version = odx.version.clone().unwrap_or_default();

    let mut variants = Vec::new();
    let mut all_dtcs = Vec::new();

    // Process base variants
    if let Some(w) = &dlc.base_variants {
        for layer in &w.items {
            let merged = MergedLayer::merge(layer, index);
            let (variant, dtcs) = layer_to_variant(&merged, index, true)?;
            variants.push(variant);
            all_dtcs.extend(dtcs);
        }
    }

    // Process ECU variants
    if let Some(w) = &dlc.ecu_variants {
        for layer in &w.items {
            let merged = MergedLayer::merge(layer, index);
            let (variant, dtcs) = layer_to_variant(&merged, index, false)?;
            variants.push(variant);
            all_dtcs.extend(dtcs);
        }
    }

    let functional_groups = if let Some(w) = &dlc.functional_groups {
        w.items
            .iter()
            .map(|layer| {
                let merged = MergedLayer::merge(layer, index);
                layer_to_functional_group(&merged, index)
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };

    // Dedup DTCs by trouble_code
    dedup_dtcs(&mut all_dtcs);

    Ok(DiagDatabase {
        version,
        ecu_name,
        revision,
        metadata: Default::default(),
        variants,
        functional_groups,
        dtcs: all_dtcs,
        memory: None,
    })
}

fn layer_to_variant(
    merged: &MergedLayer,
    index: &OdxIndex,
    is_base: bool,
) -> Result<(Variant, Vec<Dtc>), OdxParseError> {
    let (diag_layer, dtcs) = build_diag_layer(merged, index)?;

    let variant_patterns = extract_variant_patterns(merged.layer);
    let parent_refs = extract_parent_refs(merged.layer, index);

    Ok((
        Variant {
            diag_layer,
            is_base_variant: is_base,
            variant_patterns,
            parent_refs,
        },
        dtcs,
    ))
}

fn layer_to_functional_group(
    merged: &MergedLayer,
    index: &OdxIndex,
) -> Result<FunctionalGroup, OdxParseError> {
    let (diag_layer, _dtcs) = build_diag_layer(merged, index)?;
    let parent_refs = extract_parent_refs(merged.layer, index);

    Ok(FunctionalGroup {
        diag_layer,
        parent_refs,
    })
}

fn build_diag_layer(
    merged: &MergedLayer,
    index: &OdxIndex,
) -> Result<(DiagLayer, Vec<Dtc>), OdxParseError> {
    let layer = merged.layer;

    // Build request/response lookup for this layer
    let mut req_map: HashMap<&str, &odx_model::OdxRequest> = HashMap::new();
    for r in &merged.requests {
        if let Some(id) = r.id.as_deref() {
            req_map.insert(id, r);
        }
    }
    let mut pos_resp_map: HashMap<&str, &odx_model::OdxResponse> = HashMap::new();
    for r in &merged.pos_responses {
        if let Some(id) = r.id.as_deref() {
            pos_resp_map.insert(id, r);
        }
    }
    let mut neg_resp_map: HashMap<&str, &odx_model::OdxResponse> = HashMap::new();
    for r in &merged.neg_responses {
        if let Some(id) = r.id.as_deref() {
            neg_resp_map.insert(id, r);
        }
    }
    let mut global_neg_map: HashMap<&str, &odx_model::OdxResponse> = HashMap::new();
    for r in &merged.global_neg_responses {
        if let Some(id) = r.id.as_deref() {
            global_neg_map.insert(id, r);
        }
    }

    // Map diag services
    let diag_services: Vec<DiagService> = merged
        .diag_services
        .iter()
        .map(|ds| map_diag_service(ds, index, &req_map, &pos_resp_map, &neg_resp_map))
        .collect();

    // Map single ECU jobs
    let single_ecu_jobs: Vec<SingleEcuJob> = merged
        .single_ecu_jobs
        .iter()
        .map(|job| map_single_ecu_job(job, index))
        .collect();

    // Map state charts
    let state_charts = if let Some(w) = &layer.state_charts {
        w.items.iter().map(map_state_chart).collect()
    } else {
        Vec::new()
    };

    // Map additional audiences
    let additional_audiences = if let Some(w) = &layer.additional_audiences {
        w.items.iter().map(map_additional_audience).collect()
    } else {
        Vec::new()
    };

    // Map funct classes
    let funct_classes = if let Some(w) = &layer.funct_classs {
        w.items
            .iter()
            .map(|fc| diag_ir::FunctClass {
                short_name: fc.short_name.clone().unwrap_or_default(),
            })
            .collect()
    } else {
        Vec::new()
    };

    // Extract DTCs from DTC-DOPs
    let mut dtcs = Vec::new();
    for dtc_dop in &merged.dtc_dops {
        if let Some(w) = &dtc_dop.dtcs {
            for odx_dtc in &w.items {
                dtcs.push(map_dtc(odx_dtc));
            }
        }
    }

    let sdgs = map_sdgs_opt(&layer.sdgs);

    let diag_layer = DiagLayer {
        short_name: layer.short_name.clone().unwrap_or_default(),
        long_name: layer
            .long_name
            .as_ref()
            .map(|ln| LongName {
                value: ln.clone(),
                ti: String::new(),
            }),
        funct_classes,
        com_param_refs: Vec::new(),
        diag_services,
        single_ecu_jobs,
        state_charts,
        additional_audiences,
        sdgs,
    };

    Ok((diag_layer, dtcs))
}

// --- Service mapping ---

fn map_diag_service(
    ds: &odx_model::OdxDiagService,
    index: &OdxIndex,
    req_map: &HashMap<&str, &odx_model::OdxRequest>,
    pos_resp_map: &HashMap<&str, &odx_model::OdxResponse>,
    neg_resp_map: &HashMap<&str, &odx_model::OdxResponse>,
) -> DiagService {
    let request = ds
        .request_ref
        .as_ref()
        .and_then(|r| r.id_ref.as_deref())
        .and_then(|id| req_map.get(id).or_else(|| index.requests.get(id)))
        .map(|r| map_request(r, index));

    let pos_responses = ds
        .pos_response_refs
        .as_ref()
        .map(|w| {
            w.items
                .iter()
                .filter_map(|r| r.id_ref.as_deref())
                .filter_map(|id| pos_resp_map.get(id).or_else(|| index.pos_responses.get(id)))
                .map(|r| map_response(r, index, ResponseType::PosResponse))
                .collect()
        })
        .unwrap_or_default();

    let neg_responses = ds
        .neg_response_refs
        .as_ref()
        .map(|w| {
            w.items
                .iter()
                .filter_map(|r| r.id_ref.as_deref())
                .filter_map(|id| neg_resp_map.get(id).or_else(|| index.neg_responses.get(id)))
                .map(|r| map_response(r, index, ResponseType::NegResponse))
                .collect()
        })
        .unwrap_or_default();

    let audience = ds.audience.as_ref().map(map_audience);

    DiagService {
        diag_comm: DiagComm {
            short_name: ds.short_name.clone().unwrap_or_default(),
            long_name: ds.long_name.as_ref().map(|ln| LongName {
                value: ln.clone(),
                ti: String::new(),
            }),
            semantic: ds.semantic.clone().unwrap_or_default(),
            funct_classes: Vec::new(),
            sdgs: map_sdgs_opt(&ds.sdgs),
            diag_class_type: parse_diag_class(&ds.diagnostic_class),
            pre_condition_state_refs: Vec::new(),
            state_transition_refs: Vec::new(),
            protocols: Vec::new(),
            audience,
            is_mandatory: ds.is_mandatory.as_deref() == Some("true"),
            is_executable: ds.is_executable.as_deref() != Some("false"),
            is_final: ds.is_final.as_deref() == Some("true"),
        },
        request,
        pos_responses,
        neg_responses,
        is_cyclic: ds.is_cyclic.as_deref() == Some("true"),
        is_multiple: ds.is_multiple.as_deref() == Some("true"),
        addressing: parse_addressing(&ds.addressing),
        transmission_mode: parse_transmission_mode(&ds.transmission_mode),
        com_param_refs: Vec::new(),
    }
}

fn map_single_ecu_job(
    job: &odx_model::OdxSingleEcuJob,
    index: &OdxIndex,
) -> SingleEcuJob {
    let prog_codes = job
        .prog_codes
        .as_ref()
        .map(|w| w.items.iter().map(map_prog_code).collect())
        .unwrap_or_default();

    let input_params = job
        .input_params
        .as_ref()
        .map(|w| w.items.iter().map(|p| map_job_param(p, index)).collect())
        .unwrap_or_default();

    let output_params = job
        .output_params
        .as_ref()
        .map(|w| w.items.iter().map(|p| map_job_param(p, index)).collect())
        .unwrap_or_default();

    let neg_output_params = job
        .neg_output_params
        .as_ref()
        .map(|w| w.items.iter().map(|p| map_job_param(p, index)).collect())
        .unwrap_or_default();

    SingleEcuJob {
        diag_comm: DiagComm {
            short_name: job.short_name.clone().unwrap_or_default(),
            long_name: job.long_name.as_ref().map(|ln| LongName {
                value: ln.clone(),
                ti: String::new(),
            }),
            semantic: String::new(),
            funct_classes: Vec::new(),
            sdgs: map_sdgs_opt(&job.sdgs),
            diag_class_type: DiagClassType::StartComm,
            pre_condition_state_refs: Vec::new(),
            state_transition_refs: Vec::new(),
            protocols: Vec::new(),
            audience: None,
            is_mandatory: false,
            is_executable: true,
            is_final: false,
        },
        prog_codes,
        input_params,
        output_params,
        neg_output_params,
    }
}

// --- Request/Response mapping ---

fn map_request(req: &odx_model::OdxRequest, index: &OdxIndex) -> Request {
    Request {
        params: req
            .params
            .as_ref()
            .map(|w| w.items.iter().enumerate().map(|(i, p)| map_param(p, i as u32, index)).collect())
            .unwrap_or_default(),
        sdgs: map_sdgs_opt(&req.sdgs),
    }
}

fn map_response(
    resp: &odx_model::OdxResponse,
    index: &OdxIndex,
    response_type: ResponseType,
) -> Response {
    Response {
        response_type,
        params: resp
            .params
            .as_ref()
            .map(|w| w.items.iter().enumerate().map(|(i, p)| map_param(p, i as u32, index)).collect())
            .unwrap_or_default(),
        sdgs: map_sdgs_opt(&resp.sdgs),
    }
}

// --- Parameter mapping ---

fn map_param(p: &odx_model::OdxParam, id: u32, index: &OdxIndex) -> Param {
    let xsi_type = p.xsi_type.as_deref().unwrap_or("");

    let (param_type, specific_data) = match xsi_type {
        "CODED-CONST" => (
            ParamType::CodedConst,
            Some(ParamData::CodedConst {
                coded_value: p.coded_value.clone().unwrap_or_default(),
                diag_coded_type: p
                    .diag_coded_type
                    .as_ref()
                    .map(map_diag_coded_type)
                    .unwrap_or_else(default_diag_coded_type),
            }),
        ),
        "NRC-CONST" => (
            ParamType::NrcConst,
            Some(ParamData::NrcConst {
                coded_values: p
                    .coded_values
                    .as_ref()
                    .map(|w| w.items.clone())
                    .unwrap_or_default(),
                diag_coded_type: p
                    .diag_coded_type
                    .as_ref()
                    .map(map_diag_coded_type)
                    .unwrap_or_else(default_diag_coded_type),
            }),
        ),
        "VALUE" => {
            let dop = resolve_dop(p, index);
            (
                ParamType::Value,
                Some(ParamData::Value {
                    physical_default_value: p.physical_default_value.clone().unwrap_or_default(),
                    dop: Box::new(dop),
                }),
            )
        }
        "PHYS-CONST" => {
            let dop = resolve_dop(p, index);
            (
                ParamType::PhysConst,
                Some(ParamData::PhysConst {
                    phys_constant_value: p.phys_constant_value.clone().unwrap_or_default(),
                    dop: Box::new(dop),
                }),
            )
        }
        "MATCHING-REQUEST-PARAM" => (
            ParamType::MatchingRequestParam,
            Some(ParamData::MatchingRequestParam {
                request_byte_pos: p.request_byte_pos.unwrap_or(0),
                byte_length: p.match_byte_length.unwrap_or(0),
            }),
        ),
        "RESERVED" => (
            ParamType::Reserved,
            Some(ParamData::Reserved {
                bit_length: p.bit_length.unwrap_or(0),
            }),
        ),
        "SYSTEM" => {
            let dop = resolve_dop(p, index);
            (
                ParamType::System,
                Some(ParamData::System {
                    dop: Box::new(dop),
                    sys_param: String::new(),
                }),
            )
        }
        "LENGTH-KEY" => {
            let dop = resolve_dop(p, index);
            (
                ParamType::LengthKey,
                Some(ParamData::LengthKeyRef {
                    dop: Box::new(dop),
                }),
            )
        }
        "DYNAMIC" => (ParamType::Dynamic, Some(ParamData::Dynamic)),
        _ => (ParamType::Value, None),
    };

    Param {
        id,
        param_type,
        short_name: p.short_name.clone().unwrap_or_default(),
        semantic: p.semantic.clone().unwrap_or_default(),
        sdgs: map_sdgs_opt(&p.sdgs),
        physical_default_value: p.physical_default_value.clone().unwrap_or_default(),
        byte_position: p.byte_position,
        bit_position: p.bit_position,
        specific_data,
    }
}

fn resolve_dop(p: &odx_model::OdxParam, index: &OdxIndex) -> Dop {
    // Try DOP-REF first
    if let Some(dop_ref) = &p.dop_ref {
        if let Some(id) = dop_ref.id_ref.as_deref() {
            if let Some(odx_dop) = index.data_object_props.get(id) {
                return map_data_object_prop(odx_dop, index);
            }
            if let Some(odx_dtc_dop) = index.dtc_dops.get(id) {
                return map_dtc_dop_to_dop(odx_dtc_dop);
            }
            if let Some(odx_struct) = index.structures.get(id) {
                return map_structure_to_dop(odx_struct);
            }
        }
    }

    // Try DOP-SNREF
    if let Some(snref) = &p.dop_snref {
        if let Some(sn) = &snref.short_name {
            for dop in index.data_object_props.values() {
                if dop.short_name.as_deref() == Some(sn.as_str()) {
                    return map_data_object_prop(dop, index);
                }
            }
        }
    }

    // Fallback: empty DOP
    Dop {
        dop_type: DopType::Regular,
        short_name: String::new(),
        sdgs: None,
        specific_data: None,
    }
}

// --- DOP mapping ---

fn map_data_object_prop(dop: &odx_model::OdxDataObjectProp, index: &OdxIndex) -> Dop {
    let diag_coded_type = dop.diag_coded_type.as_ref().map(map_diag_coded_type);
    let physical_type = dop.physical_type.as_ref().map(map_physical_type);
    let compu_method = dop.compu_method.as_ref().map(map_compu_method);
    let internal_constr = dop.internal_constr.as_ref().map(map_internal_constr);
    let phys_constr = dop.phys_constr.as_ref().map(map_internal_constr);

    let unit_ref = dop
        .unit_ref
        .as_ref()
        .and_then(|r| r.id_ref.as_deref())
        .and_then(|id| index.units.get(id))
        .map(|u| map_unit(u, index));

    Dop {
        dop_type: DopType::Regular,
        short_name: dop.short_name.clone().unwrap_or_default(),
        sdgs: map_sdgs_opt(&dop.sdgs),
        specific_data: Some(DopData::NormalDop {
            compu_method,
            diag_coded_type,
            physical_type,
            internal_constr,
            unit_ref,
            phys_constr,
        }),
    }
}

fn map_dtc_dop_to_dop(dop: &odx_model::OdxDtcDop) -> Dop {
    let dtcs = dop
        .dtcs
        .as_ref()
        .map(|w| w.items.iter().map(map_dtc).collect())
        .unwrap_or_default();

    Dop {
        dop_type: DopType::Dtc,
        short_name: dop.short_name.clone().unwrap_or_default(),
        sdgs: map_sdgs_opt(&dop.sdgs),
        specific_data: Some(DopData::DtcDop {
            diag_coded_type: dop.diag_coded_type.as_ref().map(map_diag_coded_type),
            physical_type: dop.physical_type.as_ref().map(map_physical_type),
            compu_method: dop.compu_method.as_ref().map(map_compu_method),
            dtcs,
            is_visible: dop.is_visible.as_deref() != Some("false"),
        }),
    }
}

fn map_structure_to_dop(s: &odx_model::OdxStructure) -> Dop {
    Dop {
        dop_type: DopType::Structure,
        short_name: s.short_name.clone().unwrap_or_default(),
        sdgs: map_sdgs_opt(&s.sdgs),
        specific_data: Some(DopData::Structure {
            params: Vec::new(),
            byte_size: s.byte_size,
            is_visible: true,
        }),
    }
}

// --- Type mapping ---

fn map_diag_coded_type(dct: &odx_model::OdxDiagCodedType) -> DiagCodedType {
    let xsi_type = dct.xsi_type.as_deref().unwrap_or("STANDARD-LENGTH-TYPE");
    let base_data_type = parse_data_type(dct.base_data_type.as_deref());
    let is_high_low = dct.is_highlow_byte_order.as_deref() != Some("false");

    let (type_name, specific_data) = match xsi_type {
        "MIN-MAX-LENGTH-TYPE" => (
            DiagCodedTypeName::MinMaxLengthType,
            Some(DiagCodedTypeData::MinMax {
                min_length: dct.min_length.unwrap_or(0),
                max_length: dct.max_length,
                termination: parse_termination(dct.termination.as_deref()),
            }),
        ),
        "LEADING-LENGTH-INFO-TYPE" => (
            DiagCodedTypeName::LeadingLengthInfoType,
            Some(DiagCodedTypeData::LeadingLength {
                bit_length: dct.bit_length.unwrap_or(0),
            }),
        ),
        "PARAM-LENGTH-INFO-TYPE" => (
            DiagCodedTypeName::ParamLengthInfoType,
            None, // length_key handled separately
        ),
        _ => (
            DiagCodedTypeName::StandardLengthType,
            Some(DiagCodedTypeData::StandardLength {
                bit_length: dct.bit_length.unwrap_or(0),
                bit_mask: dct
                    .bit_mask
                    .as_ref()
                    .map(|s| hex_to_bytes(s))
                    .unwrap_or_default(),
                condensed: dct.is_condensed.as_deref() == Some("true"),
            }),
        ),
    };

    DiagCodedType {
        type_name,
        base_type_encoding: dct.base_type_encoding.clone().unwrap_or_default(),
        base_data_type,
        is_high_low_byte_order: is_high_low,
        specific_data,
    }
}

fn default_diag_coded_type() -> DiagCodedType {
    DiagCodedType {
        type_name: DiagCodedTypeName::StandardLengthType,
        base_type_encoding: String::new(),
        base_data_type: DataType::AUint32,
        is_high_low_byte_order: true,
        specific_data: Some(DiagCodedTypeData::StandardLength {
            bit_length: 8,
            bit_mask: Vec::new(),
            condensed: false,
        }),
    }
}

fn map_compu_method(cm: &odx_model::OdxCompuMethod) -> CompuMethod {
    let category = parse_compu_category(cm.category.as_deref());

    CompuMethod {
        category,
        internal_to_phys: cm
            .compu_internal_to_phys
            .as_ref()
            .map(map_compu_internal_to_phys),
        phys_to_internal: cm
            .compu_phys_to_internal
            .as_ref()
            .map(map_compu_phys_to_internal),
    }
}

fn map_compu_internal_to_phys(
    citp: &odx_model::OdxCompuInternalToPhys,
) -> CompuInternalToPhys {
    CompuInternalToPhys {
        compu_scales: citp
            .compu_scales
            .as_ref()
            .map(|w| w.items.iter().map(map_compu_scale).collect())
            .unwrap_or_default(),
        prog_code: citp.prog_code.as_ref().map(map_prog_code),
        compu_default_value: citp.compu_default_value.as_ref().map(map_compu_default_value),
    }
}

fn map_compu_phys_to_internal(
    cpti: &odx_model::OdxCompuPhysToInternal,
) -> CompuPhysToInternal {
    CompuPhysToInternal {
        compu_scales: cpti
            .compu_scales
            .as_ref()
            .map(|w| w.items.iter().map(map_compu_scale).collect())
            .unwrap_or_default(),
        prog_code: cpti.prog_code.as_ref().map(map_prog_code),
        compu_default_value: cpti.compu_default_value.as_ref().map(map_compu_default_value),
    }
}

fn map_compu_scale(cs: &odx_model::OdxCompuScale) -> CompuScale {
    CompuScale {
        short_label: cs.short_label.as_ref().map(|s| Text {
            value: s.clone(),
            ti: String::new(),
        }),
        lower_limit: cs.lower_limit.as_ref().map(map_limit),
        upper_limit: cs.upper_limit.as_ref().map(map_limit),
        inverse_values: cs.compu_inverse_value.as_ref().map(map_compu_values),
        consts: cs.compu_const.as_ref().map(map_compu_values),
        rational_co_effs: cs.compu_rational_coeffs.as_ref().map(map_rational_coeffs),
    }
}

fn map_compu_values(cv: &odx_model::OdxCompuValues) -> CompuValues {
    CompuValues {
        v: cv.v.as_ref().and_then(|s| s.parse().ok()),
        vt: cv.vt.clone().unwrap_or_default(),
        vt_ti: String::new(),
    }
}

fn map_compu_default_value(dv: &odx_model::OdxCompuDefaultValue) -> CompuDefaultValue {
    CompuDefaultValue {
        values: Some(CompuValues {
            v: dv.v.as_ref().and_then(|s| s.parse().ok()),
            vt: dv.vt.clone().unwrap_or_default(),
            vt_ti: String::new(),
        }),
        inverse_values: None,
    }
}

fn map_rational_coeffs(rc: &odx_model::OdxCompuRationalCoeffs) -> CompuRationalCoEffs {
    CompuRationalCoEffs {
        numerator: rc
            .compu_numerator
            .as_ref()
            .map(|w| w.items.iter().filter_map(|s| s.parse().ok()).collect())
            .unwrap_or_default(),
        denominator: rc
            .compu_denominator
            .as_ref()
            .map(|w| w.items.iter().filter_map(|s| s.parse().ok()).collect())
            .unwrap_or_default(),
    }
}

fn map_limit(lim: &odx_model::OdxLimit) -> Limit {
    Limit {
        value: lim.value.clone().unwrap_or_default(),
        interval_type: match lim.interval_type.as_deref() {
            Some("OPEN") => IntervalType::Open,
            Some("INFINITE") => IntervalType::Infinite,
            _ => IntervalType::Closed,
        },
    }
}

fn map_physical_type(pt: &odx_model::OdxPhysicalType) -> PhysicalType {
    PhysicalType {
        precision: pt.precision,
        base_data_type: parse_physical_data_type(pt.base_data_type.as_deref()),
        display_radix: match pt.display_radix.as_deref() {
            Some("HEX") => Radix::Hex,
            Some("BIN") => Radix::Bin,
            Some("OCT") => Radix::Oct,
            _ => Radix::Dec,
        },
    }
}

fn map_internal_constr(ic: &odx_model::OdxInternalConstr) -> InternalConstr {
    InternalConstr {
        lower_limit: ic.lower_limit.as_ref().map(map_limit),
        upper_limit: ic.upper_limit.as_ref().map(map_limit),
        scale_constrs: ic
            .scale_constrs
            .as_ref()
            .map(|w| w.items.iter().map(map_scale_constr).collect())
            .unwrap_or_default(),
    }
}

fn map_scale_constr(sc: &odx_model::OdxScaleConstr) -> ScaleConstr {
    ScaleConstr {
        short_label: sc.short_label.as_ref().map(|s| Text {
            value: s.clone(),
            ti: String::new(),
        }),
        lower_limit: sc.lower_limit.as_ref().map(map_limit),
        upper_limit: sc.upper_limit.as_ref().map(map_limit),
        validity: match sc.validity.as_deref() {
            Some("VALID") => ValidType::Valid,
            Some("NOT-VALID") => ValidType::NotValid,
            Some("NOT-AVAILABLE") => ValidType::NotAvailable,
            _ => ValidType::NotDefined,
        },
    }
}

// --- Unit mapping ---

fn map_unit(u: &odx_model::OdxUnit, index: &OdxIndex) -> Unit {
    let physical_dimension = u
        .physical_dimension_ref
        .as_ref()
        .and_then(|r| r.id_ref.as_deref())
        .and_then(|id| index.physical_dimensions.get(id))
        .map(|pd| map_physical_dimension(pd));

    Unit {
        short_name: u.short_name.clone().unwrap_or_default(),
        display_name: u.display_name.clone().unwrap_or_default(),
        factor_si_to_unit: u.factor_si_to_unit,
        offset_si_to_unit: u.offset_si_to_unit,
        physical_dimension,
    }
}

fn map_physical_dimension(pd: &odx_model::OdxPhysicalDimension) -> PhysicalDimension {
    PhysicalDimension {
        short_name: pd.short_name.clone().unwrap_or_default(),
        long_name: None,
        length_exp: pd.length_exp,
        mass_exp: pd.mass_exp,
        time_exp: pd.time_exp,
        current_exp: pd.current_exp,
        temperature_exp: pd.temperature_exp,
        molar_amount_exp: pd.molar_amount_exp,
        luminous_intensity_exp: pd.luminous_intensity_exp,
    }
}

// --- DTC mapping ---

fn map_dtc(dtc: &odx_model::OdxDtc) -> Dtc {
    Dtc {
        short_name: dtc.short_name.clone().unwrap_or_default(),
        trouble_code: dtc.trouble_code.unwrap_or(0),
        display_trouble_code: dtc.display_trouble_code.clone().unwrap_or_default(),
        text: dtc.text.as_ref().map(|t| Text {
            value: t.value.clone().unwrap_or_default(),
            ti: t.ti.clone().unwrap_or_default(),
        }),
        level: dtc.level,
        sdgs: map_sdgs_opt(&dtc.sdgs),
        is_temporary: dtc.is_temporary.as_deref() == Some("true"),
    }
}

// --- StateChart mapping ---

fn map_state_chart(sc: &odx_model::OdxStateChart) -> StateChart {
    StateChart {
        short_name: sc.short_name.clone().unwrap_or_default(),
        semantic: sc.semantic.clone().unwrap_or_default(),
        start_state_short_name_ref: sc
            .start_state_snref
            .as_ref()
            .and_then(|s| s.short_name.clone())
            .unwrap_or_default(),
        states: sc
            .states
            .as_ref()
            .map(|w| {
                w.items
                    .iter()
                    .map(|s| State {
                        short_name: s.short_name.clone().unwrap_or_default(),
                        long_name: s.long_name.as_ref().map(|ln| LongName {
                            value: ln.clone(),
                            ti: String::new(),
                        }),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        state_transitions: sc
            .state_transitions
            .as_ref()
            .map(|w| {
                w.items
                    .iter()
                    .map(|t| StateTransition {
                        short_name: t.short_name.clone().unwrap_or_default(),
                        source_short_name_ref: t
                            .source_snref
                            .as_ref()
                            .and_then(|s| s.short_name.clone())
                            .unwrap_or_default(),
                        target_short_name_ref: t
                            .target_snref
                            .as_ref()
                            .and_then(|s| s.short_name.clone())
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

// --- Misc mapping ---

fn map_additional_audience(aa: &odx_model::OdxAdditionalAudience) -> AdditionalAudience {
    AdditionalAudience {
        short_name: aa.short_name.clone().unwrap_or_default(),
        long_name: aa.long_name.as_ref().map(|ln| LongName {
            value: ln.clone(),
            ti: String::new(),
        }),
    }
}

fn map_audience(aud: &odx_model::OdxAudience) -> Audience {
    Audience {
        enabled_audiences: Vec::new(),
        disabled_audiences: Vec::new(),
        is_supplier: aud.is_supplier.as_deref() == Some("true"),
        is_development: aud.is_development.as_deref() == Some("true"),
        is_manufacturing: aud.is_manufacturing.as_deref() == Some("true"),
        is_after_sales: aud.is_aftersales.as_deref() == Some("true"),
        is_after_market: aud.is_aftermarket.as_deref() == Some("true"),
    }
}

fn map_prog_code(pc: &odx_model::OdxProgCode) -> ProgCode {
    ProgCode {
        code_file: pc.code_file.clone().unwrap_or_default(),
        encryption: pc.encryption.clone().unwrap_or_default(),
        syntax: pc.syntax.clone().unwrap_or_default(),
        revision: pc.revision.clone().unwrap_or_default(),
        entrypoint: pc.entrypoint.clone().unwrap_or_default(),
        libraries: Vec::new(),
    }
}

fn map_job_param(jp: &odx_model::OdxJobParam, index: &OdxIndex) -> JobParam {
    let dop_base = jp.dop_base_ref.as_ref().and_then(|r| {
        r.id_ref.as_deref().and_then(|id| {
            index
                .data_object_props
                .get(id)
                .map(|dop| Box::new(map_data_object_prop(dop, index)))
                .or_else(|| {
                    index
                        .structures
                        .get(id)
                        .map(|s| Box::new(map_structure_to_dop(s)))
                })
        })
    });

    JobParam {
        short_name: jp.short_name.clone().unwrap_or_default(),
        long_name: jp.long_name.as_ref().map(|ln| LongName {
            value: ln.clone(),
            ti: String::new(),
        }),
        physical_default_value: jp.physical_default_value.clone().unwrap_or_default(),
        dop_base,
        semantic: jp.semantic.clone().unwrap_or_default(),
    }
}

fn extract_variant_patterns(layer: &odx_model::DiagLayerVariant) -> Vec<VariantPattern> {
    layer
        .ecu_variant_patterns
        .as_ref()
        .map(|w| {
            w.items
                .iter()
                .map(|p| VariantPattern {
                    matching_parameters: p
                        .matching_parameters
                        .as_ref()
                        .map(|w| {
                            w.items
                                .iter()
                                .map(|mp| MatchingParameter {
                                    expected_value: mp.expected_value.clone().unwrap_or_default(),
                                    diag_service: Box::new(DiagService {
                                        diag_comm: DiagComm {
                                            short_name: mp
                                                .diag_comm_snref
                                                .as_ref()
                                                .and_then(|s| s.short_name.clone())
                                                .unwrap_or_default(),
                                            ..Default::default()
                                        },
                                        ..Default::default()
                                    }),
                                    out_param: Box::new(Param {
                                        short_name: mp
                                            .out_param_snref
                                            .as_ref()
                                            .and_then(|s| s.short_name.clone())
                                            .unwrap_or_default(),
                                        ..Default::default()
                                    }),
                                    use_physical_addressing: None,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_parent_refs(
    layer: &odx_model::DiagLayerVariant,
    _index: &OdxIndex,
) -> Vec<ParentRef> {
    layer
        .parent_refs
        .as_ref()
        .map(|w| {
            w.items
                .iter()
                .map(|pref| {
                    let not_inherited_diag_comm_short_names = pref
                        .not_inherited_diag_comms
                        .as_ref()
                        .map(|w| {
                            w.items
                                .iter()
                                .filter_map(|ni| {
                                    ni.snref.as_ref().and_then(|s| s.short_name.clone())
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    let not_inherited_dops_short_names = pref
                        .not_inherited_dops
                        .as_ref()
                        .map(|w| {
                            w.items
                                .iter()
                                .filter_map(|ni| {
                                    ni.snref.as_ref().and_then(|s| s.short_name.clone())
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    let not_inherited_tables_short_names = pref
                        .not_inherited_tables
                        .as_ref()
                        .map(|w| {
                            w.items
                                .iter()
                                .filter_map(|ni| {
                                    ni.snref.as_ref().and_then(|s| s.short_name.clone())
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    let not_inherited_global_neg_responses_short_names = pref
                        .not_inherited_global_neg_responses
                        .as_ref()
                        .map(|w| {
                            w.items
                                .iter()
                                .filter_map(|ni| {
                                    ni.snref.as_ref().and_then(|s| s.short_name.clone())
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    // Create a stub variant for the parent ref
                    // In a full implementation, this would resolve to the actual parent
                    ParentRef {
                        ref_type: ParentRefType::Variant(Box::new(Variant {
                            diag_layer: DiagLayer {
                                short_name: String::new(),
                                ..Default::default()
                            },
                            is_base_variant: true,
                            variant_patterns: Vec::new(),
                            parent_refs: Vec::new(),
                        })),
                        not_inherited_diag_comm_short_names,
                        not_inherited_variables_short_names: Vec::new(),
                        not_inherited_dops_short_names,
                        not_inherited_tables_short_names,
                        not_inherited_global_neg_responses_short_names,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

// --- SDG mapping ---

fn map_sdgs_opt(sdgs: &Option<odx_model::SdgsWrapper>) -> Option<Sdgs> {
    sdgs.as_ref().map(|w| Sdgs {
        sdgs: w.items.iter().map(map_sdg).collect(),
    })
}

fn map_sdg(sdg: &odx_model::OdxSdg) -> Sdg {
    let mut sds = Vec::new();

    for sd in &sdg.sds {
        sds.push(SdOrSdg::Sd(Sd {
            value: sd.value.clone().unwrap_or_default(),
            si: sd.si.clone().unwrap_or_default(),
            ti: String::new(),
        }));
    }

    for nested in &sdg.nested_sdgs {
        sds.push(SdOrSdg::Sdg(map_sdg(nested)));
    }

    Sdg {
        caption_sn: sdg
            .sdg_caption
            .as_ref()
            .and_then(|c| c.short_name.clone())
            .or_else(|| sdg.gid.clone())
            .unwrap_or_default(),
        sds,
        si: sdg.si.clone().unwrap_or_default(),
    }
}

// --- Helper functions ---

fn extract_revision(admin_data: &Option<odx_model::AdminData>) -> String {
    admin_data
        .as_ref()
        .and_then(|ad| ad.doc_revisions.as_ref())
        .and_then(|w| w.items.first())
        .and_then(|r| r.revision_label.clone())
        .unwrap_or_default()
}

fn dedup_dtcs(dtcs: &mut Vec<Dtc>) {
    let mut seen = std::collections::HashSet::new();
    dtcs.retain(|dtc| seen.insert(dtc.trouble_code));
}

fn parse_data_type(s: Option<&str>) -> DataType {
    match s {
        Some("A_INT32") => DataType::AInt32,
        Some("A_UINT32") => DataType::AUint32,
        Some("A_FLOAT32") => DataType::AFloat32,
        Some("A_FLOAT64") => DataType::AFloat64,
        Some("A_ASCIISTRING") => DataType::AAsciiString,
        Some("A_UTF8STRING") => DataType::AUtf8String,
        Some("A_UNICODE2STRING") => DataType::AUnicode2String,
        Some("A_BYTEFIELD") => DataType::ABytefield,
        _ => DataType::AUint32,
    }
}

fn parse_physical_data_type(s: Option<&str>) -> PhysicalTypeDataType {
    match s {
        Some("A_INT32") => PhysicalTypeDataType::AInt32,
        Some("A_UINT32") => PhysicalTypeDataType::AUint32,
        Some("A_FLOAT32") => PhysicalTypeDataType::AFloat32,
        Some("A_FLOAT64") => PhysicalTypeDataType::AFloat64,
        Some("A_ASCIISTRING") => PhysicalTypeDataType::AAsciiString,
        Some("A_UTF8STRING") => PhysicalTypeDataType::AUtf8String,
        Some("A_UNICODE2STRING") => PhysicalTypeDataType::AUnicode2String,
        Some("A_BYTEFIELD") => PhysicalTypeDataType::ABytefield,
        _ => PhysicalTypeDataType::AFloat64,
    }
}

fn parse_compu_category(s: Option<&str>) -> CompuCategory {
    match s {
        Some("IDENTICAL") => CompuCategory::Identical,
        Some("LINEAR") => CompuCategory::Linear,
        Some("SCALE-LINEAR") => CompuCategory::ScaleLinear,
        Some("TEXTTABLE") => CompuCategory::TextTable,
        Some("COMPUCODE") => CompuCategory::CompuCode,
        Some("TAB-INTP") => CompuCategory::TabIntp,
        Some("RAT-FUNC") => CompuCategory::RatFunc,
        Some("SCALE-RAT-FUNC") => CompuCategory::ScaleRatFunc,
        _ => CompuCategory::Identical,
    }
}

fn parse_termination(s: Option<&str>) -> Termination {
    match s {
        Some("ZERO") => Termination::Zero,
        Some("HEX-FF") => Termination::HexFf,
        _ => Termination::EndOfPdu,
    }
}

fn parse_diag_class(s: &Option<String>) -> DiagClassType {
    match s.as_deref() {
        Some("STARTCOMM") => DiagClassType::StartComm,
        Some("STOPCOMM") => DiagClassType::StopComm,
        Some("VARIANTIDENTIFICATION") => DiagClassType::VariantIdentification,
        Some("READDYNDEFMESSAGE") => DiagClassType::ReadDynDefMessage,
        Some("DYNDEFMESSAGE") => DiagClassType::DynDefMessage,
        Some("CLEARDYNDEFMESSAGE") => DiagClassType::ClearDynDefMessage,
        _ => DiagClassType::StartComm,
    }
}

fn parse_addressing(s: &Option<String>) -> Addressing {
    match s.as_deref() {
        Some("FUNCTIONAL") => Addressing::Functional,
        Some("PHYSICAL") => Addressing::Physical,
        Some("FUNCTIONAL-OR-PHYSICAL") => Addressing::FunctionalOrPhysical,
        _ => Addressing::Physical,
    }
}

fn parse_transmission_mode(s: &Option<String>) -> TransmissionMode {
    match s.as_deref() {
        Some("SEND-ONLY") | Some("SEND") => TransmissionMode::SendOnly,
        Some("RECEIVE-ONLY") | Some("RECEIVE") => TransmissionMode::ReceiveOnly,
        Some("SEND-AND-RECEIVE") => TransmissionMode::SendAndReceive,
        Some("SEND-OR-RECEIVE") => TransmissionMode::SendOrReceive,
        _ => TransmissionMode::SendAndReceive,
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2.min(hex.len() - i)], 16).ok())
        .collect()
}
