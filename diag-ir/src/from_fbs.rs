use crate::types::*;
use mdd_format::dataformat;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("FlatBuffers parse error: {0}")]
    FlatBuffersParse(String),
}

/// Convert FlatBuffers EcuData bytes to IR DiagDatabase.
pub fn flatbuffers_to_ir(fbs_data: &[u8]) -> Result<DiagDatabase, ConversionError> {
    let ecu_data = dataformat::root_as_ecu_data(fbs_data)
        .map_err(|e| ConversionError::FlatBuffersParse(e.to_string()))?;

    let mut metadata = std::collections::BTreeMap::new();
    if let Some(kv_vec) = ecu_data.metadata() {
        for i in 0..kv_vec.len() {
            let kv = kv_vec.get(i);
            if let (Some(k), Some(v)) = (kv.key(), kv.value()) {
                metadata.insert(k.to_string(), v.to_string());
            }
        }
    }

    let variants = ecu_data
        .variants()
        .map(|v| (0..v.len()).map(|i| convert_variant(&v.get(i))).collect())
        .unwrap_or_default();

    let functional_groups = ecu_data
        .functional_groups()
        .map(|v| (0..v.len()).map(|i| convert_functional_group(&v.get(i))).collect())
        .unwrap_or_default();

    let dtcs = ecu_data
        .dtcs()
        .map(|v| (0..v.len()).map(|i| convert_dtc(&v.get(i))).collect())
        .unwrap_or_default();

    Ok(DiagDatabase {
        version: ecu_data.version().unwrap_or("").to_string(),
        ecu_name: ecu_data.ecu_name().unwrap_or("").to_string(),
        revision: ecu_data.revision().unwrap_or("").to_string(),
        metadata,
        variants,
        functional_groups,
        dtcs,
        memory: ecu_data.memory().map(|m| convert_memory_config(&m)),
        type_definitions: vec![],
    })
}

fn s(opt: Option<&str>) -> String {
    opt.unwrap_or("").to_string()
}

fn convert_variant(v: &dataformat::Variant<'_>) -> Variant {
    Variant {
        diag_layer: v.diag_layer().map(|dl| convert_diag_layer(&dl)).unwrap_or_else(empty_diag_layer),
        is_base_variant: v.is_base_variant(),
        variant_patterns: v.variant_pattern()
            .map(|vp| (0..vp.len()).map(|i| convert_variant_pattern(&vp.get(i))).collect())
            .unwrap_or_default(),
        parent_refs: v.parent_refs()
            .map(|pr| (0..pr.len()).map(|i| convert_parent_ref(&pr.get(i))).collect())
            .unwrap_or_default(),
    }
}

fn convert_functional_group(fg: &dataformat::FunctionalGroup<'_>) -> FunctionalGroup {
    FunctionalGroup {
        diag_layer: fg.diag_layer().map(|dl| convert_diag_layer(&dl)).unwrap_or_else(empty_diag_layer),
        parent_refs: fg.parent_refs()
            .map(|pr| (0..pr.len()).map(|i| convert_parent_ref(&pr.get(i))).collect())
            .unwrap_or_default(),
    }
}

fn empty_diag_layer() -> DiagLayer {
    DiagLayer {
        short_name: String::new(),
        long_name: None,
        funct_classes: vec![],
        com_param_refs: vec![],
        diag_services: vec![],
        single_ecu_jobs: vec![],
        state_charts: vec![],
        additional_audiences: vec![],
        sdgs: None,
    }
}

fn convert_diag_layer(dl: &dataformat::DiagLayer<'_>) -> DiagLayer {
    DiagLayer {
        short_name: s(dl.short_name()),
        long_name: dl.long_name().map(|ln| convert_long_name(&ln)),
        funct_classes: dl.funct_classes()
            .map(|v| (0..v.len()).map(|i| FunctClass { short_name: s(v.get(i).short_name()) }).collect())
            .unwrap_or_default(),
        com_param_refs: dl.com_param_refs()
            .map(|v| (0..v.len()).map(|i| convert_com_param_ref(&v.get(i))).collect())
            .unwrap_or_default(),
        diag_services: dl.diag_services()
            .map(|v| (0..v.len()).map(|i| convert_diag_service(&v.get(i))).collect())
            .unwrap_or_default(),
        single_ecu_jobs: dl.single_ecu_jobs()
            .map(|v| (0..v.len()).map(|i| convert_single_ecu_job(&v.get(i))).collect())
            .unwrap_or_default(),
        state_charts: dl.state_charts()
            .map(|v| (0..v.len()).map(|i| convert_state_chart(&v.get(i))).collect())
            .unwrap_or_default(),
        additional_audiences: dl.additional_audiences()
            .map(|v| (0..v.len()).map(|i| convert_additional_audience(&v.get(i))).collect())
            .unwrap_or_default(),
        sdgs: dl.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
    }
}

fn convert_diag_service(ds: &dataformat::DiagService<'_>) -> DiagService {
    DiagService {
        diag_comm: ds.diag_comm().map(|dc| convert_diag_comm(&dc)).unwrap_or_else(empty_diag_comm),
        request: ds.request().map(|r| convert_request(&r)),
        pos_responses: ds.pos_responses()
            .map(|v| (0..v.len()).map(|i| convert_response(&v.get(i))).collect())
            .unwrap_or_default(),
        neg_responses: ds.neg_responses()
            .map(|v| (0..v.len()).map(|i| convert_response(&v.get(i))).collect())
            .unwrap_or_default(),
        is_cyclic: ds.is_cyclic(),
        is_multiple: ds.is_multiple(),
        addressing: convert_addressing(ds.addressing()),
        transmission_mode: convert_transmission_mode(ds.transmission_mode()),
        com_param_refs: ds.com_param_refs()
            .map(|v| (0..v.len()).map(|i| convert_com_param_ref(&v.get(i))).collect())
            .unwrap_or_default(),
    }
}

fn empty_diag_comm() -> DiagComm {
    DiagComm {
        short_name: String::new(),
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
    }
}

fn convert_diag_comm(dc: &dataformat::DiagComm<'_>) -> DiagComm {
    DiagComm {
        short_name: s(dc.short_name()),
        long_name: dc.long_name().map(|ln| convert_long_name(&ln)),
        semantic: s(dc.semantic()),
        funct_classes: dc.funct_class()
            .map(|v| (0..v.len()).map(|i| FunctClass { short_name: s(v.get(i).short_name()) }).collect())
            .unwrap_or_default(),
        sdgs: dc.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
        diag_class_type: convert_diag_class_type(dc.diag_class_type()),
        pre_condition_state_refs: dc.pre_condition_state_refs()
            .map(|v| (0..v.len()).map(|i| convert_pre_condition_state_ref(&v.get(i))).collect())
            .unwrap_or_default(),
        state_transition_refs: dc.state_transition_refs()
            .map(|v| (0..v.len()).map(|i| convert_state_transition_ref(&v.get(i))).collect())
            .unwrap_or_default(),
        protocols: dc.protocols()
            .map(|v| (0..v.len()).map(|i| convert_protocol(&v.get(i))).collect())
            .unwrap_or_default(),
        audience: dc.audience().map(|a| convert_audience(&a)),
        is_mandatory: dc.is_mandatory(),
        is_executable: dc.is_executable(),
        is_final: dc.is_final(),
    }
}

fn convert_request(r: &dataformat::Request<'_>) -> Request {
    Request {
        params: r.params()
            .map(|v| (0..v.len()).map(|i| convert_param(&v.get(i))).collect())
            .unwrap_or_default(),
        sdgs: r.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
    }
}

fn convert_response(r: &dataformat::Response<'_>) -> Response {
    Response {
        response_type: convert_response_type(r.response_type()),
        params: r.params()
            .map(|v| (0..v.len()).map(|i| convert_param(&v.get(i))).collect())
            .unwrap_or_default(),
        sdgs: r.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
    }
}

fn convert_param(p: &dataformat::Param<'_>) -> Param {
    Param {
        id: p.id(),
        param_type: convert_param_type(p.param_type()),
        short_name: s(p.short_name()),
        semantic: s(p.semantic()),
        sdgs: p.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
        physical_default_value: s(p.physical_default_value()),
        byte_position: p.byte_position(),
        bit_position: p.bit_position(),
        specific_data: convert_param_specific_data(p),
    }
}

fn convert_param_specific_data(p: &dataformat::Param<'_>) -> Option<ParamData> {
    let sd_type = p.specific_data_type();
    match sd_type {
        dataformat::ParamSpecificData::CodedConst => {
            p.specific_data_as_coded_const().map(|cc| ParamData::CodedConst {
                coded_value: s(cc.coded_value()),
                diag_coded_type: cc.diag_coded_type().map(|dct| convert_diag_coded_type(&dct))
                    .unwrap_or_else(empty_diag_coded_type),
            })
        }
        dataformat::ParamSpecificData::Dynamic => Some(ParamData::Dynamic),
        dataformat::ParamSpecificData::LengthKeyRef => {
            p.specific_data_as_length_key_ref().map(|lkr| ParamData::LengthKeyRef {
                dop: Box::new(lkr.dop().map(|d| convert_dop(&d)).unwrap_or_else(empty_dop)),
            })
        }
        dataformat::ParamSpecificData::MatchingRequestParam => {
            p.specific_data_as_matching_request_param().map(|mrp| ParamData::MatchingRequestParam {
                request_byte_pos: mrp.request_byte_pos(),
                byte_length: mrp.byte_length(),
            })
        }
        dataformat::ParamSpecificData::NrcConst => {
            p.specific_data_as_nrc_const().map(|nc| ParamData::NrcConst {
                coded_values: nc.coded_values()
                    .map(|v| (0..v.len()).map(|i| v.get(i).to_string()).collect())
                    .unwrap_or_default(),
                diag_coded_type: nc.diag_coded_type().map(|dct| convert_diag_coded_type(&dct))
                    .unwrap_or_else(empty_diag_coded_type),
            })
        }
        dataformat::ParamSpecificData::PhysConst => {
            p.specific_data_as_phys_const().map(|pc| ParamData::PhysConst {
                phys_constant_value: s(pc.phys_constant_value()),
                dop: Box::new(pc.dop().map(|d| convert_dop(&d)).unwrap_or_else(empty_dop)),
            })
        }
        dataformat::ParamSpecificData::Reserved => {
            p.specific_data_as_reserved().map(|r| ParamData::Reserved {
                bit_length: r.bit_length(),
            })
        }
        dataformat::ParamSpecificData::System => {
            p.specific_data_as_system().map(|sys| ParamData::System {
                dop: Box::new(sys.dop().map(|d| convert_dop(&d)).unwrap_or_else(empty_dop)),
                sys_param: s(sys.sys_param()),
            })
        }
        dataformat::ParamSpecificData::Value => {
            p.specific_data_as_value().map(|v| ParamData::Value {
                physical_default_value: s(v.physical_default_value()),
                dop: Box::new(v.dop().map(|d| convert_dop(&d)).unwrap_or_else(empty_dop)),
            })
        }
        dataformat::ParamSpecificData::TableEntry => {
            p.specific_data_as_table_entry().map(|te| ParamData::TableEntry {
                param: Box::new(te.param().map(|p| convert_param(&p)).unwrap_or_else(empty_param)),
                target: convert_table_entry_row_fragment(te.target()),
                table_row: Box::new(te.table_row().map(|tr| convert_table_row(&tr)).unwrap_or_else(empty_table_row)),
            })
        }
        dataformat::ParamSpecificData::TableKey => {
            p.specific_data_as_table_key().map(|tk| {
                let table_key_reference = match tk.table_key_reference_type() {
                    dataformat::TableKeyReference::TableDop => {
                        tk.table_key_reference_as_table_dop()
                            .map(|td| TableKeyReference::TableDop(Box::new(convert_table_dop(&td))))
                            .unwrap_or(TableKeyReference::TableDop(Box::new(empty_table_dop())))
                    }
                    dataformat::TableKeyReference::TableRow => {
                        tk.table_key_reference_as_table_row()
                            .map(|tr| TableKeyReference::TableRow(Box::new(convert_table_row(&tr))))
                            .unwrap_or(TableKeyReference::TableRow(Box::new(empty_table_row())))
                    }
                    _ => TableKeyReference::TableDop(Box::new(empty_table_dop())),
                };
                ParamData::TableKey { table_key_reference }
            })
        }
        dataformat::ParamSpecificData::TableStruct => {
            p.specific_data_as_table_struct().map(|ts| ParamData::TableStruct {
                table_key: Box::new(ts.table_key().map(|tk| convert_param(&tk)).unwrap_or_else(empty_param)),
            })
        }
        _ => None,
    }
}

fn convert_dop(d: &dataformat::DOP<'_>) -> Dop {
    Dop {
        dop_type: convert_dop_type(d.dop_type()),
        short_name: s(d.short_name()),
        sdgs: d.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
        specific_data: convert_dop_specific_data(d),
    }
}

fn empty_dop() -> Dop {
    Dop {
        dop_type: DopType::Regular,
        short_name: String::new(),
        sdgs: None,
        specific_data: None,
    }
}

fn convert_dop_specific_data(d: &dataformat::DOP<'_>) -> Option<DopData> {
    let sd_type = d.specific_data_type();
    match sd_type {
        dataformat::SpecificDOPData::NormalDOP => {
            d.specific_data_as_normal_dop().map(|nd| DopData::NormalDop {
                compu_method: nd.compu_method().map(|cm| convert_compu_method(&cm)),
                diag_coded_type: nd.diag_coded_type().map(|dct| convert_diag_coded_type(&dct)),
                physical_type: nd.physical_type().map(|pt| convert_physical_type(&pt)),
                internal_constr: nd.internal_constr().map(|ic| convert_internal_constr(&ic)),
                unit_ref: nd.unit_ref().map(|u| convert_unit(&u)),
                phys_constr: nd.phys_constr().map(|pc| convert_internal_constr(&pc)),
            })
        }
        dataformat::SpecificDOPData::EndOfPduField => {
            d.specific_data_as_end_of_pdu_field().map(|eof| DopData::EndOfPduField {
                max_number_of_items: eof.max_number_of_items(),
                min_number_of_items: eof.min_number_of_items(),
                field: eof.field().map(|f| convert_field(&f)),
            })
        }
        dataformat::SpecificDOPData::StaticField => {
            d.specific_data_as_static_field().map(|sf| DopData::StaticField {
                fixed_number_of_items: sf.fixed_number_of_items(),
                item_byte_size: sf.item_byte_size(),
                field: sf.field().map(|f| convert_field(&f)),
            })
        }
        dataformat::SpecificDOPData::EnvDataDesc => {
            d.specific_data_as_env_data_desc().map(|edd| DopData::EnvDataDesc {
                param_short_name: s(edd.param_short_name()),
                param_path_short_name: s(edd.param_path_short_name()),
                env_datas: edd.env_datas()
                    .map(|v| (0..v.len()).map(|i| convert_dop(&v.get(i))).collect())
                    .unwrap_or_default(),
            })
        }
        dataformat::SpecificDOPData::EnvData => {
            d.specific_data_as_env_data().map(|ed| DopData::EnvData {
                dtc_values: ed.dtc_values()
                    .map(|v| v.iter().collect())
                    .unwrap_or_default(),
                params: ed.params()
                    .map(|v| (0..v.len()).map(|i| convert_param(&v.get(i))).collect())
                    .unwrap_or_default(),
            })
        }
        dataformat::SpecificDOPData::DTCDOP => {
            d.specific_data_as_dtcdop().map(|dd| DopData::DtcDop {
                diag_coded_type: dd.diag_coded_type().map(|dct| convert_diag_coded_type(&dct)),
                physical_type: dd.physical_type().map(|pt| convert_physical_type(&pt)),
                compu_method: dd.compu_method().map(|cm| convert_compu_method(&cm)),
                dtcs: dd.dtcs()
                    .map(|v| (0..v.len()).map(|i| convert_dtc(&v.get(i))).collect())
                    .unwrap_or_default(),
                is_visible: dd.is_visible(),
            })
        }
        dataformat::SpecificDOPData::Structure => {
            d.specific_data_as_structure().map(|st| DopData::Structure {
                params: st.params()
                    .map(|v| (0..v.len()).map(|i| convert_param(&v.get(i))).collect())
                    .unwrap_or_default(),
                byte_size: st.byte_size(),
                is_visible: st.is_visible(),
            })
        }
        dataformat::SpecificDOPData::MUXDOP => {
            d.specific_data_as_muxdop().map(|mux| DopData::MuxDop {
                byte_position: mux.byte_position(),
                switch_key: mux.switch_key().map(|sk| SwitchKey {
                    byte_position: sk.byte_position(),
                    bit_position: sk.bit_position(),
                    dop: Box::new(sk.dop().map(|d| convert_dop(&d)).unwrap_or_else(empty_dop)),
                }),
                default_case: mux.default_case().map(|dc| DefaultCase {
                    short_name: s(dc.short_name()),
                    long_name: dc.long_name().map(|ln| convert_long_name(&ln)),
                    structure: dc.structure().map(|d| Box::new(convert_dop(&d))),
                }),
                cases: mux.cases()
                    .map(|v| (0..v.len()).map(|i| {
                        let c = v.get(i);
                        Case {
                            short_name: s(c.short_name()),
                            long_name: c.long_name().map(|ln| convert_long_name(&ln)),
                            structure: c.structure().map(|d| Box::new(convert_dop(&d))),
                            lower_limit: c.lower_limit().map(|l| convert_limit(&l)),
                            upper_limit: c.upper_limit().map(|l| convert_limit(&l)),
                        }
                    }).collect())
                    .unwrap_or_default(),
                is_visible: mux.is_visible(),
            })
        }
        dataformat::SpecificDOPData::DynamicLengthField => {
            d.specific_data_as_dynamic_length_field().map(|dlf| DopData::DynamicLengthField {
                offset: dlf.offset(),
                field: dlf.field().map(|f| convert_field(&f)),
                determine_number_of_items: dlf.determine_number_of_items().map(|dni| DetermineNumberOfItems {
                    byte_position: dni.byte_position(),
                    bit_position: dni.bit_position(),
                    dop: Box::new(dni.dop().map(|d| convert_dop(&d)).unwrap_or_else(empty_dop)),
                }),
            })
        }
        _ => None,
    }
}

fn convert_field(f: &dataformat::Field<'_>) -> Field {
    Field {
        basic_structure: f.basic_structure().map(|d| Box::new(convert_dop(&d))),
        env_data_desc: f.env_data_desc().map(|d| Box::new(convert_dop(&d))),
        is_visible: f.is_visible(),
    }
}

fn convert_diag_coded_type(dct: &dataformat::DiagCodedType<'_>) -> DiagCodedType {
    let specific_data = match dct.specific_data_type() {
        dataformat::SpecificDataType::LeadingLengthInfoType => {
            dct.specific_data_as_leading_length_info_type().map(|ll| DiagCodedTypeData::LeadingLength {
                bit_length: ll.bit_length(),
            })
        }
        dataformat::SpecificDataType::MinMaxLengthType => {
            dct.specific_data_as_min_max_length_type().map(|mm| DiagCodedTypeData::MinMax {
                min_length: mm.min_length(),
                max_length: mm.max_length(),
                termination: convert_termination(mm.termination()),
            })
        }
        dataformat::SpecificDataType::ParamLengthInfoType => {
            dct.specific_data_as_param_length_info_type().map(|pl| DiagCodedTypeData::ParamLength {
                length_key: Box::new(pl.length_key().map(|p| convert_param(&p)).unwrap_or_else(empty_param)),
            })
        }
        dataformat::SpecificDataType::StandardLengthType => {
            dct.specific_data_as_standard_length_type().map(|sl| DiagCodedTypeData::StandardLength {
                bit_length: sl.bit_length(),
                bit_mask: sl.bit_mask().map(|v| v.iter().collect()).unwrap_or_default(),
                condensed: sl.condensed(),
            })
        }
        _ => None,
    };

    DiagCodedType {
        type_name: convert_diag_coded_type_name(dct.type_()),
        base_type_encoding: s(dct.base_type_encoding()),
        base_data_type: convert_data_type(dct.base_data_type()),
        is_high_low_byte_order: dct.is_high_low_byte_order(),
        specific_data,
    }
}

fn empty_diag_coded_type() -> DiagCodedType {
    DiagCodedType {
        type_name: DiagCodedTypeName::StandardLengthType,
        base_type_encoding: String::new(),
        base_data_type: DataType::AUint32,
        is_high_low_byte_order: true,
        specific_data: None,
    }
}

fn convert_compu_method(cm: &dataformat::CompuMethod<'_>) -> CompuMethod {
    CompuMethod {
        category: convert_compu_category(cm.category()),
        internal_to_phys: cm.internal_to_phys().map(|itp| convert_compu_internal_to_phys(&itp)),
        phys_to_internal: cm.phys_to_internal().map(|pti| convert_compu_phys_to_internal(&pti)),
    }
}

fn convert_compu_internal_to_phys(itp: &dataformat::CompuInternalToPhys<'_>) -> CompuInternalToPhys {
    CompuInternalToPhys {
        compu_scales: itp.compu_scales()
            .map(|v| (0..v.len()).map(|i| convert_compu_scale(&v.get(i))).collect())
            .unwrap_or_default(),
        prog_code: itp.prog_code().map(|pc| convert_prog_code(&pc)),
        compu_default_value: itp.compu_default_value().map(|cdv| CompuDefaultValue {
            values: cdv.values().map(|v| convert_compu_values(&v)),
            inverse_values: cdv.inverse_values().map(|v| convert_compu_values(&v)),
        }),
    }
}

fn convert_compu_phys_to_internal(pti: &dataformat::CompuPhysToInternal<'_>) -> CompuPhysToInternal {
    CompuPhysToInternal {
        prog_code: pti.prog_code().map(|pc| convert_prog_code(&pc)),
        compu_scales: pti.compu_scales()
            .map(|v| (0..v.len()).map(|i| convert_compu_scale(&v.get(i))).collect())
            .unwrap_or_default(),
        compu_default_value: pti.compu_default_value().map(|cdv| CompuDefaultValue {
            values: cdv.values().map(|v| convert_compu_values(&v)),
            inverse_values: cdv.inverse_values().map(|v| convert_compu_values(&v)),
        }),
    }
}

fn convert_compu_scale(cs: &dataformat::CompuScale<'_>) -> CompuScale {
    CompuScale {
        short_label: cs.short_label().map(|t| convert_text(&t)),
        lower_limit: cs.lower_limit().map(|l| convert_limit(&l)),
        upper_limit: cs.upper_limit().map(|l| convert_limit(&l)),
        inverse_values: cs.inverse_values().map(|v| convert_compu_values(&v)),
        consts: cs.consts().map(|v| convert_compu_values(&v)),
        rational_co_effs: cs.rational_co_effs().map(|rc| CompuRationalCoEffs {
            numerator: rc.numerator().map(|v| v.iter().collect()).unwrap_or_default(),
            denominator: rc.denominator().map(|v| v.iter().collect()).unwrap_or_default(),
        }),
    }
}

fn convert_compu_values(cv: &dataformat::CompuValues<'_>) -> CompuValues {
    CompuValues {
        v: cv.v(),
        vt: s(cv.vt()),
        vt_ti: s(cv.vt_ti()),
    }
}

fn convert_physical_type(pt: &dataformat::PhysicalType<'_>) -> PhysicalType {
    PhysicalType {
        precision: pt.precision(),
        base_data_type: convert_physical_type_data_type(pt.base_data_type()),
        display_radix: convert_radix(pt.display_radix()),
    }
}

fn convert_limit(l: &dataformat::Limit<'_>) -> Limit {
    Limit {
        value: s(l.value()),
        interval_type: convert_interval_type(l.interval_type()),
    }
}

fn convert_internal_constr(ic: &dataformat::InternalConstr<'_>) -> InternalConstr {
    InternalConstr {
        lower_limit: ic.lower_limit().map(|l| convert_limit(&l)),
        upper_limit: ic.upper_limit().map(|l| convert_limit(&l)),
        scale_constrs: ic.scale_constr()
            .map(|v| (0..v.len()).map(|i| {
                let sc = v.get(i);
                ScaleConstr {
                    short_label: sc.short_label().map(|t| convert_text(&t)),
                    lower_limit: sc.lower_limit().map(|l| convert_limit(&l)),
                    upper_limit: sc.upper_limit().map(|l| convert_limit(&l)),
                    validity: convert_valid_type(sc.validity()),
                }
            }).collect())
            .unwrap_or_default(),
    }
}

fn convert_unit(u: &dataformat::Unit<'_>) -> Unit {
    Unit {
        short_name: s(u.short_name()),
        display_name: s(u.display_name()),
        factor_si_to_unit: u.factorsitounit(),
        offset_si_to_unit: u.offsetitounit(),
        physical_dimension: u.physical_dimension().map(|pd| convert_physical_dimension(&pd)),
    }
}

fn convert_physical_dimension(pd: &dataformat::PhysicalDimension<'_>) -> PhysicalDimension {
    PhysicalDimension {
        short_name: s(pd.short_name()),
        long_name: pd.long_name().map(|ln| convert_long_name(&ln)),
        length_exp: pd.length_exp(),
        mass_exp: pd.mass_exp(),
        time_exp: pd.time_exp(),
        current_exp: pd.current_exp(),
        temperature_exp: pd.temperature_exp(),
        molar_amount_exp: pd.molar_amount_exp(),
        luminous_intensity_exp: pd.luminous_intensity_exp(),
    }
}

fn convert_dtc(dtc: &dataformat::DTC<'_>) -> Dtc {
    Dtc {
        short_name: s(dtc.short_name()),
        trouble_code: dtc.trouble_code(),
        display_trouble_code: s(dtc.display_trouble_code()),
        text: dtc.text().map(|t| convert_text(&t)),
        level: dtc.level(),
        sdgs: dtc.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
        is_temporary: dtc.is_temporary(),
    }
}

fn convert_variant_pattern(vp: &dataformat::VariantPattern<'_>) -> VariantPattern {
    VariantPattern {
        matching_parameters: vp.matching_parameter()
            .map(|v| (0..v.len()).map(|i| {
                let mp = v.get(i);
                MatchingParameter {
                    expected_value: s(mp.expected_value()),
                    diag_service: Box::new(mp.diag_service().map(|ds| convert_diag_service(&ds))
                        .unwrap_or_else(empty_diag_service)),
                    out_param: Box::new(mp.out_param().map(|p| convert_param(&p)).unwrap_or_else(empty_param)),
                    use_physical_addressing: mp.use_physical_addressing(),
                }
            }).collect())
            .unwrap_or_default(),
    }
}

fn empty_diag_service() -> DiagService {
    DiagService {
        diag_comm: empty_diag_comm(),
        request: None,
        pos_responses: vec![],
        neg_responses: vec![],
        is_cyclic: false,
        is_multiple: false,
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        com_param_refs: vec![],
    }
}

fn empty_param() -> Param {
    Param {
        id: 0,
        param_type: ParamType::Value,
        short_name: String::new(),
        semantic: String::new(),
        sdgs: None,
        physical_default_value: String::new(),
        byte_position: None,
        bit_position: None,
        specific_data: None,
    }
}

fn empty_table_row() -> TableRow {
    TableRow {
        short_name: String::new(), long_name: None, key: String::new(),
        dop: None, structure: None, sdgs: None, audience: None,
        funct_class_refs: vec![], state_transition_refs: vec![],
        pre_condition_state_refs: vec![], is_executable: true,
        semantic: String::new(), is_mandatory: false, is_final: false,
    }
}

fn empty_table_dop() -> TableDop {
    TableDop {
        semantic: String::new(), short_name: String::new(), long_name: None,
        key_label: String::new(), struct_label: String::new(), key_dop: None,
        rows: vec![], diag_comm_connectors: vec![], sdgs: None,
    }
}

fn convert_table_row(tr: &dataformat::TableRow<'_>) -> TableRow {
    TableRow {
        short_name: s(tr.short_name()),
        long_name: tr.long_name().map(|ln| convert_long_name(&ln)),
        key: s(tr.key()),
        dop: tr.dop().map(|d| Box::new(convert_dop(&d))),
        structure: tr.structure().map(|d| Box::new(convert_dop(&d))),
        sdgs: tr.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
        audience: tr.audience().map(|a| convert_audience(&a)),
        funct_class_refs: tr.funct_class_refs()
            .map(|v| (0..v.len()).map(|i| FunctClass { short_name: s(v.get(i).short_name()) }).collect())
            .unwrap_or_default(),
        state_transition_refs: tr.state_transition_refs()
            .map(|v| (0..v.len()).map(|i| convert_state_transition_ref(&v.get(i))).collect())
            .unwrap_or_default(),
        pre_condition_state_refs: tr.pre_condition_state_refs()
            .map(|v| (0..v.len()).map(|i| convert_pre_condition_state_ref(&v.get(i))).collect())
            .unwrap_or_default(),
        is_executable: tr.is_executable(),
        semantic: s(tr.semantic()),
        is_mandatory: tr.is_mandatory(),
        is_final: tr.is_final(),
    }
}

fn convert_table_dop(td: &dataformat::TableDop<'_>) -> TableDop {
    TableDop {
        semantic: s(td.semantic()),
        short_name: s(td.short_name()),
        long_name: td.long_name().map(|ln| convert_long_name(&ln)),
        key_label: s(td.key_label()),
        struct_label: s(td.struct_label()),
        key_dop: td.key_dop().map(|d| Box::new(convert_dop(&d))),
        rows: td.rows()
            .map(|v| (0..v.len()).map(|i| convert_table_row(&v.get(i))).collect())
            .unwrap_or_default(),
        diag_comm_connectors: td.diag_comm_connector()
            .map(|v| (0..v.len()).map(|i| {
                let tdc = v.get(i);
                TableDiagCommConnector {
                    diag_comm: match tdc.diag_comm_type() {
                        dataformat::DiagServiceOrJob::DiagService => {
                            tdc.diag_comm_as_diag_service()
                                .map(|ds| DiagServiceOrJob::DiagService(Box::new(convert_diag_service(&ds))))
                                .unwrap_or(DiagServiceOrJob::DiagService(Box::new(empty_diag_service())))
                        }
                        dataformat::DiagServiceOrJob::SingleEcuJob => {
                            tdc.diag_comm_as_single_ecu_job()
                                .map(|sej| DiagServiceOrJob::SingleEcuJob(Box::new(convert_single_ecu_job(&sej))))
                                .unwrap_or(DiagServiceOrJob::SingleEcuJob(Box::new(empty_single_ecu_job())))
                        }
                        _ => DiagServiceOrJob::DiagService(Box::new(empty_diag_service())),
                    },
                    semantic: s(tdc.semantic()),
                }
            }).collect())
            .unwrap_or_default(),
        sdgs: td.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
    }
}

fn convert_parent_ref(pr: &dataformat::ParentRef<'_>) -> ParentRef {
    let ref_type = match pr.ref_type() {
        dataformat::ParentRefType::Variant => {
            pr.ref__as_variant()
                .map(|v| ParentRefType::Variant(Box::new(convert_variant(&v))))
                .unwrap_or(ParentRefType::Variant(Box::new(Variant {
                    diag_layer: empty_diag_layer(), is_base_variant: false,
                    variant_patterns: vec![], parent_refs: vec![],
                })))
        }
        dataformat::ParentRefType::Protocol => {
            pr.ref__as_protocol()
                .map(|p| ParentRefType::Protocol(Box::new(convert_protocol(&p))))
                .unwrap_or(ParentRefType::Protocol(Box::new(empty_protocol())))
        }
        dataformat::ParentRefType::FunctionalGroup => {
            pr.ref__as_functional_group()
                .map(|fg| ParentRefType::FunctionalGroup(Box::new(convert_functional_group(&fg))))
                .unwrap_or(ParentRefType::FunctionalGroup(Box::new(FunctionalGroup {
                    diag_layer: empty_diag_layer(), parent_refs: vec![],
                })))
        }
        dataformat::ParentRefType::TableDop => {
            pr.ref__as_table_dop()
                .map(|td| ParentRefType::TableDop(Box::new(convert_table_dop(&td))))
                .unwrap_or(ParentRefType::TableDop(Box::new(empty_table_dop())))
        }
        dataformat::ParentRefType::EcuSharedData => {
            pr.ref__as_ecu_shared_data()
                .map(|esd| ParentRefType::EcuSharedData(Box::new(EcuSharedData {
                    diag_layer: esd.diag_layer().map(|dl| convert_diag_layer(&dl)).unwrap_or_else(empty_diag_layer),
                })))
                .unwrap_or(ParentRefType::EcuSharedData(Box::new(EcuSharedData { diag_layer: empty_diag_layer() })))
        }
        _ => ParentRefType::Variant(Box::new(Variant {
            diag_layer: empty_diag_layer(), is_base_variant: false,
            variant_patterns: vec![], parent_refs: vec![],
        })),
    };

    fn str_vec(v: Option<flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<&str>>>) -> Vec<String> {
        v.map(|vec| (0..vec.len()).map(|i| vec.get(i).to_string()).collect()).unwrap_or_default()
    }

    ParentRef {
        ref_type,
        not_inherited_diag_comm_short_names: str_vec(pr.not_inherited_diag_comm_short_names()),
        not_inherited_variables_short_names: str_vec(pr.not_inherited_variables_short_names()),
        not_inherited_dops_short_names: str_vec(pr.not_inherited_dops_short_names()),
        not_inherited_tables_short_names: str_vec(pr.not_inherited_tables_short_names()),
        not_inherited_global_neg_responses_short_names: str_vec(pr.not_inherited_global_neg_responses_short_names()),
    }
}

fn convert_protocol(p: &dataformat::Protocol<'_>) -> Protocol {
    Protocol {
        diag_layer: p.diag_layer().map(|dl| convert_diag_layer(&dl)).unwrap_or_else(empty_diag_layer),
        com_param_spec: p.com_param_spec().map(|cps| ComParamSpec {
            prot_stacks: cps.prot_stacks()
                .map(|v| (0..v.len()).map(|i| convert_prot_stack(&v.get(i))).collect())
                .unwrap_or_default(),
        }),
        prot_stack: p.prot_stack().map(|ps| convert_prot_stack(&ps)),
        parent_refs: p.parent_refs()
            .map(|v| (0..v.len()).map(|i| convert_protocol(&v.get(i))).collect())
            .unwrap_or_default(),
    }
}

fn empty_protocol() -> Protocol {
    Protocol {
        diag_layer: empty_diag_layer(),
        com_param_spec: None,
        prot_stack: None,
        parent_refs: vec![],
    }
}

fn convert_prot_stack(ps: &dataformat::ProtStack<'_>) -> ProtStack {
    ProtStack {
        short_name: s(ps.short_name()),
        long_name: ps.long_name().map(|ln| convert_long_name(&ln)),
        pdu_protocol_type: s(ps.pdu_protocol_type()),
        physical_link_type: s(ps.physical_link_type()),
        comparam_subset_refs: ps.comparam_subset_refs()
            .map(|v| (0..v.len()).map(|i| convert_com_param_sub_set(&v.get(i))).collect())
            .unwrap_or_default(),
    }
}

fn convert_com_param_sub_set(cpss: &dataformat::ComParamSubSet<'_>) -> ComParamSubSet {
    ComParamSubSet {
        com_params: cpss.com_params()
            .map(|v| (0..v.len()).map(|i| convert_com_param(&v.get(i))).collect())
            .unwrap_or_default(),
        complex_com_params: cpss.complex_com_params()
            .map(|v| (0..v.len()).map(|i| convert_com_param(&v.get(i))).collect())
            .unwrap_or_default(),
        data_object_props: cpss.data_object_props()
            .map(|v| (0..v.len()).map(|i| convert_dop(&v.get(i))).collect())
            .unwrap_or_default(),
        unit_spec: cpss.unit_spec().map(|us| convert_unit_spec(&us)),
    }
}

fn convert_unit_spec(us: &dataformat::UnitSpec<'_>) -> UnitSpec {
    UnitSpec {
        unit_groups: us.unit_groups()
            .map(|v| (0..v.len()).map(|i| {
                let ug = v.get(i);
                UnitGroup {
                    short_name: s(ug.short_name()),
                    long_name: ug.long_name().map(|ln| convert_long_name(&ln)),
                    unit_refs: ug.unitrefs()
                        .map(|v| (0..v.len()).map(|j| convert_unit(&v.get(j))).collect())
                        .unwrap_or_default(),
                }
            }).collect())
            .unwrap_or_default(),
        units: us.units()
            .map(|v| (0..v.len()).map(|i| convert_unit(&v.get(i))).collect())
            .unwrap_or_default(),
        physical_dimensions: us.physical_dimensions()
            .map(|v| (0..v.len()).map(|i| convert_physical_dimension(&v.get(i))).collect())
            .unwrap_or_default(),
        sdgs: us.sdgs().map(|sdgs| convert_sdgs(&sdgs)),
    }
}

fn convert_com_param_ref(cpr: &dataformat::ComParamRef<'_>) -> ComParamRef {
    ComParamRef {
        simple_value: cpr.simple_value().map(|sv| SimpleValue { value: s(sv.value()) }),
        complex_value: cpr.complex_value().map(|cv| convert_complex_value(&cv)),
        com_param: cpr.com_param().map(|cp| Box::new(convert_com_param(&cp))),
        protocol: cpr.protocol().map(|p| Box::new(convert_protocol(&p))),
        prot_stack: cpr.prot_stack().map(|ps| Box::new(convert_prot_stack(&ps))),
    }
}

fn convert_com_param(cp: &dataformat::ComParam<'_>) -> ComParam {
    let specific_data = match cp.specific_data_type() {
        dataformat::ComParamSpecificData::RegularComParam => {
            cp.specific_data_as_regular_com_param().map(|rcp| ComParamSpecificData::Regular {
                physical_default_value: s(rcp.physical_default_value()),
                dop: rcp.dop().map(|d| Box::new(convert_dop(&d))),
            })
        }
        dataformat::ComParamSpecificData::ComplexComParam => {
            cp.specific_data_as_complex_com_param().map(|ccp| ComParamSpecificData::Complex {
                com_params: ccp.com_params()
                    .map(|v| (0..v.len()).map(|i| convert_com_param(&v.get(i))).collect())
                    .unwrap_or_default(),
                complex_physical_default_values: ccp.complex_physical_default_values()
                    .map(|v| (0..v.len()).map(|i| convert_complex_value(&v.get(i))).collect())
                    .unwrap_or_default(),
                allow_multiple_values: ccp.allow_multiple_values(),
            })
        }
        _ => None,
    };

    ComParam {
        com_param_type: convert_com_param_type(cp.com_param_type()),
        short_name: s(cp.short_name()),
        long_name: cp.long_name().map(|ln| convert_long_name(&ln)),
        param_class: s(cp.param_class()),
        cp_type: convert_com_param_standardisation_level(cp.cp_type()),
        display_level: cp.display_level(),
        cp_usage: convert_com_param_usage(cp.cp_usage()),
        specific_data,
    }
}

fn convert_complex_value(cv: &dataformat::ComplexValue<'_>) -> ComplexValue {
    let entries = cv.entries_type()
        .map(|types| {
            let len = types.len();
            (0..len).map(|i| {
                match types.get(i) {
                    dataformat::SimpleOrComplexValueEntry::SimpleValue => {
                        if let Some(sv) = cv.entries_item_as_simple_value(i) {
                            SimpleOrComplexValue::Simple(SimpleValue { value: s(sv.value()) })
                        } else {
                            SimpleOrComplexValue::Simple(SimpleValue { value: String::new() })
                        }
                    }
                    dataformat::SimpleOrComplexValueEntry::ComplexValue => {
                        if let Some(nested) = cv.entries_item_as_complex_value(i) {
                            SimpleOrComplexValue::Complex(Box::new(convert_complex_value(&nested)))
                        } else {
                            SimpleOrComplexValue::Simple(SimpleValue { value: String::new() })
                        }
                    }
                    _ => SimpleOrComplexValue::Simple(SimpleValue { value: String::new() }),
                }
            }).collect()
        })
        .unwrap_or_default();
    ComplexValue { entries }
}

fn convert_single_ecu_job(sej: &dataformat::SingleEcuJob<'_>) -> SingleEcuJob {
    SingleEcuJob {
        diag_comm: sej.diag_comm().map(|dc| convert_diag_comm(&dc)).unwrap_or_else(empty_diag_comm),
        prog_codes: sej.prog_codes()
            .map(|v| (0..v.len()).map(|i| convert_prog_code(&v.get(i))).collect())
            .unwrap_or_default(),
        input_params: sej.input_params()
            .map(|v| (0..v.len()).map(|i| convert_job_param(&v.get(i))).collect())
            .unwrap_or_default(),
        output_params: sej.output_params()
            .map(|v| (0..v.len()).map(|i| convert_job_param(&v.get(i))).collect())
            .unwrap_or_default(),
        neg_output_params: sej.neg_output_params()
            .map(|v| (0..v.len()).map(|i| convert_job_param(&v.get(i))).collect())
            .unwrap_or_default(),
    }
}

fn empty_single_ecu_job() -> SingleEcuJob {
    SingleEcuJob {
        diag_comm: empty_diag_comm(),
        prog_codes: vec![],
        input_params: vec![],
        output_params: vec![],
        neg_output_params: vec![],
    }
}

fn convert_prog_code(pc: &dataformat::ProgCode<'_>) -> ProgCode {
    ProgCode {
        code_file: s(pc.code_file()),
        encryption: s(pc.encryption()),
        syntax: s(pc.syntax()),
        revision: s(pc.revision()),
        entrypoint: s(pc.entrypoint()),
        libraries: pc.library()
            .map(|v| (0..v.len()).map(|i| {
                let lib = v.get(i);
                Library {
                    short_name: s(lib.short_name()),
                    long_name: lib.long_name().map(|ln| convert_long_name(&ln)),
                    code_file: s(lib.code_file()),
                    encryption: s(lib.encryption()),
                    syntax: s(lib.syntax()),
                    entry_point: s(lib.entry_point()),
                }
            }).collect())
            .unwrap_or_default(),
    }
}

fn convert_job_param(jp: &dataformat::JobParam<'_>) -> JobParam {
    JobParam {
        short_name: s(jp.short_name()),
        long_name: jp.long_name().map(|ln| convert_long_name(&ln)),
        physical_default_value: s(jp.physical_default_value()),
        dop_base: jp.dop_base().map(|d| Box::new(convert_dop(&d))),
        semantic: s(jp.semantic()),
    }
}

fn convert_state_chart(sc: &dataformat::StateChart<'_>) -> StateChart {
    StateChart {
        short_name: s(sc.short_name()),
        semantic: s(sc.semantic()),
        state_transitions: sc.state_transitions()
            .map(|v| (0..v.len()).map(|i| {
                let st = v.get(i);
                StateTransition {
                    short_name: s(st.short_name()),
                    source_short_name_ref: s(st.source_short_name_ref()),
                    target_short_name_ref: s(st.target_short_name_ref()),
                }
            }).collect())
            .unwrap_or_default(),
        start_state_short_name_ref: s(sc.start_state_short_name_ref()),
        states: sc.states()
            .map(|v| (0..v.len()).map(|i| {
                let state = v.get(i);
                State {
                    short_name: s(state.short_name()),
                    long_name: state.long_name().map(|ln| convert_long_name(&ln)),
                }
            }).collect())
            .unwrap_or_default(),
    }
}

fn convert_audience(a: &dataformat::Audience<'_>) -> Audience {
    Audience {
        enabled_audiences: a.enabled_audiences()
            .map(|v| (0..v.len()).map(|i| convert_additional_audience(&v.get(i))).collect())
            .unwrap_or_default(),
        disabled_audiences: a.disabled_audiences()
            .map(|v| (0..v.len()).map(|i| convert_additional_audience(&v.get(i))).collect())
            .unwrap_or_default(),
        is_supplier: a.is_supplier(),
        is_development: a.is_development(),
        is_manufacturing: a.is_manufacturing(),
        is_after_sales: a.is_after_sales(),
        is_after_market: a.is_after_market(),
    }
}

fn convert_additional_audience(aa: &dataformat::AdditionalAudience<'_>) -> AdditionalAudience {
    AdditionalAudience {
        short_name: s(aa.short_name()),
        long_name: aa.long_name().map(|ln| convert_long_name(&ln)),
    }
}

fn convert_state_transition_ref(str_ref: &dataformat::StateTransitionRef<'_>) -> StateTransitionRef {
    StateTransitionRef {
        value: s(str_ref.value()),
        state_transition: str_ref.state_transition().map(|st| StateTransition {
            short_name: s(st.short_name()),
            source_short_name_ref: s(st.source_short_name_ref()),
            target_short_name_ref: s(st.target_short_name_ref()),
        }),
    }
}

fn convert_pre_condition_state_ref(pcsr: &dataformat::PreConditionStateRef<'_>) -> PreConditionStateRef {
    PreConditionStateRef {
        value: s(pcsr.value()),
        in_param_if_short_name: s(pcsr.in_param_if_short_name()),
        in_param_path_short_name: s(pcsr.in_param_path_short_name()),
        state: pcsr.state().map(|state| State {
            short_name: s(state.short_name()),
            long_name: state.long_name().map(|ln| convert_long_name(&ln)),
        }),
    }
}

// --- Text converters ---

fn convert_text(t: &dataformat::Text<'_>) -> Text {
    Text { value: s(t.value()), ti: s(t.ti()) }
}

fn convert_long_name(ln: &dataformat::LongName<'_>) -> LongName {
    LongName { value: s(ln.value()), ti: s(ln.ti()) }
}

fn convert_sdgs(sdgs: &dataformat::SDGS<'_>) -> Sdgs {
    Sdgs {
        sdgs: sdgs.sdgs()
            .map(|v| (0..v.len()).map(|i| convert_sdg(&v.get(i))).collect())
            .unwrap_or_default(),
    }
}

fn convert_sdg(sdg: &dataformat::SDG<'_>) -> Sdg {
    Sdg {
        caption_sn: s(sdg.caption_sn()),
        sds: sdg.sds()
            .map(|v| (0..v.len()).map(|i| {
                let entry = v.get(i);
                match entry.sd_or_sdg_type() {
                    dataformat::SDxorSDG::SD => {
                        entry.sd_or_sdg_as_sd()
                            .map(|sd| SdOrSdg::Sd(Sd {
                                value: s(sd.value()), si: s(sd.si()), ti: s(sd.ti()),
                            }))
                            .unwrap_or(SdOrSdg::Sd(Sd { value: String::new(), si: String::new(), ti: String::new() }))
                    }
                    dataformat::SDxorSDG::SDG => {
                        entry.sd_or_sdg_as_sdg()
                            .map(|sdg| SdOrSdg::Sdg(convert_sdg(&sdg)))
                            .unwrap_or(SdOrSdg::Sdg(Sdg { caption_sn: String::new(), sds: vec![], si: String::new() }))
                    }
                    _ => SdOrSdg::Sd(Sd { value: String::new(), si: String::new(), ti: String::new() }),
                }
            }).collect())
            .unwrap_or_default(),
        si: s(sdg.si()),
    }
}

// --- Enum converters ---

fn convert_diag_coded_type_name(v: dataformat::DiagCodedTypeName) -> DiagCodedTypeName {
    match v {
        dataformat::DiagCodedTypeName::LEADING_LENGTH_INFO_TYPE => DiagCodedTypeName::LeadingLengthInfoType,
        dataformat::DiagCodedTypeName::MIN_MAX_LENGTH_TYPE => DiagCodedTypeName::MinMaxLengthType,
        dataformat::DiagCodedTypeName::PARAM_LENGTH_INFO_TYPE => DiagCodedTypeName::ParamLengthInfoType,
        dataformat::DiagCodedTypeName::STANDARD_LENGTH_TYPE => DiagCodedTypeName::StandardLengthType,
        _ => DiagCodedTypeName::StandardLengthType,
    }
}

fn convert_data_type(v: dataformat::DataType) -> DataType {
    match v {
        dataformat::DataType::A_INT_32 => DataType::AInt32,
        dataformat::DataType::A_UINT_32 => DataType::AUint32,
        dataformat::DataType::A_FLOAT_32 => DataType::AFloat32,
        dataformat::DataType::A_ASCIISTRING => DataType::AAsciiString,
        dataformat::DataType::A_UTF_8_STRING => DataType::AUtf8String,
        dataformat::DataType::A_UNICODE_2_STRING => DataType::AUnicode2String,
        dataformat::DataType::A_BYTEFIELD => DataType::ABytefield,
        dataformat::DataType::A_FLOAT_64 => DataType::AFloat64,
        _ => DataType::AUint32,
    }
}

fn convert_termination(v: dataformat::Termination) -> Termination {
    match v {
        dataformat::Termination::END_OF_PDU => Termination::EndOfPdu,
        dataformat::Termination::ZERO => Termination::Zero,
        dataformat::Termination::HEX_FF => Termination::HexFf,
        _ => Termination::EndOfPdu,
    }
}

fn convert_interval_type(v: dataformat::IntervalType) -> IntervalType {
    match v {
        dataformat::IntervalType::OPEN => IntervalType::Open,
        dataformat::IntervalType::CLOSED => IntervalType::Closed,
        dataformat::IntervalType::INFINITE => IntervalType::Infinite,
        _ => IntervalType::Open,
    }
}

fn convert_compu_category(v: dataformat::CompuCategory) -> CompuCategory {
    match v {
        dataformat::CompuCategory::IDENTICAL => CompuCategory::Identical,
        dataformat::CompuCategory::LINEAR => CompuCategory::Linear,
        dataformat::CompuCategory::SCALE_LINEAR => CompuCategory::ScaleLinear,
        dataformat::CompuCategory::TEXT_TABLE => CompuCategory::TextTable,
        dataformat::CompuCategory::COMPU_CODE => CompuCategory::CompuCode,
        dataformat::CompuCategory::TAB_INTP => CompuCategory::TabIntp,
        dataformat::CompuCategory::RAT_FUNC => CompuCategory::RatFunc,
        dataformat::CompuCategory::SCALE_RAT_FUNC => CompuCategory::ScaleRatFunc,
        _ => CompuCategory::Identical,
    }
}

fn convert_physical_type_data_type(v: dataformat::PhysicalTypeDataType) -> PhysicalTypeDataType {
    match v {
        dataformat::PhysicalTypeDataType::A_INT_32 => PhysicalTypeDataType::AInt32,
        dataformat::PhysicalTypeDataType::A_UINT_32 => PhysicalTypeDataType::AUint32,
        dataformat::PhysicalTypeDataType::A_FLOAT_32 => PhysicalTypeDataType::AFloat32,
        dataformat::PhysicalTypeDataType::A_ASCIISTRING => PhysicalTypeDataType::AAsciiString,
        dataformat::PhysicalTypeDataType::A_UTF_8_STRING => PhysicalTypeDataType::AUtf8String,
        dataformat::PhysicalTypeDataType::A_UNICODE_2_STRING => PhysicalTypeDataType::AUnicode2String,
        dataformat::PhysicalTypeDataType::A_BYTEFIELD => PhysicalTypeDataType::ABytefield,
        dataformat::PhysicalTypeDataType::A_FLOAT_64 => PhysicalTypeDataType::AFloat64,
        _ => PhysicalTypeDataType::AUint32,
    }
}

fn convert_radix(v: dataformat::Radix) -> Radix {
    match v {
        dataformat::Radix::HEX => Radix::Hex,
        dataformat::Radix::DEC => Radix::Dec,
        dataformat::Radix::BIN => Radix::Bin,
        dataformat::Radix::OCT => Radix::Oct,
        _ => Radix::Hex,
    }
}

fn convert_valid_type(v: dataformat::ValidType) -> ValidType {
    match v {
        dataformat::ValidType::VALID => ValidType::Valid,
        dataformat::ValidType::NOT_VALID => ValidType::NotValid,
        dataformat::ValidType::NOT_DEFINED => ValidType::NotDefined,
        dataformat::ValidType::NOT_AVAILABLE => ValidType::NotAvailable,
        _ => ValidType::Valid,
    }
}

fn convert_dop_type(v: dataformat::DOPType) -> DopType {
    match v {
        dataformat::DOPType::REGULAR => DopType::Regular,
        dataformat::DOPType::ENV_DATA_DESC => DopType::EnvDataDesc,
        dataformat::DOPType::MUX => DopType::Mux,
        dataformat::DOPType::DYNAMIC_END_MARKER_FIELD => DopType::DynamicEndMarkerField,
        dataformat::DOPType::DYNAMIC_LENGTH_FIELD => DopType::DynamicLengthField,
        dataformat::DOPType::END_OF_PDU_FIELD => DopType::EndOfPduField,
        dataformat::DOPType::STATIC_FIELD => DopType::StaticField,
        dataformat::DOPType::ENV_DATA => DopType::EnvData,
        dataformat::DOPType::STRUCTURE => DopType::Structure,
        dataformat::DOPType::DTC => DopType::Dtc,
        _ => DopType::Regular,
    }
}

fn convert_param_type(v: dataformat::ParamType) -> ParamType {
    match v {
        dataformat::ParamType::CODED_CONST => ParamType::CodedConst,
        dataformat::ParamType::DYNAMIC => ParamType::Dynamic,
        dataformat::ParamType::LENGTH_KEY => ParamType::LengthKey,
        dataformat::ParamType::MATCHING_REQUEST_PARAM => ParamType::MatchingRequestParam,
        dataformat::ParamType::NRC_CONST => ParamType::NrcConst,
        dataformat::ParamType::PHYS_CONST => ParamType::PhysConst,
        dataformat::ParamType::RESERVED => ParamType::Reserved,
        dataformat::ParamType::SYSTEM => ParamType::System,
        dataformat::ParamType::TABLE_ENTRY => ParamType::TableEntry,
        dataformat::ParamType::TABLE_KEY => ParamType::TableKey,
        dataformat::ParamType::TABLE_STRUCT => ParamType::TableStruct,
        dataformat::ParamType::VALUE => ParamType::Value,
        _ => ParamType::Value,
    }
}

fn convert_table_entry_row_fragment(v: dataformat::TableEntryRowFragment) -> TableEntryRowFragment {
    match v {
        dataformat::TableEntryRowFragment::KEY => TableEntryRowFragment::Key,
        dataformat::TableEntryRowFragment::STRUCT => TableEntryRowFragment::Struct,
        _ => TableEntryRowFragment::Key,
    }
}

fn convert_diag_class_type(v: dataformat::DiagClassType) -> DiagClassType {
    match v {
        dataformat::DiagClassType::START_COMM => DiagClassType::StartComm,
        dataformat::DiagClassType::STOP_COMM => DiagClassType::StopComm,
        dataformat::DiagClassType::VARIANT_IDENTIFICATION => DiagClassType::VariantIdentification,
        dataformat::DiagClassType::READ_DYN_DEF_MESSAGE => DiagClassType::ReadDynDefMessage,
        dataformat::DiagClassType::DYN_DEF_MESSAGE => DiagClassType::DynDefMessage,
        dataformat::DiagClassType::CLEAR_DYN_DEF_MESSAGE => DiagClassType::ClearDynDefMessage,
        _ => DiagClassType::StartComm,
    }
}

fn convert_response_type(v: dataformat::ResponseType) -> ResponseType {
    match v {
        dataformat::ResponseType::POS_RESPONSE => ResponseType::PosResponse,
        dataformat::ResponseType::NEG_RESPONSE => ResponseType::NegResponse,
        dataformat::ResponseType::GLOBAL_NEG_RESPONSE => ResponseType::GlobalNegResponse,
        _ => ResponseType::PosResponse,
    }
}

fn convert_addressing(v: dataformat::Addressing) -> Addressing {
    match v {
        dataformat::Addressing::FUNCTIONAL => Addressing::Functional,
        dataformat::Addressing::PHYSICAL => Addressing::Physical,
        dataformat::Addressing::FUNCTIONAL_OR_PHYSICAL => Addressing::FunctionalOrPhysical,
        _ => Addressing::Physical,
    }
}

fn convert_transmission_mode(v: dataformat::TransmissionMode) -> TransmissionMode {
    match v {
        dataformat::TransmissionMode::SEND_ONLY => TransmissionMode::SendOnly,
        dataformat::TransmissionMode::RECEIVE_ONLY => TransmissionMode::ReceiveOnly,
        dataformat::TransmissionMode::SEND_AND_RECEIVE => TransmissionMode::SendAndReceive,
        dataformat::TransmissionMode::SEND_OR_RECEIVE => TransmissionMode::SendOrReceive,
        _ => TransmissionMode::SendAndReceive,
    }
}

fn convert_com_param_type(v: dataformat::ComParamType) -> ComParamType {
    match v {
        dataformat::ComParamType::REGULAR => ComParamType::Regular,
        dataformat::ComParamType::COMPLEX => ComParamType::Complex,
        _ => ComParamType::Regular,
    }
}

fn convert_com_param_standardisation_level(v: dataformat::ComParamStandardisationLevel) -> ComParamStandardisationLevel {
    match v {
        dataformat::ComParamStandardisationLevel::STANDARD => ComParamStandardisationLevel::Standard,
        dataformat::ComParamStandardisationLevel::OEM_SPECIFIC => ComParamStandardisationLevel::OemSpecific,
        dataformat::ComParamStandardisationLevel::OPTIONAL => ComParamStandardisationLevel::Optional,
        dataformat::ComParamStandardisationLevel::OEM_OPTIONAL => ComParamStandardisationLevel::OemOptional,
        _ => ComParamStandardisationLevel::Standard,
    }
}

fn convert_com_param_usage(v: dataformat::ComParamUsage) -> ComParamUsage {
    match v {
        dataformat::ComParamUsage::ECU_SOFTWARE => ComParamUsage::EcuSoftware,
        dataformat::ComParamUsage::ECU_COMM => ComParamUsage::EcuComm,
        dataformat::ComParamUsage::APPLICATION => ComParamUsage::Application,
        dataformat::ComParamUsage::TESTER => ComParamUsage::Tester,
        _ => ComParamUsage::EcuSoftware,
    }
}

fn convert_memory_access(v: dataformat::MemoryAccess) -> MemoryAccess {
    match v {
        dataformat::MemoryAccess::Read => MemoryAccess::Read,
        dataformat::MemoryAccess::Write => MemoryAccess::Write,
        dataformat::MemoryAccess::ReadWrite => MemoryAccess::ReadWrite,
        dataformat::MemoryAccess::Execute => MemoryAccess::Execute,
        _ => MemoryAccess::Read,
    }
}

fn convert_data_block_type(v: dataformat::DataBlockType) -> DataBlockType {
    match v {
        dataformat::DataBlockType::Download => DataBlockType::Download,
        dataformat::DataBlockType::Upload => DataBlockType::Upload,
        _ => DataBlockType::Download,
    }
}

fn convert_data_block_format(v: dataformat::DataBlockFormat) -> DataBlockFormat {
    match v {
        dataformat::DataBlockFormat::Raw => DataBlockFormat::Raw,
        dataformat::DataBlockFormat::Encrypted => DataBlockFormat::Encrypted,
        dataformat::DataBlockFormat::Compressed => DataBlockFormat::Compressed,
        dataformat::DataBlockFormat::EncryptedCompressed => DataBlockFormat::EncryptedCompressed,
        _ => DataBlockFormat::Raw,
    }
}

fn convert_address_format(af: &dataformat::AddressFormat<'_>) -> AddressFormat {
    AddressFormat {
        address_bytes: af.address_bytes(),
        length_bytes: af.length_bytes(),
    }
}

fn convert_memory_region(r: &dataformat::MemoryRegion<'_>) -> MemoryRegion {
    let session = r.session().map(|v| (0..v.len()).map(|i| v.get(i).to_string()).collect());
    MemoryRegion {
        name: s(r.name()),
        description: r.description().map(|d| d.to_string()),
        start_address: r.start_address(),
        size: r.size(),
        access: convert_memory_access(r.access()),
        address_format: r.address_format().map(|af| convert_address_format(&af)),
        security_level: r.security_level().map(|s| s.to_string()),
        session,
    }
}

fn convert_data_block(b: &dataformat::DataBlock<'_>) -> DataBlock {
    DataBlock {
        name: s(b.name()),
        description: b.description().map(|d| d.to_string()),
        block_type: convert_data_block_type(b.block_type()),
        memory_address: b.memory_address(),
        memory_size: b.memory_size(),
        format: convert_data_block_format(b.format()),
        max_block_length: if b.max_block_length() == 0 { None } else { Some(b.max_block_length()) },
        security_level: b.security_level().map(|s| s.to_string()),
        session: b.session().map(|s| s.to_string()),
        checksum_type: b.checksum_type().map(|s| s.to_string()),
    }
}

fn convert_memory_config(m: &dataformat::MemoryConfig<'_>) -> MemoryConfig {
    let default_address_format = m.default_address_format()
        .map(|af| convert_address_format(&af))
        .unwrap_or(AddressFormat { address_bytes: 4, length_bytes: 4 });
    let regions = m.regions()
        .map(|v| (0..v.len()).map(|i| convert_memory_region(&v.get(i))).collect())
        .unwrap_or_default();
    let data_blocks = m.data_blocks()
        .map(|v| (0..v.len()).map(|i| convert_data_block(&v.get(i))).collect())
        .unwrap_or_default();
    MemoryConfig {
        default_address_format,
        regions,
        data_blocks,
    }
}
