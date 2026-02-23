use crate::types::*;
use flatbuffers::FlatBufferBuilder;
use mdd_format::dataformat;

/// Convert IR DiagDatabase to FlatBuffers EcuData bytes.
pub fn ir_to_flatbuffers(db: &DiagDatabase) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::with_capacity(1024 * 256);

    let version = builder.create_string(&db.version);
    let ecu_name = builder.create_string(&db.ecu_name);
    let revision = builder.create_string(&db.revision);

    let metadata: Vec<_> = db.metadata.iter().map(|(k, v)| {
        let key = builder.create_string(k);
        let val = builder.create_string(v);
        dataformat::KeyValue::create(&mut builder, &dataformat::KeyValueArgs {
            key: Some(key), value: Some(val),
        })
    }).collect();
    let metadata = builder.create_vector(&metadata);

    let variants: Vec<_> = db.variants.iter().map(|v| build_variant(&mut builder, v)).collect();
    let variants = builder.create_vector(&variants);

    let functional_groups: Vec<_> = db.functional_groups.iter().map(|fg| build_functional_group(&mut builder, fg)).collect();
    let functional_groups = builder.create_vector(&functional_groups);

    let dtcs: Vec<_> = db.dtcs.iter().map(|dtc| build_dtc(&mut builder, dtc)).collect();
    let dtcs = builder.create_vector(&dtcs);

    let ecu_data = dataformat::EcuData::create(&mut builder, &dataformat::EcuDataArgs {
        version: Some(version),
        ecu_name: Some(ecu_name),
        revision: Some(revision),
        metadata: Some(metadata),
        feature_flags: None,
        variants: Some(variants),
        functional_groups: Some(functional_groups),
        dtcs: Some(dtcs),
    });

    dataformat::finish_ecu_data_buffer(&mut builder, ecu_data);
    builder.finished_data().to_vec()
}

fn build_variant<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    v: &Variant,
) -> flatbuffers::WIPOffset<dataformat::Variant<'a>> {
    let diag_layer = build_diag_layer(builder, &v.diag_layer);
    let variant_patterns: Vec<_> = v.variant_patterns.iter()
        .map(|vp| build_variant_pattern(builder, vp))
        .collect();
    let variant_patterns = builder.create_vector(&variant_patterns);
    let parent_refs: Vec<_> = v.parent_refs.iter().map(|pr| build_parent_ref(builder, pr)).collect();
    let parent_refs = builder.create_vector(&parent_refs);

    dataformat::Variant::create(builder, &dataformat::VariantArgs {
        diag_layer: Some(diag_layer),
        is_base_variant: v.is_base_variant,
        variant_pattern: Some(variant_patterns),
        parent_refs: Some(parent_refs),
    })
}

fn build_functional_group<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    fg: &FunctionalGroup,
) -> flatbuffers::WIPOffset<dataformat::FunctionalGroup<'a>> {
    let diag_layer = build_diag_layer(builder, &fg.diag_layer);
    let parent_refs: Vec<_> = fg.parent_refs.iter().map(|pr| build_parent_ref(builder, pr)).collect();
    let parent_refs = builder.create_vector(&parent_refs);

    dataformat::FunctionalGroup::create(builder, &dataformat::FunctionalGroupArgs {
        diag_layer: Some(diag_layer),
        parent_refs: Some(parent_refs),
    })
}

fn build_diag_layer<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    dl: &DiagLayer,
) -> flatbuffers::WIPOffset<dataformat::DiagLayer<'a>> {
    let short_name = builder.create_string(&dl.short_name);
    let long_name = dl.long_name.as_ref().map(|ln| build_long_name(builder, ln));
    let funct_classes: Vec<_> = dl.funct_classes.iter().map(|fc| {
        let sn = builder.create_string(&fc.short_name);
        dataformat::FunctClass::create(builder, &dataformat::FunctClassArgs { short_name: Some(sn) })
    }).collect();
    let funct_classes = builder.create_vector(&funct_classes);
    let com_param_refs: Vec<_> = dl.com_param_refs.iter().map(|cpr| build_com_param_ref(builder, cpr)).collect();
    let com_param_refs = builder.create_vector(&com_param_refs);
    let diag_services: Vec<_> = dl.diag_services.iter().map(|ds| build_diag_service(builder, ds)).collect();
    let diag_services = builder.create_vector(&diag_services);
    let single_ecu_jobs: Vec<_> = dl.single_ecu_jobs.iter().map(|sej| build_single_ecu_job(builder, sej)).collect();
    let single_ecu_jobs = builder.create_vector(&single_ecu_jobs);
    let state_charts: Vec<_> = dl.state_charts.iter().map(|sc| build_state_chart(builder, sc)).collect();
    let state_charts = builder.create_vector(&state_charts);
    let additional_audiences: Vec<_> = dl.additional_audiences.iter().map(|aa| build_additional_audience(builder, aa)).collect();
    let additional_audiences = builder.create_vector(&additional_audiences);
    let sdgs = dl.sdgs.as_ref().map(|s| build_sdgs(builder, s));

    dataformat::DiagLayer::create(builder, &dataformat::DiagLayerArgs {
        short_name: Some(short_name),
        long_name,
        funct_classes: Some(funct_classes),
        com_param_refs: Some(com_param_refs),
        diag_services: Some(diag_services),
        single_ecu_jobs: Some(single_ecu_jobs),
        state_charts: Some(state_charts),
        additional_audiences: Some(additional_audiences),
        sdgs,
    })
}

fn build_diag_service<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    ds: &DiagService,
) -> flatbuffers::WIPOffset<dataformat::DiagService<'a>> {
    let diag_comm = build_diag_comm(builder, &ds.diag_comm);
    let request = ds.request.as_ref().map(|r| build_request(builder, r));
    let pos_responses: Vec<_> = ds.pos_responses.iter().map(|r| build_response(builder, r)).collect();
    let pos_responses = builder.create_vector(&pos_responses);
    let neg_responses: Vec<_> = ds.neg_responses.iter().map(|r| build_response(builder, r)).collect();
    let neg_responses = builder.create_vector(&neg_responses);
    let com_param_refs: Vec<_> = ds.com_param_refs.iter().map(|cpr| build_com_param_ref(builder, cpr)).collect();
    let com_param_refs = builder.create_vector(&com_param_refs);

    dataformat::DiagService::create(builder, &dataformat::DiagServiceArgs {
        diag_comm: Some(diag_comm),
        request,
        pos_responses: Some(pos_responses),
        neg_responses: Some(neg_responses),
        is_cyclic: ds.is_cyclic,
        is_multiple: ds.is_multiple,
        addressing: ir_addressing_to_fbs(ds.addressing),
        transmission_mode: ir_transmission_mode_to_fbs(ds.transmission_mode),
        com_param_refs: Some(com_param_refs),
    })
}

fn build_diag_comm<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    dc: &DiagComm,
) -> flatbuffers::WIPOffset<dataformat::DiagComm<'a>> {
    let short_name = builder.create_string(&dc.short_name);
    let long_name = dc.long_name.as_ref().map(|ln| build_long_name(builder, ln));
    let semantic = builder.create_string(&dc.semantic);
    let funct_classes: Vec<_> = dc.funct_classes.iter().map(|fc| {
        let sn = builder.create_string(&fc.short_name);
        dataformat::FunctClass::create(builder, &dataformat::FunctClassArgs { short_name: Some(sn) })
    }).collect();
    let funct_class = builder.create_vector(&funct_classes);
    let sdgs = dc.sdgs.as_ref().map(|s| build_sdgs(builder, s));
    let pre_condition_state_refs: Vec<_> = dc.pre_condition_state_refs.iter()
        .map(|pcsr| build_pre_condition_state_ref(builder, pcsr)).collect();
    let pre_condition_state_refs = builder.create_vector(&pre_condition_state_refs);
    let state_transition_refs: Vec<_> = dc.state_transition_refs.iter()
        .map(|str_ref| build_state_transition_ref(builder, str_ref)).collect();
    let state_transition_refs = builder.create_vector(&state_transition_refs);
    let protocols: Vec<_> = dc.protocols.iter().map(|p| build_protocol(builder, p)).collect();
    let protocols = builder.create_vector(&protocols);
    let audience = dc.audience.as_ref().map(|a| build_audience(builder, a));

    dataformat::DiagComm::create(builder, &dataformat::DiagCommArgs {
        short_name: Some(short_name),
        long_name,
        semantic: Some(semantic),
        funct_class: Some(funct_class),
        sdgs,
        diag_class_type: ir_diag_class_type_to_fbs(dc.diag_class_type),
        pre_condition_state_refs: Some(pre_condition_state_refs),
        state_transition_refs: Some(state_transition_refs),
        protocols: Some(protocols),
        audience,
        is_mandatory: dc.is_mandatory,
        is_executable: dc.is_executable,
        is_final: dc.is_final,
    })
}

fn build_request<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    r: &Request,
) -> flatbuffers::WIPOffset<dataformat::Request<'a>> {
    let params: Vec<_> = r.params.iter().map(|p| build_param(builder, p)).collect();
    let params = builder.create_vector(&params);
    let sdgs = r.sdgs.as_ref().map(|s| build_sdgs(builder, s));

    dataformat::Request::create(builder, &dataformat::RequestArgs {
        params: Some(params),
        sdgs,
    })
}

fn build_response<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    r: &Response,
) -> flatbuffers::WIPOffset<dataformat::Response<'a>> {
    let params: Vec<_> = r.params.iter().map(|p| build_param(builder, p)).collect();
    let params = builder.create_vector(&params);
    let sdgs = r.sdgs.as_ref().map(|s| build_sdgs(builder, s));

    dataformat::Response::create(builder, &dataformat::ResponseArgs {
        response_type: ir_response_type_to_fbs(r.response_type),
        params: Some(params),
        sdgs,
    })
}

fn build_param<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    p: &Param,
) -> flatbuffers::WIPOffset<dataformat::Param<'a>> {
    let short_name = builder.create_string(&p.short_name);
    let semantic = builder.create_string(&p.semantic);
    let sdgs = p.sdgs.as_ref().map(|s| build_sdgs(builder, s));
    let physical_default_value = builder.create_string(&p.physical_default_value);

    let (specific_data_type, specific_data) = build_param_specific_data(builder, p.specific_data.as_ref());

    dataformat::Param::create(builder, &dataformat::ParamArgs {
        id: p.id,
        param_type: ir_param_type_to_fbs(p.param_type),
        short_name: Some(short_name),
        semantic: Some(semantic),
        sdgs,
        physical_default_value: Some(physical_default_value),
        byte_position: p.byte_position,
        bit_position: p.bit_position,
        specific_data_type,
        specific_data,
    })
}

fn build_param_specific_data<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    data: Option<&ParamData>,
) -> (dataformat::ParamSpecificData, Option<flatbuffers::WIPOffset<dataformat::ParamSpecificDataUnionValue>>) {
    let Some(data) = data else {
        return (dataformat::ParamSpecificData::NONE, None);
    };
    match data {
        ParamData::CodedConst { coded_value, diag_coded_type } => {
            let cv = builder.create_string(coded_value);
            let dct = build_diag_coded_type(builder, diag_coded_type);
            let cc = dataformat::CodedConst::create(builder, &dataformat::CodedConstArgs {
                coded_value: Some(cv), diag_coded_type: Some(dct),
            });
            (dataformat::ParamSpecificData::CodedConst, Some(dataformat::ParamSpecificData::tag_as_coded_const(cc).value_offset()))
        }
        ParamData::Dynamic => {
            let d = dataformat::Dynamic::create(builder, &dataformat::DynamicArgs {});
            (dataformat::ParamSpecificData::Dynamic, Some(dataformat::ParamSpecificData::tag_as_dynamic(d).value_offset()))
        }
        ParamData::MatchingRequestParam { request_byte_pos, byte_length } => {
            let mrp = dataformat::MatchingRequestParam::create(builder, &dataformat::MatchingRequestParamArgs {
                request_byte_pos: *request_byte_pos, byte_length: *byte_length,
            });
            (dataformat::ParamSpecificData::MatchingRequestParam, Some(dataformat::ParamSpecificData::tag_as_matching_request_param(mrp).value_offset()))
        }
        ParamData::NrcConst { coded_values, diag_coded_type } => {
            let cvs: Vec<_> = coded_values.iter().map(|cv| builder.create_string(cv)).collect();
            let cvs = builder.create_vector(&cvs);
            let dct = build_diag_coded_type(builder, diag_coded_type);
            let nc = dataformat::NrcConst::create(builder, &dataformat::NrcConstArgs {
                coded_values: Some(cvs), diag_coded_type: Some(dct),
            });
            (dataformat::ParamSpecificData::NrcConst, Some(dataformat::ParamSpecificData::tag_as_nrc_const(nc).value_offset()))
        }
        ParamData::PhysConst { phys_constant_value, dop } => {
            let pcv = builder.create_string(phys_constant_value);
            let d = build_dop(builder, dop);
            let pc = dataformat::PhysConst::create(builder, &dataformat::PhysConstArgs {
                phys_constant_value: Some(pcv), dop: Some(d),
            });
            (dataformat::ParamSpecificData::PhysConst, Some(dataformat::ParamSpecificData::tag_as_phys_const(pc).value_offset()))
        }
        ParamData::Reserved { bit_length } => {
            let r = dataformat::Reserved::create(builder, &dataformat::ReservedArgs { bit_length: *bit_length });
            (dataformat::ParamSpecificData::Reserved, Some(dataformat::ParamSpecificData::tag_as_reserved(r).value_offset()))
        }
        ParamData::System { dop, sys_param } => {
            let d = build_dop(builder, dop);
            let sp = builder.create_string(sys_param);
            let sys = dataformat::System::create(builder, &dataformat::SystemArgs {
                dop: Some(d), sys_param: Some(sp),
            });
            (dataformat::ParamSpecificData::System, Some(dataformat::ParamSpecificData::tag_as_system(sys).value_offset()))
        }
        ParamData::Value { physical_default_value, dop } => {
            let pdv = builder.create_string(physical_default_value);
            let d = build_dop(builder, dop);
            let v = dataformat::Value::create(builder, &dataformat::ValueArgs {
                physical_default_value: Some(pdv), dop: Some(d),
            });
            (dataformat::ParamSpecificData::Value, Some(dataformat::ParamSpecificData::tag_as_value(v).value_offset()))
        }
        ParamData::LengthKeyRef { dop } => {
            let d = build_dop(builder, dop);
            let lkr = dataformat::LengthKeyRef::create(builder, &dataformat::LengthKeyRefArgs { dop: Some(d) });
            (dataformat::ParamSpecificData::LengthKeyRef, Some(dataformat::ParamSpecificData::tag_as_length_key_ref(lkr).value_offset()))
        }
        ParamData::TableEntry { param, target, table_row } => {
            let p = build_param(builder, param);
            let tr = build_table_row(builder, table_row);
            let te = dataformat::TableEntry::create(builder, &dataformat::TableEntryArgs {
                param: Some(p), target: ir_table_entry_row_fragment_to_fbs(*target), table_row: Some(tr),
            });
            (dataformat::ParamSpecificData::TableEntry, Some(dataformat::ParamSpecificData::tag_as_table_entry(te).value_offset()))
        }
        ParamData::TableKey { table_key_reference } => {
            let tkr = match table_key_reference {
                TableKeyReference::TableDop(td) => {
                    let t = build_table_dop(builder, td);
                    dataformat::TableKeyReference::tag_as_table_dop(t).value_offset()
                }
                TableKeyReference::TableRow(tr) => {
                    let t = build_table_row(builder, tr);
                    dataformat::TableKeyReference::tag_as_table_row(t).value_offset()
                }
            };
            let tkr_type = match table_key_reference {
                TableKeyReference::TableDop(_) => dataformat::TableKeyReference::TableDop,
                TableKeyReference::TableRow(_) => dataformat::TableKeyReference::TableRow,
            };
            let tk = dataformat::TableKey::create(builder, &dataformat::TableKeyArgs {
                table_key_reference_type: tkr_type, table_key_reference: Some(tkr),
            });
            (dataformat::ParamSpecificData::TableKey, Some(dataformat::ParamSpecificData::tag_as_table_key(tk).value_offset()))
        }
        ParamData::TableStruct { table_key } => {
            let tk = build_param(builder, table_key);
            let ts = dataformat::TableStruct::create(builder, &dataformat::TableStructArgs { table_key: Some(tk) });
            (dataformat::ParamSpecificData::TableStruct, Some(dataformat::ParamSpecificData::tag_as_table_struct(ts).value_offset()))
        }
    }
}

fn build_dop<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    d: &Dop,
) -> flatbuffers::WIPOffset<dataformat::DOP<'a>> {
    let short_name = builder.create_string(&d.short_name);
    let sdgs = d.sdgs.as_ref().map(|s| build_sdgs(builder, s));
    let (specific_data_type, specific_data) = build_dop_specific_data(builder, d.specific_data.as_ref());

    dataformat::DOP::create(builder, &dataformat::DOPArgs {
        dop_type: ir_dop_type_to_fbs(d.dop_type),
        short_name: Some(short_name),
        sdgs,
        specific_data_type,
        specific_data,
    })
}

fn build_dop_specific_data<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    data: Option<&DopData>,
) -> (dataformat::SpecificDOPData, Option<flatbuffers::WIPOffset<dataformat::SpecificDOPDataUnionValue>>) {
    let Some(data) = data else {
        return (dataformat::SpecificDOPData::NONE, None);
    };
    match data {
        DopData::NormalDop { compu_method, diag_coded_type, physical_type, internal_constr, unit_ref, phys_constr } => {
            let cm = compu_method.as_ref().map(|cm| build_compu_method(builder, cm));
            let dct = diag_coded_type.as_ref().map(|dct| build_diag_coded_type(builder, dct));
            let pt = physical_type.as_ref().map(|pt| build_physical_type(builder, pt));
            let ic = internal_constr.as_ref().map(|ic| build_internal_constr(builder, ic));
            let ur = unit_ref.as_ref().map(|u| build_unit(builder, u));
            let pc = phys_constr.as_ref().map(|pc| build_internal_constr(builder, pc));
            let nd = dataformat::NormalDOP::create(builder, &dataformat::NormalDOPArgs {
                compu_method: cm, diag_coded_type: dct, physical_type: pt,
                internal_constr: ic, unit_ref: ur, phys_constr: pc,
            });
            (dataformat::SpecificDOPData::NormalDOP, Some(dataformat::SpecificDOPData::tag_as_normal_dop(nd).value_offset()))
        }
        DopData::Structure { params, byte_size, is_visible } => {
            let ps: Vec<_> = params.iter().map(|p| build_param(builder, p)).collect();
            let ps = builder.create_vector(&ps);
            let st = dataformat::Structure::create(builder, &dataformat::StructureArgs {
                params: Some(ps), byte_size: *byte_size, is_visible: *is_visible,
            });
            (dataformat::SpecificDOPData::Structure, Some(dataformat::SpecificDOPData::tag_as_structure(st).value_offset()))
        }
        DopData::EndOfPduField { max_number_of_items, min_number_of_items, field } => {
            let f = field.as_ref().map(|f| build_field(builder, f));
            let eof = dataformat::EndOfPduField::create(builder, &dataformat::EndOfPduFieldArgs {
                max_number_of_items: *max_number_of_items,
                min_number_of_items: *min_number_of_items,
                field: f,
            });
            (dataformat::SpecificDOPData::EndOfPduField, Some(dataformat::SpecificDOPData::tag_as_end_of_pdu_field(eof).value_offset()))
        }
        DopData::StaticField { fixed_number_of_items, item_byte_size, field } => {
            let f = field.as_ref().map(|f| build_field(builder, f));
            let sf = dataformat::StaticField::create(builder, &dataformat::StaticFieldArgs {
                fixed_number_of_items: *fixed_number_of_items, item_byte_size: *item_byte_size, field: f,
            });
            (dataformat::SpecificDOPData::StaticField, Some(dataformat::SpecificDOPData::tag_as_static_field(sf).value_offset()))
        }
        DopData::EnvDataDesc { param_short_name, param_path_short_name, env_datas } => {
            let psn = builder.create_string(param_short_name);
            let ppsn = builder.create_string(param_path_short_name);
            let eds: Vec<_> = env_datas.iter().map(|d| build_dop(builder, d)).collect();
            let eds = builder.create_vector(&eds);
            let edd = dataformat::EnvDataDesc::create(builder, &dataformat::EnvDataDescArgs {
                param_short_name: Some(psn), param_path_short_name: Some(ppsn), env_datas: Some(eds),
            });
            (dataformat::SpecificDOPData::EnvDataDesc, Some(dataformat::SpecificDOPData::tag_as_env_data_desc(edd).value_offset()))
        }
        DopData::EnvData { dtc_values, params } => {
            let dvs = builder.create_vector(dtc_values);
            let ps: Vec<_> = params.iter().map(|p| build_param(builder, p)).collect();
            let ps = builder.create_vector(&ps);
            let ed = dataformat::EnvData::create(builder, &dataformat::EnvDataArgs {
                dtc_values: Some(dvs), params: Some(ps),
            });
            (dataformat::SpecificDOPData::EnvData, Some(dataformat::SpecificDOPData::tag_as_env_data(ed).value_offset()))
        }
        DopData::DtcDop { diag_coded_type, physical_type, compu_method, dtcs, is_visible } => {
            let dct = diag_coded_type.as_ref().map(|dct| build_diag_coded_type(builder, dct));
            let pt = physical_type.as_ref().map(|pt| build_physical_type(builder, pt));
            let cm = compu_method.as_ref().map(|cm| build_compu_method(builder, cm));
            let ds: Vec<_> = dtcs.iter().map(|dtc| build_dtc(builder, dtc)).collect();
            let ds = builder.create_vector(&ds);
            let dd = dataformat::DTCDOP::create(builder, &dataformat::DTCDOPArgs {
                diag_coded_type: dct, physical_type: pt, compu_method: cm, dtcs: Some(ds), is_visible: *is_visible,
            });
            (dataformat::SpecificDOPData::DTCDOP, Some(dataformat::SpecificDOPData::tag_as_dtcdop(dd).value_offset()))
        }
        DopData::MuxDop { byte_position, switch_key, default_case, cases, is_visible } => {
            let sk = switch_key.as_ref().map(|sk| {
                let d = build_dop(builder, &sk.dop);
                dataformat::SwitchKey::create(builder, &dataformat::SwitchKeyArgs {
                    byte_position: sk.byte_position, bit_position: sk.bit_position, dop: Some(d),
                })
            });
            let dc = default_case.as_ref().map(|dc| {
                let sn = builder.create_string(&dc.short_name);
                let ln = dc.long_name.as_ref().map(|ln| build_long_name(builder, ln));
                let st = dc.structure.as_ref().map(|d| build_dop(builder, d));
                dataformat::DefaultCase::create(builder, &dataformat::DefaultCaseArgs {
                    short_name: Some(sn), long_name: ln, structure: st,
                })
            });
            let cs: Vec<_> = cases.iter().map(|c| {
                let sn = builder.create_string(&c.short_name);
                let ln = c.long_name.as_ref().map(|ln| build_long_name(builder, ln));
                let st = c.structure.as_ref().map(|d| build_dop(builder, d));
                let ll = c.lower_limit.as_ref().map(|l| build_limit(builder, l));
                let ul = c.upper_limit.as_ref().map(|l| build_limit(builder, l));
                dataformat::Case::create(builder, &dataformat::CaseArgs {
                    short_name: Some(sn), long_name: ln, structure: st, lower_limit: ll, upper_limit: ul,
                })
            }).collect();
            let cs = builder.create_vector(&cs);
            let mux = dataformat::MUXDOP::create(builder, &dataformat::MUXDOPArgs {
                byte_position: *byte_position, switch_key: sk, default_case: dc, cases: Some(cs), is_visible: *is_visible,
            });
            (dataformat::SpecificDOPData::MUXDOP, Some(dataformat::SpecificDOPData::tag_as_muxdop(mux).value_offset()))
        }
        DopData::DynamicLengthField { offset, field, determine_number_of_items } => {
            let f = field.as_ref().map(|f| build_field(builder, f));
            let dni = determine_number_of_items.as_ref().map(|dni| {
                let d = build_dop(builder, &dni.dop);
                dataformat::DetermineNumberOfItems::create(builder, &dataformat::DetermineNumberOfItemsArgs {
                    byte_position: dni.byte_position, bit_position: dni.bit_position, dop: Some(d),
                })
            });
            let dlf = dataformat::DynamicLengthField::create(builder, &dataformat::DynamicLengthFieldArgs {
                offset: *offset, field: f, determine_number_of_items: dni,
            });
            (dataformat::SpecificDOPData::DynamicLengthField, Some(dataformat::SpecificDOPData::tag_as_dynamic_length_field(dlf).value_offset()))
        }
    }
}

fn build_field<'a>(builder: &mut FlatBufferBuilder<'a>, f: &Field) -> flatbuffers::WIPOffset<dataformat::Field<'a>> {
    let bs = f.basic_structure.as_ref().map(|d| build_dop(builder, d));
    let edd = f.env_data_desc.as_ref().map(|d| build_dop(builder, d));
    dataformat::Field::create(builder, &dataformat::FieldArgs {
        basic_structure: bs, env_data_desc: edd, is_visible: f.is_visible,
    })
}

fn build_diag_coded_type<'a>(
    builder: &mut FlatBufferBuilder<'a>,
    dct: &DiagCodedType,
) -> flatbuffers::WIPOffset<dataformat::DiagCodedType<'a>> {
    let bte = builder.create_string(&dct.base_type_encoding);
    let (sd_type, sd): (dataformat::SpecificDataType, Option<flatbuffers::WIPOffset<dataformat::SpecificDataTypeUnionValue>>) = match &dct.specific_data {
        Some(DiagCodedTypeData::LeadingLength { bit_length }) => {
            let ll = dataformat::LeadingLengthInfoType::create(builder, &dataformat::LeadingLengthInfoTypeArgs { bit_length: *bit_length });
            (dataformat::SpecificDataType::LeadingLengthInfoType, Some(dataformat::SpecificDataType::tag_as_leading_length_info_type(ll).value_offset()))
        }
        Some(DiagCodedTypeData::MinMax { min_length, max_length, termination }) => {
            let mm = dataformat::MinMaxLengthType::create(builder, &dataformat::MinMaxLengthTypeArgs {
                min_length: *min_length, max_length: *max_length, termination: ir_termination_to_fbs(*termination),
            });
            (dataformat::SpecificDataType::MinMaxLengthType, Some(dataformat::SpecificDataType::tag_as_min_max_length_type(mm).value_offset()))
        }
        Some(DiagCodedTypeData::ParamLength { length_key }) => {
            let lk = build_param(builder, length_key);
            let pl = dataformat::ParamLengthInfoType::create(builder, &dataformat::ParamLengthInfoTypeArgs { length_key: Some(lk) });
            (dataformat::SpecificDataType::ParamLengthInfoType, Some(dataformat::SpecificDataType::tag_as_param_length_info_type(pl).value_offset()))
        }
        Some(DiagCodedTypeData::StandardLength { bit_length, bit_mask, condensed }) => {
            let bm = builder.create_vector(bit_mask);
            let sl = dataformat::StandardLengthType::create(builder, &dataformat::StandardLengthTypeArgs {
                bit_length: *bit_length, bit_mask: Some(bm), condensed: *condensed,
            });
            (dataformat::SpecificDataType::StandardLengthType, Some(dataformat::SpecificDataType::tag_as_standard_length_type(sl).value_offset()))
        }
        None => (dataformat::SpecificDataType::NONE, None),
    };

    dataformat::DiagCodedType::create(builder, &dataformat::DiagCodedTypeArgs {
        type_: ir_diag_coded_type_name_to_fbs(dct.type_name),
        base_type_encoding: Some(bte),
        base_data_type: ir_data_type_to_fbs(dct.base_data_type),
        is_high_low_byte_order: dct.is_high_low_byte_order,
        specific_data_type: sd_type,
        specific_data: sd,
    })
}

fn build_compu_method<'a>(builder: &mut FlatBufferBuilder<'a>, cm: &CompuMethod) -> flatbuffers::WIPOffset<dataformat::CompuMethod<'a>> {
    let itp = cm.internal_to_phys.as_ref().map(|itp| build_compu_itp(builder, itp));
    let pti = cm.phys_to_internal.as_ref().map(|pti| build_compu_pti(builder, pti));
    dataformat::CompuMethod::create(builder, &dataformat::CompuMethodArgs {
        category: ir_compu_category_to_fbs(cm.category), internal_to_phys: itp, phys_to_internal: pti,
    })
}

fn build_compu_itp<'a>(builder: &mut FlatBufferBuilder<'a>, itp: &CompuInternalToPhys) -> flatbuffers::WIPOffset<dataformat::CompuInternalToPhys<'a>> {
    let scales: Vec<_> = itp.compu_scales.iter().map(|cs| build_compu_scale(builder, cs)).collect();
    let scales = builder.create_vector(&scales);
    let pc = itp.prog_code.as_ref().map(|pc| build_prog_code(builder, pc));
    let cdv = itp.compu_default_value.as_ref().map(|cdv| build_compu_default_value(builder, cdv));
    dataformat::CompuInternalToPhys::create(builder, &dataformat::CompuInternalToPhysArgs {
        compu_scales: Some(scales), prog_code: pc, compu_default_value: cdv,
    })
}

fn build_compu_pti<'a>(builder: &mut FlatBufferBuilder<'a>, pti: &CompuPhysToInternal) -> flatbuffers::WIPOffset<dataformat::CompuPhysToInternal<'a>> {
    let pc = pti.prog_code.as_ref().map(|pc| build_prog_code(builder, pc));
    let scales: Vec<_> = pti.compu_scales.iter().map(|cs| build_compu_scale(builder, cs)).collect();
    let scales = builder.create_vector(&scales);
    let cdv = pti.compu_default_value.as_ref().map(|cdv| build_compu_default_value(builder, cdv));
    dataformat::CompuPhysToInternal::create(builder, &dataformat::CompuPhysToInternalArgs {
        prog_code: pc, compu_scales: Some(scales), compu_default_value: cdv,
    })
}

fn build_compu_scale<'a>(builder: &mut FlatBufferBuilder<'a>, cs: &CompuScale) -> flatbuffers::WIPOffset<dataformat::CompuScale<'a>> {
    let sl = cs.short_label.as_ref().map(|t| build_text(builder, t));
    let ll = cs.lower_limit.as_ref().map(|l| build_limit(builder, l));
    let ul = cs.upper_limit.as_ref().map(|l| build_limit(builder, l));
    let iv = cs.inverse_values.as_ref().map(|v| build_compu_values(builder, v));
    let c = cs.consts.as_ref().map(|v| build_compu_values(builder, v));
    let rc = cs.rational_co_effs.as_ref().map(|rc| {
        let num = builder.create_vector(&rc.numerator);
        let den = builder.create_vector(&rc.denominator);
        dataformat::CompuRationalCoEffs::create(builder, &dataformat::CompuRationalCoEffsArgs {
            numerator: Some(num), denominator: Some(den),
        })
    });
    dataformat::CompuScale::create(builder, &dataformat::CompuScaleArgs {
        short_label: sl, lower_limit: ll, upper_limit: ul, inverse_values: iv, consts: c, rational_co_effs: rc,
    })
}

fn build_compu_values<'a>(builder: &mut FlatBufferBuilder<'a>, cv: &CompuValues) -> flatbuffers::WIPOffset<dataformat::CompuValues<'a>> {
    let vt = builder.create_string(&cv.vt);
    let vt_ti = builder.create_string(&cv.vt_ti);
    dataformat::CompuValues::create(builder, &dataformat::CompuValuesArgs {
        v: cv.v, vt: Some(vt), vt_ti: Some(vt_ti),
    })
}

fn build_compu_default_value<'a>(builder: &mut FlatBufferBuilder<'a>, cdv: &CompuDefaultValue) -> flatbuffers::WIPOffset<dataformat::CompuDefaultValue<'a>> {
    let vals = cdv.values.as_ref().map(|v| build_compu_values(builder, v));
    let inv = cdv.inverse_values.as_ref().map(|v| build_compu_values(builder, v));
    dataformat::CompuDefaultValue::create(builder, &dataformat::CompuDefaultValueArgs { values: vals, inverse_values: inv })
}

fn build_physical_type<'a>(builder: &mut FlatBufferBuilder<'a>, pt: &PhysicalType) -> flatbuffers::WIPOffset<dataformat::PhysicalType<'a>> {
    dataformat::PhysicalType::create(builder, &dataformat::PhysicalTypeArgs {
        precision: pt.precision,
        base_data_type: ir_physical_type_data_type_to_fbs(pt.base_data_type),
        display_radix: ir_radix_to_fbs(pt.display_radix),
    })
}

fn build_internal_constr<'a>(builder: &mut FlatBufferBuilder<'a>, ic: &InternalConstr) -> flatbuffers::WIPOffset<dataformat::InternalConstr<'a>> {
    let ll = ic.lower_limit.as_ref().map(|l| build_limit(builder, l));
    let ul = ic.upper_limit.as_ref().map(|l| build_limit(builder, l));
    let scs: Vec<_> = ic.scale_constrs.iter().map(|sc| {
        let sl = sc.short_label.as_ref().map(|t| build_text(builder, t));
        let ll = sc.lower_limit.as_ref().map(|l| build_limit(builder, l));
        let ul = sc.upper_limit.as_ref().map(|l| build_limit(builder, l));
        dataformat::ScaleConstr::create(builder, &dataformat::ScaleConstrArgs {
            short_label: sl, lower_limit: ll, upper_limit: ul, validity: ir_valid_type_to_fbs(sc.validity),
        })
    }).collect();
    let scs = builder.create_vector(&scs);
    dataformat::InternalConstr::create(builder, &dataformat::InternalConstrArgs {
        lower_limit: ll, upper_limit: ul, scale_constr: Some(scs),
    })
}

fn build_limit<'a>(builder: &mut FlatBufferBuilder<'a>, l: &Limit) -> flatbuffers::WIPOffset<dataformat::Limit<'a>> {
    let v = builder.create_string(&l.value);
    dataformat::Limit::create(builder, &dataformat::LimitArgs {
        value: Some(v), interval_type: ir_interval_type_to_fbs(l.interval_type),
    })
}

fn build_unit<'a>(builder: &mut FlatBufferBuilder<'a>, u: &Unit) -> flatbuffers::WIPOffset<dataformat::Unit<'a>> {
    let sn = builder.create_string(&u.short_name);
    let dn = builder.create_string(&u.display_name);
    let pd = u.physical_dimension.as_ref().map(|pd| build_physical_dimension(builder, pd));
    dataformat::Unit::create(builder, &dataformat::UnitArgs {
        short_name: Some(sn), display_name: Some(dn),
        factorsitounit: u.factor_si_to_unit,
        offsetitounit: u.offset_si_to_unit,
        physical_dimension: pd,
    })
}

fn build_physical_dimension<'a>(builder: &mut FlatBufferBuilder<'a>, pd: &PhysicalDimension) -> flatbuffers::WIPOffset<dataformat::PhysicalDimension<'a>> {
    let sn = builder.create_string(&pd.short_name);
    let ln = pd.long_name.as_ref().map(|ln| build_long_name(builder, ln));
    dataformat::PhysicalDimension::create(builder, &dataformat::PhysicalDimensionArgs {
        short_name: Some(sn), long_name: ln,
        length_exp: pd.length_exp, mass_exp: pd.mass_exp,
        time_exp: pd.time_exp, current_exp: pd.current_exp,
        temperature_exp: pd.temperature_exp, molar_amount_exp: pd.molar_amount_exp,
        luminous_intensity_exp: pd.luminous_intensity_exp,
    })
}

fn build_dtc<'a>(builder: &mut FlatBufferBuilder<'a>, dtc: &Dtc) -> flatbuffers::WIPOffset<dataformat::DTC<'a>> {
    let sn = builder.create_string(&dtc.short_name);
    let dtc_display = builder.create_string(&dtc.display_trouble_code);
    let text = dtc.text.as_ref().map(|t| build_text(builder, t));
    let sdgs = dtc.sdgs.as_ref().map(|s| build_sdgs(builder, s));
    dataformat::DTC::create(builder, &dataformat::DTCArgs {
        short_name: Some(sn), trouble_code: dtc.trouble_code, display_trouble_code: Some(dtc_display),
        text, level: dtc.level, sdgs, is_temporary: dtc.is_temporary,
    })
}

fn build_table_row<'a>(builder: &mut FlatBufferBuilder<'a>, tr: &TableRow) -> flatbuffers::WIPOffset<dataformat::TableRow<'a>> {
    let sn = builder.create_string(&tr.short_name);
    let ln = tr.long_name.as_ref().map(|ln| build_long_name(builder, ln));
    let key = builder.create_string(&tr.key);
    let dop = tr.dop.as_ref().map(|d| build_dop(builder, d));
    let structure = tr.structure.as_ref().map(|d| build_dop(builder, d));
    let sdgs = tr.sdgs.as_ref().map(|s| build_sdgs(builder, s));
    let audience = tr.audience.as_ref().map(|a| build_audience(builder, a));
    let fcrs: Vec<_> = tr.funct_class_refs.iter().map(|fc| {
        let s = builder.create_string(&fc.short_name);
        dataformat::FunctClass::create(builder, &dataformat::FunctClassArgs { short_name: Some(s) })
    }).collect();
    let fcrs = builder.create_vector(&fcrs);
    let strs: Vec<_> = tr.state_transition_refs.iter().map(|str_ref| build_state_transition_ref(builder, str_ref)).collect();
    let strs = builder.create_vector(&strs);
    let pcsrs: Vec<_> = tr.pre_condition_state_refs.iter().map(|pcsr| build_pre_condition_state_ref(builder, pcsr)).collect();
    let pcsrs = builder.create_vector(&pcsrs);
    let sem = builder.create_string(&tr.semantic);
    dataformat::TableRow::create(builder, &dataformat::TableRowArgs {
        short_name: Some(sn), long_name: ln, key: Some(key), dop, structure, sdgs, audience,
        funct_class_refs: Some(fcrs), state_transition_refs: Some(strs), pre_condition_state_refs: Some(pcsrs),
        is_executable: tr.is_executable, semantic: Some(sem), is_mandatory: tr.is_mandatory, is_final: tr.is_final,
    })
}

fn build_table_dop<'a>(builder: &mut FlatBufferBuilder<'a>, td: &TableDop) -> flatbuffers::WIPOffset<dataformat::TableDop<'a>> {
    let sem = builder.create_string(&td.semantic);
    let sn = builder.create_string(&td.short_name);
    let ln = td.long_name.as_ref().map(|ln| build_long_name(builder, ln));
    let kl = builder.create_string(&td.key_label);
    let sl = builder.create_string(&td.struct_label);
    let kd = td.key_dop.as_ref().map(|d| build_dop(builder, d));
    let rows: Vec<_> = td.rows.iter().map(|tr| build_table_row(builder, tr)).collect();
    let rows = builder.create_vector(&rows);
    let sdgs = td.sdgs.as_ref().map(|s| build_sdgs(builder, s));
    // Skip diag_comm_connector for simplicity (complex nested union)
    let dcc = builder.create_vector::<flatbuffers::WIPOffset<dataformat::TableDiagCommConnector>>(&[]);
    dataformat::TableDop::create(builder, &dataformat::TableDopArgs {
        semantic: Some(sem), short_name: Some(sn), long_name: ln, key_label: Some(kl),
        struct_label: Some(sl), key_dop: kd, rows: Some(rows), diag_comm_connector: Some(dcc), sdgs,
    })
}

fn build_variant_pattern<'a>(builder: &mut FlatBufferBuilder<'a>, vp: &VariantPattern) -> flatbuffers::WIPOffset<dataformat::VariantPattern<'a>> {
    let mps: Vec<_> = vp.matching_parameters.iter().map(|mp| {
        let ev = builder.create_string(&mp.expected_value);
        let ds = build_diag_service(builder, &mp.diag_service);
        let op = build_param(builder, &mp.out_param);
        dataformat::MatchingParameter::create(builder, &dataformat::MatchingParameterArgs {
            expected_value: Some(ev), diag_service: Some(ds), out_param: Some(op),
            use_physical_addressing: mp.use_physical_addressing,
        })
    }).collect();
    let mps = builder.create_vector(&mps);
    dataformat::VariantPattern::create(builder, &dataformat::VariantPatternArgs { matching_parameter: Some(mps) })
}

fn build_parent_ref<'a>(builder: &mut FlatBufferBuilder<'a>, pr: &ParentRef) -> flatbuffers::WIPOffset<dataformat::ParentRef<'a>> {
    // Build the ref union target first (recursive - inner objects must be built before outer)
    let (ref_type, ref_) = match &pr.ref_type {
        ParentRefType::Variant(v) => {
            let fbs_variant = build_variant(builder, v);
            (dataformat::ParentRefType::Variant,
             Some(dataformat::ParentRefType::tag_as_variant(fbs_variant).value_offset()))
        }
        ParentRefType::Protocol(p) => {
            let fbs_proto = build_protocol(builder, p);
            (dataformat::ParentRefType::Protocol,
             Some(dataformat::ParentRefType::tag_as_protocol(fbs_proto).value_offset()))
        }
        ParentRefType::FunctionalGroup(fg) => {
            let fbs_fg = build_functional_group(builder, fg);
            (dataformat::ParentRefType::FunctionalGroup,
             Some(dataformat::ParentRefType::tag_as_functional_group(fbs_fg).value_offset()))
        }
        ParentRefType::TableDop(td) => {
            let fbs_td = build_table_dop(builder, td);
            (dataformat::ParentRefType::TableDop,
             Some(dataformat::ParentRefType::tag_as_table_dop(fbs_td).value_offset()))
        }
        ParentRefType::EcuSharedData(esd) => {
            let dl = build_diag_layer(builder, &esd.diag_layer);
            let fbs_esd = dataformat::EcuSharedData::create(builder, &dataformat::EcuSharedDataArgs {
                diag_layer: Some(dl),
            });
            (dataformat::ParentRefType::EcuSharedData,
             Some(dataformat::ParentRefType::tag_as_ecu_shared_data(fbs_esd).value_offset()))
        }
    };

    let nidc: Vec<_> = pr.not_inherited_diag_comm_short_names.iter().map(|s| builder.create_string(s)).collect();
    let nidc = builder.create_vector(&nidc);
    let nivs: Vec<_> = pr.not_inherited_variables_short_names.iter().map(|s| builder.create_string(s)).collect();
    let nivs = builder.create_vector(&nivs);
    let nids: Vec<_> = pr.not_inherited_dops_short_names.iter().map(|s| builder.create_string(s)).collect();
    let nids = builder.create_vector(&nids);
    let nits: Vec<_> = pr.not_inherited_tables_short_names.iter().map(|s| builder.create_string(s)).collect();
    let nits = builder.create_vector(&nits);
    let nignr: Vec<_> = pr.not_inherited_global_neg_responses_short_names.iter().map(|s| builder.create_string(s)).collect();
    let nignr = builder.create_vector(&nignr);
    dataformat::ParentRef::create(builder, &dataformat::ParentRefArgs {
        ref_type,
        ref_,
        not_inherited_diag_comm_short_names: Some(nidc),
        not_inherited_variables_short_names: Some(nivs),
        not_inherited_dops_short_names: Some(nids),
        not_inherited_tables_short_names: Some(nits),
        not_inherited_global_neg_responses_short_names: Some(nignr),
    })
}

fn build_protocol<'a>(builder: &mut FlatBufferBuilder<'a>, p: &Protocol) -> flatbuffers::WIPOffset<dataformat::Protocol<'a>> {
    let dl = build_diag_layer(builder, &p.diag_layer);
    let cps = p.com_param_spec.as_ref().map(|cps| {
        let pss: Vec<_> = cps.prot_stacks.iter().map(|ps| build_prot_stack(builder, ps)).collect();
        let pss = builder.create_vector(&pss);
        dataformat::ComParamSpec::create(builder, &dataformat::ComParamSpecArgs { prot_stacks: Some(pss) })
    });
    let ps = p.prot_stack.as_ref().map(|ps| build_prot_stack(builder, ps));
    let prs: Vec<_> = p.parent_refs.iter().map(|pr| build_protocol(builder, pr)).collect();
    let prs = builder.create_vector(&prs);
    dataformat::Protocol::create(builder, &dataformat::ProtocolArgs {
        diag_layer: Some(dl), com_param_spec: cps, prot_stack: ps, parent_refs: Some(prs),
    })
}

fn build_prot_stack<'a>(builder: &mut FlatBufferBuilder<'a>, ps: &ProtStack) -> flatbuffers::WIPOffset<dataformat::ProtStack<'a>> {
    let sn = builder.create_string(&ps.short_name);
    let ln = ps.long_name.as_ref().map(|ln| build_long_name(builder, ln));
    let ppt = builder.create_string(&ps.pdu_protocol_type);
    let plt = builder.create_string(&ps.physical_link_type);
    let csrs = builder.create_vector::<flatbuffers::WIPOffset<dataformat::ComParamSubSet>>(&[]);
    dataformat::ProtStack::create(builder, &dataformat::ProtStackArgs {
        short_name: Some(sn), long_name: ln, pdu_protocol_type: Some(ppt),
        physical_link_type: Some(plt), comparam_subset_refs: Some(csrs),
    })
}

fn build_com_param_ref<'a>(builder: &mut FlatBufferBuilder<'a>, _cpr: &ComParamRef) -> flatbuffers::WIPOffset<dataformat::ComParamRef<'a>> {
    // Minimal implementation for ComParamRef
    let sv = _cpr.simple_value.as_ref().map(|sv| {
        let v = builder.create_string(&sv.value);
        dataformat::SimpleValue::create(builder, &dataformat::SimpleValueArgs { value: Some(v) })
    });
    dataformat::ComParamRef::create(builder, &dataformat::ComParamRefArgs {
        simple_value: sv,
        complex_value: None,
        com_param: None,
        protocol: None,
        prot_stack: None,
    })
}

fn build_single_ecu_job<'a>(builder: &mut FlatBufferBuilder<'a>, sej: &SingleEcuJob) -> flatbuffers::WIPOffset<dataformat::SingleEcuJob<'a>> {
    let dc = build_diag_comm(builder, &sej.diag_comm);
    let pcs: Vec<_> = sej.prog_codes.iter().map(|pc| build_prog_code(builder, pc)).collect();
    let pcs = builder.create_vector(&pcs);
    let ips: Vec<_> = sej.input_params.iter().map(|jp| build_job_param(builder, jp)).collect();
    let ips = builder.create_vector(&ips);
    let ops: Vec<_> = sej.output_params.iter().map(|jp| build_job_param(builder, jp)).collect();
    let ops = builder.create_vector(&ops);
    let nops: Vec<_> = sej.neg_output_params.iter().map(|jp| build_job_param(builder, jp)).collect();
    let nops = builder.create_vector(&nops);
    dataformat::SingleEcuJob::create(builder, &dataformat::SingleEcuJobArgs {
        diag_comm: Some(dc), prog_codes: Some(pcs), input_params: Some(ips),
        output_params: Some(ops), neg_output_params: Some(nops),
    })
}

fn build_prog_code<'a>(builder: &mut FlatBufferBuilder<'a>, pc: &ProgCode) -> flatbuffers::WIPOffset<dataformat::ProgCode<'a>> {
    let cf = builder.create_string(&pc.code_file);
    let enc = builder.create_string(&pc.encryption);
    let syn = builder.create_string(&pc.syntax);
    let rev = builder.create_string(&pc.revision);
    let ep = builder.create_string(&pc.entrypoint);
    let libs: Vec<_> = pc.libraries.iter().map(|lib| {
        let sn = builder.create_string(&lib.short_name);
        let ln = lib.long_name.as_ref().map(|ln| build_long_name(builder, ln));
        let cf = builder.create_string(&lib.code_file);
        let enc = builder.create_string(&lib.encryption);
        let syn = builder.create_string(&lib.syntax);
        let ep = builder.create_string(&lib.entry_point);
        dataformat::Library::create(builder, &dataformat::LibraryArgs {
            short_name: Some(sn), long_name: ln, code_file: Some(cf),
            encryption: Some(enc), syntax: Some(syn), entry_point: Some(ep),
        })
    }).collect();
    let libs = builder.create_vector(&libs);
    dataformat::ProgCode::create(builder, &dataformat::ProgCodeArgs {
        code_file: Some(cf), encryption: Some(enc), syntax: Some(syn),
        revision: Some(rev), entrypoint: Some(ep), library: Some(libs),
    })
}

fn build_job_param<'a>(builder: &mut FlatBufferBuilder<'a>, jp: &JobParam) -> flatbuffers::WIPOffset<dataformat::JobParam<'a>> {
    let sn = builder.create_string(&jp.short_name);
    let ln = jp.long_name.as_ref().map(|ln| build_long_name(builder, ln));
    let pdv = builder.create_string(&jp.physical_default_value);
    let db = jp.dop_base.as_ref().map(|d| build_dop(builder, d));
    let sem = builder.create_string(&jp.semantic);
    dataformat::JobParam::create(builder, &dataformat::JobParamArgs {
        short_name: Some(sn), long_name: ln, physical_default_value: Some(pdv),
        dop_base: db, semantic: Some(sem),
    })
}

fn build_state_chart<'a>(builder: &mut FlatBufferBuilder<'a>, sc: &StateChart) -> flatbuffers::WIPOffset<dataformat::StateChart<'a>> {
    let sn = builder.create_string(&sc.short_name);
    let sem = builder.create_string(&sc.semantic);
    let sts: Vec<_> = sc.state_transitions.iter().map(|st| {
        let sn = builder.create_string(&st.short_name);
        let src = builder.create_string(&st.source_short_name_ref);
        let tgt = builder.create_string(&st.target_short_name_ref);
        dataformat::StateTransition::create(builder, &dataformat::StateTransitionArgs {
            short_name: Some(sn), source_short_name_ref: Some(src), target_short_name_ref: Some(tgt),
        })
    }).collect();
    let sts = builder.create_vector(&sts);
    let start = builder.create_string(&sc.start_state_short_name_ref);
    let states: Vec<_> = sc.states.iter().map(|state| {
        let sn = builder.create_string(&state.short_name);
        let ln = state.long_name.as_ref().map(|ln| build_long_name(builder, ln));
        dataformat::State::create(builder, &dataformat::StateArgs { short_name: Some(sn), long_name: ln })
    }).collect();
    let states = builder.create_vector(&states);
    dataformat::StateChart::create(builder, &dataformat::StateChartArgs {
        short_name: Some(sn), semantic: Some(sem), state_transitions: Some(sts),
        start_state_short_name_ref: Some(start), states: Some(states),
    })
}

fn build_audience<'a>(builder: &mut FlatBufferBuilder<'a>, a: &Audience) -> flatbuffers::WIPOffset<dataformat::Audience<'a>> {
    let ea: Vec<_> = a.enabled_audiences.iter().map(|aa| build_additional_audience(builder, aa)).collect();
    let ea = builder.create_vector(&ea);
    let da: Vec<_> = a.disabled_audiences.iter().map(|aa| build_additional_audience(builder, aa)).collect();
    let da = builder.create_vector(&da);
    dataformat::Audience::create(builder, &dataformat::AudienceArgs {
        enabled_audiences: Some(ea), disabled_audiences: Some(da),
        is_supplier: a.is_supplier, is_development: a.is_development,
        is_manufacturing: a.is_manufacturing, is_after_sales: a.is_after_sales,
        is_after_market: a.is_after_market,
    })
}

fn build_additional_audience<'a>(builder: &mut FlatBufferBuilder<'a>, aa: &AdditionalAudience) -> flatbuffers::WIPOffset<dataformat::AdditionalAudience<'a>> {
    let sn = builder.create_string(&aa.short_name);
    let ln = aa.long_name.as_ref().map(|ln| build_long_name(builder, ln));
    dataformat::AdditionalAudience::create(builder, &dataformat::AdditionalAudienceArgs { short_name: Some(sn), long_name: ln })
}

fn build_state_transition_ref<'a>(builder: &mut FlatBufferBuilder<'a>, str_ref: &StateTransitionRef) -> flatbuffers::WIPOffset<dataformat::StateTransitionRef<'a>> {
    let v = builder.create_string(&str_ref.value);
    let st = str_ref.state_transition.as_ref().map(|st| {
        let sn = builder.create_string(&st.short_name);
        let src = builder.create_string(&st.source_short_name_ref);
        let tgt = builder.create_string(&st.target_short_name_ref);
        dataformat::StateTransition::create(builder, &dataformat::StateTransitionArgs {
            short_name: Some(sn), source_short_name_ref: Some(src), target_short_name_ref: Some(tgt),
        })
    });
    dataformat::StateTransitionRef::create(builder, &dataformat::StateTransitionRefArgs { value: Some(v), state_transition: st })
}

fn build_pre_condition_state_ref<'a>(builder: &mut FlatBufferBuilder<'a>, pcsr: &PreConditionStateRef) -> flatbuffers::WIPOffset<dataformat::PreConditionStateRef<'a>> {
    let v = builder.create_string(&pcsr.value);
    let ipisn = builder.create_string(&pcsr.in_param_if_short_name);
    let ippsn = builder.create_string(&pcsr.in_param_path_short_name);
    let state = pcsr.state.as_ref().map(|s| {
        let sn = builder.create_string(&s.short_name);
        let ln = s.long_name.as_ref().map(|ln| build_long_name(builder, ln));
        dataformat::State::create(builder, &dataformat::StateArgs { short_name: Some(sn), long_name: ln })
    });
    dataformat::PreConditionStateRef::create(builder, &dataformat::PreConditionStateRefArgs {
        value: Some(v), in_param_if_short_name: Some(ipisn), in_param_path_short_name: Some(ippsn), state,
    })
}

// --- Text builders ---

fn build_text<'a>(builder: &mut FlatBufferBuilder<'a>, t: &Text) -> flatbuffers::WIPOffset<dataformat::Text<'a>> {
    let v = builder.create_string(&t.value);
    let ti = builder.create_string(&t.ti);
    dataformat::Text::create(builder, &dataformat::TextArgs { value: Some(v), ti: Some(ti) })
}

fn build_long_name<'a>(builder: &mut FlatBufferBuilder<'a>, ln: &LongName) -> flatbuffers::WIPOffset<dataformat::LongName<'a>> {
    let v = builder.create_string(&ln.value);
    let ti = builder.create_string(&ln.ti);
    dataformat::LongName::create(builder, &dataformat::LongNameArgs { value: Some(v), ti: Some(ti) })
}

fn build_sdgs<'a>(builder: &mut FlatBufferBuilder<'a>, sdgs: &Sdgs) -> flatbuffers::WIPOffset<dataformat::SDGS<'a>> {
    let s: Vec<_> = sdgs.sdgs.iter().map(|sdg| build_sdg(builder, sdg)).collect();
    let s = builder.create_vector(&s);
    dataformat::SDGS::create(builder, &dataformat::SDGSArgs { sdgs: Some(s) })
}

fn build_sdg<'a>(builder: &mut FlatBufferBuilder<'a>, sdg: &Sdg) -> flatbuffers::WIPOffset<dataformat::SDG<'a>> {
    let csn = builder.create_string(&sdg.caption_sn);
    let si = builder.create_string(&sdg.si);
    let sds: Vec<_> = sdg.sds.iter().map(|entry| {
        match entry {
            SdOrSdg::Sd(sd) => {
                let v = builder.create_string(&sd.value);
                let si = builder.create_string(&sd.si);
                let ti = builder.create_string(&sd.ti);
                let sd_off = dataformat::SD::create(builder, &dataformat::SDArgs { value: Some(v), si: Some(si), ti: Some(ti) });
                dataformat::SDOrSDG::create(builder, &dataformat::SDOrSDGArgs {
                    sd_or_sdg_type: dataformat::SDxorSDG::SD, sd_or_sdg: Some(dataformat::SDxorSDG::tag_as_sd(sd_off).value_offset()),
                })
            }
            SdOrSdg::Sdg(nested_sdg) => {
                let nested = build_sdg(builder, nested_sdg);
                dataformat::SDOrSDG::create(builder, &dataformat::SDOrSDGArgs {
                    sd_or_sdg_type: dataformat::SDxorSDG::SDG, sd_or_sdg: Some(dataformat::SDxorSDG::tag_as_sdg(nested).value_offset()),
                })
            }
        }
    }).collect();
    let sds = builder.create_vector(&sds);
    dataformat::SDG::create(builder, &dataformat::SDGArgs { caption_sn: Some(csn), sds: Some(sds), si: Some(si) })
}

// --- Enum converters (IR -> FBS) ---

fn ir_diag_coded_type_name_to_fbs(v: DiagCodedTypeName) -> dataformat::DiagCodedTypeName {
    match v {
        DiagCodedTypeName::LeadingLengthInfoType => dataformat::DiagCodedTypeName::LEADING_LENGTH_INFO_TYPE,
        DiagCodedTypeName::MinMaxLengthType => dataformat::DiagCodedTypeName::MIN_MAX_LENGTH_TYPE,
        DiagCodedTypeName::ParamLengthInfoType => dataformat::DiagCodedTypeName::PARAM_LENGTH_INFO_TYPE,
        DiagCodedTypeName::StandardLengthType => dataformat::DiagCodedTypeName::STANDARD_LENGTH_TYPE,
    }
}
fn ir_data_type_to_fbs(v: DataType) -> dataformat::DataType {
    match v {
        DataType::AInt32 => dataformat::DataType::A_INT_32,
        DataType::AUint32 => dataformat::DataType::A_UINT_32,
        DataType::AFloat32 => dataformat::DataType::A_FLOAT_32,
        DataType::AAsciiString => dataformat::DataType::A_ASCIISTRING,
        DataType::AUtf8String => dataformat::DataType::A_UTF_8_STRING,
        DataType::AUnicode2String => dataformat::DataType::A_UNICODE_2_STRING,
        DataType::ABytefield => dataformat::DataType::A_BYTEFIELD,
        DataType::AFloat64 => dataformat::DataType::A_FLOAT_64,
    }
}
fn ir_termination_to_fbs(v: Termination) -> dataformat::Termination {
    match v { Termination::EndOfPdu => dataformat::Termination::END_OF_PDU, Termination::Zero => dataformat::Termination::ZERO, Termination::HexFf => dataformat::Termination::HEX_FF }
}
fn ir_interval_type_to_fbs(v: IntervalType) -> dataformat::IntervalType {
    match v { IntervalType::Open => dataformat::IntervalType::OPEN, IntervalType::Closed => dataformat::IntervalType::CLOSED, IntervalType::Infinite => dataformat::IntervalType::INFINITE }
}
fn ir_compu_category_to_fbs(v: CompuCategory) -> dataformat::CompuCategory {
    match v {
        CompuCategory::Identical => dataformat::CompuCategory::IDENTICAL, CompuCategory::Linear => dataformat::CompuCategory::LINEAR,
        CompuCategory::ScaleLinear => dataformat::CompuCategory::SCALE_LINEAR, CompuCategory::TextTable => dataformat::CompuCategory::TEXT_TABLE,
        CompuCategory::CompuCode => dataformat::CompuCategory::COMPU_CODE, CompuCategory::TabIntp => dataformat::CompuCategory::TAB_INTP,
        CompuCategory::RatFunc => dataformat::CompuCategory::RAT_FUNC, CompuCategory::ScaleRatFunc => dataformat::CompuCategory::SCALE_RAT_FUNC,
    }
}
fn ir_physical_type_data_type_to_fbs(v: PhysicalTypeDataType) -> dataformat::PhysicalTypeDataType {
    match v {
        PhysicalTypeDataType::AInt32 => dataformat::PhysicalTypeDataType::A_INT_32, PhysicalTypeDataType::AUint32 => dataformat::PhysicalTypeDataType::A_UINT_32,
        PhysicalTypeDataType::AFloat32 => dataformat::PhysicalTypeDataType::A_FLOAT_32, PhysicalTypeDataType::AAsciiString => dataformat::PhysicalTypeDataType::A_ASCIISTRING,
        PhysicalTypeDataType::AUtf8String => dataformat::PhysicalTypeDataType::A_UTF_8_STRING, PhysicalTypeDataType::AUnicode2String => dataformat::PhysicalTypeDataType::A_UNICODE_2_STRING,
        PhysicalTypeDataType::ABytefield => dataformat::PhysicalTypeDataType::A_BYTEFIELD, PhysicalTypeDataType::AFloat64 => dataformat::PhysicalTypeDataType::A_FLOAT_64,
    }
}
fn ir_radix_to_fbs(v: Radix) -> dataformat::Radix {
    match v { Radix::Hex => dataformat::Radix::HEX, Radix::Dec => dataformat::Radix::DEC, Radix::Bin => dataformat::Radix::BIN, Radix::Oct => dataformat::Radix::OCT }
}
fn ir_valid_type_to_fbs(v: ValidType) -> dataformat::ValidType {
    match v { ValidType::Valid => dataformat::ValidType::VALID, ValidType::NotValid => dataformat::ValidType::NOT_VALID, ValidType::NotDefined => dataformat::ValidType::NOT_DEFINED, ValidType::NotAvailable => dataformat::ValidType::NOT_AVAILABLE }
}
fn ir_dop_type_to_fbs(v: DopType) -> dataformat::DOPType {
    match v {
        DopType::Regular => dataformat::DOPType::REGULAR, DopType::EnvDataDesc => dataformat::DOPType::ENV_DATA_DESC,
        DopType::Mux => dataformat::DOPType::MUX, DopType::DynamicEndMarkerField => dataformat::DOPType::DYNAMIC_END_MARKER_FIELD,
        DopType::DynamicLengthField => dataformat::DOPType::DYNAMIC_LENGTH_FIELD, DopType::EndOfPduField => dataformat::DOPType::END_OF_PDU_FIELD,
        DopType::StaticField => dataformat::DOPType::STATIC_FIELD, DopType::EnvData => dataformat::DOPType::ENV_DATA,
        DopType::Structure => dataformat::DOPType::STRUCTURE, DopType::Dtc => dataformat::DOPType::DTC,
    }
}
fn ir_param_type_to_fbs(v: ParamType) -> dataformat::ParamType {
    match v {
        ParamType::CodedConst => dataformat::ParamType::CODED_CONST, ParamType::Dynamic => dataformat::ParamType::DYNAMIC,
        ParamType::LengthKey => dataformat::ParamType::LENGTH_KEY, ParamType::MatchingRequestParam => dataformat::ParamType::MATCHING_REQUEST_PARAM,
        ParamType::NrcConst => dataformat::ParamType::NRC_CONST, ParamType::PhysConst => dataformat::ParamType::PHYS_CONST,
        ParamType::Reserved => dataformat::ParamType::RESERVED, ParamType::System => dataformat::ParamType::SYSTEM,
        ParamType::TableEntry => dataformat::ParamType::TABLE_ENTRY, ParamType::TableKey => dataformat::ParamType::TABLE_KEY,
        ParamType::TableStruct => dataformat::ParamType::TABLE_STRUCT, ParamType::Value => dataformat::ParamType::VALUE,
    }
}
fn ir_table_entry_row_fragment_to_fbs(v: TableEntryRowFragment) -> dataformat::TableEntryRowFragment {
    match v { TableEntryRowFragment::Key => dataformat::TableEntryRowFragment::KEY, TableEntryRowFragment::Struct => dataformat::TableEntryRowFragment::STRUCT }
}
fn ir_diag_class_type_to_fbs(v: DiagClassType) -> dataformat::DiagClassType {
    match v {
        DiagClassType::StartComm => dataformat::DiagClassType::START_COMM, DiagClassType::StopComm => dataformat::DiagClassType::STOP_COMM,
        DiagClassType::VariantIdentification => dataformat::DiagClassType::VARIANT_IDENTIFICATION, DiagClassType::ReadDynDefMessage => dataformat::DiagClassType::READ_DYN_DEF_MESSAGE,
        DiagClassType::DynDefMessage => dataformat::DiagClassType::DYN_DEF_MESSAGE, DiagClassType::ClearDynDefMessage => dataformat::DiagClassType::CLEAR_DYN_DEF_MESSAGE,
    }
}
fn ir_response_type_to_fbs(v: ResponseType) -> dataformat::ResponseType {
    match v { ResponseType::PosResponse => dataformat::ResponseType::POS_RESPONSE, ResponseType::NegResponse => dataformat::ResponseType::NEG_RESPONSE, ResponseType::GlobalNegResponse => dataformat::ResponseType::GLOBAL_NEG_RESPONSE }
}
fn ir_addressing_to_fbs(v: Addressing) -> dataformat::Addressing {
    match v { Addressing::Functional => dataformat::Addressing::FUNCTIONAL, Addressing::Physical => dataformat::Addressing::PHYSICAL, Addressing::FunctionalOrPhysical => dataformat::Addressing::FUNCTIONAL_OR_PHYSICAL }
}
fn ir_transmission_mode_to_fbs(v: TransmissionMode) -> dataformat::TransmissionMode {
    match v { TransmissionMode::SendOnly => dataformat::TransmissionMode::SEND_ONLY, TransmissionMode::ReceiveOnly => dataformat::TransmissionMode::RECEIVE_ONLY, TransmissionMode::SendAndReceive => dataformat::TransmissionMode::SEND_AND_RECEIVE, TransmissionMode::SendOrReceive => dataformat::TransmissionMode::SEND_OR_RECEIVE }
}
