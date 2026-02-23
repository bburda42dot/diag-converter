//! ODX writer: IR DiagDatabase -> ODX XML string.
//!
//! Reverse of the parser. Maps IR types to odx_model types, then serializes
//! to XML via quick-xml.

use diag_ir::*;
use thiserror::Error;

use crate::odx_model::*;

#[derive(Debug, Error)]
pub enum OdxWriteError {
    #[error("XML serialization failed: {0}")]
    XmlError(#[from] quick_xml::DeError),
    #[error("XML serialization IO error: {0}")]
    SerError(String),
}

/// Write an IR DiagDatabase to an ODX XML string.
pub fn write_odx(db: &DiagDatabase) -> Result<String, OdxWriteError> {
    let odx = ir_to_odx(db);
    let xml = quick_xml::se::to_string(&odx).map_err(|e| OdxWriteError::SerError(e.to_string()))?;

    // Add XML declaration and format
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        xml
    ))
}

fn ir_to_odx(db: &DiagDatabase) -> Odx {
    let mut base_variants = Vec::new();
    let mut ecu_variants = Vec::new();

    for variant in &db.variants {
        let layer = ir_variant_to_layer(variant, db);
        if variant.is_base_variant {
            base_variants.push(layer);
        } else {
            ecu_variants.push(layer);
        }
    }

    let functional_groups: Vec<DiagLayerVariant> = db
        .functional_groups
        .iter()
        .map(|fg| ir_fg_to_layer(fg))
        .collect();

    Odx {
        version: if db.version.is_empty() {
            None
        } else {
            Some(db.version.clone())
        },
        diag_layer_container: Some(DiagLayerContainer {
            id: None,
            short_name: Some(db.ecu_name.clone()),
            long_name: None,
            admin_data: if db.revision.is_empty() {
                None
            } else {
                Some(AdminData {
                    language: None,
                    doc_revisions: Some(DocRevisionsWrapper {
                        items: vec![DocRevision {
                            revision_label: Some(db.revision.clone()),
                            state: None,
                            date: None,
                        }],
                    }),
                })
            },
            sdgs: None,
            base_variants: if base_variants.is_empty() {
                None
            } else {
                Some(BaseVariantsWrapper {
                    items: base_variants,
                })
            },
            ecu_variants: if ecu_variants.is_empty() {
                None
            } else {
                Some(EcuVariantsWrapper {
                    items: ecu_variants,
                })
            },
            ecu_shared_datas: None,
            functional_groups: if functional_groups.is_empty() {
                None
            } else {
                Some(FunctionalGroupsWrapper {
                    items: functional_groups,
                })
            },
            protocols: None,
        }),
        comparam_spec: None,
    }
}

fn ir_variant_to_layer(variant: &Variant, db: &DiagDatabase) -> DiagLayerVariant {
    let mut layer = ir_diag_layer_to_odx(&variant.diag_layer, db);

    // Add variant patterns
    if !variant.variant_patterns.is_empty() {
        layer.ecu_variant_patterns = Some(EcuVariantPatternsWrapper {
            items: variant
                .variant_patterns
                .iter()
                .map(|vp| OdxEcuVariantPattern {
                    matching_parameters: Some(MatchingParametersWrapper {
                        items: vp
                            .matching_parameters
                            .iter()
                            .map(|mp| OdxMatchingParameter {
                                expected_value: Some(mp.expected_value.clone()),
                                diag_comm_snref: Some(OdxSnRef {
                                    short_name: Some(mp.diag_service.diag_comm.short_name.clone()),
                                }),
                                out_param_snref: Some(OdxSnRef {
                                    short_name: Some(mp.out_param.short_name.clone()),
                                }),
                            })
                            .collect(),
                    }),
                })
                .collect(),
        });
    }

    // Add parent refs
    if !variant.parent_refs.is_empty() {
        layer.parent_refs = Some(ParentRefsWrapper {
            items: variant
                .parent_refs
                .iter()
                .map(ir_parent_ref_to_odx)
                .collect(),
        });
    }

    layer
}

fn ir_fg_to_layer(fg: &FunctionalGroup) -> DiagLayerVariant {
    let mut layer = ir_diag_layer_to_odx_no_dtcs(&fg.diag_layer);

    if !fg.parent_refs.is_empty() {
        layer.parent_refs = Some(ParentRefsWrapper {
            items: fg
                .parent_refs
                .iter()
                .map(ir_parent_ref_to_odx)
                .collect(),
        });
    }

    layer
}

fn ir_diag_layer_to_odx(diag_layer: &DiagLayer, db: &DiagDatabase) -> DiagLayerVariant {
    let mut layer = ir_diag_layer_to_odx_no_dtcs(diag_layer);

    // Add DTCs as DTC-DOPs in data dictionary
    if !db.dtcs.is_empty() {
        let dtc_dop = OdxDtcDop {
            id: Some("DTCDOP_generated".into()),
            is_visible: None,
            short_name: Some("DTC_DOP".into()),
            long_name: None,
            sdgs: None,
            diag_coded_type: Some(OdxDiagCodedType {
                xsi_type: Some("STANDARD-LENGTH-TYPE".into()),
                base_data_type: Some("A_UINT32".into()),
                is_highlow_byte_order: None,
                base_type_encoding: None,
                is_condensed: None,
                bit_length: Some(24),
                bit_mask: None,
                min_length: None,
                max_length: None,
                termination: None,
                length_key_ref: None,
            }),
            physical_type: None,
            compu_method: None,
            dtcs: Some(DtcsWrapper {
                items: db.dtcs.iter().map(ir_dtc_to_odx).collect(),
            }),
        };

        if let Some(spec) = &mut layer.diag_data_dictionary_spec {
            spec.dtc_dops = Some(DtcDopsWrapper {
                items: vec![dtc_dop],
            });
        } else {
            layer.diag_data_dictionary_spec = Some(DiagDataDictionarySpec {
                data_object_props: None,
                dtc_dops: Some(DtcDopsWrapper {
                    items: vec![dtc_dop],
                }),
                structures: None,
                end_of_pdu_fields: None,
                static_fields: None,
                dynamic_length_fields: None,
                muxs: None,
                env_datas: None,
                env_data_descs: None,
                tables: None,
                unit_spec: None,
                sdgs: None,
            });
        }
    }

    layer
}

fn ir_diag_layer_to_odx_no_dtcs(diag_layer: &DiagLayer) -> DiagLayerVariant {
    let mut col = DopCollection::default();
    let mut requests = Vec::new();
    let mut pos_responses = Vec::new();
    let mut neg_responses = Vec::new();
    let mut diag_comms = Vec::new();

    for (i, svc) in diag_layer.diag_services.iter().enumerate() {
        let svc_id = format!("DS_{}", i);

        if let Some(req) = &svc.request {
            collect_dops_from_params(&req.params, &mut col);
            let req_id = format!("RQ_{}", i);
            requests.push(ir_request_to_odx(req, &req_id, &col.data_object_props));

            for (j, resp) in svc.pos_responses.iter().enumerate() {
                collect_dops_from_params(&resp.params, &mut col);
                let resp_id = format!("PR_{}_{}", i, j);
                pos_responses.push(ir_response_to_odx(resp, &resp_id, &col.data_object_props));
            }

            for (j, resp) in svc.neg_responses.iter().enumerate() {
                collect_dops_from_params(&resp.params, &mut col);
                let resp_id = format!("NR_{}_{}", i, j);
                neg_responses.push(ir_response_to_odx(resp, &resp_id, &col.data_object_props));
            }

            diag_comms.push(DiagCommEntry::DiagService(ir_diag_service_to_odx(
                svc, &svc_id, i,
            )));
        } else {
            diag_comms.push(DiagCommEntry::DiagService(ir_diag_service_to_odx(
                svc, &svc_id, i,
            )));
        }
    }

    for (i, job) in diag_layer.single_ecu_jobs.iter().enumerate() {
        diag_comms.push(DiagCommEntry::SingleEcuJob(ir_ecu_job_to_odx(job, i)));
    }

    let has_any_dop = !col.data_object_props.is_empty()
        || !col.structures.is_empty()
        || !col.dtc_dops.is_empty()
        || !col.end_of_pdu_fields.is_empty()
        || !col.static_fields.is_empty()
        || !col.dynamic_length_fields.is_empty()
        || !col.muxs.is_empty()
        || !col.env_datas.is_empty()
        || !col.env_data_descs.is_empty();

    fn opt_wrap<T, W>(v: Vec<T>, wrap: impl FnOnce(Vec<T>) -> W) -> Option<W> {
        if v.is_empty() { None } else { Some(wrap(v)) }
    }

    let data_dict = if !has_any_dop {
        None
    } else {
        Some(DiagDataDictionarySpec {
            data_object_props: opt_wrap(col.data_object_props, |v| DataObjectPropsWrapper { items: v }),
            dtc_dops: opt_wrap(col.dtc_dops, |v| DtcDopsWrapper { items: v }),
            structures: opt_wrap(col.structures, |v| StructuresWrapper { items: v }),
            end_of_pdu_fields: opt_wrap(col.end_of_pdu_fields, |v| EndOfPduFieldsWrapper { items: v }),
            static_fields: opt_wrap(col.static_fields, |v| StaticFieldsWrapper { items: v }),
            dynamic_length_fields: opt_wrap(col.dynamic_length_fields, |v| DynamicLengthFieldsWrapper { items: v }),
            muxs: opt_wrap(col.muxs, |v| MuxsWrapper { items: v }),
            env_datas: opt_wrap(col.env_datas, |v| EnvDatasWrapper { items: v }),
            env_data_descs: opt_wrap(col.env_data_descs, |v| EnvDataDescsWrapper { items: v }),
            tables: None,
            unit_spec: None,
            sdgs: None,
        })
    };

    DiagLayerVariant {
        id: None,
        short_name: Some(diag_layer.short_name.clone()),
        long_name: diag_layer.long_name.as_ref().map(|ln| ln.value.clone()),
        admin_data: None,
        sdgs: ir_sdgs_to_odx(&diag_layer.sdgs),
        funct_classs: if diag_layer.funct_classes.is_empty() {
            None
        } else {
            Some(FunctClasssWrapper {
                items: diag_layer
                    .funct_classes
                    .iter()
                    .map(|fc| crate::odx_model::FunctClass {
                        id: None,
                        short_name: Some(fc.short_name.clone()),
                        long_name: None,
                    })
                    .collect(),
            })
        },
        diag_data_dictionary_spec: data_dict,
        diag_comms: if diag_comms.is_empty() {
            None
        } else {
            Some(DiagCommsWrapper {
                items: diag_comms,
            })
        },
        requests: if requests.is_empty() {
            None
        } else {
            Some(RequestsWrapper { items: requests })
        },
        pos_responses: if pos_responses.is_empty() {
            None
        } else {
            Some(PosResponsesWrapper {
                items: pos_responses,
            })
        },
        neg_responses: if neg_responses.is_empty() {
            None
        } else {
            Some(NegResponsesWrapper {
                items: neg_responses,
            })
        },
        global_neg_responses: None,
        state_charts: if diag_layer.state_charts.is_empty() {
            None
        } else {
            Some(StateChartsWrapper {
                items: diag_layer
                    .state_charts
                    .iter()
                    .map(ir_state_chart_to_odx)
                    .collect(),
            })
        },
        additional_audiences: if diag_layer.additional_audiences.is_empty() {
            None
        } else {
            Some(AdditionalAudiencesWrapper {
                items: diag_layer
                    .additional_audiences
                    .iter()
                    .map(|aa| OdxAdditionalAudience {
                        id: None,
                        short_name: Some(aa.short_name.clone()),
                        long_name: aa.long_name.as_ref().map(|ln| ln.value.clone()),
                    })
                    .collect(),
            })
        },
        parent_refs: None,
        comparam_refs: None,
        ecu_variant_patterns: None,
    }
}

// --- Service/Request/Response ---

fn ir_diag_service_to_odx(svc: &DiagService, svc_id: &str, idx: usize) -> OdxDiagService {
    let request_ref = svc.request.as_ref().map(|_| OdxRef {
        id_ref: Some(format!("RQ_{}", idx)),
        docref: None,
        doctype: None,
    });

    let pos_response_refs = if svc.pos_responses.is_empty() {
        None
    } else {
        Some(PosResponseRefsWrapper {
            items: (0..svc.pos_responses.len())
                .map(|j| OdxRef {
                    id_ref: Some(format!("PR_{}_{}", idx, j)),
                    docref: None,
                    doctype: None,
                })
                .collect(),
        })
    };

    let neg_response_refs = if svc.neg_responses.is_empty() {
        None
    } else {
        Some(NegResponseRefsWrapper {
            items: (0..svc.neg_responses.len())
                .map(|j| OdxRef {
                    id_ref: Some(format!("NR_{}_{}", idx, j)),
                    docref: None,
                    doctype: None,
                })
                .collect(),
        })
    };

    OdxDiagService {
        id: Some(svc_id.to_string()),
        semantic: if svc.diag_comm.semantic.is_empty() {
            None
        } else {
            Some(svc.diag_comm.semantic.clone())
        },
        diagnostic_class: None,
        is_mandatory: if svc.diag_comm.is_mandatory {
            Some("true".into())
        } else {
            None
        },
        is_executable: if !svc.diag_comm.is_executable {
            Some("false".into())
        } else {
            None
        },
        is_final: if svc.diag_comm.is_final {
            Some("true".into())
        } else {
            None
        },
        is_cyclic: if svc.is_cyclic {
            Some("true".into())
        } else {
            None
        },
        is_multiple: if svc.is_multiple {
            Some("true".into())
        } else {
            None
        },
        addressing: None,
        transmission_mode: None,
        short_name: Some(svc.diag_comm.short_name.clone()),
        long_name: svc.diag_comm.long_name.as_ref().map(|ln| ln.value.clone()),
        sdgs: ir_sdgs_to_odx(&svc.diag_comm.sdgs),
        funct_class_refs: None,
        audience: svc.diag_comm.audience.as_ref().map(ir_audience_to_odx),
        request_ref,
        pos_response_refs,
        neg_response_refs,
        pre_condition_state_refs: None,
        state_transition_refs: None,
        comparam_refs: None,
    }
}

fn ir_request_to_odx(
    req: &Request,
    req_id: &str,
    dops: &[OdxDataObjectProp],
) -> OdxRequest {
    OdxRequest {
        id: Some(req_id.to_string()),
        short_name: Some(req_id.to_string()),
        long_name: None,
        sdgs: ir_sdgs_to_odx(&req.sdgs),
        byte_size: None,
        params: if req.params.is_empty() {
            None
        } else {
            Some(ParamsWrapper {
                items: req.params.iter().map(|p| ir_param_to_odx(p, dops)).collect(),
            })
        },
    }
}

fn ir_response_to_odx(
    resp: &Response,
    resp_id: &str,
    dops: &[OdxDataObjectProp],
) -> OdxResponse {
    OdxResponse {
        id: Some(resp_id.to_string()),
        short_name: Some(resp_id.to_string()),
        long_name: None,
        sdgs: ir_sdgs_to_odx(&resp.sdgs),
        byte_size: None,
        params: if resp.params.is_empty() {
            None
        } else {
            Some(ParamsWrapper {
                items: resp.params.iter().map(|p| ir_param_to_odx(p, dops)).collect(),
            })
        },
    }
}

// --- Param ---

fn set_dop_ref(odx_param: &mut OdxParam, dop: &Dop, dops: &[OdxDataObjectProp]) {
    if !dop.short_name.is_empty() {
        let dop_id = dops
            .iter()
            .find(|d| d.short_name.as_deref() == Some(&dop.short_name))
            .and_then(|d| d.id.clone());
        if let Some(id) = dop_id {
            odx_param.dop_ref = Some(OdxRef {
                id_ref: Some(id),
                docref: None,
                doctype: None,
            });
        }
    }
}

fn ir_param_to_odx(p: &Param, dops: &[OdxDataObjectProp]) -> OdxParam {
    let mut odx_param = OdxParam {
        xsi_type: None,
        semantic: if p.semantic.is_empty() {
            None
        } else {
            Some(p.semantic.clone())
        },
        short_name: Some(p.short_name.clone()),
        long_name: None,
        byte_position: p.byte_position,
        bit_position: p.bit_position,
        sdgs: ir_sdgs_to_odx(&p.sdgs),
        dop_ref: None,
        dop_snref: None,
        physical_default_value: if p.physical_default_value.is_empty() {
            None
        } else {
            Some(p.physical_default_value.clone())
        },
        coded_value: None,
        diag_coded_type: None,
        coded_values: None,
        phys_constant_value: None,
        bit_length: None,
        request_byte_pos: None,
        match_byte_length: None,
        table_ref: None,
        table_snref: None,
        target: None,
        table_key_ref: None,
        table_key_snref: None,
        table_row_ref: None,
        table_row_snref: None,
    };

    match &p.specific_data {
        Some(ParamData::CodedConst {
            coded_value,
            diag_coded_type,
        }) => {
            odx_param.xsi_type = Some("CODED-CONST".into());
            odx_param.coded_value = Some(coded_value.clone());
            odx_param.diag_coded_type = Some(ir_dct_to_odx(diag_coded_type));
        }
        Some(ParamData::NrcConst {
            coded_values,
            diag_coded_type,
        }) => {
            odx_param.xsi_type = Some("NRC-CONST".into());
            odx_param.coded_values = Some(CodedValuesWrapper {
                items: coded_values.clone(),
            });
            odx_param.diag_coded_type = Some(ir_dct_to_odx(diag_coded_type));
        }
        Some(ParamData::Value { dop, .. }) => {
            odx_param.xsi_type = Some("VALUE".into());
            set_dop_ref(&mut odx_param, dop, dops);
        }
        Some(ParamData::PhysConst {
            phys_constant_value,
            dop,
        }) => {
            odx_param.xsi_type = Some("PHYS-CONST".into());
            odx_param.phys_constant_value = Some(phys_constant_value.clone());
            set_dop_ref(&mut odx_param, dop, dops);
        }
        Some(ParamData::MatchingRequestParam {
            request_byte_pos,
            byte_length,
        }) => {
            odx_param.xsi_type = Some("MATCHING-REQUEST-PARAM".into());
            odx_param.request_byte_pos = Some(*request_byte_pos);
            odx_param.match_byte_length = Some(*byte_length);
        }
        Some(ParamData::Reserved { bit_length }) => {
            odx_param.xsi_type = Some("RESERVED".into());
            odx_param.bit_length = Some(*bit_length);
        }
        Some(ParamData::Dynamic) => {
            odx_param.xsi_type = Some("DYNAMIC".into());
        }
        Some(ParamData::LengthKeyRef { dop }) => {
            odx_param.xsi_type = Some("LENGTH-KEY".into());
            set_dop_ref(&mut odx_param, dop, dops);
        }
        Some(ParamData::System { dop, .. }) => {
            odx_param.xsi_type = Some("SYSTEM".into());
            set_dop_ref(&mut odx_param, dop, dops);
        }
        Some(ParamData::TableKey { .. }) => {
            odx_param.xsi_type = Some("TABLE-KEY".into());
        }
        Some(ParamData::TableEntry { target, .. }) => {
            odx_param.xsi_type = Some("TABLE-ENTRY".into());
            odx_param.target = Some(match target {
                TableEntryRowFragment::Key => "KEY".into(),
                TableEntryRowFragment::Struct => "STRUCT".into(),
            });
        }
        Some(ParamData::TableStruct { .. }) => {
            odx_param.xsi_type = Some("TABLE-STRUCT".into());
        }
        None => {}
    }

    odx_param
}

// --- DOP collection ---

#[derive(Default)]
struct DopCollection {
    data_object_props: Vec<OdxDataObjectProp>,
    structures: Vec<OdxStructure>,
    dtc_dops: Vec<OdxDtcDop>,
    end_of_pdu_fields: Vec<OdxEndOfPduField>,
    static_fields: Vec<OdxStaticField>,
    dynamic_length_fields: Vec<OdxDynamicLengthField>,
    muxs: Vec<OdxMux>,
    env_datas: Vec<OdxEnvData>,
    env_data_descs: Vec<OdxEnvDataDesc>,
}

fn collect_dops_from_params(params: &[Param], col: &mut DopCollection) {
    for p in params {
        let dop = match &p.specific_data {
            Some(ParamData::Value { dop, .. }) => Some(dop.as_ref()),
            Some(ParamData::PhysConst { dop, .. }) => Some(dop.as_ref()),
            Some(ParamData::System { dop, .. }) => Some(dop.as_ref()),
            Some(ParamData::LengthKeyRef { dop }) => Some(dop.as_ref()),
            _ => None,
        };

        if let Some(dop) = dop {
            if dop.short_name.is_empty() {
                continue;
            }
            let name = &dop.short_name;
            match &dop.specific_data {
                Some(DopData::NormalDop { .. }) | None => {
                    if !col.data_object_props.iter().any(|d| d.short_name.as_deref() == Some(name.as_str())) {
                        col.data_object_props.push(ir_dop_to_odx(dop));
                    }
                }
                Some(DopData::Structure { params, byte_size, is_visible }) => {
                    if !col.structures.iter().any(|s| s.short_name.as_deref() == Some(name.as_str())) {
                        col.structures.push(ir_structure_to_odx(name, params, *byte_size, *is_visible, &col.data_object_props));
                    }
                }
                Some(DopData::DtcDop { diag_coded_type, physical_type, compu_method, dtcs, is_visible }) => {
                    if !col.dtc_dops.iter().any(|d| d.short_name.as_deref() == Some(name.as_str())) {
                        col.dtc_dops.push(ir_dtc_dop_to_odx(name, diag_coded_type, physical_type, compu_method, dtcs, *is_visible));
                    }
                }
                Some(DopData::EndOfPduField { max_number_of_items, min_number_of_items, .. }) => {
                    if !col.end_of_pdu_fields.iter().any(|f| f.short_name.as_deref() == Some(name.as_str())) {
                        col.end_of_pdu_fields.push(OdxEndOfPduField {
                            id: Some(format!("EOPF_{name}")),
                            short_name: Some(name.clone()),
                            max_number_of_items: *max_number_of_items,
                            min_number_of_items: *min_number_of_items,
                        });
                    }
                }
                Some(DopData::StaticField { fixed_number_of_items, item_byte_size, .. }) => {
                    if !col.static_fields.iter().any(|f| f.short_name.as_deref() == Some(name.as_str())) {
                        col.static_fields.push(OdxStaticField {
                            id: Some(format!("SF_{name}")),
                            short_name: Some(name.clone()),
                            fixed_number_of_items: Some(*fixed_number_of_items),
                            item_byte_size: Some(*item_byte_size),
                        });
                    }
                }
                Some(DopData::DynamicLengthField { offset, .. }) => {
                    if !col.dynamic_length_fields.iter().any(|f| f.short_name.as_deref() == Some(name.as_str())) {
                        col.dynamic_length_fields.push(OdxDynamicLengthField {
                            id: Some(format!("DLF_{name}")),
                            short_name: Some(name.clone()),
                            offset: Some(*offset),
                        });
                    }
                }
                Some(DopData::MuxDop { .. }) => {
                    if !col.muxs.iter().any(|m| m.short_name.as_deref() == Some(name.as_str())) {
                        col.muxs.push(OdxMux {
                            id: Some(format!("MUX_{name}")),
                            short_name: Some(name.clone()),
                        });
                    }
                }
                Some(DopData::EnvData { .. }) => {
                    if !col.env_datas.iter().any(|e| e.short_name.as_deref() == Some(name.as_str())) {
                        col.env_datas.push(OdxEnvData {
                            id: Some(format!("ED_{name}")),
                            short_name: Some(name.clone()),
                        });
                    }
                }
                Some(DopData::EnvDataDesc { .. }) => {
                    if !col.env_data_descs.iter().any(|e| e.short_name.as_deref() == Some(name.as_str())) {
                        col.env_data_descs.push(OdxEnvDataDesc {
                            id: Some(format!("EDD_{name}")),
                            short_name: Some(name.clone()),
                        });
                    }
                }
            }
        }
    }
}

fn ir_structure_to_odx(
    name: &str,
    params: &[Param],
    byte_size: Option<u32>,
    _is_visible: bool,
    dops: &[OdxDataObjectProp],
) -> OdxStructure {
    OdxStructure {
        id: Some(format!("STRUCT_{name}")),
        short_name: Some(name.to_string()),
        byte_size,
        params: if params.is_empty() {
            None
        } else {
            Some(ParamsWrapper {
                items: params.iter().map(|p| ir_param_to_odx(p, dops)).collect(),
            })
        },
        sdgs: None,
    }
}

fn ir_dtc_dop_to_odx(
    name: &str,
    diag_coded_type: &Option<DiagCodedType>,
    physical_type: &Option<PhysicalType>,
    compu_method: &Option<CompuMethod>,
    _dtcs: &[Dtc],
    is_visible: bool,
) -> OdxDtcDop {
    OdxDtcDop {
        id: Some(format!("DTCDOP_{name}")),
        short_name: Some(name.to_string()),
        long_name: None,
        sdgs: None,
        is_visible: Some(is_visible.to_string()),
        diag_coded_type: diag_coded_type.as_ref().map(ir_dct_to_odx),
        physical_type: physical_type.as_ref().map(ir_pt_to_odx),
        compu_method: compu_method.as_ref().map(ir_cm_to_odx),
        dtcs: None,
    }
}

fn ir_dop_to_odx(dop: &Dop) -> OdxDataObjectProp {
    let (dct, pt, cm, ic, pc, unit_ref) = match &dop.specific_data {
        Some(DopData::NormalDop {
            compu_method,
            diag_coded_type,
            physical_type,
            internal_constr,
            unit_ref,
            phys_constr,
        }) => (
            diag_coded_type.as_ref().map(ir_dct_to_odx),
            physical_type.as_ref().map(ir_pt_to_odx),
            compu_method.as_ref().map(ir_cm_to_odx),
            internal_constr.as_ref().map(ir_ic_to_odx),
            phys_constr.as_ref().map(ir_ic_to_odx),
            unit_ref.as_ref().map(|u| OdxRef {
                id_ref: Some(format!("UNIT_{}", u.short_name)),
                docref: None,
                doctype: None,
            }),
        ),
        _ => (None, None, None, None, None, None),
    };

    OdxDataObjectProp {
        id: Some(format!("DOP_{}", dop.short_name)),
        short_name: Some(dop.short_name.clone()),
        long_name: None,
        sdgs: ir_sdgs_to_odx(&dop.sdgs),
        diag_coded_type: dct,
        physical_type: pt,
        compu_method: cm,
        internal_constr: ic,
        phys_constr: pc,
        unit_ref,
    }
}

// --- Type conversions ---

fn ir_dct_to_odx(dct: &DiagCodedType) -> OdxDiagCodedType {
    let (xsi_type, bit_length, min_length, max_length, termination) = match &dct.specific_data {
        Some(DiagCodedTypeData::StandardLength { bit_length, .. }) => {
            (Some("STANDARD-LENGTH-TYPE".into()), Some(*bit_length), None, None, None)
        }
        Some(DiagCodedTypeData::MinMax {
            min_length,
            max_length,
            termination,
        }) => {
            let term = match termination {
                Termination::Zero => "ZERO",
                Termination::HexFf => "HEX-FF",
                Termination::EndOfPdu => "END-OF-PDU",
            };
            (
                Some("MIN-MAX-LENGTH-TYPE".into()),
                None,
                Some(*min_length),
                *max_length,
                Some(term.into()),
            )
        }
        Some(DiagCodedTypeData::LeadingLength { bit_length }) => {
            (Some("LEADING-LENGTH-INFO-TYPE".into()), Some(*bit_length), None, None, None)
        }
        Some(DiagCodedTypeData::ParamLength { .. }) => {
            (Some("PARAM-LENGTH-INFO-TYPE".into()), None, None, None, None)
        }
        None => (Some("STANDARD-LENGTH-TYPE".into()), Some(8), None, None, None),
    };

    OdxDiagCodedType {
        xsi_type,
        base_data_type: Some(ir_data_type_to_str(&dct.base_data_type).into()),
        is_highlow_byte_order: if dct.is_high_low_byte_order {
            None
        } else {
            Some("false".into())
        },
        base_type_encoding: if dct.base_type_encoding.is_empty() {
            None
        } else {
            Some(dct.base_type_encoding.clone())
        },
        is_condensed: None,
        bit_length,
        bit_mask: None,
        min_length,
        max_length,
        termination,
        length_key_ref: None,
    }
}

fn ir_cm_to_odx(cm: &CompuMethod) -> OdxCompuMethod {
    let category = match cm.category {
        CompuCategory::Identical => "IDENTICAL",
        CompuCategory::Linear => "LINEAR",
        CompuCategory::ScaleLinear => "SCALE-LINEAR",
        CompuCategory::TextTable => "TEXTTABLE",
        CompuCategory::CompuCode => "COMPUCODE",
        CompuCategory::TabIntp => "TAB-INTP",
        CompuCategory::RatFunc => "RAT-FUNC",
        CompuCategory::ScaleRatFunc => "SCALE-RAT-FUNC",
    };

    OdxCompuMethod {
        category: Some(category.into()),
        compu_internal_to_phys: cm.internal_to_phys.as_ref().map(|itp| {
            OdxCompuInternalToPhys {
                compu_scales: if itp.compu_scales.is_empty() {
                    None
                } else {
                    Some(CompuScalesWrapper {
                        items: itp.compu_scales.iter().map(ir_scale_to_odx).collect(),
                    })
                },
                prog_code: None,
                compu_default_value: itp.compu_default_value.as_ref().map(|dv| {
                    OdxCompuDefaultValue {
                        v: dv.values.as_ref().and_then(|v| v.v.map(|f| f.to_string())),
                        vt: dv
                            .values
                            .as_ref()
                            .and_then(|v| {
                                if v.vt.is_empty() {
                                    None
                                } else {
                                    Some(v.vt.clone())
                                }
                            }),
                    }
                }),
            }
        }),
        compu_phys_to_internal: None,
    }
}

fn ir_scale_to_odx(scale: &CompuScale) -> OdxCompuScale {
    OdxCompuScale {
        short_label: scale.short_label.as_ref().map(|t| t.value.clone()),
        lower_limit: scale.lower_limit.as_ref().map(ir_limit_to_odx),
        upper_limit: scale.upper_limit.as_ref().map(ir_limit_to_odx),
        compu_inverse_value: scale.inverse_values.as_ref().map(ir_cv_to_odx),
        compu_const: scale.consts.as_ref().map(ir_cv_to_odx),
        compu_rational_coeffs: scale.rational_co_effs.as_ref().map(|rc| {
            OdxCompuRationalCoeffs {
                compu_numerator: Some(CompuCoeffsWrapper {
                    items: rc.numerator.iter().map(|v| v.to_string()).collect(),
                }),
                compu_denominator: if rc.denominator.is_empty() {
                    None
                } else {
                    Some(CompuCoeffsWrapper {
                        items: rc.denominator.iter().map(|v| v.to_string()).collect(),
                    })
                },
            }
        }),
    }
}

fn ir_limit_to_odx(lim: &Limit) -> OdxLimit {
    OdxLimit {
        interval_type: match lim.interval_type {
            IntervalType::Open => Some("OPEN".into()),
            IntervalType::Infinite => Some("INFINITE".into()),
            IntervalType::Closed => None, // default
        },
        value: if lim.value.is_empty() {
            None
        } else {
            Some(lim.value.clone())
        },
    }
}

fn ir_cv_to_odx(cv: &CompuValues) -> OdxCompuValues {
    OdxCompuValues {
        v: cv.v.map(|f| f.to_string()),
        vt: if cv.vt.is_empty() {
            None
        } else {
            Some(cv.vt.clone())
        },
    }
}

fn ir_pt_to_odx(pt: &PhysicalType) -> OdxPhysicalType {
    OdxPhysicalType {
        base_data_type: Some(ir_phys_data_type_to_str(&pt.base_data_type).into()),
        display_radix: match pt.display_radix {
            Radix::Hex => Some("HEX".into()),
            Radix::Dec => None,
            Radix::Bin => Some("BIN".into()),
            Radix::Oct => Some("OCT".into()),
        },
        precision: pt.precision,
    }
}

fn ir_ic_to_odx(ic: &InternalConstr) -> OdxInternalConstr {
    OdxInternalConstr {
        lower_limit: ic.lower_limit.as_ref().map(ir_limit_to_odx),
        upper_limit: ic.upper_limit.as_ref().map(ir_limit_to_odx),
        scale_constrs: None,
    }
}

// --- DTC ---

fn ir_dtc_to_odx(dtc: &Dtc) -> OdxDtc {
    OdxDtc {
        id: Some(format!("DTC_{}", dtc.short_name)),
        is_temporary: if dtc.is_temporary {
            Some("true".into())
        } else {
            None
        },
        short_name: Some(dtc.short_name.clone()),
        long_name: None,
        trouble_code: Some(dtc.trouble_code),
        display_trouble_code: Some(dtc.display_trouble_code.clone()),
        text: dtc.text.as_ref().map(|t| OdxText {
            ti: if t.ti.is_empty() { None } else { Some(t.ti.clone()) },
            value: if t.value.is_empty() {
                None
            } else {
                Some(t.value.clone())
            },
        }),
        level: dtc.level,
        sdgs: ir_sdgs_to_odx(&dtc.sdgs),
    }
}

// --- StateChart ---

fn ir_state_chart_to_odx(sc: &StateChart) -> OdxStateChart {
    OdxStateChart {
        id: None,
        short_name: Some(sc.short_name.clone()),
        semantic: if sc.semantic.is_empty() {
            None
        } else {
            Some(sc.semantic.clone())
        },
        start_state_snref: Some(OdxSnRef {
            short_name: Some(sc.start_state_short_name_ref.clone()),
        }),
        states: if sc.states.is_empty() {
            None
        } else {
            Some(StatesWrapper {
                items: sc
                    .states
                    .iter()
                    .map(|s| OdxState {
                        id: None,
                        short_name: Some(s.short_name.clone()),
                        long_name: s.long_name.as_ref().map(|ln| ln.value.clone()),
                    })
                    .collect(),
            })
        },
        state_transitions: if sc.state_transitions.is_empty() {
            None
        } else {
            Some(StateTransitionsWrapper {
                items: sc
                    .state_transitions
                    .iter()
                    .map(|t| OdxStateTransition {
                        id: None,
                        short_name: Some(t.short_name.clone()),
                        source_snref: Some(OdxSnRef {
                            short_name: Some(t.source_short_name_ref.clone()),
                        }),
                        target_snref: Some(OdxSnRef {
                            short_name: Some(t.target_short_name_ref.clone()),
                        }),
                    })
                    .collect(),
            })
        },
    }
}

// --- Audience ---

fn ir_audience_to_odx(aud: &Audience) -> OdxAudience {
    OdxAudience {
        enabled_audience_refs: None,
        disabled_audience_refs: None,
        is_supplier: if aud.is_supplier {
            Some("true".into())
        } else {
            None
        },
        is_development: if aud.is_development {
            Some("true".into())
        } else {
            None
        },
        is_manufacturing: if aud.is_manufacturing {
            Some("true".into())
        } else {
            None
        },
        is_aftersales: if aud.is_after_sales {
            Some("true".into())
        } else {
            None
        },
        is_aftermarket: if aud.is_after_market {
            Some("true".into())
        } else {
            None
        },
    }
}

// --- ECU Job ---

fn ir_ecu_job_to_odx(job: &SingleEcuJob, idx: usize) -> OdxSingleEcuJob {
    OdxSingleEcuJob {
        id: Some(format!("SEJ_{}", idx)),
        short_name: Some(job.diag_comm.short_name.clone()),
        long_name: job.diag_comm.long_name.as_ref().map(|ln| ln.value.clone()),
        sdgs: ir_sdgs_to_odx(&job.diag_comm.sdgs),
        prog_codes: if job.prog_codes.is_empty() {
            None
        } else {
            Some(ProgCodesWrapper {
                items: job
                    .prog_codes
                    .iter()
                    .map(|pc| OdxProgCode {
                        code_file: Some(pc.code_file.clone()),
                        encryption: if pc.encryption.is_empty() {
                            None
                        } else {
                            Some(pc.encryption.clone())
                        },
                        syntax: if pc.syntax.is_empty() {
                            None
                        } else {
                            Some(pc.syntax.clone())
                        },
                        revision: if pc.revision.is_empty() {
                            None
                        } else {
                            Some(pc.revision.clone())
                        },
                        entrypoint: if pc.entrypoint.is_empty() {
                            None
                        } else {
                            Some(pc.entrypoint.clone())
                        },
                    })
                    .collect(),
            })
        },
        input_params: if job.input_params.is_empty() {
            None
        } else {
            Some(InputParamsWrapper {
                items: job.input_params.iter().map(ir_job_param_to_odx).collect(),
            })
        },
        output_params: if job.output_params.is_empty() {
            None
        } else {
            Some(OutputParamsWrapper {
                items: job.output_params.iter().map(ir_job_param_to_odx).collect(),
            })
        },
        neg_output_params: if job.neg_output_params.is_empty() {
            None
        } else {
            Some(NegOutputParamsWrapper {
                items: job
                    .neg_output_params
                    .iter()
                    .map(ir_job_param_to_odx)
                    .collect(),
            })
        },
    }
}

fn ir_job_param_to_odx(jp: &JobParam) -> OdxJobParam {
    OdxJobParam {
        short_name: Some(jp.short_name.clone()),
        long_name: jp.long_name.as_ref().map(|ln| ln.value.clone()),
        physical_default_value: if jp.physical_default_value.is_empty() {
            None
        } else {
            Some(jp.physical_default_value.clone())
        },
        dop_base_ref: None,
        semantic: if jp.semantic.is_empty() {
            None
        } else {
            Some(jp.semantic.clone())
        },
    }
}

// --- ParentRef ---

fn ir_parent_ref_to_odx(pref: &ParentRef) -> OdxParentRef {
    let id_ref = match &pref.ref_type {
        ParentRefType::Variant(v) => Some(v.diag_layer.short_name.clone()),
        ParentRefType::Protocol(p) => Some(p.diag_layer.short_name.clone()),
        ParentRefType::FunctionalGroup(fg) => Some(fg.diag_layer.short_name.clone()),
        ParentRefType::EcuSharedData(esd) => Some(esd.diag_layer.short_name.clone()),
        ParentRefType::TableDop(td) => Some(td.short_name.clone()),
    };
    OdxParentRef {
        id_ref,
        docref: None,
        doctype: Some("LAYER".into()),
        not_inherited_diag_comms: if pref.not_inherited_diag_comm_short_names.is_empty() {
            None
        } else {
            Some(NotInheritedDiagCommsWrapper {
                items: pref
                    .not_inherited_diag_comm_short_names
                    .iter()
                    .map(|sn| NotInheritedSnRef {
                        snref: Some(OdxSnRef {
                            short_name: Some(sn.clone()),
                        }),
                    })
                    .collect(),
            })
        },
        not_inherited_dops: if pref.not_inherited_dops_short_names.is_empty() {
            None
        } else {
            Some(NotInheritedDopsWrapper {
                items: pref
                    .not_inherited_dops_short_names
                    .iter()
                    .map(|sn| NotInheritedSnRef {
                        snref: Some(OdxSnRef {
                            short_name: Some(sn.clone()),
                        }),
                    })
                    .collect(),
            })
        },
        not_inherited_tables: if pref.not_inherited_tables_short_names.is_empty() {
            None
        } else {
            Some(NotInheritedTablesWrapper {
                items: pref
                    .not_inherited_tables_short_names
                    .iter()
                    .map(|sn| NotInheritedSnRef {
                        snref: Some(OdxSnRef {
                            short_name: Some(sn.clone()),
                        }),
                    })
                    .collect(),
            })
        },
        not_inherited_global_neg_responses: if pref.not_inherited_global_neg_responses_short_names.is_empty() {
            None
        } else {
            Some(NotInheritedGlobalNegResponsesWrapper {
                items: pref
                    .not_inherited_global_neg_responses_short_names
                    .iter()
                    .map(|sn| NotInheritedSnRef {
                        snref: Some(OdxSnRef {
                            short_name: Some(sn.clone()),
                        }),
                    })
                    .collect(),
            })
        },
    }
}

// --- SDG ---

fn ir_sdgs_to_odx(sdgs: &Option<Sdgs>) -> Option<SdgsWrapper> {
    sdgs.as_ref().map(|s| SdgsWrapper {
        items: s.sdgs.iter().map(ir_sdg_to_odx).collect(),
    })
}

fn ir_sdg_to_odx(sdg: &Sdg) -> OdxSdg {
    let mut sds = Vec::new();
    let mut nested = Vec::new();

    for entry in &sdg.sds {
        match entry {
            SdOrSdg::Sd(sd) => {
                sds.push(OdxSd {
                    si: if sd.si.is_empty() {
                        None
                    } else {
                        Some(sd.si.clone())
                    },
                    value: if sd.value.is_empty() {
                        None
                    } else {
                        Some(sd.value.clone())
                    },
                });
            }
            SdOrSdg::Sdg(inner) => {
                nested.push(ir_sdg_to_odx(inner));
            }
        }
    }

    OdxSdg {
        gid: Some(sdg.caption_sn.clone()),
        si: if sdg.si.is_empty() {
            None
        } else {
            Some(sdg.si.clone())
        },
        sdg_caption: None,
        sds,
        nested_sdgs: nested,
    }
}

// --- Helpers ---

fn ir_data_type_to_str(dt: &DataType) -> &'static str {
    match dt {
        DataType::AInt32 => "A_INT32",
        DataType::AUint32 => "A_UINT32",
        DataType::AFloat32 => "A_FLOAT32",
        DataType::AFloat64 => "A_FLOAT64",
        DataType::AAsciiString => "A_ASCIISTRING",
        DataType::AUtf8String => "A_UTF8STRING",
        DataType::AUnicode2String => "A_UNICODE2STRING",
        DataType::ABytefield => "A_BYTEFIELD",
    }
}

fn ir_phys_data_type_to_str(dt: &PhysicalTypeDataType) -> &'static str {
    match dt {
        PhysicalTypeDataType::AInt32 => "A_INT32",
        PhysicalTypeDataType::AUint32 => "A_UINT32",
        PhysicalTypeDataType::AFloat32 => "A_FLOAT32",
        PhysicalTypeDataType::AFloat64 => "A_FLOAT64",
        PhysicalTypeDataType::AAsciiString => "A_ASCIISTRING",
        PhysicalTypeDataType::AUtf8String => "A_UTF8STRING",
        PhysicalTypeDataType::AUnicode2String => "A_UNICODE2STRING",
        PhysicalTypeDataType::ABytefield => "A_BYTEFIELD",
    }
}
