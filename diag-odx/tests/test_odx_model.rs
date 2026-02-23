use diag_odx::odx_model::Odx;

fn parse_minimal() -> Odx {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    quick_xml::de::from_str(xml).expect("Failed to parse minimal ODX")
}

#[test]
fn test_parse_root_version() {
    let odx = parse_minimal();
    assert_eq!(odx.version.as_deref(), Some("2.2.0"));
}

#[test]
fn test_parse_diag_layer_container() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    assert_eq!(dlc.id.as_deref(), Some("DLC_Test"));
    assert_eq!(dlc.short_name.as_deref(), Some("TestECU"));
    assert_eq!(dlc.long_name.as_deref(), Some("Test ECU for unit tests"));
}

#[test]
fn test_parse_admin_data() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let admin = dlc.admin_data.as_ref().unwrap();
    assert_eq!(admin.language.as_deref(), Some("en"));
    let rev = &admin.doc_revisions.as_ref().unwrap().items[0];
    assert_eq!(rev.revision_label.as_deref(), Some("1.0.0"));
    assert_eq!(rev.state.as_deref(), Some("released"));
}

#[test]
fn test_parse_base_variant() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let variants = &dlc.base_variants.as_ref().unwrap().items;
    assert_eq!(variants.len(), 1);
    let bv = &variants[0];
    assert_eq!(bv.id.as_deref(), Some("BV_TestECU"));
    assert_eq!(bv.short_name.as_deref(), Some("TestECU_Base"));
}

#[test]
fn test_parse_data_object_props() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let bv = &dlc.base_variants.as_ref().unwrap().items[0];
    let dops = &bv
        .diag_data_dictionary_spec
        .as_ref()
        .unwrap()
        .data_object_props
        .as_ref()
        .unwrap()
        .items;
    assert_eq!(dops.len(), 2);

    // VehicleSpeed DOP
    let speed = &dops[0];
    assert_eq!(speed.id.as_deref(), Some("DOP_VehicleSpeed"));
    assert_eq!(speed.short_name.as_deref(), Some("VehicleSpeed"));

    let dct = speed.diag_coded_type.as_ref().unwrap();
    assert_eq!(dct.xsi_type.as_deref(), Some("STANDARD-LENGTH-TYPE"));
    assert_eq!(dct.base_data_type.as_deref(), Some("A_UINT32"));
    assert_eq!(dct.bit_length, Some(16));

    let cm = speed.compu_method.as_ref().unwrap();
    assert_eq!(cm.category.as_deref(), Some("LINEAR"));
    let scales = &cm
        .compu_internal_to_phys
        .as_ref()
        .unwrap()
        .compu_scales
        .as_ref()
        .unwrap()
        .items;
    assert_eq!(scales.len(), 1);
    let coeffs = scales[0].compu_rational_coeffs.as_ref().unwrap();
    let num = &coeffs.compu_numerator.as_ref().unwrap().items;
    assert_eq!(num.len(), 2);
    assert_eq!(num[0], "0");
    assert_eq!(num[1], "0.01");

    // EngineStatus DOP - TEXTTABLE
    let status = &dops[1];
    assert_eq!(status.short_name.as_deref(), Some("EngineStatus"));
    let cm2 = status.compu_method.as_ref().unwrap();
    assert_eq!(cm2.category.as_deref(), Some("TEXTTABLE"));
    let scales2 = &cm2
        .compu_internal_to_phys
        .as_ref()
        .unwrap()
        .compu_scales
        .as_ref()
        .unwrap()
        .items;
    assert_eq!(scales2.len(), 3);
    assert_eq!(scales2[0].compu_const.as_ref().unwrap().vt.as_deref(), Some("OFF"));
    assert_eq!(scales2[1].compu_const.as_ref().unwrap().vt.as_deref(), Some("RUNNING"));
    assert_eq!(scales2[2].compu_const.as_ref().unwrap().vt.as_deref(), Some("CRANKING"));
}

#[test]
fn test_parse_dtc_dop() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let bv = &dlc.base_variants.as_ref().unwrap().items[0];
    let dtc_dops = &bv
        .diag_data_dictionary_spec
        .as_ref()
        .unwrap()
        .dtc_dops
        .as_ref()
        .unwrap()
        .items;
    assert_eq!(dtc_dops.len(), 1);

    let dtcs = &dtc_dops[0].dtcs.as_ref().unwrap().items;
    assert_eq!(dtcs.len(), 2);
    assert_eq!(dtcs[0].short_name.as_deref(), Some("P0100"));
    assert_eq!(dtcs[0].trouble_code, Some(256));
    assert_eq!(dtcs[0].display_trouble_code.as_deref(), Some("P0100"));
    assert_eq!(dtcs[0].text.as_ref().unwrap().ti.as_deref(), Some("Mass Air Flow Circuit Malfunction"));
    assert_eq!(dtcs[0].level, Some(2));
    assert_eq!(dtcs[1].trouble_code, Some(512));
}

#[test]
fn test_parse_diag_services() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let bv = &dlc.base_variants.as_ref().unwrap().items[0];
    let comms = &bv.diag_comms.as_ref().unwrap().items;
    assert_eq!(comms.len(), 2);

    // DiagService
    match &comms[0] {
        diag_odx::odx_model::DiagCommEntry::DiagService(ds) => {
            assert_eq!(ds.id.as_deref(), Some("DS_ReadSpeed"));
            assert_eq!(ds.semantic.as_deref(), Some("DATA-READ"));
            assert_eq!(ds.short_name.as_deref(), Some("Read_VehicleSpeed"));
            assert_eq!(
                ds.request_ref.as_ref().unwrap().id_ref.as_deref(),
                Some("RQ_ReadSpeed")
            );
            let pos_refs = &ds.pos_response_refs.as_ref().unwrap().items;
            assert_eq!(pos_refs.len(), 1);
            assert_eq!(pos_refs[0].id_ref.as_deref(), Some("PR_ReadSpeed"));
        }
        other => panic!("Expected DiagService, got {:?}", other),
    }

    // SingleEcuJob
    match &comms[1] {
        diag_odx::odx_model::DiagCommEntry::SingleEcuJob(job) => {
            assert_eq!(job.short_name.as_deref(), Some("FlashECU"));
            let pc = &job.prog_codes.as_ref().unwrap().items[0];
            assert_eq!(pc.code_file.as_deref(), Some("flash.jar"));
            assert_eq!(pc.syntax.as_deref(), Some("JAR"));
            let inp = &job.input_params.as_ref().unwrap().items;
            assert_eq!(inp.len(), 1);
            assert_eq!(inp[0].short_name.as_deref(), Some("FilePath"));
        }
        other => panic!("Expected SingleEcuJob, got {:?}", other),
    }
}

#[test]
fn test_parse_request_with_params() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let bv = &dlc.base_variants.as_ref().unwrap().items[0];
    let requests = &bv.requests.as_ref().unwrap().items;
    assert_eq!(requests.len(), 1);

    let req = &requests[0];
    assert_eq!(req.id.as_deref(), Some("RQ_ReadSpeed"));
    assert_eq!(req.byte_size, Some(3));

    let params = &req.params.as_ref().unwrap().items;
    assert_eq!(params.len(), 2);

    // SID param (CODED-CONST)
    assert_eq!(params[0].xsi_type.as_deref(), Some("CODED-CONST"));
    assert_eq!(params[0].semantic.as_deref(), Some("SERVICE-ID"));
    assert_eq!(params[0].coded_value.as_deref(), Some("34"));
    assert_eq!(params[0].byte_position, Some(0));

    // DID param (CODED-CONST)
    assert_eq!(params[1].coded_value.as_deref(), Some("256"));
    assert_eq!(params[1].byte_position, Some(1));
}

#[test]
fn test_parse_neg_response_nrc_const() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let bv = &dlc.base_variants.as_ref().unwrap().items[0];
    let neg = &bv.neg_responses.as_ref().unwrap().items;
    assert_eq!(neg.len(), 1);

    let params = &neg[0].params.as_ref().unwrap().items;
    let nrc = &params[1];
    assert_eq!(nrc.xsi_type.as_deref(), Some("NRC-CONST"));
    let coded_vals = &nrc.coded_values.as_ref().unwrap().items;
    assert_eq!(coded_vals.len(), 3);
    assert_eq!(coded_vals[0], "18");
    assert_eq!(coded_vals[1], "19");
    assert_eq!(coded_vals[2], "49");
}

#[test]
fn test_parse_ecu_variant() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let ecu_vars = &dlc.ecu_variants.as_ref().unwrap().items;
    assert_eq!(ecu_vars.len(), 1);

    let ev = &ecu_vars[0];
    assert_eq!(ev.short_name.as_deref(), Some("TestECU_HW1"));

    // Parent ref
    let parent = &ev.parent_refs.as_ref().unwrap().items[0];
    assert_eq!(parent.id_ref.as_deref(), Some("BV_TestECU"));
    let not_inherited = &parent.not_inherited_diag_comms.as_ref().unwrap().items;
    assert_eq!(not_inherited.len(), 1);

    // Variant pattern
    let pattern = &ev.ecu_variant_patterns.as_ref().unwrap().items[0];
    let mp = &pattern.matching_parameters.as_ref().unwrap().items[0];
    assert_eq!(mp.expected_value.as_deref(), Some("HW1"));
}

#[test]
fn test_parse_state_chart() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let bv = &dlc.base_variants.as_ref().unwrap().items[0];
    let charts = &bv.state_charts.as_ref().unwrap().items;
    assert_eq!(charts.len(), 1);

    let sc = &charts[0];
    assert_eq!(sc.short_name.as_deref(), Some("SessionState"));
    assert_eq!(
        sc.start_state_snref.as_ref().unwrap().short_name.as_deref(),
        Some("Default")
    );

    let states = &sc.states.as_ref().unwrap().items;
    assert_eq!(states.len(), 2);
    assert_eq!(states[0].short_name.as_deref(), Some("Default"));
    assert_eq!(states[1].short_name.as_deref(), Some("Extended"));

    let transitions = &sc.state_transitions.as_ref().unwrap().items;
    assert_eq!(transitions.len(), 1);
    assert_eq!(
        transitions[0].source_snref.as_ref().unwrap().short_name.as_deref(),
        Some("Default")
    );
    assert_eq!(
        transitions[0].target_snref.as_ref().unwrap().short_name.as_deref(),
        Some("Extended")
    );
}

#[test]
fn test_parse_unit_spec() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let bv = &dlc.base_variants.as_ref().unwrap().items[0];
    let unit_spec = &bv
        .diag_data_dictionary_spec
        .as_ref()
        .unwrap()
        .unit_spec
        .as_ref()
        .unwrap();

    let units = &unit_spec.units.as_ref().unwrap().items;
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].short_name.as_deref(), Some("km_h"));
    assert_eq!(units[0].display_name.as_deref(), Some("km/h"));

    let dims = &unit_spec.physical_dimensions.as_ref().unwrap().items;
    assert_eq!(dims.len(), 1);
    assert_eq!(dims[0].short_name.as_deref(), Some("Speed"));
    assert_eq!(dims[0].length_exp, Some(1));
    assert_eq!(dims[0].time_exp, Some(-1));
}

#[test]
fn test_parse_sdgs() {
    let odx = parse_minimal();
    let dlc = odx.diag_layer_container.as_ref().unwrap();
    let bv = &dlc.base_variants.as_ref().unwrap().items[0];
    let sdgs = &bv.sdgs.as_ref().unwrap().items;
    assert_eq!(sdgs.len(), 1);
    assert_eq!(sdgs[0].gid.as_deref(), Some("TestGroup"));
    assert_eq!(sdgs[0].sds.len(), 2);
    assert_eq!(sdgs[0].sds[0].si.as_deref(), Some("Key1"));
    assert_eq!(sdgs[0].sds[0].value.as_deref(), Some("Value1"));
}
