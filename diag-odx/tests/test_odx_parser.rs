use diag_ir::*;
use diag_odx::parse_odx;

fn parse_minimal() -> DiagDatabase {
    let xml = include_str!("../../test-fixtures/odx/minimal.odx");
    parse_odx(xml).expect("Failed to parse minimal ODX to IR")
}

#[test]
fn test_parse_odx_ecu_name() {
    let db = parse_minimal();
    assert_eq!(db.ecu_name, "TestECU");
    assert_eq!(db.version, "2.2.0");
}

#[test]
fn test_parse_odx_revision() {
    let db = parse_minimal();
    assert_eq!(db.revision, "1.0.0");
}

#[test]
fn test_parse_odx_base_variant() {
    let db = parse_minimal();
    assert!(!db.variants.is_empty());
    let base = db
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .expect("Should have a base variant");
    assert_eq!(base.diag_layer.short_name, "TestECU_Base");
}

#[test]
fn test_parse_odx_ecu_variant() {
    let db = parse_minimal();
    let ecu_var = db
        .variants
        .iter()
        .find(|v| !v.is_base_variant)
        .expect("Should have an ECU variant");
    assert_eq!(ecu_var.diag_layer.short_name, "TestECU_HW1");
    assert!(!ecu_var.parent_refs.is_empty());
}

#[test]
fn test_parse_odx_diag_services() {
    let db = parse_minimal();
    let base = db
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .unwrap();
    assert!(
        !base.diag_layer.diag_services.is_empty(),
        "Base variant should have diag services"
    );

    let read_speed = base
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VehicleSpeed")
        .expect("Should have Read_VehicleSpeed service");

    assert_eq!(read_speed.diag_comm.semantic, "DATA-READ");
    assert!(read_speed.request.is_some());
    assert!(!read_speed.pos_responses.is_empty());
    assert!(!read_speed.neg_responses.is_empty());
}

#[test]
fn test_parse_odx_request_params() {
    let db = parse_minimal();
    let base = &db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let svc = base
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VehicleSpeed")
        .unwrap();

    let req = svc.request.as_ref().unwrap();
    assert_eq!(req.params.len(), 2);

    // SID param
    let sid = &req.params[0];
    assert_eq!(sid.param_type, ParamType::CodedConst);
    assert_eq!(sid.semantic, "SERVICE-ID");
    match &sid.specific_data {
        Some(ParamData::CodedConst { coded_value, .. }) => {
            assert_eq!(coded_value, "34");
        }
        other => panic!("Expected CodedConst, got {:?}", other),
    }
}

#[test]
fn test_parse_odx_response_value_param() {
    let db = parse_minimal();
    let base = &db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let svc = base
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VehicleSpeed")
        .unwrap();

    let pos_resp = &svc.pos_responses[0];
    // Second param should be VALUE type with DOP ref to VehicleSpeed
    let value_param = pos_resp
        .params
        .iter()
        .find(|p| p.param_type == ParamType::Value)
        .expect("Should have a VALUE param");

    assert_eq!(value_param.short_name, "VehicleSpeed");
    match &value_param.specific_data {
        Some(ParamData::Value { dop, .. }) => {
            assert_eq!(dop.short_name, "VehicleSpeed");
            match &dop.specific_data {
                Some(DopData::NormalDop {
                    compu_method,
                    diag_coded_type,
                    ..
                }) => {
                    let cm = compu_method.as_ref().unwrap();
                    assert_eq!(cm.category, CompuCategory::Linear);

                    let dct = diag_coded_type.as_ref().unwrap();
                    assert_eq!(dct.base_data_type, DataType::AUint32);
                    match &dct.specific_data {
                        Some(DiagCodedTypeData::StandardLength { bit_length, .. }) => {
                            assert_eq!(*bit_length, 16);
                        }
                        other => panic!("Expected StandardLength, got {:?}", other),
                    }
                }
                other => panic!("Expected NormalDop, got {:?}", other),
            }
        }
        other => panic!("Expected Value, got {:?}", other),
    }
}

#[test]
fn test_parse_odx_nrc_const() {
    let db = parse_minimal();
    let base = &db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let svc = base
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VehicleSpeed")
        .unwrap();

    let neg_resp = &svc.neg_responses[0];
    let nrc_param = neg_resp
        .params
        .iter()
        .find(|p| p.param_type == ParamType::NrcConst)
        .expect("Should have NRC-CONST param");

    match &nrc_param.specific_data {
        Some(ParamData::NrcConst { coded_values, .. }) => {
            assert_eq!(coded_values.len(), 3);
            assert_eq!(coded_values[0], "18");
        }
        other => panic!("Expected NrcConst, got {:?}", other),
    }
}

#[test]
fn test_parse_odx_single_ecu_job() {
    let db = parse_minimal();
    let base = &db.variants.iter().find(|v| v.is_base_variant).unwrap();
    assert!(
        !base.diag_layer.single_ecu_jobs.is_empty(),
        "Should have SingleEcuJobs"
    );

    let flash = &base.diag_layer.single_ecu_jobs[0];
    assert_eq!(flash.diag_comm.short_name, "FlashECU");
    assert!(!flash.prog_codes.is_empty());
    assert_eq!(flash.prog_codes[0].syntax, "JAR");
    assert_eq!(flash.input_params.len(), 1);
    assert_eq!(flash.output_params.len(), 1);

    // DOP-BASE-REF should be resolved
    let file_path_param = &flash.input_params[0];
    assert_eq!(file_path_param.short_name, "FilePath");
    assert!(
        file_path_param.dop_base.is_some(),
        "Job param with DOP-BASE-REF should have resolved dop_base"
    );
    let dop = file_path_param.dop_base.as_ref().unwrap();
    assert_eq!(dop.short_name, "VehicleSpeed");
}

#[test]
fn test_parse_odx_dtcs() {
    let db = parse_minimal();
    assert_eq!(db.dtcs.len(), 2);

    let p0100 = db
        .dtcs
        .iter()
        .find(|d| d.short_name == "P0100")
        .expect("Should have P0100 DTC");
    assert_eq!(p0100.trouble_code, 256);
    assert_eq!(p0100.display_trouble_code, "P0100");
    assert_eq!(p0100.level, Some(2));
    assert_eq!(
        p0100.text.as_ref().unwrap().ti,
        "Mass Air Flow Circuit Malfunction"
    );
}

#[test]
fn test_parse_odx_state_chart() {
    let db = parse_minimal();
    let base = &db.variants.iter().find(|v| v.is_base_variant).unwrap();
    assert_eq!(base.diag_layer.state_charts.len(), 1);

    let sc = &base.diag_layer.state_charts[0];
    assert_eq!(sc.short_name, "SessionState");
    assert_eq!(sc.start_state_short_name_ref, "Default");
    assert_eq!(sc.states.len(), 2);
    assert_eq!(sc.state_transitions.len(), 1);
    assert_eq!(sc.state_transitions[0].source_short_name_ref, "Default");
    assert_eq!(sc.state_transitions[0].target_short_name_ref, "Extended");
}

#[test]
fn test_parse_odx_sdgs() {
    let db = parse_minimal();
    let base = &db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let sdgs = base.diag_layer.sdgs.as_ref().unwrap();
    assert_eq!(sdgs.sdgs.len(), 1);
    assert_eq!(sdgs.sdgs[0].caption_sn, "TestGroup");
    assert_eq!(sdgs.sdgs[0].sds.len(), 2);
}

#[test]
fn test_parse_odx_audience() {
    let db = parse_minimal();
    let base = &db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let svc = base
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VehicleSpeed")
        .unwrap();

    let audience = svc.diag_comm.audience.as_ref().expect("Should have audience");
    assert!(audience.is_development);
    assert!(audience.is_after_sales);
    assert!(!audience.is_supplier);
}

#[test]
fn test_parse_odx_variant_pattern() {
    let db = parse_minimal();
    let ecu_var = db
        .variants
        .iter()
        .find(|v| !v.is_base_variant)
        .unwrap();

    assert_eq!(ecu_var.variant_patterns.len(), 1);
    let mp = &ecu_var.variant_patterns[0].matching_parameters[0];
    assert_eq!(mp.expected_value, "HW1");
}

#[test]
fn test_ecu_variant_inherits_services_from_base() {
    let db = parse_minimal();
    let ecu_var = db
        .variants
        .iter()
        .find(|v| !v.is_base_variant)
        .unwrap();

    // ECU variant should inherit Read_VehicleSpeed from base
    // (FlashECU is in NOT-INHERITED, so it should be excluded)
    let has_read_speed = ecu_var
        .diag_layer
        .diag_services
        .iter()
        .any(|s| s.diag_comm.short_name == "Read_VehicleSpeed");
    assert!(
        has_read_speed,
        "ECU variant should inherit Read_VehicleSpeed from base"
    );

    // FlashECU should NOT be inherited
    let has_flash = ecu_var
        .diag_layer
        .single_ecu_jobs
        .iter()
        .any(|j| j.diag_comm.short_name == "FlashECU");
    assert!(
        !has_flash,
        "FlashECU should be excluded via NOT-INHERITED-DIAG-COMMS"
    );
}

#[test]
fn test_ecu_variant_inherits_dtcs() {
    let db = parse_minimal();
    // DTCs come from DTC-DOPs which are inherited
    assert!(
        db.dtcs.len() >= 2,
        "Should have DTCs inherited from base variant"
    );
}

#[test]
fn test_parse_odx_compu_method_linear() {
    let db = parse_minimal();
    let base = &db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let svc = base
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "Read_VehicleSpeed")
        .unwrap();

    let pos_resp = &svc.pos_responses[0];
    let value_param = pos_resp
        .params
        .iter()
        .find(|p| p.param_type == ParamType::Value)
        .unwrap();

    if let Some(ParamData::Value { dop, .. }) = &value_param.specific_data {
        if let Some(DopData::NormalDop { compu_method, .. }) = &dop.specific_data {
            let cm = compu_method.as_ref().unwrap();
            let scales = &cm.internal_to_phys.as_ref().unwrap().compu_scales;
            assert_eq!(scales.len(), 1);

            let coeffs = scales[0].rational_co_effs.as_ref().unwrap();
            assert_eq!(coeffs.numerator, vec![0.0, 0.01]);
            assert_eq!(coeffs.denominator, vec![1.0]);
        }
    }
}
