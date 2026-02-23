//! UDS service generation from the YAML `services` section.
//!
//! Each public method generates `Vec<DiagService>` for one UDS service type.

use crate::yaml_model::YamlServices;
use diag_ir::*;

/// Generates DiagService instances from the YAML `services` configuration.
pub struct ServiceGenerator<'a> {
    services: &'a YamlServices,
}

impl<'a> ServiceGenerator<'a> {
    pub fn new(services: &'a YamlServices) -> Self {
        Self { services }
    }

    /// Generate all enabled services.
    pub fn generate_all(&self) -> Vec<DiagService> {
        let mut result = Vec::new();
        result.extend(self.generate_tester_present());
        result.extend(self.generate_control_dtc_setting());
        result.extend(self.generate_clear_diagnostic_information());
        result.extend(self.generate_read_dtc_information());
        result
    }

    /// TesterPresent (0x3E): Request = [SID, subfunc=0x00], Response = [SID+0x40, subfunc echo]
    pub fn generate_tester_present(&self) -> Vec<DiagService> {
        let entry = match &self.services.tester_present {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };
        let _ = entry;
        vec![build_service(
            "TesterPresent",
            "TESTING",
            vec![
                coded_const_param("SID", 0, 8, "0x3E"),
                coded_const_param("SubFunction", 1, 8, "0x00"),
            ],
            vec![
                coded_const_param("SID", 0, 8, "0x7E"),
                matching_request_param("SubFunction_Echo", 1, 1),
            ],
        )]
    }

    /// ControlDTCSetting (0x85): subfunctions on (0x01), off (0x02)
    pub fn generate_control_dtc_setting(&self) -> Vec<DiagService> {
        let entry = match &self.services.control_dtc_setting {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };
        let _ = entry;
        let subfunctions = [("on", 0x01u8), ("off", 0x02u8)];
        subfunctions.iter().map(|(name, subfunc)| {
            build_service(
                &format!("ControlDTCSetting_{name}"),
                "CONTROL-DTC-SETTING",
                vec![
                    coded_const_param("SID", 0, 8, "0x85"),
                    coded_const_param("SubFunction", 1, 8, &format!("0x{subfunc:02X}")),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0xC5"),
                    matching_request_param("SubFunction_Echo", 1, 1),
                ],
            )
        }).collect()
    }

    /// ClearDiagnosticInformation (0x14): Request = [SID, DTCGroupOfDTC (3 bytes)], Response = [SID+0x40]
    pub fn generate_clear_diagnostic_information(&self) -> Vec<DiagService> {
        let entry = match &self.services.clear_diagnostic_information {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };
        let _ = entry;
        vec![build_service(
            "ClearDiagnosticInformation",
            "CLEAR-DTC",
            vec![
                coded_const_param("SID", 0, 8, "0x14"),
                value_param("DTCGroupOfDTC", 1, 24),
            ],
            vec![
                coded_const_param("SID", 0, 8, "0x54"),
            ],
        )]
    }

    /// ReadDTCInformation (0x19): Request = [SID, subfunc, optional DTC], Response = [SID+0x40, subfunc echo, data]
    pub fn generate_read_dtc_information(&self) -> Vec<DiagService> {
        let entry = match &self.services.read_dtc_information {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };
        let _ = entry;
        vec![build_service(
            "ReadDTCInformation",
            "READ-DTC-INFO",
            vec![
                coded_const_param("SID", 0, 8, "0x19"),
                value_param("SubFunction", 1, 8),
            ],
            vec![
                coded_const_param("SID", 0, 8, "0x59"),
                matching_request_param("SubFunction_Echo", 1, 1),
            ],
        )]
    }
}

// --- Helper functions ---

fn build_service(
    short_name: &str,
    semantic: &str,
    request_params: Vec<Param>,
    response_params: Vec<Param>,
) -> DiagService {
    DiagService {
        diag_comm: DiagComm {
            short_name: short_name.to_string(),
            semantic: semantic.to_string(),
            ..Default::default()
        },
        request: Some(Request {
            params: request_params,
            sdgs: None,
        }),
        pos_responses: vec![Response {
            response_type: ResponseType::PosResponse,
            params: response_params,
            sdgs: None,
        }],
        neg_responses: vec![],
        ..Default::default()
    }
}

fn coded_const_param(name: &str, byte_pos: u32, bit_size: u32, value: &str) -> Param {
    Param {
        short_name: name.to_string(),
        param_type: ParamType::CodedConst,
        byte_position: Some(byte_pos),
        bit_position: Some(0),
        specific_data: Some(ParamData::CodedConst {
            coded_value: value.to_string(),
            diag_coded_type: DiagCodedType {
                base_data_type: DataType::AUint32,
                is_high_low_byte_order: true,
                specific_data: Some(DiagCodedTypeData::StandardLength {
                    bit_length: bit_size,
                    bit_mask: vec![],
                    condensed: false,
                }),
                ..Default::default()
            },
        }),
        ..Default::default()
    }
}

fn value_param(name: &str, byte_pos: u32, bit_size: u32) -> Param {
    Param {
        short_name: name.to_string(),
        param_type: ParamType::Value,
        byte_position: Some(byte_pos),
        bit_position: Some(0),
        specific_data: Some(ParamData::Value {
            dop: Box::new(Dop {
                dop_type: DopType::Regular,
                short_name: format!("{name}_DOP"),
                specific_data: Some(DopData::NormalDop {
                    diag_coded_type: Some(DiagCodedType {
                        base_data_type: DataType::AUint32,
                        is_high_low_byte_order: true,
                        specific_data: Some(DiagCodedTypeData::StandardLength {
                            bit_length: bit_size,
                            bit_mask: vec![],
                            condensed: false,
                        }),
                        ..Default::default()
                    }),
                    compu_method: None,
                    unit_ref: None,
                    internal_constr: None,
                    physical_type: None,
                    phys_constr: None,
                }),
                sdgs: None,
            }),
            physical_default_value: String::new(),
        }),
        ..Default::default()
    }
}

fn matching_request_param(name: &str, byte_pos: u32, byte_length: u32) -> Param {
    Param {
        short_name: name.to_string(),
        param_type: ParamType::MatchingRequestParam,
        byte_position: Some(byte_pos),
        bit_position: Some(0),
        specific_data: Some(ParamData::MatchingRequestParam {
            request_byte_pos: byte_pos as i32,
            byte_length,
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml_model::{YamlServices, ServiceEntry};

    fn services_with(configure: impl FnOnce(&mut YamlServices)) -> YamlServices {
        let mut svc = YamlServices::default();
        configure(&mut svc);
        svc
    }

    fn enabled_entry() -> ServiceEntry {
        ServiceEntry {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_tester_present_generation() {
        let svc = services_with(|s| s.tester_present = Some(enabled_entry()));
        let gen = ServiceGenerator::new(&svc);
        let services = gen.generate_tester_present();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].diag_comm.short_name, "TesterPresent");

        let req = services[0].request.as_ref().unwrap();
        assert_eq!(req.params.len(), 2);
        assert_eq!(req.params[0].short_name, "SID");
        if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[0].specific_data {
            assert_eq!(coded_value, "0x3E");
        } else {
            panic!("expected CodedConst for SID");
        }
    }

    #[test]
    fn test_control_dtc_setting_generation() {
        let svc = services_with(|s| s.control_dtc_setting = Some(enabled_entry()));
        let gen = ServiceGenerator::new(&svc);
        let services = gen.generate_control_dtc_setting();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].diag_comm.short_name, "ControlDTCSetting_on");
        assert_eq!(services[1].diag_comm.short_name, "ControlDTCSetting_off");
    }

    #[test]
    fn test_clear_dtc_generation() {
        let svc = services_with(|s| s.clear_diagnostic_information = Some(enabled_entry()));
        let gen = ServiceGenerator::new(&svc);
        let services = gen.generate_clear_diagnostic_information();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].diag_comm.short_name, "ClearDiagnosticInformation");

        let req = services[0].request.as_ref().unwrap();
        assert_eq!(req.params.len(), 2);
        assert_eq!(req.params[1].short_name, "DTCGroupOfDTC");
    }

    #[test]
    fn test_read_dtc_info_generation() {
        let svc = services_with(|s| s.read_dtc_information = Some(enabled_entry()));
        let gen = ServiceGenerator::new(&svc);
        let services = gen.generate_read_dtc_information();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].diag_comm.short_name, "ReadDTCInformation");
    }

    #[test]
    fn test_disabled_service_generates_nothing() {
        let svc = YamlServices::default();
        let gen = ServiceGenerator::new(&svc);
        assert!(gen.generate_tester_present().is_empty());
        assert!(gen.generate_control_dtc_setting().is_empty());
        assert!(gen.generate_clear_diagnostic_information().is_empty());
        assert!(gen.generate_read_dtc_information().is_empty());
        assert!(gen.generate_all().is_empty());
    }

    #[test]
    fn test_generate_all_with_multiple_enabled() {
        let svc = services_with(|s| {
            s.tester_present = Some(enabled_entry());
            s.clear_diagnostic_information = Some(enabled_entry());
        });
        let gen = ServiceGenerator::new(&svc);
        let all = gen.generate_all();
        // TesterPresent (1) + ClearDiagnosticInformation (1) = 2
        assert_eq!(all.len(), 2);
    }
}
