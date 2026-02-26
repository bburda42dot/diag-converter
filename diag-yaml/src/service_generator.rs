//! UDS service generation from the YAML `services` section.
//!
//! Each public method generates `Vec<DiagService>` for one UDS service type.

use crate::yaml_model::{SecurityLevel, Session, YamlServices};
use diag_ir::*;
use std::collections::BTreeMap;

/// Generates DiagService instances from the YAML `services` configuration.
pub struct ServiceGenerator<'a> {
    services: &'a YamlServices,
    sessions: Option<&'a BTreeMap<String, Session>>,
    security: Option<&'a BTreeMap<String, SecurityLevel>>,
}

impl<'a> ServiceGenerator<'a> {
    pub fn new(services: &'a YamlServices) -> Self {
        Self { services, sessions: None, security: None }
    }

    pub fn with_sessions(mut self, sessions: Option<&'a BTreeMap<String, Session>>) -> Self {
        self.sessions = sessions;
        self
    }

    pub fn with_security(mut self, security: Option<&'a BTreeMap<String, SecurityLevel>>) -> Self {
        self.security = security;
        self
    }

    /// Generate all enabled services.
    pub fn generate_all(&self) -> Vec<DiagService> {
        let mut result = Vec::new();
        result.extend(self.generate_diagnostic_session_control());
        result.extend(self.generate_security_access());
        result.extend(self.generate_ecu_reset());
        result.extend(self.generate_authentication());
        result.extend(self.generate_communication_control());
        result.extend(self.generate_request_download());
        result.extend(self.generate_request_upload());
        result.extend(self.generate_tester_present());
        result.extend(self.generate_control_dtc_setting());
        result.extend(self.generate_clear_diagnostic_information());
        result.extend(self.generate_read_dtc_information());
        result
    }

    // --- Session, Security, Reset (Task 12b) ---

    /// DiagnosticSessionControl (0x10): one service per session.
    pub fn generate_diagnostic_session_control(&self) -> Vec<DiagService> {
        let entry = match &self.services.diagnostic_session_control {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        // If subfunctions are provided explicitly, use them
        if let Some(subfuncs) = &entry.subfunctions {
            return self.session_services_from_subfunctions(subfuncs);
        }

        // Otherwise generate from sessions section
        let sessions = match self.sessions {
            Some(s) if !s.is_empty() => s,
            _ => return vec![],
        };

        sessions.iter().map(|(name, session)| {
            let id = yaml_value_to_u8(&session.id);
            build_service(
                &format!("DiagnosticSessionControl_{name}"),
                "SESSION",
                vec![
                    coded_const_param("SID", 0, 8, "0x10"),
                    coded_const_param("SubFunction", 1, 8, &format!("0x{id:02X}")),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x50"),
                    matching_request_param("SubFunction_Echo", 1, 1),
                    value_param("P2_Server", 2, 16),
                    value_param("P2Star_Server", 4, 16),
                ],
            )
        }).collect()
    }

    fn session_services_from_subfunctions(&self, subfuncs: &serde_yaml::Value) -> Vec<DiagService> {
        match subfuncs {
            // Map form: {default: 0x01, programming: 0x02, extended: 0x03}
            serde_yaml::Value::Mapping(map) => {
                map.iter().filter_map(|(k, v)| {
                    let name = k.as_str()?;
                    let id = yaml_value_to_u8(v);
                    Some(build_service(
                        &format!("DiagnosticSessionControl_{name}"),
                        "SESSION",
                        vec![
                            coded_const_param("SID", 0, 8, "0x10"),
                            coded_const_param("SubFunction", 1, 8, &format!("0x{id:02X}")),
                        ],
                        vec![
                            coded_const_param("SID", 0, 8, "0x50"),
                            matching_request_param("SubFunction_Echo", 1, 1),
                            value_param("P2_Server", 2, 16),
                            value_param("P2Star_Server", 4, 16),
                        ],
                    ))
                }).collect()
            }
            // Sequence form: [0x01, 0x02, 0x03]
            serde_yaml::Value::Sequence(seq) => {
                seq.iter().map(|v| {
                    let id = yaml_value_to_u8(v);
                    build_service(
                        &format!("DiagnosticSessionControl_0x{id:02X}"),
                        "SESSION",
                        vec![
                            coded_const_param("SID", 0, 8, "0x10"),
                            coded_const_param("SubFunction", 1, 8, &format!("0x{id:02X}")),
                        ],
                        vec![
                            coded_const_param("SID", 0, 8, "0x50"),
                            matching_request_param("SubFunction_Echo", 1, 1),
                            value_param("P2_Server", 2, 16),
                            value_param("P2Star_Server", 4, 16),
                        ],
                    )
                }).collect()
            }
            _ => vec![],
        }
    }

    /// SecurityAccess (0x27): two services per security level (RequestSeed + SendKey).
    pub fn generate_security_access(&self) -> Vec<DiagService> {
        let entry = match &self.services.security_access {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };
        let _ = entry;
        let security = match self.security {
            Some(s) if !s.is_empty() => s,
            _ => return vec![],
        };

        let mut services = Vec::new();
        for (name, level) in security {
            let seed_byte = yaml_value_to_u8(&level.seed_request);
            let key_byte = yaml_value_to_u8(&level.key_send);

            services.push(build_service(
                &format!("SecurityAccess_RequestSeed_{name}"),
                "SECURITY-ACCESS",
                vec![
                    coded_const_param("SID", 0, 8, "0x27"),
                    coded_const_param("SubFunction", 1, 8, &format!("0x{seed_byte:02X}")),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x67"),
                    matching_request_param("SubFunction_Echo", 1, 1),
                    value_param("SecuritySeed", 2, (level.seed_size * 8).max(8)),
                ],
            ));

            services.push(build_service(
                &format!("SecurityAccess_SendKey_{name}"),
                "SECURITY-ACCESS",
                vec![
                    coded_const_param("SID", 0, 8, "0x27"),
                    coded_const_param("SubFunction", 1, 8, &format!("0x{key_byte:02X}")),
                    value_param("SecurityKey", 2, (level.key_size * 8).max(8)),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x67"),
                    matching_request_param("SubFunction_Echo", 1, 1),
                ],
            ));
        }
        services
    }

    /// ECUReset (0x11): one service per configured reset type.
    pub fn generate_ecu_reset(&self) -> Vec<DiagService> {
        let entry = match &self.services.ecu_reset {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        if let Some(serde_yaml::Value::Mapping(subfuncs)) = &entry.subfunctions {
            subfuncs.iter().filter_map(|(k, v)| {
                let name = k.as_str()?;
                let subfunc = yaml_value_to_u8(v);
                Some(build_service(
                    &format!("ECUReset_{name}"),
                    "ECU-RESET",
                    vec![
                        coded_const_param("SID", 0, 8, "0x11"),
                        coded_const_param("SubFunction", 1, 8, &format!("0x{subfunc:02X}")),
                    ],
                    vec![
                        coded_const_param("SID", 0, 8, "0x51"),
                        matching_request_param("SubFunction_Echo", 1, 1),
                    ],
                ))
            }).collect()
        } else {
            // Default reset types if no subfunctions specified
            [("hardReset", 0x01u8), ("keyOffOnReset", 0x02), ("softReset", 0x03)]
                .iter()
                .map(|(name, subfunc)| {
                    build_service(
                        &format!("ECUReset_{name}"),
                        "ECU-RESET",
                        vec![
                            coded_const_param("SID", 0, 8, "0x11"),
                            coded_const_param("SubFunction", 1, 8, &format!("0x{subfunc:02X}")),
                        ],
                        vec![
                            coded_const_param("SID", 0, 8, "0x51"),
                            matching_request_param("SubFunction_Echo", 1, 1),
                        ],
                    )
                })
                .collect()
        }
    }

    // --- Authentication and Communication Control (Task 12c) ---

    /// Authentication (0x29): one service per configured subfunction.
    pub fn generate_authentication(&self) -> Vec<DiagService> {
        let entry = match &self.services.authentication {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        let subfuncs = match &entry.subfunctions {
            Some(serde_yaml::Value::Mapping(map)) => map,
            _ => return vec![],
        };

        subfuncs.iter().filter_map(|(k, v)| {
            let name = k.as_str()?;
            let subfunc = yaml_value_to_u8(v);
            Some(build_service(
                &format!("Authentication_{name}"),
                "AUTHENTICATION",
                vec![
                    coded_const_param("SID", 0, 8, "0x29"),
                    coded_const_param("SubFunction", 1, 8, &format!("0x{subfunc:02X}")),
                    value_param("AuthenticationData", 2, 0), // variable length
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x69"),
                    matching_request_param("SubFunction_Echo", 1, 1),
                    value_param("ReturnParameter", 2, 8),
                    value_param("AuthReturnValue", 3, 0), // variable length
                ],
            ))
        }).collect()
    }

    /// CommunicationControl (0x28): one service per configured subfunction.
    pub fn generate_communication_control(&self) -> Vec<DiagService> {
        let entry = match &self.services.communication_control {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        match &entry.subfunctions {
            Some(serde_yaml::Value::Mapping(map)) => {
                map.iter().filter_map(|(k, v)| {
                    let name = k.as_str()?;
                    let subfunc = yaml_value_to_u8(v);
                    Some(comm_control_service(name, subfunc))
                }).collect()
            }
            Some(serde_yaml::Value::Sequence(seq)) => {
                seq.iter().map(|v| {
                    let subfunc = yaml_value_to_u8(v);
                    let name = comm_control_name(subfunc);
                    comm_control_service(&name, subfunc)
                }).collect()
            }
            _ => {
                // Default subtypes
                DEFAULT_COMM_CONTROL_SUBTYPES.iter().map(|(name, subfunc)| {
                    comm_control_service(name, *subfunc)
                }).collect()
            }
        }
    }

    // --- Transfer data services (Task 12d) ---

    /// RequestDownload (0x34) + TransferData (0x36) + RequestTransferExit (0x37) as a group.
    pub fn generate_request_download(&self) -> Vec<DiagService> {
        match &self.services.request_download {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
        vec![
            build_service(
                "RequestDownload",
                "DOWNLOAD",
                vec![
                    coded_const_param("SID", 0, 8, "0x34"),
                    value_param("DataFormatIdentifier", 1, 8),
                    value_param("AddressAndLengthFormatIdentifier", 2, 8),
                    value_param("MemoryAddress", 3, 32),
                    value_param("MemorySize", 7, 32),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x74"),
                    value_param("LengthFormatIdentifier", 1, 8),
                    value_param("MaxNumberOfBlockLength", 2, 32),
                ],
            ),
            build_service(
                "TransferData",
                "DOWNLOAD",
                vec![
                    coded_const_param("SID", 0, 8, "0x36"),
                    value_param("BlockSequenceCounter", 1, 8),
                    value_param("TransferRequestParameterRecord", 2, 0),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x76"),
                    matching_request_param("BlockSequenceCounter_Echo", 1, 1),
                    value_param("TransferResponseParameterRecord", 2, 0),
                ],
            ),
            build_service(
                "RequestTransferExit",
                "DOWNLOAD",
                vec![
                    coded_const_param("SID", 0, 8, "0x37"),
                    value_param("TransferRequestParameterRecord", 1, 0),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x77"),
                ],
            ),
        ]
    }

    /// RequestUpload (0x35) + TransferData + RequestTransferExit as a group.
    pub fn generate_request_upload(&self) -> Vec<DiagService> {
        match &self.services.request_upload {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
        vec![
            build_service(
                "RequestUpload",
                "UPLOAD",
                vec![
                    coded_const_param("SID", 0, 8, "0x35"),
                    value_param("DataFormatIdentifier", 1, 8),
                    value_param("AddressAndLengthFormatIdentifier", 2, 8),
                    value_param("MemoryAddress", 3, 32),
                    value_param("MemorySize", 7, 32),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x75"),
                    value_param("LengthFormatIdentifier", 1, 8),
                    value_param("MaxNumberOfBlockLength", 2, 32),
                ],
            ),
            build_service(
                "TransferData_Upload",
                "UPLOAD",
                vec![
                    coded_const_param("SID", 0, 8, "0x36"),
                    value_param("BlockSequenceCounter", 1, 8),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x76"),
                    matching_request_param("BlockSequenceCounter_Echo", 1, 1),
                    value_param("TransferResponseParameterRecord", 2, 0),
                ],
            ),
            build_service(
                "RequestTransferExit_Upload",
                "UPLOAD",
                vec![
                    coded_const_param("SID", 0, 8, "0x37"),
                ],
                vec![
                    coded_const_param("SID", 0, 8, "0x77"),
                ],
            ),
        ]
    }

    // --- Simple enable/disable services (Task 12a) ---

    /// TesterPresent (0x3E)
    pub fn generate_tester_present(&self) -> Vec<DiagService> {
        match &self.services.tester_present {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
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

    /// ControlDTCSetting (0x85)
    pub fn generate_control_dtc_setting(&self) -> Vec<DiagService> {
        match &self.services.control_dtc_setting {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
        [("on", 0x01u8), ("off", 0x02u8)].iter().map(|(name, subfunc)| {
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

    /// ClearDiagnosticInformation (0x14)
    pub fn generate_clear_diagnostic_information(&self) -> Vec<DiagService> {
        match &self.services.clear_diagnostic_information {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
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

    /// ReadDTCInformation (0x19)
    pub fn generate_read_dtc_information(&self) -> Vec<DiagService> {
        match &self.services.read_dtc_information {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
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

fn yaml_value_to_u8(v: &serde_yaml::Value) -> u8 {
    match v {
        serde_yaml::Value::Number(n) => {
            let val = n.as_u64().unwrap_or_else(|| {
                log::warn!("yaml_value_to_u8: non-u64 number {:?}, defaulting to 0", n);
                0
            });
            val as u8
        }
        serde_yaml::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).unwrap_or_else(|e| {
                    log::warn!("yaml_value_to_u8: invalid hex '{}': {}, defaulting to 0", s, e);
                    0
                })
            } else {
                s.parse().unwrap_or_else(|e| {
                    log::warn!("yaml_value_to_u8: invalid decimal '{}': {}, defaulting to 0", s, e);
                    0
                })
            }
        }
        other => {
            log::warn!("yaml_value_to_u8: unexpected YAML type {:?}, defaulting to 0", other);
            0
        }
    }
}

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

const DEFAULT_COMM_CONTROL_SUBTYPES: &[(&str, u8)] = &[
    ("enableRxAndTx", 0x00),
    ("enableRxAndDisableTx", 0x01),
    ("disableRxAndEnableTx", 0x02),
    ("disableRxAndTx", 0x03),
];

fn comm_control_name(subfunc: u8) -> String {
    DEFAULT_COMM_CONTROL_SUBTYPES
        .iter()
        .find(|(_, v)| *v == subfunc)
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| format!("0x{subfunc:02X}"))
}

fn comm_control_service(name: &str, subfunc: u8) -> DiagService {
    build_service(
        &format!("CommunicationControl_{name}"),
        "COMMUNICATION-CONTROL",
        vec![
            coded_const_param("SID", 0, 8, "0x28"),
            coded_const_param("SubFunction", 1, 8, &format!("0x{subfunc:02X}")),
            value_param("CommunicationType", 2, 8),
        ],
        vec![
            coded_const_param("SID", 0, 8, "0x68"),
            matching_request_param("SubFunction_Echo", 1, 1),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml_model::ServiceEntry;

    fn services_with(configure: impl FnOnce(&mut YamlServices)) -> YamlServices {
        let mut svc = YamlServices::default();
        configure(&mut svc);
        svc
    }

    fn enabled_entry() -> ServiceEntry {
        ServiceEntry { enabled: true, ..Default::default() }
    }

    #[test]
    fn test_tester_present_generation() {
        let svc = services_with(|s| s.tester_present = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_tester_present();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].diag_comm.short_name, "TesterPresent");
        let req = services[0].request.as_ref().unwrap();
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
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_control_dtc_setting();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].diag_comm.short_name, "ControlDTCSetting_on");
        assert_eq!(services[1].diag_comm.short_name, "ControlDTCSetting_off");
    }

    #[test]
    fn test_clear_dtc_generation() {
        let svc = services_with(|s| s.clear_diagnostic_information = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_clear_diagnostic_information();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].diag_comm.short_name, "ClearDiagnosticInformation");
    }

    #[test]
    fn test_read_dtc_info_generation() {
        let svc = services_with(|s| s.read_dtc_information = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_read_dtc_information();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].diag_comm.short_name, "ReadDTCInformation");
    }

    #[test]
    fn test_disabled_service_generates_nothing() {
        let svc = YamlServices::default();
        let generator = ServiceGenerator::new(&svc);
        assert!(generator.generate_all().is_empty());
    }

    #[test]
    fn test_session_control_from_subfunctions_map() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            let mut map = serde_yaml::Mapping::new();
            map.insert("default".into(), serde_yaml::Value::Number(1.into()));
            map.insert("extended".into(), serde_yaml::Value::Number(3.into()));
            entry.subfunctions = Some(serde_yaml::Value::Mapping(map));
            s.diagnostic_session_control = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_diagnostic_session_control();
        assert_eq!(services.len(), 2);
        assert!(services.iter().any(|s| s.diag_comm.short_name == "DiagnosticSessionControl_default"));
        assert!(services.iter().any(|s| s.diag_comm.short_name == "DiagnosticSessionControl_extended"));
    }

    #[test]
    fn test_session_control_from_subfunctions_seq() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            entry.subfunctions = Some(serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::Number(1.into()),
                serde_yaml::Value::Number(2.into()),
            ]));
            s.diagnostic_session_control = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_diagnostic_session_control();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].diag_comm.short_name, "DiagnosticSessionControl_0x01");
    }

    #[test]
    fn test_session_control_from_sessions_section() {
        let svc = services_with(|s| {
            s.diagnostic_session_control = Some(enabled_entry());
        });
        let mut sessions = BTreeMap::new();
        sessions.insert("default".into(), Session {
            id: serde_yaml::Value::Number(1.into()),
            alias: None, requires_unlock: None, timing: None,
        });
        sessions.insert("programming".into(), Session {
            id: serde_yaml::Value::Number(2.into()),
            alias: None, requires_unlock: None, timing: None,
        });
        let generator = ServiceGenerator::new(&svc).with_sessions(Some(&sessions));
        let services = generator.generate_diagnostic_session_control();
        assert_eq!(services.len(), 2);
        // Response should include P2 timing params
        let resp = &services[0].pos_responses[0];
        assert_eq!(resp.params.len(), 4); // SID, subfunc echo, P2, P2*
    }

    #[test]
    fn test_security_access_generation() {
        let svc = services_with(|s| s.security_access = Some(enabled_entry()));
        let mut sec = BTreeMap::new();
        sec.insert("level_01".into(), SecurityLevel {
            level: 1,
            seed_request: serde_yaml::Value::Number(1.into()),
            key_send: serde_yaml::Value::Number(2.into()),
            seed_size: 4, key_size: 4,
            algorithm: String::new(), max_attempts: 0,
            delay_on_fail_ms: 0, allowed_sessions: vec![],
        });
        let generator = ServiceGenerator::new(&svc).with_security(Some(&sec));
        let services = generator.generate_security_access();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].diag_comm.short_name, "SecurityAccess_RequestSeed_level_01");
        assert_eq!(services[1].diag_comm.short_name, "SecurityAccess_SendKey_level_01");

        // Verify seed subfunc byte
        let req = services[0].request.as_ref().unwrap();
        if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[1].specific_data {
            assert_eq!(coded_value, "0x01");
        } else {
            panic!("expected CodedConst for subfunc");
        }
    }

    #[test]
    fn test_ecu_reset_from_subfunctions() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            let mut map = serde_yaml::Mapping::new();
            map.insert("hardReset".into(), serde_yaml::Value::Number(1.into()));
            map.insert("softReset".into(), serde_yaml::Value::Number(3.into()));
            entry.subfunctions = Some(serde_yaml::Value::Mapping(map));
            s.ecu_reset = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_ecu_reset();
        assert_eq!(services.len(), 2);
        assert!(services.iter().any(|s| s.diag_comm.short_name == "ECUReset_hardReset"));
        assert!(services.iter().any(|s| s.diag_comm.short_name == "ECUReset_softReset"));
    }

    #[test]
    fn test_ecu_reset_defaults() {
        let svc = services_with(|s| s.ecu_reset = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_ecu_reset();
        assert_eq!(services.len(), 3); // hardReset, keyOffOnReset, softReset
    }

    #[test]
    fn test_authentication_from_subfunctions() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            let mut map = serde_yaml::Mapping::new();
            map.insert("deAuthenticate".into(), serde_yaml::Value::Number(0.into()));
            map.insert("verifyCertificateUnidirectional".into(), serde_yaml::Value::Number(1.into()));
            map.insert("proofOfOwnership".into(), serde_yaml::Value::Number(3.into()));
            entry.subfunctions = Some(serde_yaml::Value::Mapping(map));
            s.authentication = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_authentication();
        assert_eq!(services.len(), 3);
        assert!(services.iter().any(|s| s.diag_comm.short_name == "Authentication_deAuthenticate"));
        assert!(services.iter().any(|s| s.diag_comm.short_name == "Authentication_proofOfOwnership"));
        // Verify SID
        let req = services[0].request.as_ref().unwrap();
        if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[0].specific_data {
            assert_eq!(coded_value, "0x29");
        }
    }

    #[test]
    fn test_authentication_disabled() {
        let svc = services_with(|_| {}); // no authentication entry
        let generator = ServiceGenerator::new(&svc);
        assert!(generator.generate_authentication().is_empty());
    }

    #[test]
    fn test_communication_control_from_sequence() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            entry.subfunctions = Some(serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::Number(0.into()),
                serde_yaml::Value::Number(1.into()),
                serde_yaml::Value::Number(3.into()),
            ]));
            s.communication_control = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_communication_control();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].diag_comm.short_name, "CommunicationControl_enableRxAndTx");
        assert_eq!(services[1].diag_comm.short_name, "CommunicationControl_enableRxAndDisableTx");
        assert_eq!(services[2].diag_comm.short_name, "CommunicationControl_disableRxAndTx");
        // Verify SID
        let req = services[0].request.as_ref().unwrap();
        if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[0].specific_data {
            assert_eq!(coded_value, "0x28");
        }
    }

    #[test]
    fn test_communication_control_defaults() {
        let svc = services_with(|s| s.communication_control = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_communication_control();
        assert_eq!(services.len(), 4); // 4 default subtypes
    }

    #[test]
    fn test_communication_control_from_map() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            let mut map = serde_yaml::Mapping::new();
            map.insert("enableRxAndTx".into(), serde_yaml::Value::Number(0.into()));
            map.insert("disableRxAndTx".into(), serde_yaml::Value::Number(3.into()));
            entry.subfunctions = Some(serde_yaml::Value::Mapping(map));
            s.communication_control = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_communication_control();
        assert_eq!(services.len(), 2);
        assert!(services.iter().any(|s| s.diag_comm.short_name == "CommunicationControl_enableRxAndTx"));
        assert!(services.iter().any(|s| s.diag_comm.short_name == "CommunicationControl_disableRxAndTx"));
    }

    #[test]
    fn test_request_download_group() {
        let svc = services_with(|s| s.request_download = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_request_download();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].diag_comm.short_name, "RequestDownload");
        assert_eq!(services[1].diag_comm.short_name, "TransferData");
        assert_eq!(services[2].diag_comm.short_name, "RequestTransferExit");
        // Verify SIDs
        let check_sid = |svc: &DiagService, expected: &str| {
            let req = svc.request.as_ref().unwrap();
            if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[0].specific_data {
                assert_eq!(coded_value, expected, "SID mismatch for {}", svc.diag_comm.short_name);
            }
        };
        check_sid(&services[0], "0x34");
        check_sid(&services[1], "0x36");
        check_sid(&services[2], "0x37");
    }

    #[test]
    fn test_request_upload_group() {
        let svc = services_with(|s| s.request_upload = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_request_upload();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].diag_comm.short_name, "RequestUpload");
        assert_eq!(services[1].diag_comm.short_name, "TransferData_Upload");
        assert_eq!(services[2].diag_comm.short_name, "RequestTransferExit_Upload");
    }

    #[test]
    fn test_request_download_disabled() {
        let svc = services_with(|_| {});
        let generator = ServiceGenerator::new(&svc);
        assert!(generator.generate_request_download().is_empty());
        assert!(generator.generate_request_upload().is_empty());
    }
}
