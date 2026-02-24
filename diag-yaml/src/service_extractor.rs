//! Inverse of service_generator: extracts YamlServices from IR DiagServices.
//!
//! The ServiceGenerator (parser side) generates DiagService IR entries from
//! declarative YAML sections. This module does the reverse: given a list of
//! DiagService entries, it reconstructs the YamlServices struct by detecting
//! UDS service patterns via the `semantic` field and SID constants.
//!
//! ## Known limitations
//!
//! ServiceEntry fields that are YAML-level config hints (addressing_mode,
//! state_effects, audience, response_outputs, request_layout, communication_types,
//! nrc_on_fail, etc.) are not reconstructible from IR and will be `None`.
//! This does not affect IR -> YAML -> IR roundtrip because these fields are
//! only consumed during initial YAML parsing.

use diag_ir::types::{DiagService, ParamData, ParamType};

use crate::yaml_model::ServiceEntry;

/// Extract the UDS SID byte from a service's first request parameter.
/// Returns `None` if the service has no request or no SID CodedConst param.
pub fn extract_sid(svc: &DiagService) -> Option<u8> {
    let request = svc.request.as_ref()?;
    let sid_param = request.params.iter().find(|p| {
        p.short_name == "SID" && p.param_type == ParamType::CodedConst
    })?;
    match &sid_param.specific_data {
        Some(ParamData::CodedConst { coded_value, .. }) => parse_hex_or_decimal(coded_value),
        _ => None,
    }
}

/// Extract a CodedConst subfunction byte from a service's request parameters.
///
/// Searches for a CodedConst param at byte position 1 (the standard UDS
/// subfunction location). Matches any param name - not just "SubFunction" -
/// because ODX-originated services may use names like "SecurityAccessType",
/// "ResetType", or "SessionType".
pub fn extract_subfunction(svc: &DiagService) -> Option<u8> {
    let request = svc.request.as_ref()?;
    let sf_param = request.params.iter().find(|p| {
        p.param_type == ParamType::CodedConst && p.byte_position == Some(1)
    })?;
    match &sf_param.specific_data {
        Some(ParamData::CodedConst { coded_value, .. }) => parse_hex_or_decimal(coded_value),
        _ => None,
    }
}

fn parse_hex_or_decimal(s: &str) -> Option<u8> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Build a ServiceEntry with subfunctions extracted from service names.
///
/// Given services named `"{prefix}{name}"` (e.g. `"ECUReset_hardReset"`),
/// extracts the subfunction byte from each service's request and builds a
/// subfunctions mapping `{name: hex_value}`.
fn extract_subfunction_entry(services: &[&DiagService], name_prefix: &str) -> ServiceEntry {
    let mut subfuncs = serde_yaml::Mapping::new();
    for svc in services {
        let name = svc
            .diag_comm
            .short_name
            .strip_prefix(name_prefix)
            .unwrap_or(&svc.diag_comm.short_name);
        if let Some(sf) = extract_subfunction(svc) {
            subfuncs.insert(
                serde_yaml::Value::String(name.to_string()),
                serde_yaml::Value::String(format!("0x{sf:02X}")),
            );
        }
    }

    ServiceEntry {
        enabled: true,
        subfunctions: if subfuncs.is_empty() {
            None
        } else {
            Some(serde_yaml::Value::Mapping(subfuncs))
        },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diag_ir::types::*;

    fn make_service(name: &str, semantic: &str, sid: &str) -> DiagService {
        DiagService {
            diag_comm: DiagComm {
                short_name: name.to_string(),
                semantic: semantic.to_string(),
                ..Default::default()
            },
            request: Some(Request {
                params: vec![Param {
                    short_name: "SID".to_string(),
                    param_type: ParamType::CodedConst,
                    byte_position: Some(0),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: sid.to_string(),
                        diag_coded_type: DiagCodedType {
                            is_high_low_byte_order: true,
                            ..Default::default()
                        },
                    }),
                    ..Default::default()
                }],
                sdgs: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_extract_sid_from_service() {
        let svc = make_service("TesterPresent", "TESTING", "0x3E");
        assert_eq!(extract_sid(&svc), Some(0x3E));
    }

    #[test]
    fn test_extract_sid_returns_none_for_no_request() {
        let svc = DiagService::default();
        assert_eq!(extract_sid(&svc), None);
    }
}
