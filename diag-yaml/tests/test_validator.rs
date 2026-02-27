use diag_yaml::validate_yaml_schema;

const VALID_MINIMAL: &str = r#"
schema: "opensovd.cda.diagdesc/v1"
meta:
  author: "Test"
  domain: "test"
  created: "2026-01-01"
  revision: "1.0.0"
  description: "Test ECU"
ecu:
  id: "TEST"
  name: "Test ECU"
  addressing: {}
sessions:
  default:
    id: 0x01
  programming:
    id: 0x02
services: {}
access_patterns:
  default:
    sessions: "any"
    security: "none"
    authentication: "none"
"#;

#[test]
fn test_valid_minimal_yaml_passes_schema() {
    let result = validate_yaml_schema(VALID_MINIMAL);
    assert!(
        result.is_ok(),
        "minimal valid YAML should pass: {:?}",
        result.err()
    );
}

#[test]
fn test_missing_required_field_fails() {
    // Remove 'sessions' - a required top-level field
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
meta:
  author: "Test"
  domain: "test"
  created: "2026-01-01"
  revision: "1.0.0"
  description: "Test ECU"
ecu:
  id: "TEST"
  name: "Test ECU"
  addressing: {}
services: {}
access_patterns:
  default:
    sessions: "any"
    security: "none"
    authentication: "none"
"#;
    let result = validate_yaml_schema(yaml);
    assert!(result.is_err(), "missing 'sessions' should fail");
    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.message.contains("sessions")),
        "error should mention 'sessions': {:?}",
        errors
    );
}

#[test]
fn test_wrong_schema_version_fails() {
    let yaml = r#"
schema: "wrong/version"
meta:
  author: "Test"
  domain: "test"
  created: "2026-01-01"
  revision: "1.0.0"
  description: "Test ECU"
ecu:
  id: "TEST"
  name: "Test ECU"
  addressing: {}
sessions:
  default:
    id: 0x01
services: {}
access_patterns:
  default:
    sessions: "any"
    security: "none"
    authentication: "none"
"#;
    let result = validate_yaml_schema(yaml);
    assert!(result.is_err(), "wrong schema version should fail");
}

#[test]
fn test_additional_properties_rejected() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
meta:
  author: "Test"
  domain: "test"
  created: "2026-01-01"
  revision: "1.0.0"
  description: "Test ECU"
ecu:
  id: "TEST"
  name: "Test ECU"
  addressing: {}
sessions:
  default:
    id: 0x01
services: {}
access_patterns:
  default:
    sessions: "any"
    security: "none"
    authentication: "none"
bogus_field: "not allowed"
"#;
    let result = validate_yaml_schema(yaml);
    assert!(result.is_err(), "additional properties should be rejected");
}

#[test]
fn test_malformed_yaml_returns_parse_error() {
    let yaml = "{{{{invalid yaml";
    let result = validate_yaml_schema(yaml);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors[0].message.contains("YAML parse error"));
}

#[test]
fn test_error_includes_path() {
    // Session missing required 'id' field
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
meta:
  author: "Test"
  domain: "test"
  created: "2026-01-01"
  revision: "1.0.0"
  description: "Test ECU"
ecu:
  id: "TEST"
  name: "Test ECU"
  addressing: {}
sessions:
  default:
    alias: "no_id_here"
services: {}
access_patterns:
  default:
    sessions: "any"
    security: "none"
    authentication: "none"
"#;
    let result = validate_yaml_schema(yaml);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.path.contains("sessions")),
        "error path should point to sessions: {:?}",
        errors
    );
}
