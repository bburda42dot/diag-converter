use diag_yaml::semantic_validator::{validate_semantics, Severity};
use diag_yaml::yaml_model::YamlDocument;

fn parse_doc(yaml: &str) -> YamlDocument {
    serde_yaml::from_str(yaml).unwrap()
}

#[test]
fn test_valid_document_has_no_issues() {
    let doc = parse_doc(r#"
sessions:
  default:
    id: 0x01
  programming:
    id: 0x02
access_patterns:
  default:
    sessions: "any"
    security: "none"
    authentication: "none"
"#);
    let issues = validate_semantics(&doc);
    assert!(issues.is_empty(), "valid doc should have no issues: {:?}", issues);
}

#[test]
fn test_duplicate_session_ids() {
    let doc = parse_doc(r#"
sessions:
  default:
    id: 0x01
  extended:
    id: 0x01
"#);
    let issues = validate_semantics(&doc);
    assert!(
        issues.iter().any(|i| i.severity == Severity::Error && i.message.contains("duplicate session ID")),
        "should detect duplicate session IDs: {:?}",
        issues
    );
}

#[test]
fn test_duplicate_security_levels() {
    let doc = parse_doc(r#"
security:
  level_a:
    level: 1
    seed_request: 0x27
    key_send: 0x28
    seed_size: 4
    key_size: 4
    algorithm: "xor"
    max_attempts: 3
    delay_on_fail_ms: 1000
    allowed_sessions: []
  level_b:
    level: 1
    seed_request: 0x29
    key_send: 0x2A
    seed_size: 4
    key_size: 4
    algorithm: "xor"
    max_attempts: 3
    delay_on_fail_ms: 1000
    allowed_sessions: []
"#);
    let issues = validate_semantics(&doc);
    assert!(
        issues.iter().any(|i| i.severity == Severity::Error && i.message.contains("duplicate security level")),
        "should detect duplicate security levels: {:?}",
        issues
    );
}

#[test]
fn test_access_pattern_references_undefined_session() {
    let doc = parse_doc(r#"
sessions:
  default:
    id: 0x01
access_patterns:
  strict:
    sessions:
      - default
      - nonexistent_session
    security: "none"
    authentication: "none"
"#);
    let issues = validate_semantics(&doc);
    assert!(
        issues.iter().any(|i| i.severity == Severity::Error && i.message.contains("nonexistent_session")),
        "should detect undefined session reference: {:?}",
        issues
    );
}

#[test]
fn test_access_pattern_references_undefined_security() {
    let doc = parse_doc(r#"
sessions:
  default:
    id: 0x01
access_patterns:
  strict:
    sessions: "any"
    security:
      - nonexistent_level
    authentication: "none"
"#);
    let issues = validate_semantics(&doc);
    assert!(
        issues.iter().any(|i| i.severity == Severity::Error && i.message.contains("nonexistent_level")),
        "should detect undefined security reference: {:?}",
        issues
    );
}

#[test]
fn test_state_model_undefined_session_warning() {
    let doc = parse_doc(r#"
sessions:
  default:
    id: 0x01
state_model:
  session_transitions:
    default:
      - unknown_session
"#);
    let issues = validate_semantics(&doc);
    assert!(
        issues.iter().any(|i| i.severity == Severity::Warning && i.message.contains("unknown_session")),
        "should warn about undefined transition target: {:?}",
        issues
    );
}

#[test]
fn test_access_pattern_any_sessions_no_error() {
    // "any" as a string should not trigger reference errors
    let doc = parse_doc(r#"
access_patterns:
  default:
    sessions: "any"
    security: "none"
    authentication: "none"
"#);
    let issues = validate_semantics(&doc);
    let session_errors: Vec<_> = issues.iter()
        .filter(|i| i.path.contains("sessions"))
        .collect();
    assert!(session_errors.is_empty(), "\"any\" should not trigger errors: {:?}", session_errors);
}
