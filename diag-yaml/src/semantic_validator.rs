use crate::yaml_model::YamlDocument;
use std::collections::{BTreeMap, HashSet};

/// Severity of a semantic validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// A semantic validation finding.
#[derive(Debug, Clone)]
pub struct SemanticIssue {
    pub severity: Severity,
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for SemanticIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        if self.path.is_empty() {
            write!(f, "{prefix}: {}", self.message)
        } else {
            write!(f, "{prefix}: {}: {}", self.path, self.message)
        }
    }
}

/// Run all semantic validations on a parsed YAML document.
///
/// Returns a list of issues (errors and warnings). Empty means valid.
pub fn validate_semantics(doc: &YamlDocument) -> Vec<SemanticIssue> {
    let mut issues = Vec::new();

    validate_session_id_uniqueness(doc, &mut issues);
    validate_security_level_uniqueness(doc, &mut issues);
    validate_access_pattern_session_refs(doc, &mut issues);
    validate_access_pattern_security_refs(doc, &mut issues);
    validate_state_model_session_refs(doc, &mut issues);

    issues
}

/// Check that no two sessions have the same byte value.
fn validate_session_id_uniqueness(doc: &YamlDocument, issues: &mut Vec<SemanticIssue>) {
    let sessions = match &doc.sessions {
        Some(s) => s,
        None => return,
    };

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (name, session) in sessions {
        let id_str = format!("{:?}", session.id);
        if let Some(prev) = seen.get(&id_str) {
            issues.push(SemanticIssue {
                severity: Severity::Error,
                path: format!("sessions/{name}"),
                message: format!("duplicate session ID {id_str} (already used by '{prev}')"),
            });
        } else {
            seen.insert(id_str, name.clone());
        }
    }
}

/// Check that no two security levels have the same level byte value.
fn validate_security_level_uniqueness(doc: &YamlDocument, issues: &mut Vec<SemanticIssue>) {
    let security = match &doc.security {
        Some(s) => s,
        None => return,
    };

    let mut seen: BTreeMap<u64, String> = BTreeMap::new();
    for (name, level) in security {
        if let Some(prev) = seen.get(&(level.level as u64)) {
            issues.push(SemanticIssue {
                severity: Severity::Error,
                path: format!("security/{name}"),
                message: format!(
                    "duplicate security level {} (already used by '{prev}')",
                    level.level
                ),
            });
        } else {
            seen.insert(level.level as u64, name.clone());
        }
    }
}

/// Check that session references in access_patterns point to defined sessions.
fn validate_access_pattern_session_refs(doc: &YamlDocument, issues: &mut Vec<SemanticIssue>) {
    let patterns = match &doc.access_patterns {
        Some(p) => p,
        None => return,
    };
    let session_names: HashSet<&str> = doc
        .sessions
        .as_ref()
        .map(|s| s.keys().map(std::string::String::as_str).collect())
        .unwrap_or_default();

    for (pat_name, pattern) in patterns {
        // sessions can be "any" (string) or a list of session names
        if let serde_yaml::Value::Sequence(refs) = &pattern.sessions {
            for r in refs {
                if let serde_yaml::Value::String(ref_name) = r {
                    if !session_names.contains(ref_name.as_str()) {
                        issues.push(SemanticIssue {
                            severity: Severity::Error,
                            path: format!("access_patterns/{pat_name}/sessions"),
                            message: format!("references undefined session '{ref_name}'"),
                        });
                    }
                }
            }
        }
    }
}

/// Check that security references in access_patterns point to defined security levels.
fn validate_access_pattern_security_refs(doc: &YamlDocument, issues: &mut Vec<SemanticIssue>) {
    let patterns = match &doc.access_patterns {
        Some(p) => p,
        None => return,
    };
    let security_names: HashSet<&str> = doc
        .security
        .as_ref()
        .map(|s| s.keys().map(std::string::String::as_str).collect())
        .unwrap_or_default();

    for (pat_name, pattern) in patterns {
        // security can be "none" (string) or a list of security level names
        if let serde_yaml::Value::Sequence(refs) = &pattern.security {
            for r in refs {
                if let serde_yaml::Value::String(ref_name) = r {
                    if !security_names.contains(ref_name.as_str()) {
                        issues.push(SemanticIssue {
                            severity: Severity::Error,
                            path: format!("access_patterns/{pat_name}/security"),
                            message: format!("references undefined security level '{ref_name}'"),
                        });
                    }
                }
            }
        }
    }
}

/// Check that session names in state_model.session_transitions reference defined sessions.
fn validate_state_model_session_refs(doc: &YamlDocument, issues: &mut Vec<SemanticIssue>) {
    let state_model = match &doc.state_model {
        Some(sm) => sm,
        None => return,
    };
    let transitions = match &state_model.session_transitions {
        Some(t) => t,
        None => return,
    };
    let session_names: HashSet<&str> = doc
        .sessions
        .as_ref()
        .map(|s| s.keys().map(std::string::String::as_str).collect())
        .unwrap_or_default();

    for (from, targets) in transitions {
        if !session_names.contains(from.as_str()) {
            issues.push(SemanticIssue {
                severity: Severity::Warning,
                path: format!("state_model/session_transitions/{from}"),
                message: format!("transition source '{from}' is not a defined session"),
            });
        }
        for target in targets {
            if !session_names.contains(target.as_str()) {
                issues.push(SemanticIssue {
                    severity: Severity::Warning,
                    path: format!("state_model/session_transitions/{from}"),
                    message: format!("transition target '{target}' is not a defined session"),
                });
            }
        }
    }
}
