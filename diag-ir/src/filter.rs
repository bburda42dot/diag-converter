use crate::types::{Audience, DiagDatabase};

/// Filter the database to only include entities visible to the given audience.
///
/// For each service/job with an `Audience` field:
/// - If `enabled_audiences` is non-empty and the target is not in it: remove.
/// - If `disabled_audiences` contains the target: remove.
/// - If no audience is set, the entity is kept (visible to all).
pub fn filter_by_audience(db: &mut DiagDatabase, audience: &str) {
    for variant in &mut db.variants {
        variant
            .diag_layer
            .diag_services
            .retain(|svc| is_visible(&svc.diag_comm.audience, audience));
        variant
            .diag_layer
            .single_ecu_jobs
            .retain(|job| is_visible(&job.diag_comm.audience, audience));
    }

    for fg in &mut db.functional_groups {
        fg.diag_layer
            .diag_services
            .retain(|svc| is_visible(&svc.diag_comm.audience, audience));
        fg.diag_layer
            .single_ecu_jobs
            .retain(|job| is_visible(&job.diag_comm.audience, audience));
    }
}

fn is_visible(audience_field: &Option<Audience>, target: &str) -> bool {
    let aud = match audience_field {
        Some(a) => a,
        None => return true, // no audience restriction
    };

    // If enabled list is non-empty, target must be in it
    if !aud.enabled_audiences.is_empty()
        && !aud
            .enabled_audiences
            .iter()
            .any(|a| a.short_name == target)
    {
        return false;
    }

    // If target is in the disabled list, exclude
    if aud
        .disabled_audiences
        .iter()
        .any(|a| a.short_name == target)
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn make_service(name: &str, audience: Option<Audience>) -> DiagService {
        DiagService {
            diag_comm: DiagComm {
                short_name: name.to_string(),
                audience,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn aa(name: &str) -> AdditionalAudience {
        AdditionalAudience {
            short_name: name.to_string(),
            long_name: None,
        }
    }

    #[test]
    fn test_no_audience_keeps_all() {
        let svc = make_service("ReadDID", None);
        assert!(is_visible(&svc.diag_comm.audience, "development"));
    }

    #[test]
    fn test_enabled_audience_match() {
        let svc = make_service(
            "DevOnly",
            Some(Audience {
                enabled_audiences: vec![aa("development")],
                ..Default::default()
            }),
        );
        assert!(is_visible(&svc.diag_comm.audience, "development"));
        assert!(!is_visible(&svc.diag_comm.audience, "aftermarket"));
    }

    #[test]
    fn test_disabled_audience_excludes() {
        let svc = make_service(
            "NotForDev",
            Some(Audience {
                disabled_audiences: vec![aa("development")],
                ..Default::default()
            }),
        );
        assert!(!is_visible(&svc.diag_comm.audience, "development"));
        assert!(is_visible(&svc.diag_comm.audience, "aftermarket"));
    }

    #[test]
    fn test_filter_functional_groups() {
        let mut db = DiagDatabase {
            ecu_name: "TEST".into(),
            functional_groups: vec![FunctionalGroup {
                diag_layer: DiagLayer {
                    short_name: "FG_Ident".into(),
                    diag_services: vec![
                        make_service("PublicFG", None),
                        make_service(
                            "DevOnlyFG",
                            Some(Audience {
                                enabled_audiences: vec![aa("development")],
                                ..Default::default()
                            }),
                        ),
                    ],
                    ..Default::default()
                },
                parent_refs: vec![],
            }],
            ..Default::default()
        };

        filter_by_audience(&mut db, "aftermarket");

        let names: Vec<&str> = db.functional_groups[0]
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        assert_eq!(names, vec!["PublicFG"], "DevOnlyFG should be filtered from functional groups");
    }

    #[test]
    fn test_filter_database() {
        let mut db = DiagDatabase {
            ecu_name: "TEST".into(),
            variants: vec![Variant {
                is_base_variant: true,
                diag_layer: DiagLayer {
                    short_name: "Base".into(),
                    diag_services: vec![
                        make_service("Public", None),
                        make_service(
                            "DevOnly",
                            Some(Audience {
                                enabled_audiences: vec![aa("development")],
                                ..Default::default()
                            }),
                        ),
                        make_service(
                            "NoAftermarket",
                            Some(Audience {
                                disabled_audiences: vec![aa("aftermarket")],
                                ..Default::default()
                            }),
                        ),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };

        filter_by_audience(&mut db, "aftermarket");

        let names: Vec<&str> = db.variants[0]
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        // "Public" kept (no audience), "DevOnly" removed (not in enabled), "NoAftermarket" removed (in disabled)
        assert_eq!(names, vec!["Public"]);
    }
}
