use crate::types::DiagDatabase;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("duplicate service name '{0}' in variant '{1}'")]
    DuplicateServiceName(String, String),
    #[error("duplicate DOP name '{0}' in service '{1}'")]
    DuplicateDopName(String, String),
    #[error("empty ECU name")]
    EmptyEcuName,
    #[error("empty service name in variant '{0}'")]
    EmptyServiceName(String),
    #[error("duplicate DTC ID {0} in database '{1}'")]
    DuplicateDtcId(u32, String),
    #[error("state chart '{0}' has no states in variant '{1}'")]
    EmptyStateChart(String, String),
    #[error("variant '{0}' has no services")]
    EmptyVariant(String),
}

/// Validate a DiagDatabase for structural consistency.
pub fn validate_database(db: &DiagDatabase) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if db.ecu_name.is_empty() && !db.variants.is_empty() {
        errors.push(ValidationError::EmptyEcuName);
    }

    for variant in &db.variants {
        let layer = &variant.diag_layer;
        let vname = &layer.short_name;

        // Duplicate service names
        let mut service_names = HashSet::new();
        for svc in &layer.diag_services {
            let name = &svc.diag_comm.short_name;
            if name.is_empty() {
                errors.push(ValidationError::EmptyServiceName(vname.clone()));
            } else if !service_names.insert(name.as_str()) {
                errors.push(ValidationError::DuplicateServiceName(
                    name.clone(),
                    vname.clone(),
                ));
            }
        }

        // Variant with no services (warn via log, not an error)
        if variant.is_base_variant
            && layer.diag_services.is_empty()
            && layer.single_ecu_jobs.is_empty()
        {
            log::warn!("variant '{}' has no services", vname);
        }

        // State charts with no states
        for sc in &layer.state_charts {
            if sc.states.is_empty() {
                errors.push(ValidationError::EmptyStateChart(
                    sc.short_name.clone(),
                    vname.clone(),
                ));
            }
        }
    }

    // Duplicate DTC IDs (database-wide check, not per-variant)
    let mut dtc_ids = HashSet::new();
    for dtc in &db.dtcs {
        if !dtc_ids.insert(dtc.trouble_code) {
            errors.push(ValidationError::DuplicateDtcId(
                dtc.trouble_code,
                db.ecu_name.clone(),
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
