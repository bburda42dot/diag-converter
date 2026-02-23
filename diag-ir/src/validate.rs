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
}

/// Validate a DiagDatabase for structural consistency.
pub fn validate_database(db: &DiagDatabase) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Check ECU name is non-empty (if any variants exist)
    if db.ecu_name.is_empty() && !db.variants.is_empty() {
        errors.push(ValidationError::EmptyEcuName);
    }

    // Check for duplicate service names within each variant's DiagLayer
    for variant in &db.variants {
        let layer = &variant.diag_layer;
        let mut service_names = HashSet::new();
        for svc in &layer.diag_services {
            let name = &svc.diag_comm.short_name;
            if !name.is_empty() && !service_names.insert(name.as_str()) {
                errors.push(ValidationError::DuplicateServiceName(
                    name.clone(),
                    layer.short_name.clone(),
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
