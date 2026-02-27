use serde_json::Value;

const SCHEMA_JSON: &str = include_str!("../../docs/yaml-schema/schema.json");

/// A validation error with a JSON path and message.
#[derive(Debug, Clone)]
pub struct SchemaError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// Validate a YAML string against the embedded JSON Schema.
///
/// Returns `Ok(())` if valid, or a list of schema validation errors.
pub fn validate_yaml_schema(yaml_text: &str) -> Result<(), Vec<SchemaError>> {
    let instance: Value = serde_yaml::from_str(yaml_text).map_err(|e| {
        vec![SchemaError {
            path: String::new(),
            message: format!("YAML parse error: {e}"),
        }]
    })?;

    let schema: Value = serde_json::from_str(SCHEMA_JSON).expect("embedded schema is valid JSON");

    let validator =
        jsonschema::draft202012::new(&schema).expect("embedded schema is a valid JSON Schema");

    let errors: Vec<SchemaError> = validator
        .iter_errors(&instance)
        .map(|e| SchemaError {
            path: e.instance_path().to_string(),
            message: e.to_string(),
        })
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
