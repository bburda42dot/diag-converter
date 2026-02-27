use anyhow::{Context, Result, bail};
use std::path::Path;

use crate::Format;
use crate::convert::parse_input;

pub fn run_validate(input: &Path, quiet: bool, summary: bool) -> Result<()> {
    let mut all_errors: Vec<String> = Vec::new();

    // Schema + semantic validation for YAML files
    let in_fmt = crate::detect_format(input).context("input file")?;
    if in_fmt == Format::Yaml {
        let text = std::fs::read_to_string(input)
            .with_context(|| format!("reading {}", input.display()))?;
        if let Err(schema_errors) = diag_yaml::validate_yaml_schema(&text) {
            for e in &schema_errors {
                all_errors.push(format!("schema: {e}"));
            }
        }
        // Semantic validation on YAML model
        if let Ok(doc) = serde_yaml::from_str::<diag_yaml::yaml_model::YamlDocument>(&text) {
            let semantic_issues = diag_yaml::validate_semantics(&doc);
            for issue in &semantic_issues {
                all_errors.push(issue.to_string());
            }
        }
    }

    // IR-level validation (parse first)
    let db = parse_input(input, false)?;
    if let Err(ir_errors) = diag_ir::validate_database(&db) {
        for e in &ir_errors {
            all_errors.push(e.to_string());
        }
    }

    if all_errors.is_empty() {
        if !quiet {
            println!("{}: valid", input.display());
        }
        return Ok(());
    }

    if !quiet && !summary {
        for e in &all_errors {
            eprintln!("{}: {e}", input.display());
        }
    }

    if summary || (!quiet && !all_errors.is_empty()) {
        println!(
            "{}: {} validation error{}",
            input.display(),
            all_errors.len(),
            if all_errors.len() == 1 { "" } else { "s" }
        );
    }

    bail!(
        "{} validation error{} in {}",
        all_errors.len(),
        if all_errors.len() == 1 { "" } else { "s" },
        input.display()
    );
}
