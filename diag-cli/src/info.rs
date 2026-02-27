use anyhow::{Context, Result};
use std::path::Path;

use crate::Format;
use crate::convert::parse_input;

pub fn run_info(input: &Path) -> Result<()> {
    let in_fmt = crate::detect_format(input).context("input file")?;
    let db = parse_input(input, false)?;

    let format_str = match in_fmt {
        Format::Odx => "ODX",
        Format::Pdx => "PDX",
        Format::Yaml => "YAML",
        Format::Mdd => "MDD",
    };

    println!("File:        {}", input.display());
    println!("Format:      {format_str}");
    println!("ECU:         {}", db.ecu_name);
    println!("Version:     {}", db.version);
    println!("Revision:    {}", db.revision);

    let variant_names: Vec<&str> = db
        .variants
        .iter()
        .map(|v| v.diag_layer.short_name.as_str())
        .collect();
    println!(
        "Variants:    {} ({})",
        db.variants.len(),
        variant_names.join(", ")
    );

    if let Some(base) = db.variants.iter().find(|v| v.is_base_variant) {
        println!("Services:    {}", base.diag_layer.diag_services.len());
        let com_params = base.diag_layer.com_param_refs.len();
        if com_params > 0 {
            println!("ComParams:   {com_params}");
        }
    }

    println!("DTCs:        {}", db.dtcs.len());

    let state_charts: usize = db
        .variants
        .iter()
        .map(|v| v.diag_layer.state_charts.len())
        .sum();
    if state_charts > 0 {
        println!("StateCharts: {state_charts}");
    }

    Ok(())
}
