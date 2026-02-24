use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "diag-converter", about = "Convert between ODX, YAML, and MDD diagnostic formats")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Bare positional input file (backwards compat: treated as `convert <input>`)
    #[arg(hide = true)]
    bare_input: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Convert between diagnostic formats (ODX, YAML, MDD)
    Convert {
        /// Input file (.odx, .yml/.yaml, .mdd)
        input: PathBuf,

        /// Output file (.odx, .yml/.yaml, .mdd)
        #[arg(short, long)]
        output: PathBuf,

        /// Compression for MDD output (lzma, gzip, zstd, none)
        #[arg(long, default_value = "lzma")]
        compression: String,

        /// Enable verbose logging with timing info
        #[arg(short, long)]
        verbose: bool,

        /// Parse and validate without writing output
        #[arg(long)]
        dry_run: bool,

        /// Filter output by audience (e.g. development, aftermarket, oem)
        #[arg(long)]
        audience: Option<String>,
    },

    /// Validate a diagnostic input file
    Validate {
        /// Input file to validate (.odx, .yml/.yaml, .mdd)
        input: PathBuf,

        /// Suppress individual error output
        #[arg(short, long)]
        quiet: bool,

        /// Print summary count only
        #[arg(short, long)]
        summary: bool,
    },

    /// Display information about a diagnostic file
    Info {
        /// Input file (.odx, .yml/.yaml, .mdd)
        input: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Format {
    Odx,
    Pdx,
    Yaml,
    Mdd,
}

fn detect_format(path: &Path) -> Result<Format> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("odx") => Ok(Format::Odx),
        Some("pdx") => Ok(Format::Pdx),
        Some("yml" | "yaml") => Ok(Format::Yaml),
        Some("mdd") => Ok(Format::Mdd),
        Some(ext) => bail!("Unknown file extension: .{ext}"),
        None => bail!("Cannot detect format: file has no extension"),
    }
}

fn parse_compression(s: &str) -> Result<mdd_format::compression::Compression> {
    match s {
        "lzma" => Ok(mdd_format::compression::Compression::Lzma),
        "gzip" => Ok(mdd_format::compression::Compression::Gzip),
        "zstd" => Ok(mdd_format::compression::Compression::Zstd),
        "none" => Ok(mdd_format::compression::Compression::None),
        other => bail!("Unknown compression: {other}. Use lzma, gzip, zstd, or none"),
    }
}

fn parse_input(input: &Path, verbose: bool) -> Result<diag_ir::types::DiagDatabase> {
    let in_fmt = detect_format(input).context("input file")?;
    let start = Instant::now();

    let db = match in_fmt {
        Format::Yaml => {
            let text = std::fs::read_to_string(input)
                .with_context(|| format!("reading {}", input.display()))?;
            diag_yaml::parse_yaml(&text)
                .with_context(|| format!("parsing YAML from {}", input.display()))?
        }
        Format::Odx => {
            let text = std::fs::read_to_string(input)
                .with_context(|| format!("reading {}", input.display()))?;
            diag_odx::parse_odx(&text)
                .with_context(|| format!("parsing ODX from {}", input.display()))?
        }
        Format::Pdx => {
            diag_odx::read_pdx_file(input)
                .with_context(|| format!("reading PDX from {}", input.display()))?
        }
        Format::Mdd => {
            let (_meta, fbs_data) = mdd_format::reader::read_mdd_file(input)
                .with_context(|| format!("reading MDD from {}", input.display()))?;
            diag_ir::flatbuffers_to_ir(&fbs_data)
                .with_context(|| "converting FlatBuffers to IR")?
        }
    };

    if verbose {
        eprintln!("Parse time: {:.1}ms", start.elapsed().as_secs_f64() * 1000.0);
    }

    Ok(db)
}

fn run_convert(
    input: &Path,
    output: &Path,
    compression: &str,
    verbose: bool,
    dry_run: bool,
    audience: Option<&str>,
) -> Result<()> {
    if verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }

    let out_fmt = detect_format(output).context("output file")?;
    let in_fmt = detect_format(input).context("input file")?;

    if in_fmt == out_fmt {
        bail!("Input and output formats are the same ({in_fmt:?}). Nothing to convert.");
    }

    log::info!("Converting {:?} -> {:?}", in_fmt, out_fmt);

    let mut db = parse_input(input, verbose)?;

    if let Some(aud) = audience {
        let before = db.variants.iter().map(|v| v.diag_layer.diag_services.len()).sum::<usize>();
        diag_ir::filter_by_audience(&mut db, aud);
        let after = db.variants.iter().map(|v| v.diag_layer.diag_services.len()).sum::<usize>();
        if before != after {
            log::info!("Audience filter '{aud}': {before} -> {after} services");
        }
    }

    let validate_start = Instant::now();
    if let Err(errors) = diag_ir::validate_database(&db) {
        for e in &errors {
            log::warn!("Validation: {e}");
        }
    }
    if verbose {
        eprintln!(
            "Validate time: {:.1}ms",
            validate_start.elapsed().as_secs_f64() * 1000.0
        );
    }

    log::info!(
        "Parsed: ecu={}, variants={}, dtcs={}",
        db.ecu_name,
        db.variants.len(),
        db.dtcs.len()
    );

    if dry_run {
        let fbs_data = diag_ir::ir_to_flatbuffers(&db);
        println!(
            "dry run: would write {} bytes to {}",
            fbs_data.len(),
            output.display()
        );
        return Ok(());
    }

    let write_start = Instant::now();
    match out_fmt {
        Format::Yaml => {
            let yaml = diag_yaml::write_yaml(&db).context("writing YAML")?;
            std::fs::write(output, &yaml)
                .with_context(|| format!("writing {}", output.display()))?;
        }
        Format::Odx => {
            let xml = diag_odx::write_odx(&db).context("writing ODX")?;
            std::fs::write(output, &xml)
                .with_context(|| format!("writing {}", output.display()))?;
        }
        Format::Mdd => {
            let fbs_data = diag_ir::ir_to_flatbuffers(&db);
            let options = mdd_format::writer::WriteOptions {
                version: db.version.clone(),
                ecu_name: db.ecu_name.clone(),
                revision: db.revision.clone(),
                compression: parse_compression(compression)?,
                ..Default::default()
            };
            mdd_format::writer::write_mdd_file(&fbs_data, &options, output)
                .with_context(|| format!("writing MDD to {}", output.display()))?;
        }
        Format::Pdx => {
            bail!("PDX is an input-only format (ZIP archive). Use .odx for ODX output.");
        }
    }

    if verbose {
        eprintln!(
            "Write time: {:.1}ms",
            write_start.elapsed().as_secs_f64() * 1000.0
        );
    }

    log::info!("Written: {}", output.display());
    println!("Converted {} -> {}", input.display(), output.display());

    Ok(())
}

fn run_validate(input: &Path, quiet: bool, summary: bool) -> Result<()> {
    let mut all_errors: Vec<String> = Vec::new();

    // Schema + semantic validation for YAML files
    let in_fmt = detect_format(input).context("input file")?;
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

fn run_info(input: &Path) -> Result<()> {
    let in_fmt = detect_format(input).context("input file")?;
    let db = parse_input(input, false)?;

    let format_str = match in_fmt {
        Format::Odx => "ODX",
        Format::Pdx => "PDX",
        Format::Yaml => "YAML",
        Format::Mdd => "MDD",
    };

    println!("File:        {}", input.display());
    println!("Format:      {}", format_str);
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
            println!("ComParams:   {}", com_params);
        }
    }

    println!("DTCs:        {}", db.dtcs.len());

    let state_charts: usize = db
        .variants
        .iter()
        .map(|v| v.diag_layer.state_charts.len())
        .sum();
    if state_charts > 0 {
        println!("StateCharts: {}", state_charts);
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Convert {
            input,
            output,
            compression,
            verbose,
            dry_run,
            audience,
        }) => run_convert(&input, &output, &compression, verbose, dry_run, audience.as_deref()),

        Some(Command::Validate {
            input,
            quiet,
            summary,
        }) => run_validate(&input, quiet, summary),

        Some(Command::Info { input }) => run_info(&input),

        None => {
            // Backwards compat: bare positional arg treated as convert
            // but we need --output too, so just show help
            if let Some(bare) = cli.bare_input {
                bail!(
                    "Missing --output. Usage: diag-converter convert {} -o <output>",
                    bare.display()
                );
            }
            bail!("No command specified. Use: diag-converter convert|validate|info. Run with --help for details.");
        }
    }
}
