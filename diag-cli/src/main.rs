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
        /// Input file(s) (.odx, .pdx, .yml/.yaml, .mdd)
        #[arg(required = true)]
        input: Vec<PathBuf>,

        /// Output file (single input mode)
        #[arg(short, long, conflicts_with = "output_dir")]
        output: Option<PathBuf>,

        /// Output directory (multi-file mode, output extension inferred from -f/--format)
        #[arg(short = 'O', long, conflicts_with = "output")]
        output_dir: Option<PathBuf>,

        /// Output format when using -O (odx, yaml, mdd)
        #[arg(short, long, default_value = "mdd")]
        format: String,

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

        /// Directory containing job files (JARs) referenced by SingleEcuJob ProgCode entries
        #[arg(long)]
        include_job_files: Option<PathBuf>,

        /// Lenient parsing: log warnings instead of failing on malformed ODX references
        #[arg(short = 'L', long)]
        lenient: bool,

        /// Write .log file alongside output (off, info, debug)
        #[arg(long, default_value = "off")]
        log_level: String,
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

fn parse_input(input: &Path, verbose: bool, lenient: bool) -> Result<diag_ir::types::DiagDatabase> {
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
            if lenient {
                diag_odx::parse_odx_lenient(&text)
            } else {
                diag_odx::parse_odx(&text)
            }
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

/// Collect unique code_file names from all SingleEcuJob ProgCode entries.
fn collect_code_file_refs(db: &diag_ir::types::DiagDatabase) -> Vec<String> {
    let mut refs = std::collections::BTreeSet::new();
    for variant in &db.variants {
        for job in &variant.diag_layer.single_ecu_jobs {
            for pc in &job.prog_codes {
                if !pc.code_file.is_empty() {
                    refs.insert(pc.code_file.clone());
                }
                for lib in &pc.libraries {
                    if !lib.code_file.is_empty() {
                        refs.insert(lib.code_file.clone());
                    }
                }
            }
        }
    }
    refs.into_iter().collect()
}

/// Build ExtraChunk entries by reading referenced job files from a directory.
fn build_job_file_chunks(
    db: &diag_ir::types::DiagDatabase,
    job_files_dir: &Path,
) -> Result<Vec<mdd_format::writer::ExtraChunk>> {
    let refs = collect_code_file_refs(db);
    let mut chunks = Vec::new();
    for name in &refs {
        let file_path = job_files_dir.join(name);
        if !file_path.exists() {
            log::warn!("Job file not found: {}", file_path.display());
            continue;
        }
        let data = std::fs::read(&file_path)
            .with_context(|| format!("reading job file {}", file_path.display()))?;
        log::info!("Including job file: {} ({} bytes)", name, data.len());
        chunks.push(mdd_format::writer::ExtraChunk {
            chunk_type: mdd_format::writer::ExtraChunkType::JarFile,
            name: name.clone(),
            data,
        });
    }
    Ok(chunks)
}

fn run_convert(
    input: &Path,
    output: &Path,
    compression: &str,
    verbose: bool,
    dry_run: bool,
    audience: Option<&str>,
    include_job_files: Option<&Path>,
    lenient: bool,
    log_level: &str,
) -> Result<()> {
    let total_start = Instant::now();
    let out_fmt = detect_format(output).context("output file")?;
    let in_fmt = detect_format(input).context("input file")?;

    if in_fmt == out_fmt {
        bail!("Input and output formats are the same ({in_fmt:?}). Nothing to convert.");
    }

    log::info!("Converting {:?} -> {:?}", in_fmt, out_fmt);

    let input_size = std::fs::metadata(input)
        .map(|m| m.len())
        .unwrap_or(0);

    let parse_start = Instant::now();
    let mut db = parse_input(input, verbose, lenient)?;
    let parse_ms = parse_start.elapsed().as_secs_f64() * 1000.0;

    if let Some(aud) = audience {
        let before = db.variants.iter().map(|v| v.diag_layer.diag_services.len()).sum::<usize>();
        diag_ir::filter_by_audience(&mut db, aud);
        let after = db.variants.iter().map(|v| v.diag_layer.diag_services.len()).sum::<usize>();
        if before != after {
            log::info!("Audience filter '{aud}': {before} -> {after} services");
        }
    }

    let validate_start = Instant::now();
    let validation_warnings: Vec<String> =
        if let Err(errors) = diag_ir::validate_database(&db) {
            for e in &errors {
                log::warn!("Validation: {e}");
            }
            errors.into_iter().map(|e| e.to_string()).collect()
        } else {
            Vec::new()
        };
    let validate_ms = validate_start.elapsed().as_secs_f64() * 1000.0;

    if verbose {
        eprintln!("Parse time: {parse_ms:.1}ms");
        eprintln!("Validate time: {validate_ms:.1}ms");
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
    let mut fbs_size: Option<usize> = None;

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
            fbs_size = Some(fbs_data.len());
            let extra_chunks = if let Some(dir) = include_job_files {
                build_job_file_chunks(&db, dir)?
            } else {
                vec![]
            };
            let options = mdd_format::writer::WriteOptions {
                version: db.version.clone(),
                ecu_name: db.ecu_name.clone(),
                revision: db.revision.clone(),
                compression: parse_compression(compression)?,
                extra_chunks,
                ..Default::default()
            };
            mdd_format::writer::write_mdd_file(&fbs_data, &options, output)
                .with_context(|| format!("writing MDD to {}", output.display()))?;
        }
        Format::Pdx => {
            bail!("PDX is an input-only format (ZIP archive). Use .odx for ODX output.");
        }
    }

    let write_ms = write_start.elapsed().as_secs_f64() * 1000.0;
    let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    if verbose {
        eprintln!("Write time: {write_ms:.1}ms");
    }

    log::info!("Written: {}", output.display());
    println!("Converted {} -> {}", input.display(), output.display());

    // Write .log file if requested
    if log_level != "off" {
        let log_path = output.with_extension(
            format!("{}.log", output.extension().and_then(|e| e.to_str()).unwrap_or("out"))
        );
        let output_size = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);
        let mut log_lines = Vec::new();
        log_lines.push(format!("input: {}", input.display()));
        log_lines.push(format!("input_size: {} bytes", input_size));
        log_lines.push(format!("output: {}", output.display()));
        log_lines.push(format!("output_size: {} bytes", output_size));
        log_lines.push(format!("input_format: {:?}", in_fmt));
        log_lines.push(format!("output_format: {:?}", out_fmt));
        log_lines.push(format!("parse_time: {parse_ms:.1}ms"));
        log_lines.push(format!("validate_time: {validate_ms:.1}ms"));
        log_lines.push(format!("write_time: {write_ms:.1}ms"));
        log_lines.push(format!("total_time: {total_ms:.1}ms"));
        log_lines.push(format!("ecu: {}", db.ecu_name));
        log_lines.push(format!("variants: {}", db.variants.len()));
        log_lines.push(format!("dtcs: {}", db.dtcs.len()));

        if let Some(fbs) = fbs_size {
            log_lines.push(format!("fbs_size: {} bytes", fbs));
            if output_size > 0 {
                let ratio = fbs as f64 / output_size as f64;
                log_lines.push(format!("compression_ratio: {ratio:.2}x"));
            }
        }

        if !validation_warnings.is_empty() {
            log_lines.push(format!("validation_warnings: {}", validation_warnings.len()));
            if log_level == "debug" {
                for w in &validation_warnings {
                    log_lines.push(format!("  - {w}"));
                }
            }
        }

        if log_level == "debug" {
            let services: usize = db.variants.iter()
                .map(|v| v.diag_layer.diag_services.len())
                .sum();
            let jobs: usize = db.variants.iter()
                .map(|v| v.diag_layer.single_ecu_jobs.len())
                .sum();
            log_lines.push(format!("total_services: {services}"));
            log_lines.push(format!("total_single_ecu_jobs: {jobs}"));
            for v in &db.variants {
                log_lines.push(format!(
                    "  variant '{}': {} services, {} jobs",
                    v.diag_layer.short_name,
                    v.diag_layer.diag_services.len(),
                    v.diag_layer.single_ecu_jobs.len(),
                ));
            }
        }

        let log_content = log_lines.join("\n") + "\n";
        std::fs::write(&log_path, &log_content)
            .with_context(|| format!("writing log to {}", log_path.display()))?;
    }

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
    let db = parse_input(input, false, false)?;
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
    let db = parse_input(input, false, false)?;

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

fn format_extension(fmt: &str) -> Result<&str> {
    match fmt {
        "odx" => Ok("odx"),
        "yaml" | "yml" => Ok("yml"),
        "mdd" => Ok("mdd"),
        other => bail!("Unknown output format: {other}. Use odx, yaml, or mdd"),
    }
}

fn run_batch_convert(
    inputs: &[PathBuf],
    output_dir: &Path,
    out_ext: &str,
    compression: &str,
    verbose: bool,
    dry_run: bool,
    audience: Option<&str>,
    include_job_files: Option<&Path>,
    lenient: bool,
    log_level: &str,
) -> Result<()> {
    use rayon::prelude::*;

    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("creating output directory {}", output_dir.display()))?;
    }

    let results: Vec<(PathBuf, Result<()>)> = inputs
        .par_iter()
        .map(|input| {
            let stem = input.file_stem().unwrap_or_default();
            let out_path = output_dir.join(format!("{}.{}", stem.to_string_lossy(), out_ext));
            let result = run_convert(
                input,
                &out_path,
                compression,
                verbose,
                dry_run,
                audience,
                include_job_files,
                lenient,
                log_level,
            );
            (input.clone(), result)
        })
        .collect();

    let mut failed = 0;
    for (input, result) in &results {
        if let Err(e) = result {
            eprintln!("FAILED {}: {e:#}", input.display());
            failed += 1;
        }
    }

    if failed > 0 {
        bail!("{failed} of {} files failed to convert", inputs.len());
    }

    println!(
        "Batch complete: {} files converted to {}",
        inputs.len(),
        output_dir.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Convert {
            input,
            output,
            output_dir,
            format,
            compression,
            verbose,
            dry_run,
            audience,
            include_job_files,
            lenient,
            log_level,
        }) => {
            if verbose {
                env_logger::Builder::from_env(
                    env_logger::Env::default().default_filter_or("debug"),
                )
                .init();
            } else {
                env_logger::Builder::from_env(
                    env_logger::Env::default().default_filter_or("warn"),
                )
                .init();
            }

            if input.len() == 1 && output.is_some() {
                run_convert(
                    &input[0],
                    output.as_ref().unwrap(),
                    &compression,
                    verbose,
                    dry_run,
                    audience.as_deref(),
                    include_job_files.as_deref(),
                    lenient,
                    &log_level,
                )
            } else if let Some(dir) = &output_dir {
                let ext = format_extension(&format)?;
                run_batch_convert(
                    &input,
                    dir,
                    ext,
                    &compression,
                    verbose,
                    dry_run,
                    audience.as_deref(),
                    include_job_files.as_deref(),
                    lenient,
                    &log_level,
                )
            } else if input.len() > 1 {
                bail!("Multiple input files require -O/--output-dir instead of -o/--output")
            } else {
                bail!("Specify -o/--output (single file) or -O/--output-dir (batch)")
            }
        }

        Some(Command::Validate {
            input,
            quiet,
            summary,
        }) => run_validate(&input, quiet, summary),

        Some(Command::Info { input }) => run_info(&input),

        None => {
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
