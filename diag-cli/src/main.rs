use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "diag-converter", about = "Convert between ODX, YAML, and MDD diagnostic formats")]
struct Cli {
    /// Input file (.odx, .yml/.yaml, .mdd)
    input: PathBuf,

    /// Output file (.odx, .yml/.yaml, .mdd)
    #[arg(short, long)]
    output: PathBuf,

    /// Compression for MDD output (lzma, gzip, zstd, none)
    #[arg(long, default_value = "lzma")]
    compression: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Format {
    Odx,
    Yaml,
    Mdd,
}

fn detect_format(path: &Path) -> Result<Format> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("odx" | "pdx") => Ok(Format::Odx),
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }

    let in_fmt = detect_format(&cli.input).context("input file")?;
    let out_fmt = detect_format(&cli.output).context("output file")?;

    if in_fmt == out_fmt {
        bail!("Input and output formats are the same ({in_fmt:?}). Nothing to convert.");
    }

    log::info!("Converting {:?} -> {:?}", in_fmt, out_fmt);

    // Phase 1: Parse input -> IR
    let db = match in_fmt {
        Format::Yaml => {
            let text = std::fs::read_to_string(&cli.input)
                .with_context(|| format!("reading {}", cli.input.display()))?;
            diag_yaml::parse_yaml(&text)
                .with_context(|| format!("parsing YAML from {}", cli.input.display()))?
        }
        Format::Odx => {
            let text = std::fs::read_to_string(&cli.input)
                .with_context(|| format!("reading {}", cli.input.display()))?;
            diag_odx::parse_odx(&text)
                .with_context(|| format!("parsing ODX from {}", cli.input.display()))?
        }
        Format::Mdd => {
            let (_meta, fbs_data) = mdd_format::reader::read_mdd_file(&cli.input)
                .with_context(|| format!("reading MDD from {}", cli.input.display()))?;
            diag_ir::flatbuffers_to_ir(&fbs_data)
                .with_context(|| "converting FlatBuffers to IR")?
        }
    };

    // Phase 2: Validate IR
    if let Err(errors) = diag_ir::validate_database(&db) {
        for e in &errors {
            log::warn!("Validation: {e}");
        }
    }

    log::info!(
        "Parsed: ecu={}, variants={}, dtcs={}",
        db.ecu_name,
        db.variants.len(),
        db.dtcs.len()
    );

    // Phase 3: Write output
    match out_fmt {
        Format::Yaml => {
            let yaml = diag_yaml::write_yaml(&db).context("writing YAML")?;
            std::fs::write(&cli.output, &yaml)
                .with_context(|| format!("writing {}", cli.output.display()))?;
        }
        Format::Odx => {
            let xml = diag_odx::write_odx(&db).context("writing ODX")?;
            std::fs::write(&cli.output, &xml)
                .with_context(|| format!("writing {}", cli.output.display()))?;
        }
        Format::Mdd => {
            let fbs_data = diag_ir::ir_to_flatbuffers(&db);
            let options = mdd_format::writer::WriteOptions {
                version: db.version.clone(),
                ecu_name: db.ecu_name.clone(),
                revision: db.revision.clone(),
                compression: parse_compression(&cli.compression)?,
                ..Default::default()
            };
            mdd_format::writer::write_mdd_file(&fbs_data, &options, &cli.output)
                .with_context(|| format!("writing MDD to {}", cli.output.display()))?;
        }
    }

    log::info!("Written: {}", cli.output.display());
    println!(
        "Converted {} -> {}",
        cli.input.display(),
        cli.output.display()
    );

    Ok(())
}
