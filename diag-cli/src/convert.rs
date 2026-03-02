use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::Format;

pub fn parse_compression(s: &str) -> Result<mdd_format::compression::Compression> {
    match s {
        "lzma" => Ok(mdd_format::compression::Compression::Lzma),
        "gzip" => Ok(mdd_format::compression::Compression::Gzip),
        "zstd" => Ok(mdd_format::compression::Compression::Zstd),
        "none" => Ok(mdd_format::compression::Compression::None),
        other => bail!("Unknown compression: {other}. Use lzma, gzip, zstd, or none"),
    }
}

pub fn parse_input(input: &Path, lenient: bool) -> Result<diag_ir::types::DiagDatabase> {
    let in_fmt = crate::detect_format(input).context("input file")?;

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
        Format::Pdx => diag_odx::read_pdx_file(input)
            .with_context(|| format!("reading PDX from {}", input.display()))?,
        Format::Mdd => {
            let (_meta, fbs_data) = mdd_format::reader::read_mdd_file(input)
                .with_context(|| format!("reading MDD from {}", input.display()))?;
            diag_ir::flatbuffers_to_ir(&fbs_data).with_context(|| "converting FlatBuffers to IR")?
        }
    };

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

pub fn format_extension(fmt: &str) -> Result<&str> {
    match fmt {
        "odx" => Ok("odx"),
        "yaml" | "yml" => Ok("yml"),
        "mdd" => Ok("mdd"),
        other => bail!("Unknown output format: {other}. Use odx, yaml, or mdd"),
    }
}

pub fn run_convert(
    input: &Path,
    output: &Path,
    compression: &str,
    dry_run: bool,
    audience: Option<&str>,
    include_job_files: Option<&Path>,
    lenient: bool,
    log_level: &str,
) -> Result<()> {
    let total_start = Instant::now();
    let out_fmt = crate::detect_format(output).context("output file")?;
    let in_fmt = crate::detect_format(input).context("input file")?;

    if in_fmt == out_fmt {
        bail!("Input and output formats are the same ({in_fmt:?}). Nothing to convert.");
    }

    log::info!("Converting {:?} -> {:?}", in_fmt, out_fmt);

    let input_size = std::fs::metadata(input).map(|m| m.len()).unwrap_or(0);

    let parse_start = Instant::now();
    let mut db = parse_input(input, lenient)?;
    let parse_ms = parse_start.elapsed().as_secs_f64() * 1000.0;

    if let Some(aud) = audience {
        let before = db
            .variants
            .iter()
            .map(|v| v.diag_layer.diag_services.len())
            .sum::<usize>();
        diag_ir::filter_by_audience(&mut db, aud);
        let after = db
            .variants
            .iter()
            .map(|v| v.diag_layer.diag_services.len())
            .sum::<usize>();
        if before != after {
            log::info!("Audience filter '{aud}': {before} -> {after} services");
        }
    }

    let validate_start = Instant::now();
    let validation_warnings: Vec<String> = if let Err(errors) = diag_ir::validate_database(&db) {
        for e in &errors {
            log::warn!("Validation: {e}");
        }
        errors.into_iter().map(|e| e.to_string()).collect()
    } else {
        Vec::new()
    };
    let validate_ms = validate_start.elapsed().as_secs_f64() * 1000.0;

    log::debug!("Parse time: {parse_ms:.1}ms");
    log::debug!("Validate time: {validate_ms:.1}ms");

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

    log::debug!("Write time: {write_ms:.1}ms");
    log::info!("Written: {}", output.display());
    println!("Converted {} -> {}", input.display(), output.display());

    // Write .log file if requested
    if log_level != "off" {
        let log_path = output.with_extension(format!(
            "{}.log",
            output.extension().and_then(|e| e.to_str()).unwrap_or("out")
        ));
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
            log_lines.push(format!(
                "validation_warnings: {}",
                validation_warnings.len()
            ));
            if log_level == "debug" {
                for w in &validation_warnings {
                    log_lines.push(format!("  - {w}"));
                }
            }
        }

        if log_level == "debug" {
            let services: usize = db
                .variants
                .iter()
                .map(|v| v.diag_layer.diag_services.len())
                .sum();
            let jobs: usize = db
                .variants
                .iter()
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

pub fn run_batch_convert(
    inputs: &[PathBuf],
    output_dir: &Path,
    out_ext: &str,
    compression: &str,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_compression_lzma() {
        assert_eq!(
            parse_compression("lzma").unwrap(),
            mdd_format::compression::Compression::Lzma
        );
    }

    #[test]
    fn parse_compression_gzip() {
        assert_eq!(
            parse_compression("gzip").unwrap(),
            mdd_format::compression::Compression::Gzip
        );
    }

    #[test]
    fn parse_compression_zstd() {
        assert_eq!(
            parse_compression("zstd").unwrap(),
            mdd_format::compression::Compression::Zstd
        );
    }

    #[test]
    fn parse_compression_none() {
        assert_eq!(
            parse_compression("none").unwrap(),
            mdd_format::compression::Compression::None
        );
    }

    #[test]
    fn parse_compression_invalid() {
        let err = parse_compression("brotli").unwrap_err();
        assert!(err.to_string().contains("Unknown compression"));
    }

    #[test]
    fn format_extension_odx() {
        assert_eq!(format_extension("odx").unwrap(), "odx");
    }

    #[test]
    fn format_extension_yaml() {
        assert_eq!(format_extension("yaml").unwrap(), "yml");
    }

    #[test]
    fn format_extension_yml() {
        assert_eq!(format_extension("yml").unwrap(), "yml");
    }

    #[test]
    fn format_extension_mdd() {
        assert_eq!(format_extension("mdd").unwrap(), "mdd");
    }

    #[test]
    fn format_extension_invalid() {
        let err = format_extension("json").unwrap_err();
        assert!(err.to_string().contains("Unknown output format"));
    }
}
