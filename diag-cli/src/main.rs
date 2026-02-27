mod convert;
mod info;
mod validate;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "diag-converter",
    about = "Convert between ODX, YAML, and MDD diagnostic formats"
)]
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
pub(crate) enum Format {
    Odx,
    Pdx,
    Yaml,
    Mdd,
}

pub(crate) fn detect_format(path: &Path) -> Result<Format> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("odx") => Ok(Format::Odx),
        Some("pdx") => Ok(Format::Pdx),
        Some("yml" | "yaml") => Ok(Format::Yaml),
        Some("mdd") => Ok(Format::Mdd),
        Some(ext) => bail!("Unknown file extension: .{ext}"),
        None => bail!("Cannot detect format: file has no extension"),
    }
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
            dry_run,
            audience,
            include_job_files,
            lenient,
            log_level,
        }) => {
            let env_level = match log_level.as_str() {
                "debug" => "debug",
                "info" => "info",
                _ => "warn",
            };
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(env_level))
                .init();

            if let (1, Some(out)) = (input.len(), &output) {
                convert::run_convert(
                    &input[0],
                    out,
                    &compression,
                    dry_run,
                    audience.as_deref(),
                    include_job_files.as_deref(),
                    lenient,
                    &log_level,
                )
            } else if let Some(dir) = &output_dir {
                let ext = convert::format_extension(&format)?;
                convert::run_batch_convert(
                    &input,
                    dir,
                    ext,
                    &compression,
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
        }) => validate::run_validate(&input, quiet, summary),

        Some(Command::Info { input }) => info::run_info(&input),

        None => {
            if let Some(bare) = cli.bare_input {
                bail!(
                    "Missing --output. Usage: diag-converter convert {} -o <output>",
                    bare.display()
                );
            }
            bail!(
                "No command specified. Use: diag-converter convert|validate|info. Run with --help for details."
            );
        }
    }
}
