// Forked from classic-diagnostic-adapter/cda-database/build.rs
// Generates Rust code from Protobuf and FlatBuffers schemas.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    generate_protos()?;
    generate_flatbuffers()?;
    Ok(())
}

fn generate_protos() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["proto/file_format.proto"], &["proto/"])?;
    Ok(())
}

/// Get FlatBuffers git repo and revision from workspace Cargo.toml [patch.crates-io]
fn get_flatbuffers_info() -> Result<(String, String), Box<dyn std::error::Error>> {
    let workspace_manifest = {
        let mut path = PathBuf::from(
            std::env::var("CARGO_MANIFEST_DIR")
                .map_err(|e| format!("CARGO_MANIFEST_DIR not set: {e}"))?,
        );
        path.pop(); // up to workspace root
        path.push("Cargo.toml");
        path
    };

    let manifest = cargo_toml::Manifest::from_path(&workspace_manifest)?;
    let flatbuffers = manifest
        .patch
        .get("crates-io")
        .and_then(|patches| patches.get("flatbuffers"))
        .ok_or("flatbuffers patch not found in [patch.crates-io]")?;

    match flatbuffers.detail() {
        Some(detail) if detail.git.is_some() && detail.rev.is_some() => Ok((
            detail.git.clone().unwrap(),
            detail.rev.clone().unwrap(),
        )),
        _ => Err("flatbuffers git/rev not found in patch".into()),
    }
}

fn generate_flatbuffers() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR")?;

    // If FLATC is set, use the pre-built binary instead of building from source.
    // This is required for Bazel builds where network and cmake are unavailable in sandbox.
    let flatc_binary = if let Ok(flatc) = std::env::var("FLATC") {
        PathBuf::from(flatc)
    } else {
        // Cargo path: clone flatbuffers repo and build flatc via cmake
        let (flatc_repo, flatc_rev) = get_flatbuffers_info()?;
        let flatc_dir = PathBuf::from(&out_dir).join("flatc");

        if !flatc_dir.exists() {
            let status = std::process::Command::new("git")
                .args(["clone", &flatc_repo, flatc_dir.to_str().unwrap()])
                .status()?;
            if !status.success() {
                return Err("git clone flatbuffers failed".into());
            }

            let status = std::process::Command::new("git")
                .args(["checkout", &flatc_rev])
                .current_dir(&flatc_dir)
                .status()?;
            if !status.success() {
                return Err("git checkout flatc rev failed".into());
            }
        }

        let flatc_built = flatc_dir.join("build").join("flatc");
        if !flatc_built.exists() {
            let status = std::process::Command::new("cmake")
                .args(["-B", "build", "-S", "."])
                .current_dir(&flatc_dir)
                .status()?;
            if !status.success() {
                return Err("cmake configure flatc failed".into());
            }

            let status = std::process::Command::new("cmake")
                .args(["--build", "build", "--target", "flatc", "-j"])
                .current_dir(&flatc_dir)
                .status()?;
            if !status.success() {
                return Err("cmake build flatc failed".into());
            }
        }
        flatc_built
    };

    // Generate Rust code from FBS schema
    let fbs_output_dir = PathBuf::from(&out_dir).join("fbs_generated");
    std::fs::create_dir_all(&fbs_output_dir)?;

    let status = std::process::Command::new(&flatc_binary)
        .args([
            "--rust",
            "-o",
            fbs_output_dir.to_str().unwrap(),
            "schemas/diagnostic_description.fbs",
        ])
        .status()?;
    if !status.success() {
        return Err("flatc --rust failed".into());
    }

    // flatc generates diagnostic_description_generated.rs
    let generated = fbs_output_dir.join("diagnostic_description_generated.rs");
    let target = fbs_output_dir.join("diagnostic_description.rs");
    if generated.exists() && generated != target {
        std::fs::rename(&generated, &target)?;
    }

    Ok(())
}
