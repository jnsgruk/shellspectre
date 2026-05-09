#![allow(clippy::expect_used, clippy::print_stderr)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Tailwind CSS standalone CLI version.
const TAILWIND_VERSION: &str = "v4.1.8";

fn main() {
    println!("cargo:rerun-if-changed=static/css/input.css");
    println!("cargo:rerun-if-changed=templates/");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let binary_name = tailwind_binary_name();
    let binary_path = out_dir.join(&binary_name);

    // Download if not cached.
    if !binary_path.exists() {
        download_tailwind(&binary_path, &binary_name);
    }

    // Run Tailwind compilation.
    let input = Path::new("static/css/input.css");
    let output = out_dir.join("styles.css");

    let status = Command::new(&binary_path)
        .args([
            "-i",
            &input.display().to_string(),
            "-o",
            &output.display().to_string(),
            "--minify",
        ])
        .status()
        .expect("failed to run tailwindcss");

    assert!(status.success(), "tailwindcss exited with error");

    // Make the output path available to the crate.
    println!("cargo:rustc-env=TAILWIND_CSS_PATH={}", output.display());
}

fn tailwind_binary_name() -> String {
    let (os, ext) = if cfg!(target_os = "linux") {
        ("linux", "")
    } else if cfg!(target_os = "macos") {
        ("macos", "")
    } else {
        panic!("unsupported OS for Tailwind standalone CLI");
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        panic!("unsupported architecture for Tailwind standalone CLI");
    };

    format!("tailwindcss-{os}-{arch}{ext}")
}

fn download_tailwind(dest: &Path, binary_name: &str) {
    let url = format!(
        "https://github.com/tailwindlabs/tailwindcss/releases/download/{TAILWIND_VERSION}/{binary_name}"
    );

    eprintln!("Downloading Tailwind CSS from {url}");

    let status = Command::new("curl")
        .args(["-sSL", "-o", &dest.display().to_string(), &url])
        .status()
        .expect("failed to run curl");

    assert!(status.success(), "failed to download tailwindcss");

    // Make executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dest, fs::Permissions::from_mode(0o755));
    }
}
