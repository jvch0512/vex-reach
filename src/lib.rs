//! vex-reach: decide which known vulnerabilities actually reach your code, and say so in OpenVEX.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)] // newer clippy suggests as_chunks, which older toolchains lack

pub mod advisory;
pub mod json;
pub mod manifest;
pub mod report;
pub mod scan;
pub mod version;
pub mod vex;

use std::path::Path;

pub struct Scan {
    pub statements: Vec<vex::Statement>,
    pub warnings: Vec<String>,
    pub product: String,
}

pub fn scan_project(
    root: &Path,
    advisories: &[advisory::Advisory],
    include_absent: bool,
) -> Result<Scan, String> {
    if !root.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }
    let (deps, mut warnings) = manifest::discover(root);
    if deps.is_empty() {
        warnings.push("no lockfile found (requirements.txt, package-lock.json, Cargo.lock, go.mod): nothing to match against".into());
    }
    let (files, w2) = scan::load_project(root);
    warnings.extend(w2);
    let product = root
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "project".into());
    Ok(Scan {
        statements: vex::evaluate(advisories, &deps, &files, include_absent),
        warnings,
        product,
    })
}
