//! Finds lockfiles and reads the packages they pin.

use crate::advisory::{normalise, Eco};
use crate::json::{self, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub eco: Eco,
    pub name: String,
    pub version: String,
    pub file: String,
}

pub const IGNORED_DIRS: [&str; 9] = [
    "node_modules",
    "target",
    ".git",
    "vendor",
    "__pycache__",
    "venv",
    ".venv",
    "dist",
    "build",
];
const MAX_FILES: usize = 50_000;
const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Every regular file under `root`, skipping symlinks and dependency or build directories.
pub fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().to_string();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if !IGNORED_DIRS.contains(&name.as_str()) {
                    stack.push(e.path());
                }
            } else if ft.is_file() && out.len() < MAX_FILES {
                out.push(e.path());
            }
        }
    }
    out.sort();
    out
}

pub fn read_small(p: &Path) -> Option<String> {
    if fs::metadata(p).ok()?.len() > MAX_BYTES {
        return None;
    }
    String::from_utf8(fs::read(p).ok()?).ok()
}

pub fn parse_requirements(text: &str, file: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        let line = line.split(';').next().unwrap_or("").trim();
        let Some((name, ver)) = line.split_once("==") else {
            continue;
        };
        let name = name.split('[').next().unwrap_or("");
        let ver = ver.trim_start_matches('=').trim();
        if !name.is_empty() && !ver.is_empty() && !ver.contains('*') {
            out.push(Dep {
                eco: Eco::Pypi,
                name: normalise(Eco::Pypi, name),
                version: ver.to_string(),
                file: file.to_string(),
            });
        }
    }
    out
}

pub fn parse_package_lock(text: &str, file: &str) -> Result<Vec<Dep>, String> {
    let v = json::parse(text)?;
    let mut out = Vec::new();
    if let Some(Value::Obj(pk)) = v.get("packages") {
        for (k, val) in pk {
            if let (Some(idx), Some(ver)) = (
                k.rfind("node_modules/"),
                val.get("version").and_then(Value::as_str),
            ) {
                let name = &k[idx + "node_modules/".len()..];
                out.push(Dep {
                    eco: Eco::Npm,
                    name: normalise(Eco::Npm, name),
                    version: ver.to_string(),
                    file: file.to_string(),
                });
            }
        }
    } else if let Some(Value::Obj(deps)) = v.get("dependencies") {
        fn rec(deps: &[(String, Value)], file: &str, out: &mut Vec<Dep>, depth: usize) {
            for (name, val) in deps {
                if let Some(ver) = val.get("version").and_then(Value::as_str) {
                    out.push(Dep {
                        eco: Eco::Npm,
                        name: normalise(Eco::Npm, name),
                        version: ver.to_string(),
                        file: file.to_string(),
                    });
                }
                if let (Some(Value::Obj(inner)), true) = (val.get("dependencies"), depth < 32) {
                    rec(inner, file, out, depth + 1);
                }
            }
        }
        rec(deps, file, &mut out, 0);
    }
    Ok(out)
}

pub fn parse_cargo_lock(text: &str, file: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    let (mut name, mut ver): (Option<String>, Option<String>) = (None, None);
    let mut flush = |name: &mut Option<String>, ver: &mut Option<String>| {
        if let (Some(n), Some(v)) = (name.take(), ver.take()) {
            out.push(Dep {
                eco: Eco::Cargo,
                name: normalise(Eco::Cargo, &n),
                version: v,
                file: file.to_string(),
            });
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            flush(&mut name, &mut ver);
        } else if let Some(v) = line.strip_prefix("name = ") {
            name = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("version = ") {
            ver = Some(v.trim_matches('"').to_string());
        }
    }
    flush(&mut name, &mut ver);
    out
}

pub fn parse_go_mod(text: &str, file: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        let spec = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if line == "require (" {
            in_block = true;
            continue;
        } else if let Some(r) = line.strip_prefix("require ") {
            r.trim()
        } else {
            continue;
        };
        let mut it = spec.split_whitespace();
        if let (Some(n), Some(v)) = (it.next(), it.next()) {
            out.push(Dep {
                eco: Eco::Go,
                name: n.to_ascii_lowercase(),
                version: v.to_string(),
                file: file.to_string(),
            });
        }
    }
    out
}

/// Reads every supported lockfile under `root`. Problems are returned as warnings, never silently dropped.
pub fn discover(root: &Path) -> (Vec<Dep>, Vec<String>) {
    let mut deps: Vec<Dep> = Vec::new();
    let mut warn = Vec::new();
    for p in walk(root) {
        let base = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .to_string();
        let is_req = base == "requirements.txt"
            || (base.starts_with("requirements") && base.ends_with(".txt"));
        if !(is_req || matches!(base, "package-lock.json" | "Cargo.lock" | "go.mod")) {
            continue;
        }
        let Some(text) = read_small(&p) else {
            warn.push(format!("{rel}: unreadable or too large, skipped"));
            continue;
        };
        let found = if is_req {
            parse_requirements(&text, &rel)
        } else if base == "package-lock.json" {
            match parse_package_lock(&text, &rel) {
                Ok(d) => d,
                Err(e) => {
                    warn.push(format!("{rel}: {e}"));
                    continue;
                }
            }
        } else if base == "Cargo.lock" {
            parse_cargo_lock(&text, &rel)
        } else {
            parse_go_mod(&text, &rel)
        };
        for d in found {
            if !deps
                .iter()
                .any(|x| x.eco == d.eco && x.name == d.name && x.version == d.version)
            {
                deps.push(d);
            }
        }
    }
    (deps, warn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements() {
        let d = parse_requirements("# c\nFast_YAML==1.2.0  # pin\nrequests[socks]==2.0.1 ; python_version>'3'\n-r other.txt\nflask>=2\nbad==1.*\n", "r.txt");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].name, "fast-yaml");
        assert_eq!(d[1].name, "requests");
    }

    #[test]
    fn package_lock_v3_and_nested() {
        let t = r#"{"packages":{"":{"name":"app"},"node_modules/minipack":{"version":"2.1.0"},"node_modules/a/node_modules/@s/pk":{"version":"1.0.0"}}}"#;
        let d = parse_package_lock(t, "p").unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[1].name, "@s/pk");
        let old = r#"{"dependencies":{"x":{"version":"1.0.0","dependencies":{"y":{"version":"2.0.0"}}}}}"#;
        assert_eq!(parse_package_lock(old, "p").unwrap().len(), 2);
        assert!(parse_package_lock("{", "p").is_err());
    }

    #[test]
    fn cargo_lock() {
        let t = "[[package]]\nname = \"byte_smith\"\nversion = \"0.3.1\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n";
        let d = parse_cargo_lock(t, "c");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].name, "byte-smith");
    }

    #[test]
    fn go_mod_block_and_single() {
        let t = "module x\n\nrequire example.com/gzipx v1.2.0\nrequire (\n\texample.com/b v0.1.0 // indirect\n)\n";
        let d = parse_go_mod(t, "g");
        assert_eq!(d.len(), 2);
        assert_eq!(d[1].version, "v0.1.0");
    }
}
