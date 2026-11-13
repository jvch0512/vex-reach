//! The advisory file: what is vulnerable, in which versions, and which symbols are the dangerous ones.

use crate::json::{self, Value};
use crate::version::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eco {
    Pypi,
    Npm,
    Cargo,
    Go,
}

impl Eco {
    pub fn parse(t: &str) -> Option<Eco> {
        match t {
            "pypi" => Some(Eco::Pypi),
            "npm" => Some(Eco::Npm),
            "cargo" => Some(Eco::Cargo),
            "go" | "golang" => Some(Eco::Go),
            _ => None,
        }
    }
    pub fn purl_type(self) -> &'static str {
        match self {
            Eco::Pypi => "pypi",
            Eco::Npm => "npm",
            Eco::Cargo => "cargo",
            Eco::Go => "golang",
        }
    }
}

pub fn normalise(eco: Eco, name: &str) -> String {
    let n = name.trim().to_ascii_lowercase();
    match eco {
        Eco::Pypi => n.replace(['_', '.'], "-"),
        Eco::Cargo => n.replace('_', "-"),
        _ => n,
    }
}

#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub eco: Eco,
    pub package: String,
    pub affected: Vec<Range>,
    pub affected_text: Vec<String>,
    pub fixed: Option<String>,
    pub symbols: Vec<Vec<String>>,
    pub symbol_text: Vec<String>,
    pub modules: Vec<Vec<String>>,
    pub severity: String,
    pub summary: String,
}

fn strings(v: Option<&Value>, what: &str) -> Result<Vec<String>, String> {
    match v {
        None => Ok(vec![]),
        Some(Value::Arr(a)) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{what} must contain only strings"))
            })
            .collect(),
        Some(_) => Err(format!("{what} must be an array")),
    }
}

fn split_symbol(t: &str) -> Vec<String> {
    t.replace("::", ".")
        .split('.')
        .map(str::to_string)
        .collect()
}

fn split_module(eco: Eco, t: &str) -> Vec<String> {
    match eco {
        Eco::Pypi => t.split('.').map(str::to_string).collect(),
        Eco::Cargo => vec![t.replace('-', "_")],
        Eco::Npm | Eco::Go => t.split('/').map(str::to_string).collect(),
    }
}

pub fn load(text: &str) -> Result<Vec<Advisory>, String> {
    let root = json::parse(text)?;
    let list = root
        .get("advisories")
        .and_then(Value::as_arr)
        .ok_or("advisory file needs an \"advisories\" array")?;
    let mut out = Vec::new();
    for (n, a) in list.iter().enumerate() {
        let at = |m: &str| format!("advisory #{}: {m}", n + 1);
        let id = a
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| at("missing id"))?
            .to_string();
        let eco = a
            .get("ecosystem")
            .and_then(Value::as_str)
            .and_then(Eco::parse)
            .ok_or_else(|| at("ecosystem must be pypi, npm, cargo or go"))?;
        let package = normalise(
            eco,
            a.get("package")
                .and_then(Value::as_str)
                .ok_or_else(|| at("missing package"))?,
        );
        let affected_text = strings(a.get("affected"), "affected").map_err(|e| at(&e))?;
        if affected_text.is_empty() {
            return Err(at("affected needs at least one range"));
        }
        let affected = affected_text
            .iter()
            .map(|r| Range::parse(r))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| at(&e))?;
        let symbol_text = strings(a.get("symbols"), "symbols").map_err(|e| at(&e))?;
        if symbol_text.iter().any(|s| s.trim().is_empty()) {
            return Err(at("empty symbol"));
        }
        let symbols = symbol_text.iter().map(|s| split_symbol(s)).collect();
        let module_text = strings(a.get("modules"), "modules").map_err(|e| at(&e))?;
        let modules = if module_text.is_empty() {
            vec![split_module(
                eco,
                &match eco {
                    Eco::Pypi => package.replace('-', "_"),
                    _ => package.clone(),
                },
            )]
        } else {
            module_text.iter().map(|m| split_module(eco, m)).collect()
        };
        out.push(Advisory {
            id,
            eco,
            package,
            affected,
            affected_text,
            fixed: a.get("fixed").and_then(Value::as_str).map(str::to_string),
            symbols,
            symbol_text,
            modules,
            severity: a
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            summary: a
                .get("summary")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"{"advisories":[{"id":"X-1","ecosystem":"pypi","package":"Fast_YAML","affected":["<1.4.0"],"symbols":["load_unsafe","Loader.load"],"fixed":"1.4.0"}]}"#;

    #[test]
    fn loads_and_normalises() {
        let a = load(OK).unwrap();
        assert_eq!(a[0].package, "fast-yaml");
        assert_eq!(a[0].modules, vec![vec!["fast_yaml".to_string()]]);
        assert_eq!(a[0].symbols[1], vec!["Loader", "load"]);
    }

    #[test]
    fn rejects_bad_files() {
        for bad in [
            r#"{}"#,
            r#"{"advisories":[{"ecosystem":"pypi","package":"a","affected":["<1"]}]}"#,
            r#"{"advisories":[{"id":"x","ecosystem":"ruby","package":"a","affected":["<1"]}]}"#,
            r#"{"advisories":[{"id":"x","ecosystem":"npm","package":"a","affected":[]}]}"#,
            r#"{"advisories":[{"id":"x","ecosystem":"npm","package":"a","affected":["<<1"]}]}"#,
            r#"{"advisories":[{"id":"x","ecosystem":"npm","package":"a","affected":["<1"],"symbols":[""]}]}"#,
        ] {
            assert!(load(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cargo_modules_use_underscores() {
        let a = load(r#"{"advisories":[{"id":"x","ecosystem":"cargo","package":"byte-smith","affected":["<1"],"symbols":["codec::decode"]}]}"#).unwrap();
        assert_eq!(a[0].modules[0], vec!["byte_smith"]);
        assert_eq!(a[0].symbols[0], vec!["codec", "decode"]);
    }
}
