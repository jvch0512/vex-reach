use std::path::PathBuf;
use std::process::ExitCode;
use vex_reach::{advisory, json, report, scan_project, vex};

const USAGE: &str = "vex-reach 1.0.0

USAGE:
  vex-reach scan <project-dir> --advisories <file.json> [options]
  vex-reach check <vex.json>          validate an OpenVEX document

OPTIONS (scan):
  --out <file>          write the OpenVEX document (default: print the summary only)
  --md <file>           write a Markdown report
  --author <text>       VEX author (default: vex-reach)
  --timestamp <rfc3339> fixed timestamp, for reproducible output
  --include-absent      also emit not_affected/component_not_present for advisories with no matching package
  --fail-on <level>     exit 1 if any statement is 'affected' or 'under_investigation'
";

fn fail(m: &str) -> ExitCode {
    eprintln!("error: {m}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scan") => scan(&args[1..]),
        Some("check") => check(&args[1..]),
        _ => {
            print!("{USAGE}");
            ExitCode::from(if args.is_empty() { 0 } else { 2 })
        }
    }
}

fn check(a: &[String]) -> ExitCode {
    let Some(p) = a.first() else {
        return fail("check needs a file");
    };
    let text = match std::fs::read_to_string(p) {
        Ok(t) => t,
        Err(e) => return fail(&format!("{p}: {e}")),
    };
    match json::parse(&text) {
        Err(e) => fail(&e),
        Ok(doc) => {
            let probs = vex::check_document(&doc);
            if probs.is_empty() {
                println!("valid OpenVEX document");
                ExitCode::SUCCESS
            } else {
                for x in probs {
                    eprintln!("{x}");
                }
                ExitCode::from(1)
            }
        }
    }
}

fn scan(a: &[String]) -> ExitCode {
    let mut dir: Option<PathBuf> = None;
    let (mut advs, mut out, mut md, mut ts, mut fail_on) = (None, None, None, None, None);
    let mut author = "vex-reach".to_string();
    let mut absent = false;
    let mut i = 0;
    while i < a.len() {
        let flag = a[i].clone();
        let flag_ref = flag.clone();
        let mut val = || -> Result<String, String> {
            i += 1;
            a.get(i)
                .cloned()
                .ok_or_else(|| format!("{} needs a value", flag_ref))
        };
        let r = match flag.as_str() {
            "--advisories" => val().map(|v| advs = Some(v)),
            "--out" => val().map(|v| out = Some(v)),
            "--md" => val().map(|v| md = Some(v)),
            "--author" => val().map(|v| author = v),
            "--timestamp" => val().map(|v| ts = Some(v)),
            "--fail-on" => val().map(|v| fail_on = Some(v)),
            "--include-absent" => {
                absent = true;
                Ok(())
            }
            x if x.starts_with("--") => Err(format!("unknown option {x}")),
            x => {
                dir = Some(PathBuf::from(x));
                Ok(())
            }
        };
        if let Err(e) = r {
            return fail(&e);
        }
        i += 1;
    }
    let (Some(dir), Some(advs)) = (dir, advs) else {
        return fail("scan needs a project directory and --advisories");
    };
    if let Some(l) = &fail_on {
        if l != "affected" && l != "under_investigation" {
            return fail("--fail-on must be 'affected' or 'under_investigation'");
        }
    }
    let advisories = match std::fs::read_to_string(&advs)
        .map_err(|e| format!("{advs}: {e}"))
        .and_then(|t| advisory::load(&t))
    {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let scan = match scan_project(&dir, &advisories, absent) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    for w in &scan.warnings {
        eprintln!("warning: {w}");
    }
    print!("{}", report::terminal(&scan.statements));
    let write =
        |path: &str, body: String| std::fs::write(path, body).map_err(|e| format!("{path}: {e}"));
    if let Some(p) = out {
        let doc = vex::document(
            &scan.statements,
            &scan.product,
            &author,
            &ts.clone().unwrap_or_else(vex::now_rfc3339),
        );
        if let Err(e) = write(&p, json::pretty(&doc)) {
            return fail(&e);
        }
        println!("OpenVEX written to {p}");
    }
    if let Some(p) = md {
        if let Err(e) = write(&p, report::markdown(&scan.statements, &scan.product)) {
            return fail(&e);
        }
    }
    let (aff, _, ui) = report::counts(&scan.statements);
    let tripped = match fail_on.as_deref() {
        Some("affected") => aff > 0,
        Some(_) => aff + ui > 0,
        None => false,
    };
    ExitCode::from(u8::from(tripped))
}
