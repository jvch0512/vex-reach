//! Human-readable output.

use crate::vex::{Statement, Status};

pub fn counts(s: &[Statement]) -> (usize, usize, usize) {
    let c = |st| s.iter().filter(|x| x.status == st).count();
    (
        c(Status::Affected),
        c(Status::NotAffected),
        c(Status::UnderInvestigation),
    )
}

pub fn markdown(s: &[Statement], product: &str) -> String {
    let (a, n, u) = counts(s);
    let mut out = format!("# VEX report for {product}\n\n**{a} affected**, {n} not affected, {u} under investigation.\n\n");
    out.push_str("| Vulnerability | Severity | Package | Status | Why |\n|---|---|---|---|---|\n");
    let order = |x: &Statement| match x.status {
        Status::Affected => 0,
        Status::UnderInvestigation => 1,
        Status::NotAffected => 2,
    };
    let mut sorted: Vec<&Statement> = s.iter().collect();
    sorted.sort_by_key(|x| order(x));
    for x in sorted {
        let status = match x.justification {
            Some(j) => format!("{} ({j})", x.status.as_str()),
            None => x.status.as_str().to_string(),
        };
        out.push_str(&format!(
            "| {} | {} | {}@{} | {} | {} |\n",
            x.vuln,
            x.severity,
            x.package,
            x.version,
            status,
            x.note.replace('|', "\\|")
        ));
    }
    out.push_str("\nThis is a textual reachability analysis: a reference in non-test code means the symbol is used, not proven to run. \"Not affected\" means no reference was found.\n");
    out
}

pub fn terminal(s: &[Statement]) -> String {
    let mut out = String::new();
    for x in s {
        let tag = match x.status {
            Status::Affected => "AFFECTED           ",
            Status::NotAffected => "not affected       ",
            Status::UnderInvestigation => "under investigation",
        };
        out.push_str(&format!(
            "{tag}  {:<16} {}@{}\n    {}\n",
            x.vuln, x.package, x.version, x.note
        ));
    }
    let (a, n, u) = counts(s);
    out.push_str(&format!(
        "\n{a} affected, {n} not affected, {u} under investigation\n"
    ));
    out
}
