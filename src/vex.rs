//! Decisions and the OpenVEX document.

use crate::advisory::{normalise, Advisory};
use crate::json::{self, Value};
use crate::manifest::Dep;
use crate::scan::{self, Evidence, FileInfo};
use crate::version::Version;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Affected,
    NotAffected,
    UnderInvestigation,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Affected => "affected",
            Status::NotAffected => "not_affected",
            Status::UnderInvestigation => "under_investigation",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Statement {
    pub vuln: String,
    pub severity: String,
    pub package: String,
    pub version: String,
    pub purl: String,
    pub status: Status,
    pub justification: Option<&'static str>,
    pub note: String,
    pub action: Option<String>,
    pub evidence: Vec<Evidence>,
}

pub fn purl(adv: &Advisory, name: &str, version: &str) -> String {
    let v = version.trim_start_matches('v');
    let enc = name.replace('@', "%40");
    format!("pkg:{}/{}@{}", adv.eco.purl_type(), enc, v)
}

fn site(e: &Evidence) -> String {
    format!("{}:{}", e.file, e.line)
}

fn list(ev: &[&Evidence]) -> String {
    let mut sites: Vec<String> = Vec::new();
    for e in ev {
        let s = site(e);
        if !sites.contains(&s) {
            sites.push(s);
        }
    }
    let more = sites.len().saturating_sub(3);
    sites.truncate(3);
    if more > 0 {
        sites.push(format!("and {more} more"));
    }
    sites.join(", ")
}

pub fn decide(adv: &Advisory, dep: &Dep, files: &[FileInfo]) -> Statement {
    let mut st = Statement {
        vuln: adv.id.clone(),
        severity: adv.severity.clone(),
        package: dep.name.clone(),
        version: dep.version.clone(),
        purl: purl(adv, &dep.name, &dep.version),
        status: Status::UnderInvestigation,
        justification: None,
        note: String::new(),
        action: None,
        evidence: vec![],
    };
    let fix = match &adv.fixed {
        Some(f) => format!("Upgrade {} to {} or later.", adv.package, f),
        None => format!(
            "No fixed version is listed for {}; apply the advisory's mitigation.",
            adv.package
        ),
    };
    let ver = match Version::parse(&dep.version) {
        Ok(v) => v,
        Err(_) => {
            st.note = format!(
                "Version {:?} could not be parsed, so the affected range was not checked.",
                dep.version
            );
            return st;
        }
    };
    if !adv.affected.iter().any(|r| r.contains(&ver)) {
        st.status = Status::NotAffected;
        st.justification = Some("vulnerable_code_not_present");
        st.note = format!(
            "{} {} is outside the affected range ({}).",
            adv.package,
            dep.version,
            adv.affected_text.join(" or ")
        );
        return st;
    }
    let a = scan::analyse(files, adv);
    let prod_uses: Vec<&Evidence> = a.uses.iter().filter(|e| !e.test).collect();
    let prod_imports: Vec<&Evidence> = a.imports.iter().filter(|e| !e.test).collect();
    let has_symbols = !adv.symbols.is_empty();
    if has_symbols && !prod_uses.is_empty() {
        st.status = Status::Affected;
        st.note = format!("Vulnerable code is referenced: {}.", list(&prod_uses));
        st.action = Some(fix);
        st.evidence = prod_uses.into_iter().cloned().collect();
    } else if !has_symbols && !prod_imports.is_empty() {
        st.status = Status::Affected;
        st.note = format!("The package is imported ({}) and the advisory names no specific symbols, so reachability cannot be ruled out.", list(&prod_imports));
        st.action = Some(fix);
        st.evidence = prod_imports.into_iter().cloned().collect();
    } else if !prod_imports.is_empty() {
        st.status = Status::NotAffected;
        st.justification = Some("vulnerable_code_not_in_execute_path");
        st.note = format!("{} is imported ({}) but none of the vulnerable symbols ({}) are referenced in non-test code.", adv.package, list(&prod_imports), adv.symbol_text.join(", "));
        st.evidence = prod_imports.into_iter().cloned().collect();
    } else if !a.imports.is_empty() {
        let all: Vec<&Evidence> = a.uses.iter().chain(a.imports.iter()).collect();
        st.status = Status::NotAffected;
        st.justification = Some("vulnerable_code_not_in_execute_path");
        st.note = format!(
            "{} is only used from test code ({}).",
            adv.package,
            list(&all)
        );
        st.evidence = all.into_iter().cloned().collect();
    } else {
        st.status = Status::UnderInvestigation;
        st.note = format!("{} {} is in the lockfile but never imported directly. It may be a transitive dependency; check which package pulls it in.", adv.package, dep.version);
    }
    st
}

pub fn evaluate(
    advisories: &[Advisory],
    deps: &[Dep],
    files: &[FileInfo],
    include_absent: bool,
) -> Vec<Statement> {
    let mut out = Vec::new();
    for adv in advisories {
        let matches: Vec<&Dep> = deps
            .iter()
            .filter(|d| d.eco == adv.eco && normalise(d.eco, &d.name) == adv.package)
            .collect();
        if matches.is_empty() {
            if include_absent {
                out.push(Statement {
                    vuln: adv.id.clone(),
                    severity: adv.severity.clone(),
                    package: adv.package.clone(),
                    version: String::new(),
                    purl: format!(
                        "pkg:{}/{}",
                        adv.eco.purl_type(),
                        adv.package.replace('@', "%40")
                    ),
                    status: Status::NotAffected,
                    justification: Some("component_not_present"),
                    note: format!("{} is not in any lockfile.", adv.package),
                    action: None,
                    evidence: vec![],
                });
            }
            continue;
        }
        for d in matches {
            out.push(decide(adv, d, files));
        }
    }
    out
}

// ---- OpenVEX ----

pub fn document(statements: &[Statement], product: &str, author: &str, timestamp: &str) -> Value {
    let stmts: Vec<Value> = statements
        .iter()
        .map(|s| {
            let mut f: Vec<(&str, Value)> = vec![
                ("vulnerability", json::obj(vec![("name", json::s(&s.vuln))])),
                (
                    "products",
                    Value::Arr(vec![json::obj(vec![
                        ("@id", json::s(format!("pkg:generic/{product}"))),
                        (
                            "subcomponents",
                            Value::Arr(vec![json::obj(vec![("@id", json::s(&s.purl))])]),
                        ),
                    ])]),
                ),
                ("status", json::s(s.status.as_str())),
            ];
            match s.status {
                Status::NotAffected => {
                    f.push((
                        "justification",
                        json::s(s.justification.unwrap_or("vulnerable_code_not_present")),
                    ));
                    f.push(("impact_statement", json::s(&s.note)));
                }
                Status::Affected => {
                    f.push((
                        "action_statement",
                        json::s(s.action.clone().unwrap_or_default()),
                    ));
                    f.push(("status_notes", json::s(&s.note)));
                }
                Status::UnderInvestigation => f.push(("status_notes", json::s(&s.note))),
            }
            json::obj(f)
        })
        .collect();
    let body = json::pretty(&Value::Arr(stmts.clone()));
    let id = &sha256_hex(body.as_bytes())[..32];
    json::obj(vec![
        ("@context", json::s("https://openvex.dev/ns/v0.2.0")),
        (
            "@id",
            json::s(format!("https://openvex.dev/docs/vex-reach/{id}")),
        ),
        ("author", json::s(author)),
        ("timestamp", json::s(timestamp)),
        ("version", Value::Num(1.0)),
        (
            "tooling",
            json::s(concat!("vex-reach ", env!("CARGO_PKG_VERSION"))),
        ),
        ("statements", Value::Arr(stmts)),
    ])
}

/// Checks the rules of OpenVEX that this tool relies on. Returns a list of problems.
pub fn check_document(doc: &Value) -> Vec<String> {
    let mut p = Vec::new();
    for k in ["@context", "@id", "author", "timestamp", "version"] {
        if doc.get(k).is_none() {
            p.push(format!("missing {k}"));
        }
    }
    let Some(stmts) = doc.get("statements").and_then(Value::as_arr) else {
        p.push("missing statements".into());
        return p;
    };
    for (i, s) in stmts.iter().enumerate() {
        let st = s.get("status").and_then(Value::as_str).unwrap_or("");
        let n = |m: &str| format!("statement {}: {m}", i + 1);
        if s.get("vulnerability").and_then(|v| v.get("name")).is_none() {
            p.push(n("missing vulnerability.name"));
        }
        if s.get("products")
            .and_then(Value::as_arr)
            .is_none_or(<[Value]>::is_empty)
        {
            p.push(n("missing products"));
        }
        match st {
            "not_affected"
                if s.get("justification").is_none() && s.get("impact_statement").is_none() =>
            {
                p.push(n("not_affected needs a justification or impact_statement"))
            }
            "affected" if s.get("action_statement").is_none() => {
                p.push(n("affected needs action_statement"))
            }
            "not_affected" | "affected" | "under_investigation" | "fixed" => {}
            _ => p.push(n("unknown status")),
        }
    }
    p
}

pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    rfc3339(secs)
}

pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, c) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(&[b'a'; 1000]).len(), 64);
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_794_000_000), "2026-11-06T21:20:00Z");
    }
}
