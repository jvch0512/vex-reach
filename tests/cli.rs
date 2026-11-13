use std::path::PathBuf;
use std::process::Command;
use vex_reach::json::{self, Value};
use vex_reach::vex::{self, Status};
use vex_reach::{advisory, scan_project};

fn ex(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(p)
}

fn run(project: &str, absent: bool) -> Vec<vex::Statement> {
    let advs = advisory::load(&std::fs::read_to_string(ex("advisories.json")).unwrap()).unwrap();
    scan_project(&ex(project), &advs, absent)
        .unwrap()
        .statements
}

fn find<'a>(s: &'a [vex::Statement], id: &str) -> &'a vex::Statement {
    s.iter()
        .find(|x| x.vuln == id)
        .unwrap_or_else(|| panic!("no statement for {id}"))
}

#[test]
fn python_project_covers_every_outcome() {
    let s = run("py-webapp", false);
    let a = find(&s, "EXAMPLE-2026-0001");
    assert_eq!(a.status, Status::Affected);
    assert_eq!(a.evidence[0].file, "src/app.py");
    assert_eq!(
        a.evidence[0].line, 12,
        "the comment on line 11 must not count"
    );
    assert_eq!(a.purl, "pkg:pypi/fastyaml@1.2.0");

    let n = find(&s, "EXAMPLE-2026-0002");
    assert_eq!(
        (n.status, n.justification),
        (
            Status::NotAffected,
            Some("vulnerable_code_not_in_execute_path")
        )
    );
    assert_eq!(
        find(&s, "EXAMPLE-2026-0003").status,
        Status::NotAffected,
        "test-only use"
    );
    assert!(find(&s, "EXAMPLE-2026-0003").note.contains("test code"));
    assert_eq!(
        find(&s, "EXAMPLE-2026-0004").status,
        Status::Affected,
        "no symbols: cannot rule out"
    );
    assert_eq!(
        find(&s, "EXAMPLE-2026-0005").justification,
        Some("vulnerable_code_not_present")
    );
    assert_eq!(
        find(&s, "EXAMPLE-2026-0006").status,
        Status::UnderInvestigation
    );
    assert!(
        s.iter().all(|x| x.vuln != "EXAMPLE-2026-0010"),
        "absent advisories are omitted by default"
    );
}

#[test]
fn other_ecosystems() {
    assert_eq!(
        find(&run("js-service", false), "EXAMPLE-2026-0007").status,
        Status::Affected
    );
    assert_eq!(
        find(&run("go-svc", false), "EXAMPLE-2026-0008").status,
        Status::NotAffected
    );
    let r = run("rust-tool", false);
    assert_eq!(find(&r, "EXAMPLE-2026-0009").status, Status::Affected);
    assert_eq!(
        find(&r, "EXAMPLE-2026-0009").purl,
        "pkg:cargo/byte-smith@0.3.1"
    );
}

#[test]
fn include_absent_adds_component_not_present() {
    let s = run("js-service", true);
    let g = find(&s, "EXAMPLE-2026-0010");
    assert_eq!(g.justification, Some("component_not_present"));
}

#[test]
fn emitted_document_is_valid_openvex_and_stable() {
    let s = run("py-webapp", false);
    let d1 = vex::document(&s, "py-webapp", "tester", "2026-01-01T00:00:00Z");
    let d2 = vex::document(&s, "py-webapp", "tester", "2026-01-01T00:00:00Z");
    assert_eq!(
        json::pretty(&d1),
        json::pretty(&d2),
        "same input, same output"
    );
    assert!(vex::check_document(&d1).is_empty());
    let back = json::parse(&json::pretty(&d1)).unwrap();
    assert_eq!(
        back.get("@context").and_then(Value::as_str),
        Some("https://openvex.dev/ns/v0.2.0")
    );
    let stmts = back.get("statements").and_then(Value::as_arr).unwrap();
    assert_eq!(stmts.len(), s.len());
    for st in stmts {
        match st.get("status").and_then(Value::as_str).unwrap() {
            "affected" => assert!(st.get("action_statement").is_some()),
            "not_affected" => assert!(st.get("justification").is_some()),
            _ => {}
        }
    }
}

#[test]
fn check_document_flags_broken_statements() {
    let bad = json::parse(r#"{"@context":"x","@id":"y","author":"a","timestamp":"t","version":1,"statements":[{"vulnerability":{"name":"V"},"products":[{"@id":"p"}],"status":"not_affected"},{"vulnerability":{"name":"W"},"products":[{"@id":"p"}],"status":"affected"},{"vulnerability":{"name":"X"},"products":[],"status":"maybe"}]}"#).unwrap();
    assert_eq!(vex::check_document(&bad).len(), 4);
}

#[test]
fn scanning_a_missing_directory_is_an_error() {
    let advs = advisory::load(&std::fs::read_to_string(ex("advisories.json")).unwrap()).unwrap();
    assert!(scan_project(&ex("nope"), &advs, false).is_err());
}

#[test]
fn dependency_directories_are_not_scanned() {
    let dir = std::env::temp_dir().join(format!("vex-reach-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("node_modules/x")).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"packages":{"node_modules/minipack":{"version":"2.1.0"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/x/evil.js"),
        "const m=require('minipack');m.unpackSync(1);",
    )
    .unwrap();
    let advs = advisory::load(&std::fs::read_to_string(ex("advisories.json")).unwrap()).unwrap();
    let s = scan_project(&dir, &advs, false).unwrap().statements;
    assert_eq!(
        find(&s, "EXAMPLE-2026-0007").status,
        Status::UnderInvestigation
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vex-reach"))
}

#[test]
fn cli_exit_codes_and_files() {
    let out = std::env::temp_dir().join(format!("vex-out-{}.json", std::process::id()));
    let base = |c: &mut Command| {
        c.arg("scan")
            .arg(ex("py-webapp"))
            .arg("--advisories")
            .arg(ex("advisories.json"));
    };
    let mut c = bin();
    base(&mut c);
    assert_eq!(c.status().unwrap().code(), Some(0));
    let mut c = bin();
    base(&mut c);
    assert_eq!(
        c.args(["--fail-on", "affected"]).status().unwrap().code(),
        Some(1)
    );
    let mut c = bin();
    base(&mut c);
    assert_eq!(
        c.args(["--fail-on", "sometimes"]).status().unwrap().code(),
        Some(2)
    );
    let mut c = bin();
    base(&mut c);
    assert!(c
        .arg("--out")
        .arg(&out)
        .args(["--timestamp", "2026-01-01T00:00:00Z"])
        .status()
        .unwrap()
        .success());
    assert_eq!(
        bin().arg("check").arg(&out).status().unwrap().code(),
        Some(0)
    );
    let _ = std::fs::remove_file(&out);
    assert_eq!(bin().arg("scan").status().unwrap().code(), Some(2));
    assert_eq!(
        bin()
            .args(["scan", "/nonexistent", "--advisories", "x"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
}
