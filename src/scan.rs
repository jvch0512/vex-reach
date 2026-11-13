//! Looks for uses of vulnerable symbols in source code.
//!
//! Method: strip comments and string contents, read the imports, then search for the vulnerable
//! symbols through the names those imports bind. This is a textual analysis, not a call graph:
//! it finds code that *references* a symbol, and does not prove that the code is ever executed.

use crate::advisory::{Advisory, Eco};
use crate::manifest;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Py,
    Js,
    Go,
    Rs,
}

pub fn lang_of(p: &Path) -> Option<Lang> {
    match p.extension()?.to_str()? {
        "py" => Some(Lang::Py),
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => Some(Lang::Js),
        "go" => Some(Lang::Go),
        "rs" => Some(Lang::Rs),
        _ => None,
    }
}

fn eco_lang(e: Eco) -> Lang {
    match e {
        Eco::Pypi => Lang::Py,
        Eco::Npm => Lang::Js,
        Eco::Go => Lang::Go,
        Eco::Cargo => Lang::Rs,
    }
}

pub fn is_test_path(rel: &str) -> bool {
    let l = rel.to_ascii_lowercase().replace('\\', "/");
    let base = l.rsplit('/').next().unwrap_or("");
    l.split('/').any(|s| {
        matches!(
            s,
            "test"
                | "tests"
                | "__tests__"
                | "spec"
                | "specs"
                | "testdata"
                | "fixtures"
                | "examples"
        )
    }) || base.starts_with("test_")
        || base.ends_with("_test.py")
        || base.ends_with("_test.go")
        || base.ends_with("_test.rs")
        || base.contains(".test.")
        || base.contains(".spec.")
        || base == "conftest.py"
}

/// Returns (comments blanked, comments and string contents blanked). Newlines and offsets are preserved.
pub fn strip(src: &str, lang: Lang) -> (String, String) {
    let b = src.as_bytes();
    let n = b.len();
    let mut nc = b.to_vec();
    let mut mk = b.to_vec();
    let blank = |v: &mut Vec<u8>, from: usize, to: usize| {
        for x in &mut v[from..to] {
            if *x != b'\n' {
                *x = b' ';
            }
        }
    };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i < n {
        let c = b[i];
        let next = b.get(i + 1).copied().unwrap_or(0);
        // comments
        let line_comment = match lang {
            Lang::Py => c == b'#',
            _ => c == b'/' && next == b'/',
        };
        if line_comment {
            let e = b[i..].iter().position(|&x| x == b'\n').map_or(n, |p| i + p);
            blank(&mut nc, i, e);
            blank(&mut mk, i, e);
            i = e;
            continue;
        }
        if lang != Lang::Py && c == b'/' && next == b'*' {
            let e = src[i + 2..].find("*/").map_or(n, |p| i + 2 + p + 2);
            blank(&mut nc, i, e);
            blank(&mut mk, i, e);
            i = e;
            continue;
        }
        // strings
        let mut quote: Option<(usize, usize)> = None; // (content start, content end) searched below
        let mut raw_hashes: Option<usize> = None;
        let mut triple = false;
        let mut qc = 0u8;
        if lang == Lang::Rs && c == b'r' && (i == 0 || !ident(b[i - 1])) {
            let mut j = i + 1;
            while j < n && b[j] == b'#' {
                j += 1;
            }
            if j < n && b[j] == b'"' {
                raw_hashes = Some(j - i - 1);
                qc = b'"';
                quote = Some((j + 1, j + 1));
            }
        }
        if quote.is_none()
            && (c == b'"' || c == b'\'' || (c == b'`' && matches!(lang, Lang::Js | Lang::Go)))
        {
            if lang == Lang::Rs && c == b'\'' {
                // char literal or lifetime: a literal closes within a few bytes
                let close = if next == b'\\' {
                    b[i + 2..]
                        .iter()
                        .take(8)
                        .position(|&x| x == b'\'')
                        .map(|p| i + 2 + p)
                } else if b.get(i + 2) == Some(&b'\'') {
                    Some(i + 2)
                } else {
                    None
                };
                if let Some(e) = close {
                    blank(&mut mk, i + 1, e);
                    i = e + 1;
                } else {
                    i += 1;
                }
                continue;
            }
            qc = c;
            triple = lang == Lang::Py && b.get(i + 1) == Some(&c) && b.get(i + 2) == Some(&c);
            quote = Some((i + if triple { 3 } else { 1 }, 0));
        }
        let Some((start, _)) = quote else {
            i += 1;
            continue;
        };
        let mut j = start;
        let end;
        loop {
            if j >= n {
                end = n;
                break;
            }
            if let Some(h) = raw_hashes {
                if b[j] == b'"'
                    && b[j + 1..].iter().take(h).filter(|&&x| x == b'#').count() == h
                    && j + h < n + 1
                {
                    end = (j + 1 + h).min(n);
                    break;
                }
            } else if triple {
                if b[j] == qc && b.get(j + 1) == Some(&qc) && b.get(j + 2) == Some(&qc) {
                    end = j + 3;
                    break;
                }
            } else if b[j] == b'\\' && qc != b'`' {
                j += 2;
                continue;
            } else if b[j] == qc {
                end = j + 1;
                break;
            } else if b[j] == b'\n' && !matches!(qc, b'`') && lang != Lang::Rs {
                end = j;
                break;
            }
            j += 1;
        }
        let close_len = if raw_hashes.is_some() {
            1 + raw_hashes.unwrap_or(0)
        } else if triple {
            3
        } else {
            1
        };
        let content_end = end.saturating_sub(close_len).max(start).min(n);
        let start = start.min(n);
        blank(&mut mk, start, content_end);
        i = end.max(i + 1);
    }
    (
        String::from_utf8_lossy(&nc).into_owned(),
        String::from_utf8_lossy(&mk).into_owned(),
    )
}

#[derive(Debug, Clone)]
pub struct Bind {
    /// Full path of what is bound, e.g. ["pkg", "sub", "f"].
    pub path: Vec<String>,
    /// The name the code uses for it.
    pub local: String,
    pub wildcard: bool,
    pub line: usize,
}

pub struct FileInfo {
    pub rel: String,
    pub lang: Lang,
    pub is_test: bool,
    pub masked: String,
    pub binds: Vec<Bind>,
    pub import_lines: Vec<(usize, usize)>,
}

fn ident_name(t: &str) -> String {
    t.trim().to_string()
}

fn py_imports(nc: &str) -> (Vec<Bind>, Vec<(usize, usize)>) {
    let lines: Vec<&str> = nc.lines().collect();
    let (mut binds, mut ranges) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        let start = i;
        if t.starts_with("import ") || t.starts_with("from ") {
            let mut stmt = t.to_string();
            while (stmt.matches('(').count() > stmt.matches(')').count() || stmt.ends_with('\\'))
                && i + 1 < lines.len()
            {
                i += 1;
                stmt.push(' ');
                stmt.push_str(lines[i].trim().trim_end_matches('\\'));
            }
            let stmt = stmt.replace(['(', ')'], " ").replace('\\', " ");
            let line = start + 1;
            if let Some(rest) = stmt.strip_prefix("import ") {
                for part in rest.split(',') {
                    let (m, alias) = match part.split_once(" as ") {
                        Some((m, a)) => (m.trim(), Some(a.trim())),
                        None => (part.trim(), None),
                    };
                    let segs: Vec<String> = m.split('.').map(ident_name).collect();
                    if segs.iter().any(String::is_empty) {
                        continue;
                    }
                    match alias {
                        Some(a) => binds.push(Bind {
                            path: segs,
                            local: a.to_string(),
                            wildcard: false,
                            line,
                        }),
                        None => binds.push(Bind {
                            path: vec![segs[0].clone()],
                            local: segs[0].clone(),
                            wildcard: false,
                            line,
                        }),
                    }
                }
            } else if let Some(rest) = stmt.strip_prefix("from ") {
                if let Some((m, names)) = rest.split_once(" import ") {
                    let base: Vec<String> = m.trim().split('.').map(ident_name).collect();
                    if !base.iter().any(String::is_empty) {
                        for part in names.split(',') {
                            let part = part.trim();
                            if part == "*" {
                                binds.push(Bind {
                                    path: base.clone(),
                                    local: String::new(),
                                    wildcard: true,
                                    line,
                                });
                                continue;
                            }
                            let (nm, local) = match part.split_once(" as ") {
                                Some((a, b)) => (a.trim(), b.trim()),
                                None => (part, part),
                            };
                            if !nm.is_empty() {
                                let mut p = base.clone();
                                p.push(nm.to_string());
                                binds.push(Bind {
                                    path: p,
                                    local: local.to_string(),
                                    wildcard: false,
                                    line,
                                });
                            }
                        }
                    }
                }
            }
            ranges.push((line, i + 1));
        }
        i += 1;
    }
    (binds, ranges)
}

fn quoted(t: &str) -> Option<String> {
    let s = t.find(['\'', '"', '`'])?;
    let q = t.as_bytes()[s] as char;
    let e = t[s + 1..].find(q)?;
    Some(t[s + 1..s + 1 + e].to_string())
}

fn js_path(spec: &str) -> Vec<String> {
    let spec = spec.strip_prefix("node:").unwrap_or(spec);
    spec.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .map(str::to_string)
        .collect()
}

fn js_imports(nc: &str) -> (Vec<Bind>, Vec<(usize, usize)>) {
    let (mut binds, mut ranges) = (Vec::new(), Vec::new());
    let lines: Vec<&str> = nc.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        let start = i;
        let is_import = t.starts_with("import ") || t.starts_with("import{");
        let has_require = t.contains("require(");
        if is_import
            || has_require
            || ((t.starts_with("const ") || t.starts_with("let ") || t.starts_with("var "))
                && t.ends_with('{'))
        {
            let mut stmt = t.to_string();
            let complete = |s: &str| {
                if is_import {
                    s.contains(" from ") && quoted(&s[s.rfind(" from ").unwrap_or(0)..]).is_some()
                        || (s.starts_with("import ") && quoted(s).is_some() && !s.contains('{'))
                } else {
                    s.contains("require(") && s.contains(')')
                }
            };
            while !complete(&stmt) && i + 1 < lines.len() && i - start < 40 {
                i += 1;
                stmt.push(' ');
                stmt.push_str(lines[i].trim());
            }
            let line = start + 1;
            if is_import {
                let body = stmt.trim_start_matches("import").trim();
                if let Some(spec) = quoted(body.rsplit(" from ").next().unwrap_or(body)) {
                    let base = js_path(&spec);
                    let head = body
                        .rsplit_once(" from ")
                        .map_or("", |(h, _)| h)
                        .trim()
                        .trim_start_matches("type ");
                    if head.is_empty() {
                        // side-effect import: no names bound
                    }
                    let (default_part, named) = match (head.find('{'), head.find('}')) {
                        (Some(a), Some(b)) if a < b => (
                            head[..a].trim().trim_end_matches(',').trim(),
                            Some(&head[a + 1..b]),
                        ),
                        _ => (head, None),
                    };
                    if let Some(ns) = default_part.strip_prefix("* as ") {
                        binds.push(Bind {
                            path: base.clone(),
                            local: ns.trim().to_string(),
                            wildcard: false,
                            line,
                        });
                    } else if !default_part.is_empty() {
                        for d in default_part.split(',') {
                            let d = d.trim();
                            if let Some(ns) = d.strip_prefix("* as ") {
                                binds.push(Bind {
                                    path: base.clone(),
                                    local: ns.trim().to_string(),
                                    wildcard: false,
                                    line,
                                });
                            } else if !d.is_empty() {
                                binds.push(Bind {
                                    path: base.clone(),
                                    local: d.to_string(),
                                    wildcard: false,
                                    line,
                                });
                            }
                        }
                    }
                    for part in named.unwrap_or("").split(',') {
                        let part = part.trim();
                        if part.is_empty() {
                            continue;
                        }
                        let (nm, local) = match part.split_once(" as ") {
                            Some((a, b)) => (a.trim(), b.trim()),
                            None => (part, part),
                        };
                        let mut p = base.clone();
                        p.push(nm.to_string());
                        binds.push(Bind {
                            path: p,
                            local: local.to_string(),
                            wildcard: false,
                            line,
                        });
                    }
                }
            } else if let Some(r) = stmt.find("require(") {
                let spec = quoted(&stmt[r..]);
                let lhs = stmt[..r]
                    .trim()
                    .trim_start_matches("const ")
                    .trim_start_matches("let ")
                    .trim_start_matches("var ")
                    .trim()
                    .trim_end_matches('=')
                    .trim()
                    .to_string();
                if let Some(spec) = spec {
                    let base = js_path(&spec);
                    if let (Some(a), Some(b)) = (lhs.find('{'), lhs.find('}')) {
                        for part in lhs[a + 1..b].split(',') {
                            let part = part.trim();
                            if part.is_empty() {
                                continue;
                            }
                            let (nm, local) = match part.split_once(':') {
                                Some((x, y)) => (x.trim(), y.trim()),
                                None => (part, part),
                            };
                            let mut p = base.clone();
                            p.push(nm.to_string());
                            binds.push(Bind {
                                path: p,
                                local: local.to_string(),
                                wildcard: false,
                                line,
                            });
                        }
                    } else if !lhs.is_empty()
                        && lhs
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
                    {
                        binds.push(Bind {
                            path: base,
                            local: lhs,
                            wildcard: false,
                            line,
                        });
                    }
                }
            }
            ranges.push((line, i + 1));
        }
        i += 1;
    }
    (binds, ranges)
}

fn go_pkg_name(path: &[String]) -> String {
    let mut segs: Vec<&String> = path.iter().collect();
    while segs.len() > 1
        && segs.last().is_some_and(|s| {
            s.len() > 1 && s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit())
        })
    {
        segs.pop();
    }
    let last = segs.last().map(|s| s.as_str()).unwrap_or("");
    let last = last.split('.').next().unwrap_or(last);
    last.replace('-', "_")
}

fn go_imports(nc: &str) -> (Vec<Bind>, Vec<(usize, usize)>) {
    let (mut binds, mut ranges) = (Vec::new(), Vec::new());
    let lines: Vec<&str> = nc.lines().collect();
    let mut in_block = false;
    let mut block_start = 0;
    let one = |t: &str, line: usize, binds: &mut Vec<Bind>| {
        let Some(spec) = quoted(t) else { return };
        let pre = t[..t.find(['"', '`']).unwrap_or(0)].trim();
        let mut path: Vec<String> = spec.split('/').map(str::to_string).collect();
        if path.len() > 1
            && path.last().is_some_and(|s| {
                s.len() > 1 && s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit())
            })
        {
            path.pop(); // major-version suffix (/v2) is not part of the package identity
        }
        match pre {
            "_" => {}
            "." => binds.push(Bind {
                path,
                local: String::new(),
                wildcard: true,
                line,
            }),
            "" => {
                let l = go_pkg_name(&path);
                binds.push(Bind {
                    path,
                    local: l,
                    wildcard: false,
                    line,
                })
            }
            alias => binds.push(Bind {
                path,
                local: alias.to_string(),
                wildcard: false,
                line,
            }),
        }
    };
    for (i, raw) in lines.iter().enumerate() {
        let t = raw.trim();
        if in_block {
            if t.starts_with(')') {
                in_block = false;
                ranges.push((block_start, i + 1));
            } else {
                one(t, i + 1, &mut binds);
            }
        } else if t == "import (" {
            in_block = true;
            block_start = i + 1;
        } else if let Some(r) = t.strip_prefix("import ") {
            one(r, i + 1, &mut binds);
            ranges.push((i + 1, i + 1));
        }
    }
    (binds, ranges)
}

fn rs_use_expand(prefix: &[String], body: &str, line: usize, out: &mut Vec<Bind>, depth: usize) {
    let body = body.trim();
    if depth > 8 || body.is_empty() {
        return;
    }
    if let Some(open) = body.find('{') {
        let close = body.rfind('}').unwrap_or(body.len());
        let head: Vec<String> = body[..open]
            .split("::")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let mut p = prefix.to_vec();
        p.extend(head);
        // split the inside on top-level commas
        let inner = &body[open + 1..close];
        let (mut lvl, mut last) = (0, 0);
        let mut parts = Vec::new();
        for (k, ch) in inner.char_indices() {
            match ch {
                '{' => lvl += 1,
                '}' => lvl -= 1,
                ',' if lvl == 0 => {
                    parts.push(&inner[last..k]);
                    last = k + 1;
                }
                _ => {}
            }
        }
        parts.push(&inner[last..]);
        for part in parts {
            rs_use_expand(&p, part, line, out, depth + 1);
        }
        return;
    }
    let (path_txt, alias) = match body.split_once(" as ") {
        Some((a, b)) => (a.trim(), Some(b.trim().to_string())),
        None => (body, None),
    };
    let mut p = prefix.to_vec();
    p.extend(
        path_txt
            .split("::")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    );
    if p.last().map(String::as_str) == Some("*") {
        p.pop();
        out.push(Bind {
            path: p,
            local: String::new(),
            wildcard: true,
            line,
        });
    } else if p.last().map(String::as_str) == Some("self") {
        p.pop();
        if let Some(l) = p.last().cloned() {
            out.push(Bind {
                path: p,
                local: alias.unwrap_or(l),
                wildcard: false,
                line,
            });
        }
    } else if let Some(l) = p.last().cloned() {
        out.push(Bind {
            path: p,
            local: alias.unwrap_or(l),
            wildcard: false,
            line,
        });
    }
}

fn rs_imports(nc: &str) -> (Vec<Bind>, Vec<(usize, usize)>) {
    let (mut binds, mut ranges) = (Vec::new(), Vec::new());
    let lines: Vec<&str> = nc.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        let t2 = t.strip_prefix("pub ").unwrap_or(t);
        if let Some(rest) = t2.strip_prefix("use ") {
            let start = i;
            let mut stmt = rest.to_string();
            while !stmt.contains(';') && i + 1 < lines.len() && i - start < 60 {
                i += 1;
                stmt.push(' ');
                stmt.push_str(lines[i].trim());
            }
            let stmt = stmt.split(';').next().unwrap_or("").to_string();
            rs_use_expand(&[], &stmt, start + 1, &mut binds, 0);
            ranges.push((start + 1, i + 1));
        }
        i += 1;
    }
    (binds, ranges)
}

pub fn analyse_file(rel: &str, src: &str, lang: Lang) -> FileInfo {
    let (nc, masked) = strip(src, lang);
    let (binds, import_lines) = match lang {
        Lang::Py => py_imports(&nc),
        Lang::Js => js_imports(&nc),
        Lang::Go => go_imports(&nc),
        Lang::Rs => rs_imports(&nc),
    };
    FileInfo {
        rel: rel.to_string(),
        lang,
        is_test: is_test_path(rel),
        masked,
        binds,
        import_lines,
    }
}

pub fn load_project(root: &Path) -> (Vec<FileInfo>, Vec<String>) {
    let mut files = Vec::new();
    let mut warn = Vec::new();
    for p in manifest::walk(root) {
        let Some(lang) = lang_of(&p) else { continue };
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        match manifest::read_small(&p) {
            Some(src) => files.push(analyse_file(&rel, &src, lang)),
            None => warn.push(format!("{rel}: unreadable or too large, skipped")),
        }
    }
    (files, warn)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub file: String,
    pub line: usize,
    pub what: String,
    pub test: bool,
}

#[derive(Debug, Default)]
pub struct Analysis {
    pub imports: Vec<Evidence>,
    pub uses: Vec<Evidence>,
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// Lines of `masked` where `needle` appears as a whole token path (not part of a longer name or a member access).
pub fn find_token(masked: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for (ln, line) in masked.lines().enumerate() {
        let mut from = 0;
        while let Some(p) = line[from..].find(needle) {
            let s = from + p;
            let e = s + needle.len();
            let before = line[..s].chars().next_back();
            let after = line[e..].chars().next();
            let ok_before = before.is_none_or(|c| !is_ident(c) && c != '.' && c != ':');
            let ok_after = after.is_none_or(|c| !is_ident(c));
            if ok_before && ok_after {
                out.push(ln + 1);
                break;
            }
            from = e;
        }
    }
    out
}

fn join(lang: Lang, parts: &[String]) -> String {
    parts.join(if lang == Lang::Rs { "::" } else { "." })
}

pub fn analyse(files: &[FileInfo], adv: &Advisory) -> Analysis {
    let lang = eco_lang(adv.eco);
    let mut res = Analysis::default();
    for f in files.iter().filter(|f| f.lang == lang) {
        let in_import = |l: usize| f.import_lines.iter().any(|&(a, b)| l >= a && l <= b);
        let push_use = |line: usize, what: String, res: &mut Analysis| {
            let e = Evidence {
                file: f.rel.clone(),
                line,
                what,
                test: f.is_test,
            };
            if !res.uses.contains(&e) {
                res.uses.push(e);
            }
        };
        let mut binds: Vec<Bind> = f.binds.clone();
        if lang == Lang::Rs {
            // paths can be written in full without a `use`
            for m in &adv.modules {
                binds.push(Bind {
                    path: m.clone(),
                    local: m[0].clone(),
                    wildcard: false,
                    line: 0,
                });
            }
        }
        for b in &binds {
            for m in &adv.modules {
                let hit = b.path.len() >= m.len() && b.path[..m.len()] == m[..];
                // wildcard of a parent such as `from pkg import *` where pkg is the module root
                if !hit {
                    continue;
                }
                let rel: Vec<String> = b.path[m.len()..].to_vec();
                if b.line > 0 {
                    let e = Evidence {
                        file: f.rel.clone(),
                        line: b.line,
                        what: format!("imports {}", join(lang, &b.path)),
                        test: f.is_test,
                    };
                    if !res.imports.contains(&e) {
                        res.imports.push(e);
                    }
                }
                if b.wildcard {
                    if b.line > 0 {
                        push_use(
                            b.line,
                            format!(
                                "wildcard import of {} may expose every symbol",
                                join(lang, &b.path)
                            ),
                            &mut res,
                        );
                    }
                    continue;
                }
                for (si, sym) in adv.symbols.iter().enumerate() {
                    let needle = if rel.is_empty() {
                        format!(
                            "{}{}{}",
                            b.local,
                            if lang == Lang::Rs { "::" } else { "." },
                            join(lang, sym)
                        )
                    } else if sym.len() >= rel.len() && sym[..rel.len()] == rel[..] {
                        let rest = &sym[rel.len()..];
                        if rest.is_empty() {
                            b.local.clone()
                        } else {
                            format!(
                                "{}{}{}",
                                b.local,
                                if lang == Lang::Rs { "::" } else { "." },
                                join(lang, rest)
                            )
                        }
                    } else if rel.len() > sym.len() && rel[..sym.len()] == sym[..] {
                        b.local.clone()
                    } else {
                        continue;
                    };
                    for ln in find_token(&f.masked, &needle) {
                        if !in_import(ln) {
                            push_use(ln, format!("references {}", adv.symbol_text[si]), &mut res);
                        }
                    }
                }
            }
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory;

    fn adv(eco: &str, pkg: &str, syms: &str) -> Advisory {
        advisory::load(&format!(r#"{{"advisories":[{{"id":"A","ecosystem":"{eco}","package":"{pkg}","affected":["<9"],"symbols":[{syms}]}}]}}"#)).unwrap().remove(0)
    }

    fn uses(src: &str, lang: Lang, a: &Advisory) -> Vec<usize> {
        let f = analyse_file("src/app", src, lang);
        analyse(&[f], a).uses.iter().map(|u| u.line).collect()
    }

    #[test]
    fn strip_blanks_comments_and_strings() {
        let (nc, mk) = strip("x = 'fy.load_unsafe(' # fy.load_unsafe(\ny()\n", Lang::Py);
        assert!(nc.contains("'fy.load_unsafe('") && !nc.contains("# fy"));
        assert!(!mk.contains("load_unsafe"));
        assert_eq!(
            nc.len(),
            "x = 'fy.load_unsafe(' # fy.load_unsafe(\ny()\n".len()
        );
    }

    #[test]
    fn strip_handles_rust_edge_cases() {
        let src =
            "let a: &'static str = r#\"x::bad()\"#; let c = '\\''; foo::bad();\n/* foo::bad() */\n";
        let (_, mk) = strip(src, Lang::Rs);
        assert_eq!(mk.matches("bad").count(), 1);
    }

    #[test]
    fn python_symbol_through_alias_and_from_import() {
        let a = adv("pypi", "fastyaml", r#""load_unsafe""#);
        assert_eq!(
            uses(
                "import fastyaml as fy\nx = fy.load_unsafe(s)\n",
                Lang::Py,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses(
                "from fastyaml import load_unsafe as lu\nlu(s)\n",
                Lang::Py,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses(
                "from fastyaml import (\n    safe_load,\n    load_unsafe,\n)\nload_unsafe(1)\n",
                Lang::Py,
                &a
            ),
            vec![5]
        );
    }

    #[test]
    fn python_ignores_comments_strings_and_unused_imports() {
        let a = adv("pypi", "fastyaml", r#""load_unsafe""#);
        assert!(uses("import fastyaml\n# fastyaml.load_unsafe(x)\ns = 'fastyaml.load_unsafe(x)'\nfastyaml.safe_load(x)\n", Lang::Py, &a).is_empty());
        assert!(uses("from fastyaml import load_unsafe\n", Lang::Py, &a).is_empty());
        assert!(uses(
            "import fastyaml\nother.fastyaml.load_unsafe(x)\n",
            Lang::Py,
            &a
        )
        .is_empty());
    }

    #[test]
    fn python_class_method_symbols_and_submodules() {
        let a = adv("pypi", "fastyaml", r#""Loader.load""#);
        assert_eq!(
            uses(
                "from fastyaml import Loader\nLoader.load(x)\n",
                Lang::Py,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses("import fastyaml\nfastyaml.Loader.load(x)\n", Lang::Py, &a),
            vec![2]
        );
        assert!(uses(
            "from fastyaml import Loader\nLoader.dump(x)\n",
            Lang::Py,
            &a
        )
        .is_empty());
    }

    #[test]
    fn python_wildcard_is_conservative() {
        let a = adv("pypi", "fastyaml", r#""load_unsafe""#);
        assert_eq!(uses("from fastyaml import *\n", Lang::Py, &a), vec![1]);
    }

    #[test]
    fn javascript_forms() {
        let a = adv("npm", "minipack", r#""unpackSync""#);
        assert_eq!(
            uses(
                "const mp = require('minipack');\nmp.unpackSync(b);\n",
                Lang::Js,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses(
                "const { unpackSync: u } = require(\"minipack\");\nu(b);\n",
                Lang::Js,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses(
                "import { unpackSync } from 'minipack';\nunpackSync(b);\n",
                Lang::Js,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses(
                "import * as mp from 'minipack';\nmp.unpackSync(b);\n",
                Lang::Js,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses(
                "import mp from 'minipack';\nmp.unpackSync(b);\n",
                Lang::Js,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses(
                "import {\n  pack,\n  unpackSync,\n} from 'minipack';\nunpackSync(b);\n",
                Lang::Js,
                &a
            ),
            vec![5]
        );
        assert!(uses(
            "const mp = require('minipack');\n// mp.unpackSync(b)\nmp.pack(b);\n",
            Lang::Js,
            &a
        )
        .is_empty());
    }

    #[test]
    fn javascript_scoped_package_and_subpath() {
        let a = adv("npm", "@acme/pk", r#""sub.run""#);
        assert_eq!(
            uses(
                "import { run } from '@acme/pk/sub';\nrun();\n",
                Lang::Js,
                &a
            ),
            vec![2]
        );
    }

    #[test]
    fn go_forms() {
        let a = adv("go", "example.com/gzipx", r#""Inflate""#);
        assert_eq!(uses("package m\nimport (\n\t\"fmt\"\n\t\"example.com/gzipx\"\n)\nfunc f() { gzipx.Inflate(b) }\n", Lang::Go, &a), vec![6]);
        assert_eq!(
            uses(
                "package m\nimport gz \"example.com/gzipx\"\nfunc f() { gz.Inflate(b) }\n",
                Lang::Go,
                &a
            ),
            vec![3]
        );
        assert_eq!(
            uses(
                "package m\nimport \"example.com/gzipx/v2\"\nfunc f() { gzipx.Inflate(b) }\n",
                Lang::Go,
                &adv("go", "example.com/gzipx", r#""Inflate""#)
            ),
            vec![3]
        );
        assert!(uses(
            "package m\nimport \"example.com/gzipx\"\nfunc f() { gzipx.Deflate(b) }\n",
            Lang::Go,
            &a
        )
        .is_empty());
    }

    #[test]
    fn rust_forms() {
        let a = adv("cargo", "byte-smith", r#""codec::decode""#);
        assert_eq!(
            uses(
                "use byte_smith::codec;\nfn f(){ codec::decode(b); }\n",
                Lang::Rs,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses(
                "use byte_smith::codec::{decode as d, encode};\nfn f(){ d(b); }\n",
                Lang::Rs,
                &a
            ),
            vec![2]
        );
        assert_eq!(
            uses("fn f(){ byte_smith::codec::decode(b); }\n", Lang::Rs, &a),
            vec![1]
        );
        assert!(uses(
            "use byte_smith::codec;\nfn f(){ codec::encode(b); }\n",
            Lang::Rs,
            &a
        )
        .is_empty());
        assert!(uses(
            "fn f(){ let s = \"byte_smith::codec::decode(\"; }\n",
            Lang::Rs,
            &a
        )
        .is_empty());
    }

    #[test]
    fn test_paths() {
        for p in [
            "tests/a.py",
            "src/test_a.py",
            "pkg/a_test.go",
            "web/a.test.js",
            "a/__tests__/b.js",
            "examples/x.rs",
        ] {
            assert!(is_test_path(p), "{p}");
        }
        for p in ["src/app.py", "latest/main.go", "contest.js"] {
            assert!(!is_test_path(p), "{p}");
        }
    }

    #[test]
    fn find_token_boundaries() {
        assert_eq!(
            find_token(
                "a.fy.load(1)\nfy.load(2)\nfy.loader(3)\nxfy.load(4)\n",
                "fy.load"
            ),
            vec![2]
        );
    }
}
