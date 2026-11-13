//! Version parsing and range matching. Understands dotted numeric versions with an optional
//! pre-release tail (1.2.3-rc.1, 1.2.3rc1, 1.2.3a1), a leading "v", and "+build" metadata.

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    nums: Vec<u64>,
    pre: Option<String>,
}

impl Version {
    pub fn parse(t: &str) -> Result<Version, String> {
        let t = t.trim().trim_start_matches('v');
        let t = t.split('+').next().unwrap_or("");
        let end = t
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(t.len());
        let (head, tail) = t.split_at(end);
        if head.is_empty() {
            return Err(format!("not a version: {t:?}"));
        }
        let mut nums = Vec::new();
        for p in head.trim_end_matches('.').split('.') {
            nums.push(
                p.parse::<u64>()
                    .map_err(|_| format!("not a version: {t:?}"))?,
            );
        }
        while nums.len() > 1 && *nums.last().unwrap() == 0 {
            nums.pop();
        }
        let tail = tail.trim_start_matches(['-', '.', '_']);
        Ok(Version {
            nums,
            pre: if tail.is_empty() {
                None
            } else {
                Some(tail.to_ascii_lowercase())
            },
        })
    }
}

impl Ord for Version {
    fn cmp(&self, o: &Self) -> Ordering {
        let n = self.nums.len().max(o.nums.len());
        for i in 0..n {
            let (a, b) = (
                self.nums.get(i).copied().unwrap_or(0),
                o.nums.get(i).copied().unwrap_or(0),
            );
            if a != b {
                return a.cmp(&b);
            }
        }
        match (&self.pre, &o.pre) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less, // a pre-release sorts before its release
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// One range such as ">=1.0.0,<1.4.2". Every comma-separated constraint must hold.
#[derive(Debug, Clone)]
pub struct Range {
    cons: Vec<(String, Version)>,
}

impl Range {
    pub fn parse(t: &str) -> Result<Range, String> {
        let mut cons = Vec::new();
        for part in t.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(format!("empty constraint in {t:?}"));
            }
            let op_len = part
                .find(|c: char| !matches!(c, '<' | '>' | '=' | '!'))
                .unwrap_or(0);
            let (op, v) = part.split_at(op_len);
            let op = if op.is_empty() { "==" } else { op };
            if !matches!(op, "<" | "<=" | ">" | ">=" | "==" | "=" | "!=") {
                return Err(format!("bad operator {op:?} in {t:?}"));
            }
            cons.push((op.to_string(), Version::parse(v)?));
        }
        Ok(Range { cons })
    }

    pub fn contains(&self, v: &Version) -> bool {
        self.cons.iter().all(|(op, c)| match op.as_str() {
            "<" => v < c,
            "<=" => v <= c,
            ">" => v > c,
            ">=" => v >= c,
            "!=" => v != c,
            _ => v == c,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(t: &str) -> Version {
        Version::parse(t).unwrap()
    }

    #[test]
    fn ordering() {
        assert!(v("1.2.10") > v("1.2.9"));
        assert!(v("1.0") == v("1.0.0"));
        assert!(v("v2.0.0") > v("1.99.99"));
        assert!(v("1.4.0-rc.1") < v("1.4.0"));
        assert!(v("1.4.0rc1") < v("1.4.0"));
        assert!(v("1.4.0+build5") == v("1.4.0"));
    }

    #[test]
    fn ranges() {
        let r = Range::parse(">=1.0.0,<1.4.2").unwrap();
        assert!(r.contains(&v("1.0.0")));
        assert!(r.contains(&v("1.4.1")));
        assert!(!r.contains(&v("1.4.2")));
        assert!(!r.contains(&v("0.9.9")));
        assert!(Range::parse("<2.0").unwrap().contains(&v("1.9.9")));
        assert!(Range::parse("==1.5.0").unwrap().contains(&v("1.5.0")));
        assert!(!Range::parse("!=1.5.0").unwrap().contains(&v("1.5.0")));
    }

    #[test]
    fn bad_input() {
        assert!(Version::parse("").is_err());
        assert!(Version::parse("abc").is_err());
        assert!(Range::parse("<>1.0").is_err());
        assert!(Range::parse(">=1.0,").is_err());
    }
}
