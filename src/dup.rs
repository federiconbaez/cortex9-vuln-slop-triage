//! Detección de duplicados contra reportes ya aceptados.
//!
//! Dos vías: (1) huella de evidencia (objetivo + oráculo disparado) igual a la
//! de un reporte conocido; (2) similitud de texto (Jaccard de 3-gramas de
//! palabras) junto con al menos un símbolo verificado en común.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Fingerprint {
    pub target: String,
    pub oracle: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KnownEntry {
    pub id: String,
    pub report: String,
    pub fingerprint: Option<Fingerprint>,
    #[serde(default)]
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Known {
    pub id: String,
    pub fingerprint: Option<Fingerprint>,
    pub symbols: Vec<String>,
    pub shingles: HashSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DupMatch {
    pub id: String,
    pub via: &'static str,
    pub jaccard: f64,
}

pub const JACCARD_MIN: f64 = 0.20;

pub fn load_index(path: &Path) -> Result<Vec<Known>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let entries: Vec<KnownEntry> =
        serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    entries
        .into_iter()
        .map(|e| {
            let text = fs::read_to_string(dir.join(&e.report))
                .map_err(|err| format!("{}: {err}", e.report))?;
            Ok(Known {
                id: e.id,
                fingerprint: e.fingerprint,
                symbols: e.symbols,
                shingles: shingles(&text),
            })
        })
        .collect()
}

pub fn shingles(text: &str) -> HashSet<String> {
    let words: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| w.len() > 2)
        .map(str::to_lowercase)
        .collect();
    words.windows(3).map(|w| w.join(" ")).collect()
}

/// Jaccard clásico |A∩B| / |A∪B|.
pub fn jaccard_exact(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count() as f64;
    let uni = a.union(b).count() as f64;
    inter / uni
}

pub fn find(
    known: &[Known],
    text: &str,
    verified_symbols: &[String],
    fp: Option<&Fingerprint>,
) -> Option<DupMatch> {
    let sh = shingles(text);
    let mut best: Option<DupMatch> = None;
    for k in known {
        let j = jaccard_exact(&sh, &k.shingles);
        if let (Some(a), Some(b)) = (fp, k.fingerprint.as_ref()) {
            if a == b {
                return Some(DupMatch {
                    id: k.id.clone(),
                    via: "fingerprint",
                    jaccard: j,
                });
            }
        }
        let shared = verified_symbols.iter().any(|s| k.symbols.contains(s));
        if shared && j >= JACCARD_MIN && best.as_ref().is_none_or(|b| j > b.jaccard) {
            best = Some(DupMatch {
                id: k.id.clone(),
                via: "text+symbol",
                jaccard: j,
            });
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jaccard_identical_is_one() {
        let a = shingles("the quick brown fox jumps over");
        assert!((jaccard_exact(&a, &a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn fingerprint_beats_text() {
        let k = Known {
            id: "k1".into(),
            fingerprint: Some(Fingerprint {
                target: "t".into(),
                oracle: "crash".into(),
            }),
            symbols: vec![],
            shingles: shingles("unrelated words entirely here"),
        };
        let fp = Fingerprint {
            target: "t".into(),
            oracle: "crash".into(),
        };
        let m = find(&[k], "something else", &[], Some(&fp)).unwrap();
        assert_eq!(m.via, "fingerprint");
    }
}
