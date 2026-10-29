//! Señales textuales del reporte. Ninguna señal blanda alcanza sola para
//! cerrar: `triage` exige al menos una señal dura verificable.

use crate::project::Project;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Signal {
    pub code: &'static str,
    pub weight: i32,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    /// Señales duras: hechos falsables que el reporte afirma y no se sostienen.
    pub hard: Vec<Signal>,
    /// Señales blandas: estilo/plantilla. Suman puntaje, nunca cierran solas.
    pub soft: Vec<Signal>,
    /// Indicadores de reporte humano/verificable (restan puntaje).
    pub human: Vec<Signal>,
    pub cves: Vec<String>,
    pub symbols: Vec<String>,
    pub verified_symbols: Vec<String>,
    pub files: Vec<String>,
    pub claims_critical: bool,
    pub has_poc_section: bool,
}

impl Analysis {
    pub fn soft_score(&self) -> i32 {
        let s: i32 = self.soft.iter().map(|s| s.weight).sum();
        let h: i32 = self.human.iter().map(|s| s.weight).sum();
        s - h
    }
}

/// Funciones de libc/estándar que un reporte puede nombrar sin que estén en el árbol.
const STD_FUNCS: &[&str] = &[
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat", "strlen", "sprintf",
    "snprintf", "printf", "fprintf", "scanf", "sscanf", "fgets", "gets", "fread", "fwrite",
    "fopen", "fclose", "malloc", "calloc", "realloc", "free", "read", "write", "open", "close",
    "exit", "abort", "main", "system", "execve", "strcspn", "strdup", "alloca", "atoi", "strtol",
    "strtoul",
];

const FILLER: &[&str] = &[
    "it is important to note",
    "as an ai",
    "i hope this helps",
    "i hope this report",
    "certainly!",
    "in conclusion",
    "delve",
    "comprehensive security assessment",
    "robust security",
    "this vulnerability poses a significant risk",
    "could lead to severe consequences",
    "with years of experience",
    "during my security research",
    "i have discovered a critical",
    "industry best practices",
    "thorough analysis",
    "potential attackers",
    "owasp top 10",
    "es importante destacar",
    "en conclusión",
    "espero que este reporte",
    "mejores prácticas de la industria",
    "representa un riesgo significativo",
];

const TEMPLATE: &[&str] = &[
    "vulnerability type:",
    "cvss score:",
    "severity: critical",
    "impact:",
    "remediation:",
    "recommendation:",
    "affected component:",
    "steps to reproduce:",
    "tipo de vulnerabilidad:",
    "severidad:",
];

const HEDGES: &[&str] = &[
    "could potentially",
    "may potentially",
    "might be possible",
    "may allow an attacker",
    "could allow an attacker",
    "it is possible that",
    "theoretically",
    "podría potencialmente",
];

const PLACEHOLDER_HOSTS: &[&str] = &[
    "example.com",
    "target.com",
    "victim.com",
    "vulnerable-site.com",
    "yourdomain.com",
    "targetsite.com",
];

const PLACEHOLDER_POC: &[&str] = &[
    "exploit code here",
    "insert payload",
    "<payload>",
    "your_payload",
    "todo: add exploit",
    "poc to be provided",
    "[poc]",
    "malicious_payload_here",
];

fn re(s: &'static str, cell: &'static OnceLock<Regex>) -> &'static Regex {
    cell.get_or_init(|| Regex::new(s).expect("regex válida"))
}

static RE_CVE: OnceLock<Regex> = OnceLock::new();
static RE_SYM: OnceLock<Regex> = OnceLock::new();
static RE_TRACE: OnceLock<Regex> = OnceLock::new();
static RE_FILE: OnceLock<Regex> = OnceLock::new();
static RE_CVSS: OnceLock<Regex> = OnceLock::new();
static RE_COMMIT: OnceLock<Regex> = OnceLock::new();
static RE_VERSION: OnceLock<Regex> = OnceLock::new();
static RE_FENCE: OnceLock<Regex> = OnceLock::new();

/// Analiza el markdown. `current_year` se pasa explícito para tests deterministas.
pub fn analyze(md: &str, project: Option<&Project>, current_year: u32) -> Analysis {
    let mut a = Analysis::default();
    // Espacios colapsados: las frases no deben depender del corte de línea.
    let lower = md
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let prose = strip_code(md);

    // CVEs
    for c in re(r"CVE-(\d{4})-(\d{4,7})", &RE_CVE).captures_iter(md) {
        let id = c[0].to_string();
        if a.cves.contains(&id) {
            continue;
        }
        let year: u32 = c[1].parse().unwrap_or(0);
        let num = &c[2];
        if year > current_year || year < 1999 {
            a.hard
                .push(sig("INVENTED_CVE", 3, format!("{id}: año imposible")));
        } else if is_suspicious_cve_num(num) {
            a.hard
                .push(sig("INVENTED_CVE", 3, format!("{id}: número de plantilla")));
        } else if let Some(p) = project {
            if !p.cfg.known_cves.iter().any(|k| k == &id) {
                a.soft.push(sig(
                    "CVE_NOT_IN_PROJECT",
                    1,
                    format!("{id} no figura en known_cves"),
                ));
            }
        }
        a.cves.push(id);
    }

    // Símbolos: `foo_bar()` en prosa y frames "#N 0x.. in foo" en trazas.
    let mut syms: Vec<String> = Vec::new();
    for c in re(r"`?\b([A-Za-z_][A-Za-z0-9_]{2,})\(\)?`?", &RE_SYM).captures_iter(&prose) {
        let s = c[1].to_string();
        if s.contains('_') || c[0].starts_with('`') {
            syms.push(s);
        }
    }
    for c in re(
        r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+([A-Za-z_][A-Za-z0-9_]*)",
        &RE_TRACE,
    )
    .captures_iter(md)
    {
        syms.push(c[1].to_string());
    }
    syms.sort();
    syms.dedup();
    syms.retain(|s| !STD_FUNCS.contains(&s.as_str()) && !s.starts_with("__"));
    a.symbols = syms.clone();

    // Archivos fuente citados (opcionalmente con :línea)
    let mut files: Vec<(String, Option<usize>)> = Vec::new();
    for c in re(
        r"\b((?:[\w.-]+/)*[\w-]+\.(?:c|h|cc|cpp|rs|py|js|go|json|php|java))(?::(\d+))?\b",
        &RE_FILE,
    )
    .captures_iter(md)
    {
        let f = c[1].to_string();
        if f.starts_with("www.") || f.contains("example") {
            continue;
        }
        files.push((f, c.get(2).and_then(|m| m.as_str().parse().ok())));
    }
    // Un archivo por nombre; si alguna mención trae línea, se conserva esa.
    files.sort_by(|x, y| x.0.cmp(&y.0).then(y.1.cmp(&x.1)));
    files.dedup_by(|a, b| a.0 == b.0);
    a.files = files.iter().map(|(f, _)| f.clone()).collect();

    if let Some(p) = project {
        for s in &syms {
            if p.symbol_exists(s) {
                a.verified_symbols.push(s.clone());
            } else {
                a.hard.push(sig(
                    "HALLUCINATED_SYMBOL",
                    3,
                    format!("{s}() no existe en el árbol"),
                ));
            }
        }
        for (f, line) in &files {
            match p.file_exists(f) {
                None => a.hard.push(sig(
                    "HALLUCINATED_FILE",
                    3,
                    format!("{f} no existe en el árbol"),
                )),
                Some(content) => {
                    let n = content.lines().count();
                    match line {
                        Some(l) if *l > n => a.hard.push(sig(
                            "LINE_OUT_OF_RANGE",
                            3,
                            format!("{f}:{l} pero el archivo tiene {n} líneas"),
                        )),
                        Some(_) => a.human.push(sig("VERIFIED_FILE_LINE", 1, f.clone())),
                        None => {}
                    }
                }
            }
        }
    }

    // PoC en el texto
    a.has_poc_section = lower.contains("proof of concept")
        || lower.contains("## poc")
        || lower.contains("poc:")
        || lower.contains("steps to reproduce")
        || lower.contains("reproducir")
        || lower.contains("reproduce");
    for ph in PLACEHOLDER_POC {
        if lower.contains(ph) {
            a.hard.push(sig(
                "PLACEHOLDER_POC",
                3,
                format!("PoC de plantilla: {ph:?}"),
            ));
            break;
        }
    }
    if !a.has_poc_section {
        a.soft
            .push(sig("NO_REPRO_STEPS", 1, "sin pasos de reproducción".into()));
    }

    // Estilo
    let filler: Vec<&str> = FILLER
        .iter()
        .copied()
        .filter(|f| lower.contains(f))
        .collect();
    if !filler.is_empty() {
        a.soft.push(sig(
            "FILLER_PHRASES",
            (filler.len() as i32).min(4),
            filler.join(", "),
        ));
    }
    let tmpl: Vec<&str> = TEMPLATE
        .iter()
        .copied()
        .filter(|f| lower.contains(f))
        .collect();
    if tmpl.len() >= 2 {
        a.soft.push(sig(
            "BOUNTY_TEMPLATE",
            ((tmpl.len() as i32) - 1).min(3),
            tmpl.join(", "),
        ));
    }
    if lower.contains("dear security team") || lower.contains("dear team") {
        a.soft.push(sig("FORMAL_LETTER", 1, "carta formal".into()));
    }
    let hedges = HEDGES.iter().filter(|h| lower.contains(*h)).count() as i32;
    if hedges > 0 {
        a.soft
            .push(sig("HEDGING", hedges.min(2), format!("{hedges} hedges")));
    }
    for h in PLACEHOLDER_HOSTS {
        if lower.contains(h) {
            a.soft
                .push(sig("PLACEHOLDER_HOST", 2, format!("host genérico {h}")));
            break;
        }
    }
    if let Some(c) = re(r"(?i)cvss[^0-9\n]{0,20}(\d{1,2}\.\d)", &RE_CVSS).captures(md) {
        if c[1].parse::<f32>().unwrap_or(0.0) >= 9.0 {
            a.claims_critical = true;
        }
    }
    if lower.contains("severity: critical") || lower.contains("severidad: crítica") {
        a.claims_critical = true;
    }

    // Indicadores humanos/verificables
    if re(r"\b[0-9a-f]{12,40}\b", &RE_COMMIT).is_match(md) {
        a.human.push(sig("COMMIT_REF", 1, "cita commit".into()));
    }
    if re(r"(?i)\bv?\d+\.\d+\.\d+\b", &RE_VERSION).is_match(&prose) {
        a.human
            .push(sig("EXACT_VERSION", 1, "versión exacta".into()));
    }
    a
}

fn sig(code: &'static str, weight: i32, detail: String) -> Signal {
    Signal {
        code,
        weight,
        detail,
    }
}

/// Números de CVE típicos de plantillas LLM: 12345, 1234, 99999, dígitos repetidos.
pub fn is_suspicious_cve_num(num: &str) -> bool {
    let b = num.as_bytes();
    let all_same = b.iter().all(|c| *c == b[0]);
    let ascending = b.windows(2).all(|w| w[1] == w[0] + 1);
    let zeros = num.trim_end_matches('0').len() <= 1;
    all_same || ascending || zeros
}

/// Quita bloques ``` ... ``` para que el código del PoC no cuente como prosa.
pub fn strip_code(md: &str) -> String {
    re(r"(?s)```.*?```", &RE_FENCE)
        .replace_all(md, " ")
        .into_owned()
}

/// ¿El adjunto está vacío o es solo espacios?
pub fn poc_is_empty(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| b.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_patterns() {
        assert!(is_suspicious_cve_num("12345"));
        assert!(is_suspicious_cve_num("99999"));
        assert!(is_suspicious_cve_num("10000"));
        assert!(!is_suspicious_cve_num("38545"));
    }

    #[test]
    fn future_cve_is_hard() {
        let a = analyze("See CVE-2031-44120 for details.", None, 2026);
        assert_eq!(a.hard[0].code, "INVENTED_CVE");
    }

    #[test]
    fn real_cve_shape_is_not_hard() {
        let a = analyze("Similar to CVE-2023-38545.", None, 2026);
        assert!(a.hard.is_empty());
    }

    #[test]
    fn code_blocks_do_not_count_as_prose() {
        let s = strip_code("text ```\nrequests.post_data()\n``` more");
        assert!(!s.contains("post_data"));
    }

    #[test]
    fn std_funcs_are_not_hallucinations() {
        let a = analyze("The call to `memcpy()` overflows.", None, 2026);
        assert!(a.symbols.is_empty());
    }

    #[test]
    fn empty_poc() {
        assert!(poc_is_empty(b""));
        assert!(poc_is_empty(b" \n\t"));
        assert!(!poc_is_empty(b"\x01"));
    }
}
