//! Política de veredicto.
//!
//! - PRIORITIZE: el PoC dispara un oráculo y no es duplicado conocido.
//! - AUTO_CLOSE: el PoC no reproduce (o no hay) **y** hay al menos una señal
//!   dura falsable **y** el puntaje blando llega al umbral; o hay ≥2 señales duras.
//! - NEEDS_HUMAN: todo lo demás (incluye duplicados candidatos).
//!
//! La regla es deliberadamente conservadora: un reporte bien escrito por un
//! LLM pero con PoC que reproduce nunca se cierra.

use crate::dup::{self, DupMatch, Fingerprint, Known};
use crate::harness::{self, HarnessCfg, Run};
use crate::project::Project;
use crate::report::{self, Analysis, Signal};
use serde::Serialize;
use std::time::Instant;

pub const SOFT_THRESHOLD: i32 = 3;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerdictKind {
    AutoClose,
    NeedsHuman,
    Prioritize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PocInfo {
    pub provided: bool,
    pub bytes: usize,
    pub empty: bool,
    pub runs: Vec<Run>,
    pub reproduced: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub verdict: VerdictKind,
    pub reasons: Vec<String>,
    pub soft_score: i32,
    pub analysis: Analysis,
    pub poc: PocInfo,
    pub duplicate_of: Option<DupMatch>,
    pub sandbox: Option<String>,
    pub elapsed_ms: u128,
    pub tool_version: &'static str,
}

pub struct TriageInput<'a> {
    pub report_md: &'a str,
    pub poc: Option<&'a [u8]>,
    pub project: Option<&'a Project>,
    pub known: &'a [Known],
    /// `None` = no ejecutar el PoC (solo análisis estático, queda declarado).
    pub harness: Option<&'a HarnessCfg>,
    pub current_year: u32,
}

pub fn triage(inp: &TriageInput) -> Result<Verdict, String> {
    let t0 = Instant::now();
    let mut a = report::analyze(inp.report_md, inp.project, inp.current_year);
    let mut reasons = Vec::new();

    let mut poc = PocInfo {
        provided: inp.poc.is_some(),
        bytes: inp.poc.map_or(0, <[u8]>::len),
        empty: inp.poc.is_some_and(report::poc_is_empty),
        runs: vec![],
        reproduced: false,
    };
    let mut sandbox = None;
    // ¿El PoC se corrió solo contra objetivos atados a símbolos verificados del reporte?
    let mut bound = false;

    if poc.empty {
        a.hard.push(Signal {
            code: "EMPTY_POC",
            weight: 3,
            detail: "adjunto vacío".into(),
        });
    }

    if let (Some(bytes), false, Some(p), Some(cfg)) = (inp.poc, poc.empty, inp.project, inp.harness)
    {
        sandbox = Some(harness::preflight(cfg).map_err(|e| e.to_string())?);
        // Objetivos atados a símbolos verificados del reporte; si no nombra ninguno, todos.
        let mut targets: Vec<_> = p
            .cfg
            .targets
            .iter()
            .filter(|t| t.symbols.iter().any(|s| a.verified_symbols.contains(s)))
            .collect();
        bound = !targets.is_empty();
        if !bound {
            targets = p.cfg.targets.iter().collect();
        }
        for t in targets {
            let r = harness::run_target(p, t, bytes, cfg).map_err(|e| e.to_string())?;
            poc.runs.push(r);
        }
        poc.reproduced = poc.runs.iter().any(|r| r.oracle.is_some());
        if !poc.reproduced {
            a.soft.push(Signal {
                code: "POC_DID_NOT_REPRODUCE",
                weight: 2,
                detail: format!("{} objetivo(s) sin oráculo", poc.runs.len()),
            });
        }
    } else if poc.provided && !poc.empty {
        reasons.push("PoC no ejecutado (sin proyecto o sin harness)".into());
    }

    if a.claims_critical && !poc.reproduced {
        a.soft.push(Signal {
            code: "SEVERITY_INFLATION",
            weight: 2,
            detail: "CVSS≥9/critical sin reproducción".into(),
        });
    }

    // La huella solo vale si es inequívoca: objetivo atado al reporte o un único objetivo con oráculo.
    let hits: Vec<&Run> = poc.runs.iter().filter(|r| r.oracle.is_some()).collect();
    let fp = if bound || hits.len() == 1 {
        hits.first().map(|r| Fingerprint {
            target: r.target.clone(),
            oracle: r.oracle.clone().unwrap_or_default(),
        })
    } else {
        None
    };
    let duplicate_of = dup::find(inp.known, inp.report_md, &a.verified_symbols, fp.as_ref());

    let soft = a.soft_score();
    let hard = a.hard.len();
    let verdict = if poc.reproduced {
        let r = poc
            .runs
            .iter()
            .find(|r| r.oracle.is_some())
            .expect("reproduced");
        reasons.push(format!(
            "PoC reproduce en {}: oráculo {}",
            r.target,
            r.oracle.as_deref().unwrap_or("?")
        ));
        if let Some(d) = &duplicate_of {
            reasons.push(format!("duplicado probable de {} ({})", d.id, d.via));
            VerdictKind::NeedsHuman
        } else {
            VerdictKind::Prioritize
        }
    } else if hard >= 2 || (hard >= 1 && soft >= SOFT_THRESHOLD) {
        for h in &a.hard {
            reasons.push(format!("{}: {}", h.code, h.detail));
        }
        reasons.push(format!("puntaje blando {soft} (umbral {SOFT_THRESHOLD})"));
        VerdictKind::AutoClose
    } else {
        if let Some(d) = &duplicate_of {
            reasons.push(format!("duplicado probable de {} ({})", d.id, d.via));
        }
        reasons.push(format!(
            "sin reproducción; señales duras={hard}, puntaje blando={soft}"
        ));
        VerdictKind::NeedsHuman
    };

    Ok(Verdict {
        verdict,
        reasons,
        soft_score: soft,
        analysis: a,
        poc,
        duplicate_of,
        sandbox,
        elapsed_ms: t0.elapsed().as_millis(),
        tool_version: env!("CARGO_PKG_VERSION"),
    })
}
