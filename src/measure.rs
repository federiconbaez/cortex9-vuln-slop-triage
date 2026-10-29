//! Medición sobre un corpus etiquetado (`labels.json`). Escala a cualquier
//! tamaño: solo hay que agregar ítems al JSON.

use crate::dup::{self, Known};
use crate::harness::HarnessCfg;
use crate::project::Project;
use crate::triage::{triage, TriageInput, VerdictKind};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Labels {
    pub project: String,
    pub known: Option<String>,
    pub items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
pub struct Item {
    pub id: String,
    pub report: String,
    pub poc: Option<String>,
    /// slop | valid | dup
    pub label: String,
    pub dup_of: Option<String>,
    /// positive (debe cerrarse) | negative (no debe cerrarse)
    pub control: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Row {
    pub id: String,
    pub label: String,
    pub verdict: VerdictKind,
    pub duplicate_of: Option<String>,
    pub reproduced: bool,
    pub elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct Thresholds {
    pub autoclose_precision_min: f64,
    pub valid_closed_rate_max: f64,
    pub valid_poc_repro_min: f64,
    pub mean_ms_max: f64,
}

pub const THRESHOLDS: Thresholds = Thresholds {
    autoclose_precision_min: 0.95,
    valid_closed_rate_max: 0.05,
    valid_poc_repro_min: 0.80,
    mean_ms_max: 90_000.0,
};

#[derive(Debug, Serialize)]
pub struct Report {
    pub n: usize,
    pub n_slop: usize,
    pub n_valid: usize,
    pub n_dup: usize,
    pub autoclose_total: usize,
    pub autoclose_slop: usize,
    pub autoclose_precision: f64,
    pub slop_recall: f64,
    pub valid_closed: usize,
    pub valid_closed_rate: f64,
    pub valid_with_poc: usize,
    pub valid_poc_reproduced: usize,
    pub valid_poc_repro_rate: f64,
    pub dup_detected: usize,
    pub dup_closed: usize,
    pub positive_controls_ok: String,
    pub negative_controls_ok: String,
    pub mean_ms: f64,
    pub max_ms: u128,
    pub sandbox: Option<String>,
    pub pass: bool,
    pub failures: Vec<String>,
    pub rows: Vec<Row>,
}

fn ratio(a: usize, b: usize) -> f64 {
    if b == 0 {
        0.0
    } else {
        a as f64 / b as f64
    }
}

pub fn run(labels_path: &Path, cfg: Option<&HarnessCfg>, year: u32) -> Result<Report, String> {
    let dir = labels_path.parent().unwrap_or(Path::new("."));
    let raw = fs::read_to_string(labels_path).map_err(|e| e.to_string())?;
    let labels: Labels = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let project = Project::load(&dir.join(&labels.project))?;
    let known: Vec<Known> = match &labels.known {
        Some(k) => dup::load_index(&dir.join(k))?,
        None => vec![],
    };
    let mut rows = Vec::new();
    let mut sandbox = None;
    let (mut pos_ok, mut pos_n, mut neg_ok, mut neg_n) = (0, 0, 0, 0);
    for it in &labels.items {
        let md =
            fs::read_to_string(dir.join(&it.report)).map_err(|e| format!("{}: {e}", it.report))?;
        let poc = match &it.poc {
            Some(p) => Some(fs::read(dir.join(p)).map_err(|e| format!("{p}: {e}"))?),
            None => None,
        };
        let v = triage(&TriageInput {
            report_md: &md,
            poc: poc.as_deref(),
            project: Some(&project),
            known: &known,
            harness: cfg,
            current_year: year,
        })?;
        if v.sandbox.is_some() {
            sandbox.clone_from(&v.sandbox);
        }
        match it.control.as_deref() {
            Some("positive") => {
                pos_n += 1;
                pos_ok += usize::from(v.verdict == VerdictKind::AutoClose);
            }
            Some("negative") => {
                neg_n += 1;
                neg_ok += usize::from(v.verdict != VerdictKind::AutoClose);
            }
            _ => {}
        }
        rows.push(Row {
            id: it.id.clone(),
            label: it.label.clone(),
            verdict: v.verdict,
            duplicate_of: v.duplicate_of.map(|d| d.id),
            reproduced: v.poc.reproduced,
            elapsed_ms: v.elapsed_ms,
        });
    }
    let count = |l: &str| rows.iter().filter(|r| r.label == l).count();
    let ac = |l: Option<&str>| {
        rows.iter()
            .filter(|r| r.verdict == VerdictKind::AutoClose && l.is_none_or(|l| r.label == l))
            .count()
    };
    let n_slop = count("slop");
    let n_valid = count("valid");
    let n_dup = count("dup");
    let autoclose_total = ac(None);
    let autoclose_slop = ac(Some("slop"));
    let valid_closed = ac(Some("valid"));
    let mut valid_with_poc = 0;
    let mut valid_poc_reproduced = 0;
    let mut dup_detected = 0;
    for (r, it) in rows.iter().zip(&labels.items) {
        if it.label == "valid" && it.poc.is_some() {
            valid_with_poc += 1;
            valid_poc_reproduced += usize::from(r.reproduced);
        }
        if it.label == "dup" && r.duplicate_of.is_some() && r.duplicate_of == it.dup_of {
            dup_detected += 1;
        }
    }
    let total_ms: u128 = rows.iter().map(|r| r.elapsed_ms).sum();
    let mean_ms = if rows.is_empty() {
        0.0
    } else {
        total_ms as f64 / rows.len() as f64
    };
    let mut rep = Report {
        n: rows.len(),
        n_slop,
        n_valid,
        n_dup,
        autoclose_total,
        autoclose_slop,
        autoclose_precision: ratio(autoclose_slop, autoclose_total),
        slop_recall: ratio(autoclose_slop, n_slop),
        valid_closed,
        valid_closed_rate: ratio(valid_closed, n_valid),
        valid_with_poc,
        valid_poc_reproduced,
        valid_poc_repro_rate: ratio(valid_poc_reproduced, valid_with_poc),
        dup_detected,
        dup_closed: ac(Some("dup")),
        positive_controls_ok: format!("{pos_ok}/{pos_n}"),
        negative_controls_ok: format!("{neg_ok}/{neg_n}"),
        mean_ms,
        max_ms: rows.iter().map(|r| r.elapsed_ms).max().unwrap_or(0),
        sandbox,
        pass: false,
        failures: vec![],
        rows,
    };
    let t = &THRESHOLDS;
    let f = &mut rep.failures;
    if rep.autoclose_precision < t.autoclose_precision_min {
        f.push(format!(
            "autoclose_precision {:.3}",
            rep.autoclose_precision
        ));
    }
    if rep.valid_closed_rate > t.valid_closed_rate_max {
        f.push(format!("valid_closed_rate {:.3}", rep.valid_closed_rate));
    }
    if cfg.is_some() && rep.valid_poc_repro_rate < t.valid_poc_repro_min {
        f.push(format!(
            "valid_poc_repro_rate {:.3}",
            rep.valid_poc_repro_rate
        ));
    }
    if rep.mean_ms > t.mean_ms_max {
        f.push(format!("mean_ms {:.0}", rep.mean_ms));
    }
    if pos_ok != pos_n {
        f.push(format!("positive_controls {pos_ok}/{pos_n}"));
    }
    if neg_ok != neg_n {
        f.push(format!("negative_controls {neg_ok}/{neg_n}"));
    }
    rep.pass = rep.failures.is_empty();
    Ok(rep)
}
