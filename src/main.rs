use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use vuln_slop_triage::dup;
use vuln_slop_triage::harness::{HarnessCfg, Net, Sandbox};
use vuln_slop_triage::measure;
use vuln_slop_triage::project::Project;
use vuln_slop_triage::triage::{triage, TriageInput, VerdictKind};

#[derive(Parser)]
#[command(
    version,
    about = "Triage de reportes de vulnerabilidades: AUTO_CLOSE | NEEDS_HUMAN | PRIORITIZE"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args, Clone)]
struct HarnessArgs {
    /// No ejecutar el PoC (solo análisis estático).
    #[arg(long)]
    no_run: bool,
    #[arg(long, value_enum, default_value = "local")]
    sandbox: Sandbox,
    #[arg(long, value_enum, default_value = "isolate")]
    net: Net,
    /// Timeout por ejecución, en milisegundos.
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
    #[arg(long, default_value = "ubuntu:24.04")]
    docker_image: String,
    /// Año de referencia para detectar CVEs con año imposible (default: año actual UTC).
    #[arg(long)]
    year: Option<u32>,
}

impl HarnessArgs {
    fn cfg(&self) -> Option<HarnessCfg> {
        (!self.no_run).then(|| HarnessCfg {
            sandbox: self.sandbox,
            net: self.net,
            timeout: Duration::from_millis(self.timeout_ms),
            docker_image: self.docker_image.clone(),
        })
    }
    fn year(&self) -> u32 {
        self.year.unwrap_or_else(current_year)
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Triage de un reporte. Imprime el veredicto JSON. Exit: 0 PRIORITIZE, 10 NEEDS_HUMAN, 20 AUTO_CLOSE, 2 error.
    Triage {
        report: PathBuf,
        #[arg(long)]
        poc: Option<PathBuf>,
        #[arg(long)]
        project: Option<PathBuf>,
        /// Índice de reportes conocidos (JSON) para detectar duplicados.
        #[arg(long)]
        known: Option<PathBuf>,
        #[command(flatten)]
        h: HarnessArgs,
    },
    /// Mide el corpus etiquetado. Exit 0 si pasa todos los umbrales.
    Measure {
        labels: PathBuf,
        /// Imprimir también las filas por reporte.
        #[arg(long)]
        rows: bool,
        /// Informar sin fallar (exit 0 aunque no pase umbrales). El JSON dice pass=false igual.
        #[arg(long)]
        no_gate: bool,
        #[command(flatten)]
        h: HarnessArgs,
    },
}

fn current_year() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Aproximación suficiente para el corte de año de un CVE.
    1970 + (secs / 31_556_952) as u32
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn main() -> ExitCode {
    match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    match Cli::parse().cmd {
        Cmd::Triage {
            report,
            poc,
            project,
            known,
            h,
        } => {
            let md = String::from_utf8_lossy(&read(&report)?).into_owned();
            let poc = poc.as_deref().map(read).transpose()?;
            let project = project.as_deref().map(Project::load).transpose()?;
            let known = known
                .as_deref()
                .map(dup::load_index)
                .transpose()?
                .unwrap_or_default();
            let cfg = h.cfg();
            let v = triage(&TriageInput {
                report_md: &md,
                poc: poc.as_deref(),
                project: project.as_ref(),
                known: &known,
                harness: cfg.as_ref(),
                current_year: h.year(),
            })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
            );
            Ok(ExitCode::from(match v.verdict {
                VerdictKind::Prioritize => 0,
                VerdictKind::NeedsHuman => 10,
                VerdictKind::AutoClose => 20,
            }))
        }
        Cmd::Measure {
            labels,
            rows,
            no_gate,
            h,
        } => {
            let cfg = h.cfg();
            let mut rep = measure::run(&labels, cfg.as_ref(), h.year())?;
            if !rows {
                rep.rows.clear();
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&rep).map_err(|e| e.to_string())?
            );
            eprintln!(
                "n={} autoclose_precision={:.4} ({}/{}) slop_recall={:.4} valid_closed={}/{} \
                 valid_poc_repro={}/{} dup_detected={}/{} controls+={} controls-={} \
                 mean_ms={:.1} max_ms={} sandbox={:?} pass={}",
                rep.n,
                rep.autoclose_precision,
                rep.autoclose_slop,
                rep.autoclose_total,
                rep.slop_recall,
                rep.valid_closed,
                rep.n_valid,
                rep.valid_poc_reproduced,
                rep.valid_with_poc,
                rep.dup_detected,
                rep.n_dup,
                rep.positive_controls_ok,
                rep.negative_controls_ok,
                rep.mean_ms,
                rep.max_ms,
                rep.sandbox.as_deref().unwrap_or("no-run"),
                rep.pass
            );
            Ok(if rep.pass || no_gate {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
    }
}
