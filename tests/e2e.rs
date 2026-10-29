//! Pruebas de punta a punta sobre el corpus y el harness.
//! Si el sandbox local (unshare -rn) no está disponible, estas pruebas FALLAN:
//! no hay skips silenciosos.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;
use std::time::Duration;
use vuln_slop_triage::harness::{self, HarnessCfg, Net, Sandbox};
use vuln_slop_triage::measure;
use vuln_slop_triage::project::Project;
use vuln_slop_triage::triage::{triage, TriageInput, VerdictKind};

static BUILD: Once = Once::new();

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn build_targets() {
    BUILD.call_once(|| {
        let st = Command::new("sh")
            .arg(root().join("scripts/build-targets.sh"))
            .status()
            .expect("sh");
        assert!(st.success(), "no se pudieron compilar los objetivos");
    });
}

fn cfg() -> HarnessCfg {
    let c = HarnessCfg {
        sandbox: Sandbox::Local,
        net: Net::Isolate,
        timeout: Duration::from_millis(1500),
        docker_image: String::new(),
    };
    harness::preflight(&c).expect("sandbox local con unshare -rn requerido para estas pruebas");
    c
}

fn project() -> Project {
    build_targets();
    Project::load(&root().join("fixtures/project/project.json")).unwrap()
}

fn run_poc(target: &str, poc: &[u8]) -> Option<String> {
    let p = project();
    let t = p.cfg.targets.iter().find(|t| t.name == target).unwrap();
    harness::run_target(&p, t, poc, &cfg()).unwrap().oracle
}

#[test]
fn oracle_crash() {
    let mut poc = vec![0xc8u8];
    poc.extend(std::iter::repeat_n(b'A', 200));
    assert_eq!(run_poc("hdrparse", &poc).as_deref(), Some("crash"));
}

#[test]
fn oracle_timeout() {
    assert_eq!(
        run_poc("rangeparse", b"bytes=5-0\n").as_deref(),
        Some("timeout")
    );
}

#[test]
fn oracle_canary_leak() {
    assert_eq!(
        run_poc("staticsrv", b"../secret/canary.txt\n").as_deref(),
        Some("canary_leak")
    );
}

#[test]
fn benign_inputs_fire_no_oracle() {
    assert_eq!(run_poc("hdrparse", b"\x04abcd"), None);
    assert_eq!(run_poc("rangeparse", b"bytes=0-10\n"), None);
    assert_eq!(run_poc("staticsrv", b"index.html\n"), None);
    assert_eq!(run_poc("chunkdec", b"4\r\nAAAA"), None);
    assert_eq!(run_poc("cookieparse", b"a=b\n"), None);
}

#[test]
fn network_is_isolated_in_local_sandbox() {
    // /proc/net/dev es por network namespace: dentro de unshare -rn solo aparece lo.
    let out = Command::new("unshare")
        .args(["-rn", "--", "cat", "/proc/net/dev"])
        .output()
        .expect("unshare");
    assert!(out.status.success());
    let ifaces: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next().map(|s| s.trim().to_string()))
        .collect();
    assert_eq!(ifaces, vec!["lo".to_string()]);
}

#[test]
fn corpus_meets_thresholds() {
    build_targets();
    let rep = measure::run(
        &root().join("fixtures/corpus/labels.json"),
        Some(&cfg()),
        2026,
    )
    .unwrap();
    assert!(rep.pass, "fallos: {:?}", rep.failures);
    assert_eq!(rep.n, 20);
    assert_eq!((rep.n_slop, rep.n_valid, rep.n_dup), (10, 5, 5));
    assert_eq!(rep.valid_closed, 0);
    assert!(rep.autoclose_precision >= 0.95);
    assert_eq!(rep.positive_controls_ok, "4/4");
    assert_eq!(rep.negative_controls_ok, "5/5");
    assert_eq!(rep.valid_poc_reproduced, rep.valid_with_poc);
}

#[test]
fn heldout_documented_limits() {
    // Set escrito después de fijar umbrales. Fija los números del README, incluido el falso positivo h2.
    build_targets();
    let rep = measure::run(
        &root().join("fixtures/heldout/labels.json"),
        Some(&cfg()),
        2026,
    )
    .unwrap();
    assert!(!rep.pass);
    assert_eq!((rep.autoclose_slop, rep.autoclose_total), (1, 2));
    assert_eq!(rep.valid_closed, 1);
    let h2 = rep.rows.iter().find(|r| r.id == "h2").unwrap();
    assert_eq!(
        h2.verdict,
        VerdictKind::AutoClose,
        "límite conocido: ver README"
    );
}

#[test]
fn polished_ai_style_with_working_poc_is_prioritized() {
    let p = project();
    let md = std::fs::read_to_string(
        root().join("fixtures/corpus/reports/v3-polished-chunk-overflow.md"),
    )
    .unwrap();
    let v = triage(&TriageInput {
        report_md: &md,
        poc: Some(b"ffffffff\r\nAAAA"),
        project: Some(&p),
        known: &[],
        harness: Some(&cfg()),
        current_year: 2026,
    })
    .unwrap();
    assert_eq!(v.verdict, VerdictKind::Prioritize);
}

#[test]
fn same_report_without_running_poc_is_not_closed() {
    let p = project();
    let md = std::fs::read_to_string(
        root().join("fixtures/corpus/reports/v3-polished-chunk-overflow.md"),
    )
    .unwrap();
    let v = triage(&TriageInput {
        report_md: &md,
        poc: Some(b"ffffffff\r\nAAAA"),
        project: Some(&p),
        known: &[],
        harness: None,
        current_year: 2026,
    })
    .unwrap();
    assert_eq!(v.verdict, VerdictKind::NeedsHuman);
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vuln-slop-triage"))
}

#[test]
fn cli_exit_codes() {
    build_targets();
    let r = root();
    let st = cli()
        .arg("triage")
        .arg(r.join("fixtures/corpus/reports/s01-future-cve.md"))
        .args(["--year", "2026", "--project"])
        .arg(r.join("fixtures/project/project.json"))
        .output()
        .unwrap();
    assert_eq!(st.status.code(), Some(20));
    let v: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
    assert_eq!(v["verdict"], "AUTO_CLOSE");
}

#[test]
fn docker_sandbox_fails_loudly_when_docker_missing() {
    let empty = std::env::temp_dir().join("vst-empty-path");
    std::fs::create_dir_all(&empty).unwrap();
    let r = root();
    let out = cli()
        .env("PATH", &empty)
        .arg("triage")
        .arg(r.join("fixtures/corpus/reports/v2-ghsa-cookie-overflow.md"))
        .arg("--poc")
        .arg(r.join("fixtures/corpus/pocs/v2-cookie.txt"))
        .arg("--project")
        .arg(r.join("fixtures/project/project.json"))
        .args(["--sandbox", "docker"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("docker no instalado"));
}

#[test]
fn missing_project_file_is_an_error() {
    assert!(Project::load(Path::new("/nonexistent/project.json")).is_err());
}
