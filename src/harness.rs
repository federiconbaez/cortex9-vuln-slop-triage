//! Harness de reproducción de PoC.
//!
//! El PoC del reportante es **solo datos**: se entrega por stdin a un binario
//! que define el mantenedor. El oráculo no lee el texto del reporte:
//! - `crash`: el proceso termina por señal (SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE);
//! - `timeout`: no termina dentro del límite (DoS);
//! - `canary_leak`: la salida contiene un canario aleatorio escrito fuera del
//!   directorio servido en cada corrida (el reportante no puede adivinarlo).

use crate::project::Project;
use serde::Serialize;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Sandbox {
    /// tmpdir + entorno vacío + timeout; red aislada con `unshare -rn`.
    Local,
    /// `docker run --network=none`; falla si docker no está.
    Docker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Net {
    /// Exigir aislamiento de red (unshare -rn o docker --network=none). Si no se puede, error.
    Isolate,
    /// Sin aislamiento de red (solo para depurar; queda registrado en el veredicto).
    Host,
}

#[derive(Debug, Clone)]
pub struct HarnessCfg {
    pub sandbox: Sandbox,
    pub net: Net,
    pub timeout: Duration,
    pub docker_image: String,
}

impl Default for HarnessCfg {
    fn default() -> Self {
        Self {
            sandbox: Sandbox::Local,
            net: Net::Isolate,
            timeout: Duration::from_secs(2),
            docker_image: "ubuntu:24.04".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Exited,
    Signaled,
    Timeout,
}

#[derive(Debug, Clone, Serialize)]
pub struct Run {
    pub target: String,
    pub outcome: Outcome,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    /// Oráculo disparado: crash | timeout | canary_leak.
    pub oracle: Option<String>,
    pub duration_ms: u128,
}

#[derive(Debug)]
pub enum HarnessError {
    Unavailable(String),
    Io(String),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(s) => write!(f, "sandbox no disponible: {s}"),
            Self::Io(s) => write!(f, "io: {s}"),
        }
    }
}

const CRASH_SIGNALS: &[i32] = &[4, 6, 7, 8, 11]; // SIGILL SIGABRT SIGBUS SIGFPE SIGSEGV

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Verifica de antemano que el sandbox pedido existe. Nunca degrada en silencio.
pub fn preflight(cfg: &HarnessCfg) -> Result<String, HarnessError> {
    match cfg.sandbox {
        Sandbox::Docker => {
            let ok = Command::new("docker")
                .args(["version", "--format", "{{.Server.Version}}"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .map_err(|e| HarnessError::Unavailable(format!("docker no instalado: {e}")))?;
            if !ok.status.success() {
                return Err(HarnessError::Unavailable(
                    "docker instalado pero el daemon no responde".into(),
                ));
            }
            Ok(format!(
                "docker {} --network=none",
                String::from_utf8_lossy(&ok.stdout).trim()
            ))
        }
        Sandbox::Local => match cfg.net {
            Net::Host => Ok("local tmpdir, red del host (sin aislar)".into()),
            Net::Isolate => {
                let st = Command::new("unshare")
                    .args(["-rn", "true"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map_err(|e| HarnessError::Unavailable(format!("unshare: {e}")))?;
                if st.success() {
                    Ok("local tmpdir + unshare -rn (sin red)".into())
                } else {
                    Err(HarnessError::Unavailable(
                        "unshare -rn falló (user namespaces sin privilegios deshabilitados); \
                         usar --sandbox docker o --net host explícito"
                            .into(),
                    ))
                }
            }
        },
    }
}

fn rand_hex() -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut s: String = b.iter().map(|x| format!("{x:02x}")).collect();
    s.push_str(&format!("{seq:x}{:x}", nanos & 0xffff));
    s
}

struct TmpDir(PathBuf);
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let p = e.path();
        let d = dst.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &d)?;
        } else {
            fs::copy(&p, &d)?;
        }
    }
    Ok(())
}

/// Corre el PoC contra un objetivo y aplica el oráculo.
pub fn run_target(
    project: &Project,
    target: &crate::project::Target,
    poc: &[u8],
    cfg: &HarnessCfg,
) -> Result<Run, HarnessError> {
    let io = |e: std::io::Error| HarnessError::Io(e.to_string());
    let base = std::env::temp_dir().join(format!("vst-{}", rand_hex()));
    let guard = TmpDir(base.clone());
    let sb = base.join("sb");
    fs::create_dir_all(sb.join("bin")).map_err(io)?;
    fs::create_dir_all(sb.join("secret")).map_err(io)?;
    for d in &project.cfg.support_dirs {
        copy_dir(&project.root.join(d), &sb.join(d)).map_err(io)?;
    }
    let bin_src = project.root.join(&target.bin);
    let bin_name = Path::new(&target.bin)
        .file_name()
        .ok_or_else(|| HarnessError::Io("bin sin nombre".into()))?;
    fs::copy(&bin_src, sb.join("bin").join(bin_name))
        .map_err(|e| HarnessError::Io(format!("{}: {e}", bin_src.display())))?;
    let canary = rand_hex();
    fs::write(sb.join("secret").join("canary.txt"), &canary).map_err(io)?;
    let poc_path = base.join("poc.bin");
    fs::write(&poc_path, poc).map_err(io)?;
    let out_path = base.join("stdout");
    let err_path = base.join("stderr");
    let rel_bin = format!("./bin/{}", bin_name.to_string_lossy());

    let mut cmd = match cfg.sandbox {
        Sandbox::Local => {
            let mut c = match cfg.net {
                Net::Isolate => {
                    let mut c = Command::new("unshare");
                    c.args(["-rn", "--", &rel_bin]);
                    c
                }
                Net::Host => Command::new(&rel_bin),
            };
            c.current_dir(&sb)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LANG", "C");
            c
        }
        Sandbox::Docker => {
            let mut c = Command::new("docker");
            let secs = cfg.timeout.as_secs_f64().max(0.1);
            c.args(["run", "--rm", "-i", "--network=none", "--cap-drop=ALL"])
                .args(["--security-opt", "no-new-privileges"])
                .args(["--pids-limit", "64", "--memory", "256m"])
                .arg("-v")
                .arg(format!("{}:/sb", sb.display()))
                .args(["-w", "/sb", &cfg.docker_image])
                .args(["timeout", &format!("{secs}"), &rel_bin]);
            c
        }
    };
    cmd.stdin(fs::File::open(&poc_path).map_err(io)?)
        .stdout(fs::File::create(&out_path).map_err(io)?)
        .stderr(fs::File::create(&err_path).map_err(io)?);

    let start = Instant::now();
    let mut child = cmd.spawn().map_err(|e| {
        HarnessError::Unavailable(format!("no se pudo lanzar {:?}: {e}", cmd.get_program()))
    })?;
    // En docker el timeout lo aplica `timeout` adentro; acá dejamos margen para el arranque.
    let deadline = match cfg.sandbox {
        Sandbox::Local => cfg.timeout,
        Sandbox::Docker => cfg.timeout + Duration::from_secs(60),
    };
    let status = loop {
        if let Some(st) = child.try_wait().map_err(io)? {
            break Some(st);
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let duration_ms = start.elapsed().as_millis();
    let stdout = fs::read(&out_path).unwrap_or_default();
    let stderr = fs::read(&err_path).unwrap_or_default();

    let (outcome, exit_code, signal) = match status {
        None => (Outcome::Timeout, None, None),
        Some(st) => {
            use std::os::unix::process::ExitStatusExt;
            if let Some(s) = st.signal() {
                (Outcome::Signaled, None, Some(s))
            } else {
                let code = st.code().unwrap_or(-1);
                match (cfg.sandbox, code) {
                    // `timeout` de coreutils: 124 = venció; 128+N = el hijo murió por señal N.
                    (Sandbox::Docker, 124) => (Outcome::Timeout, Some(code), None),
                    (Sandbox::Docker, c) if (129..=159).contains(&c) => {
                        (Outcome::Signaled, Some(c), Some(c - 128))
                    }
                    (Sandbox::Docker, 125..=127) => {
                        return Err(HarnessError::Unavailable(format!(
                            "docker run falló ({code}): {}",
                            String::from_utf8_lossy(&stderr).trim()
                        )))
                    }
                    _ => (Outcome::Exited, Some(code), None),
                }
            }
        }
    };
    if cfg.sandbox == Sandbox::Local && cfg.net == Net::Isolate && outcome == Outcome::Exited {
        // unshare devuelve 1 y escribe en stderr si no pudo crear el namespace.
        let e = String::from_utf8_lossy(&stderr);
        if e.contains("unshare failed") || e.starts_with("unshare:") {
            return Err(HarnessError::Unavailable(e.trim().to_string()));
        }
    }
    let leaked = contains(&stdout, canary.as_bytes()) || contains(&stderr, canary.as_bytes());
    let oracle = if leaked {
        Some("canary_leak".to_string())
    } else if outcome == Outcome::Timeout {
        Some("timeout".to_string())
    } else if outcome == Outcome::Signaled && signal.is_some_and(|s| CRASH_SIGNALS.contains(&s)) {
        Some("crash".to_string())
    } else {
        None
    };
    drop(guard);
    Ok(Run {
        target: target.name.clone(),
        outcome,
        exit_code,
        signal,
        oracle,
        duration_ms,
    })
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}
