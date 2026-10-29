//! Configuración del mantenedor: objetivos ejecutables, fuentes y CVEs conocidos.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    pub name: String,
    /// Binario relativo al directorio del proyecto. Recibe el PoC por stdin.
    pub bin: String,
    /// Funciones que implementa este objetivo (para atar reporte y objetivo).
    #[serde(default)]
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProjectFile {
    pub name: String,
    pub source_dir: String,
    #[serde(default)]
    pub known_cves: Vec<String>,
    #[serde(default)]
    pub support_dirs: Vec<String>,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone)]
pub struct Project {
    pub root: PathBuf,
    pub cfg: ProjectFile,
    /// (ruta relativa, contenido) de cada archivo fuente.
    pub sources: Vec<(String, String)>,
}

impl Project {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let cfg: ProjectFile =
            serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let mut sources = Vec::new();
        collect(&root.join(&cfg.source_dir), &root, &mut sources);
        sources.sort();
        Ok(Self { root, cfg, sources })
    }

    pub fn file_exists(&self, rel: &str) -> Option<&str> {
        let base = rel.rsplit('/').next().unwrap_or(rel);
        self.sources
            .iter()
            .find(|(p, _)| p.ends_with(rel) || p.rsplit('/').next() == Some(base))
            .map(|(_, c)| c.as_str())
    }

    pub fn symbol_exists(&self, sym: &str) -> bool {
        self.sources.iter().any(|(_, c)| contains_word(c, sym))
    }
}

fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, root, out);
        } else if let Ok(c) = fs::read_to_string(&p) {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .to_string();
            out.push((rel, c));
        }
    }
}

pub fn contains_word(hay: &str, w: &str) -> bool {
    let b = hay.as_bytes();
    let isw = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut start = 0;
    while let Some(i) = hay[start..].find(w) {
        let s = start + i;
        let e = s + w.len();
        if (s == 0 || !isw(b[s - 1])) && (e >= b.len() || !isw(b[e])) {
            return true;
        }
        start = s + 1;
    }
    false
}
