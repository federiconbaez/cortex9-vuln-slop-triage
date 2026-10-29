//! vuln-slop-triage: triage de reportes de vulnerabilidades.
//!
//! El veredicto se apoya primero en evidencia independiente del texto
//! (reproducir el PoC contra el objetivo con un oráculo: crash, timeout o
//! fuga de un canario aleatorio) y solo después en señales textuales.

pub mod dup;
pub mod harness;
pub mod measure;
pub mod project;
pub mod report;
pub mod triage;

pub use triage::{triage, TriageInput, Verdict, VerdictKind};
