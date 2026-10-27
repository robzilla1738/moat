//! Recognizer packs: data-only descriptions of software families.
//!
//! A recognizer combines signatures, executable paths, package metadata and entrypoints. Filenames and
//! environment variables are *hints* until bound by signing or an authenticated launcher. A process named `curl`
//! or `python3` is not suspicious by itself; who launched it, under what policy, is what matters.
//!
//! Packs adapt Digital Kingdom's extension manifest idea (`docs/EXTENSIONS.md` @ e0452c8): declarative manifest,
//! version, digest, fixtures, revocation. No scripts and no remotely supplied executable plugins.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::AppIdentity;
use crate::net::Confidence;

pub const RECOGNIZER_SCHEMA: &str = "moat.recognizer_pack.v1";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    LocalInference,
    CodingAgent,
    McpServer,
    PackageManager,
    Shell,
    NetworkTool,
    Interpreter,
    Browser,
    Broker,
    Service,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::LocalInference => "local inference",
            Category::CodingAgent => "coding agent",
            Category::McpServer => "MCP server",
            Category::PackageManager => "package manager",
            Category::Shell => "shell",
            Category::NetworkTool => "network tool",
            Category::Interpreter => "interpreter",
            Category::Browser => "browser",
            Category::Broker => "broker",
            Category::Service => "service",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    /// Executable basenames.
    #[serde(default)]
    pub executables: Vec<String>,
    /// Path substrings (e.g. `/LM Studio.app/`, `/.ollama/`).
    #[serde(default)]
    pub path_contains: Vec<String>,
    #[serde(default)]
    pub bundle_ids: Vec<String>,
    #[serde(default)]
    pub team_ids: Vec<String>,
    /// Interpreter entrypoints (module or script basename) such as `mlx_lm.server`; matched only when the
    /// observer supplies a minimized entrypoint, never a full command line.
    #[serde(default)]
    pub entrypoints: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Recognizer {
    pub family: String,
    pub display_name: String,
    pub category: Category,
    #[serde(rename = "match")]
    pub spec: MatchSpec,
    /// Suggested profile during onboarding. Never applied automatically without the owner choosing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecognizerPack {
    pub schema: String,
    pub id: String,
    pub version: String,
    pub description: String,
    pub recognizers: Vec<Recognizer>,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Recognition {
    pub family: String,
    pub display_name: String,
    pub category: Category,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    /// True only when bound by signing identity. Otherwise a hint.
    pub bound: bool,
    pub profile_hint: Option<String>,
    pub pack: String,
}

impl RecognizerPack {
    pub fn parse(json: &str) -> Result<Self, String> {
        let p: RecognizerPack = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if p.schema != RECOGNIZER_SCHEMA {
            return Err(format!("unexpected schema {}", p.schema));
        }
        let mut fams = std::collections::BTreeSet::new();
        for r in &p.recognizers {
            if !fams.insert(&r.family) {
                return Err(format!("duplicate family {}", r.family));
            }
            let s = &r.spec;
            if s.executables.is_empty()
                && s.path_contains.is_empty()
                && s.bundle_ids.is_empty()
                && s.team_ids.is_empty()
                && s.entrypoints.is_empty()
            {
                return Err(format!("{} has an empty match", r.family));
            }
        }
        Ok(p)
    }

    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(serde_json::to_vec(self).unwrap()))
    }
}

/// Built-in packs shipped with Moat.
pub fn builtin_packs() -> Vec<RecognizerPack> {
    vec![
        RecognizerPack::parse(include_str!("../../../packs/recognizers/local-inference.json")).expect("builtin pack"),
        RecognizerPack::parse(include_str!("../../../packs/recognizers/agents-and-tools.json")).expect("builtin pack"),
    ]
}

/// Recognize an app. `entrypoint` is an optional minimized interpreter entrypoint (module/script name only).
pub fn recognize(packs: &[RecognizerPack], app: &AppIdentity, entrypoint: Option<&str>) -> Option<Recognition> {
    let mut best: Option<Recognition> = None;
    for pack in packs.iter().filter(|p| !p.revoked) {
        for r in &pack.recognizers {
            let s = &r.spec;
            let mut ev = Vec::new();
            let mut score = 0u8;
            let mut bound = false;
            if let (Some(b), false) = (&app.bundle_id, s.bundle_ids.is_empty()) {
                if s.bundle_ids.contains(b) {
                    ev.push(format!("bundle id {b}"));
                    score += 1;
                }
            }
            if let (Some(t), false) = (&app.team_id, s.team_ids.is_empty()) {
                if s.team_ids.contains(t) {
                    ev.push(format!("signing team {t}"));
                    score += 2;
                    bound = app.is_signed();
                }
            }
            if let Some(base) = app.executable_basename() {
                if s.executables.iter().any(|e| e == base) {
                    ev.push(format!("executable name {base}"));
                    score += 1;
                }
            }
            if let Some(path) = &app.executable {
                if let Some(pc) = s.path_contains.iter().find(|pc| path.contains(pc.as_str())) {
                    ev.push(format!("path contains {pc}"));
                    score += 1;
                }
            }
            if let Some(ep) = entrypoint {
                if s.entrypoints.iter().any(|e| e == ep) {
                    ev.push(format!("entrypoint {ep}"));
                    score += 2;
                }
            }
            if score == 0 {
                continue;
            }
            let confidence = if bound {
                Confidence::High
            } else if score >= 2 {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let cand = Recognition {
                family: r.family.clone(),
                display_name: r.display_name.clone(),
                category: r.category,
                confidence,
                evidence: ev,
                bound,
                profile_hint: r.profile_hint.clone(),
                pack: format!("{}@{}", pack.id, pack.version),
            };
            let better = match &best {
                None => true,
                Some(b) => (cand.bound, cand.confidence, cand.evidence.len()) > (b.bound, b.confidence, b.evidence.len()),
            };
            if better {
                best = Some(cand);
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(path: &str) -> AppIdentity {
        AppIdentity { executable: Some(path.into()), ..Default::default() }
    }

    #[test]
    fn builtin_packs_parse() {
        let p = builtin_packs();
        assert!(p.iter().map(|x| x.recognizers.len()).sum::<usize>() >= 15);
    }

    #[test]
    fn recognizes_inference_runtimes() {
        let p = builtin_packs();
        let r = recognize(&p, &app("/usr/local/bin/ollama"), None).unwrap();
        assert_eq!(r.family, "ollama");
        assert_eq!(r.category, Category::LocalInference);
        assert!(!r.bound, "a filename alone is a hint");
        let r = recognize(&p, &app("/Applications/LM Studio.app/Contents/MacOS/LM Studio"), None).unwrap();
        assert_eq!(r.family, "lm-studio");
        let r = recognize(&p, &app("/opt/homebrew/bin/llama-server"), None).unwrap();
        assert_eq!(r.family, "llama.cpp");
        let r = recognize(&p, &app("/usr/bin/python3"), Some("mlx_lm.server")).unwrap();
        assert_eq!(r.family, "mlx-lm");
        let r = recognize(&p, &app("/usr/bin/python3"), Some("vllm.entrypoints.openai.api_server")).unwrap();
        assert_eq!(r.family, "vllm");
    }

    #[test]
    fn recognizes_agents_and_package_managers() {
        let p = builtin_packs();
        assert_eq!(recognize(&p, &app("/Users/r/.local/bin/claude"), None).unwrap().family, "claude-code");
        assert_eq!(recognize(&p, &app("/opt/homebrew/bin/npm"), None).unwrap().category, Category::PackageManager);
        assert_eq!(recognize(&p, &app("/usr/bin/curl"), None).unwrap().category, Category::NetworkTool);
        assert!(recognize(&p, &app("/usr/bin/some-random-thing"), None).is_none());
    }

    #[test]
    fn revoked_packs_are_ignored() {
        let mut p = builtin_packs();
        for x in &mut p {
            x.revoked = true;
        }
        assert!(recognize(&p, &app("/usr/local/bin/ollama"), None).is_none());
    }
}
