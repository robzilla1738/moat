//! Deterministic alert explanations, grounded only in event fields.
//!
//! No language model decides or phrases access decisions. Byte figures appear only when measured, with their
//! scope. A connection blocked before data was sent never reveals what the caller intended to upload.

use serde::{Deserialize, Serialize};

use crate::eval::Verdict;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransferMeasurement {
    /// No counters are available for this flow.
    NotMeasured,
    /// The endpoint blocked at the connect decision; no flow existed.
    BlockedAtConnect { source: String },
    /// Counters exist and show no completed transfer (e.g. no payload bytes after the handshake).
    NoCompletedTransfer { source: String },
    /// Measured bytes with explicit scope (`flow`, `rule`, `report-interval`).
    Measured { bytes_out: u64, bytes_in: u64, scope: String, source: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AlertFacts {
    /// Process chain display names, oldest first. Empty if unknown.
    pub chain: Vec<String>,
    pub chain_complete: bool,
    /// e.g. "HTTPS", "UDP/443 (QUIC)", "TCP/22".
    pub protocol: String,
    /// True when this destination was not seen before *within the retained, covered history*.
    pub first_seen: bool,
    /// e.g. "Alibaba OSS endpoint" or the hostname/IP.
    pub destination_label: String,
    pub destination: String,
    pub verdict: Verdict,
    pub permitted_by_observation: bool,
    /// e.g. "coding-session policy" or "rule coding-allow-github".
    pub decided_by: String,
    /// Region name derived from a documented endpoint name, if any.
    pub endpoint_region: Option<String>,
    pub transfer: TransferMeasurement,
    pub session_bound: bool,
    /// Coverage gap during the window, if any.
    pub coverage_gap: bool,
}

pub fn format_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Render the alert text. Mirrors the roadmap example:
/// "Claude Code → zsh → curl attempted HTTPS to a new Alibaba OSS endpoint. The coding-session policy blocked the
/// connection. The endpoint name indicates the Beijing region. No completed transfer was observed. Review the
/// process chain or allow this destination for this session."
pub fn render_alert(f: &AlertFacts) -> String {
    let mut out = String::new();
    let actor = if f.chain.is_empty() { "An unidentified process".to_string() } else { f.chain.join(" → ") };
    out.push_str(&actor);
    if !f.chain.is_empty() && !f.chain_complete {
        out.push_str(" (partial chain)");
    }
    let verb = match (f.verdict, f.permitted_by_observation) {
        (Verdict::Deny, _) => "attempted",
        _ => "connected over",
    };
    let novelty = if f.first_seen { "a new " } else { "" };
    let label = if novelty.is_empty() && !f.destination_label.starts_with(|c: char| c.is_ascii_digit()) {
        format!("the {}", f.destination_label)
    } else {
        format!("{novelty}{}", f.destination_label)
    };
    out.push_str(&format!(" {verb} {} to {label}.", f.protocol));
    match (f.verdict, f.permitted_by_observation) {
        (Verdict::Deny, _) => out.push_str(&format!(" The {} blocked the connection.", f.decided_by)),
        (Verdict::Allow, true) => {
            out.push_str(&format!(" The {} is observing, so the connection was permitted, not enforced.", f.decided_by))
        }
        (Verdict::Allow, false) => out.push_str(&format!(" The {} allowed the connection.", f.decided_by)),
    }
    if let Some(r) = &f.endpoint_region {
        out.push_str(&format!(" The endpoint name indicates the {r} region."));
    }
    match &f.transfer {
        TransferMeasurement::NotMeasured => {
            if f.verdict == Verdict::Allow {
                out.push_str(" Transfer size was not measured.");
            }
        }
        TransferMeasurement::BlockedAtConnect { .. } | TransferMeasurement::NoCompletedTransfer { .. } => {
            out.push_str(" No completed transfer was observed.");
        }
        TransferMeasurement::Measured { bytes_out, bytes_in, scope, source } => {
            out.push_str(&format!(
                " Measured {} sent and {} received ({scope} counters from {source}).",
                format_bytes(*bytes_out),
                format_bytes(*bytes_in)
            ));
        }
    }
    if f.coverage_gap {
        out.push_str(" Telemetry had a gap during this window, so earlier attempts may be missing.");
    }
    match f.verdict {
        Verdict::Deny if f.session_bound => out.push_str(" Review the process chain or allow this destination for this session."),
        Verdict::Deny => out.push_str(" Review the process chain or allow this destination for this app."),
        Verdict::Allow => out.push_str(" Review the process chain or add a rule."),
    }
    out
}

/// Protocol label from transport/port without claiming application-layer knowledge we do not have.
pub fn protocol_label(transport: crate::net::Transport, port: u16) -> String {
    use crate::net::Transport::*;
    match (transport, port) {
        (Tcp, 443) => "HTTPS".into(),
        (Tcp, 80) => "HTTP".into(),
        (Udp, 443) => "UDP/443 (likely QUIC)".into(),
        (Udp, 53) | (Tcp, 53) => "DNS".into(),
        (Tcp, 853) => "DNS over TLS".into(),
        (Tcp, 22) => "SSH".into(),
        (Tcp, p) => format!("TCP/{p}"),
        (Udp, p) => format!("UDP/{p}"),
        (Any, p) => format!("port {p}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> AlertFacts {
        AlertFacts {
            chain: vec!["Claude Code".into(), "zsh".into(), "curl".into()],
            chain_complete: true,
            protocol: "HTTPS".into(),
            first_seen: true,
            destination_label: "Alibaba OSS endpoint".into(),
            destination: "oss-cn-beijing.aliyuncs.com".into(),
            verdict: Verdict::Deny,
            permitted_by_observation: false,
            decided_by: "coding-session policy".into(),
            endpoint_region: Some("Beijing".into()),
            transfer: TransferMeasurement::BlockedAtConnect { source: "moatd".into() },
            session_bound: true,
            coverage_gap: false,
        }
    }

    #[test]
    fn matches_the_roadmap_example() {
        assert_eq!(
            render_alert(&facts()),
            "Claude Code → zsh → curl attempted HTTPS to a new Alibaba OSS endpoint. The coding-session policy blocked the connection. The endpoint name indicates the Beijing region. No completed transfer was observed. Review the process chain or allow this destination for this session."
        );
    }

    #[test]
    fn never_mentions_bytes_unless_measured() {
        let t = render_alert(&facts());
        assert!(!t.contains(" B ") && !t.contains("bytes") && !t.contains("MB"));
        let mut f = facts();
        f.verdict = Verdict::Allow;
        f.transfer = TransferMeasurement::NotMeasured;
        assert!(render_alert(&f).contains("not measured"));
        f.transfer =
            TransferMeasurement::Measured { bytes_out: 2_100_000, bytes_in: 512, scope: "flow".into(), source: "NEFilterReport".into() };
        let t = render_alert(&f);
        assert!(t.contains("2.1 MB sent") && t.contains("flow counters"));
    }

    #[test]
    fn labels_partial_chains_and_gaps() {
        let mut f = facts();
        f.chain_complete = false;
        f.coverage_gap = true;
        let t = render_alert(&f);
        assert!(t.contains("(partial chain)") && t.contains("gap"));
        f.chain.clear();
        assert!(render_alert(&f).starts_with("An unidentified process"));
    }

    #[test]
    fn observation_is_not_enforcement() {
        let mut f = facts();
        f.verdict = Verdict::Allow;
        f.permitted_by_observation = true;
        f.decided_by = "ordinary-desktop-learning profile".into();
        assert!(render_alert(&f).contains("permitted, not enforced"));
    }

    #[test]
    fn protocol_labels() {
        assert_eq!(protocol_label(crate::net::Transport::Udp, 443), "UDP/443 (likely QUIC)");
        assert_eq!(protocol_label(crate::net::Transport::Tcp, 8443), "TCP/8443");
    }
}
