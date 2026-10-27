//! Capability probing. The advertisement starts from the adapter's declared contract and is *downgraded* by
//! what this host can actually do right now. It is never upgraded by a probe.

use std::path::Path;
use std::process::Command;

use moat_core::capability::{Capability, CapabilityAdvertisement, CapabilityStatus, Support};

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostFacts {
    pub kernel: String,
    pub cgroup2: bool,
    pub nft_binary: bool,
    /// `nft list tables` worked (netfilter usable with our privileges).
    pub netfilter_usable: bool,
    /// A `socket cgroupv2` expression passed `nft -c`.
    pub socket_cgroupv2: bool,
    pub cgroup_kill: bool,
    /// Why the `socket cgroupv2` probe failed, verbatim from nft, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_error: Option<String>,
}

pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()).unwrap_or_default()
}

pub fn gather(cgroup_mount: &Path, moat_root: &str, nft: &str) -> HostFacts {
    let ok = |args: &[&str]| Command::new(nft).args(args).output().map(|o| o.status.success()).unwrap_or(false);
    let nft_binary = ok(&["--version"]);
    let netfilter_usable = nft_binary && ok(&["list", "tables"]);
    let mut probe_error = None;
    let socket_cgroupv2 = if !netfilter_usable {
        false
    } else if !cgroup_mount.join(moat_root).exists() {
        probe_error = Some(format!("{} does not exist", cgroup_mount.join(moat_root).display()));
        false
    } else {
        let test = format!(
            "table inet moat_probe {{\n  chain c {{\n    type filter hook output priority 0; policy accept;\n    socket cgroupv2 level 1 \"{moat_root}\" accept\n  }}\n}}\n"
        );
        let mut c = Command::new(nft);
        c.args(["-c", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        match c.spawn() {
            Ok(mut ch) => {
                use std::io::Write;
                let _ = ch.stdin.take().unwrap().write_all(test.as_bytes());
                match ch.wait_with_output() {
                    Ok(o) if o.status.success() => true,
                    Ok(o) => {
                        probe_error = Some(String::from_utf8_lossy(&o.stderr).trim().to_string());
                        false
                    }
                    Err(e) => {
                        probe_error = Some(e.to_string());
                        false
                    }
                }
            }
            Err(e) => {
                probe_error = Some(e.to_string());
                false
            }
        }
    };
    HostFacts {
        kernel: kernel_release(),
        cgroup2: crate::cgroup::is_cgroup2(cgroup_mount),
        nft_binary,
        netfilter_usable,
        socket_cgroupv2,
        cgroup_kill: cgroup_mount.join("cgroup.kill").exists() || cgroup_mount.join(moat_root).join("cgroup.kill").exists(),
        probe_error,
    }
}

fn downgrade(adv: &mut CapabilityAdvertisement, c: Capability, note: &str) {
    adv.capabilities.insert(c, CapabilityStatus { support: Support::Unsupported, note: Some(note.into()) });
}

/// Apply host facts to the declared Linux contract.
pub fn advertise(facts: &HostFacts) -> CapabilityAdvertisement {
    let mut adv = CapabilityAdvertisement::linux_nftables_cgroup();
    if !facts.nft_binary || !facts.netfilter_usable {
        let why = if !facts.nft_binary {
            "nft binary not found"
        } else {
            "netfilter (nf_tables) not usable on this kernel or without privileges"
        };
        for c in [
            Capability::SessionEnforcement,
            Capability::UserEnforcement,
            Capability::Ipv6Enforcement,
            Capability::UdpEnforcement,
            Capability::ByteCounters,
            Capability::ExistingFlowRevocation,
        ] {
            downgrade(&mut adv, c, why);
        }
    } else if !facts.cgroup2 {
        downgrade(&mut adv, Capability::SessionEnforcement, "cgroup v2 is not mounted (hybrid/v1 hierarchy)");
    } else if !facts.socket_cgroupv2 {
        let why = format!(
            "nftables 'socket cgroupv2' match unavailable: {}",
            facts.probe_error.clone().unwrap_or_else(|| "kernel or nft too old".into())
        );
        downgrade(&mut adv, Capability::SessionEnforcement, &why);
    }
    adv.advertised_at = Some(chrono::Utc::now());
    adv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_host_keeps_contract() {
        let f = HostFacts {
            kernel: "6.12".into(),
            cgroup2: true,
            nft_binary: true,
            netfilter_usable: true,
            socket_cgroupv2: true,
            cgroup_kill: true,
            probe_error: None,
        };
        let a = advertise(&f);
        assert_eq!(a.support(Capability::SessionEnforcement), Support::Supported);
        assert_eq!(a, {
            let mut b = CapabilityAdvertisement::linux_nftables_cgroup();
            b.advertised_at = a.advertised_at;
            b
        });
    }

    #[test]
    fn missing_netfilter_downgrades_everything_enforcing() {
        let f = HostFacts { kernel: "6.12".into(), cgroup2: true, nft_binary: true, netfilter_usable: false, ..Default::default() };
        let a = advertise(&f);
        assert_eq!(a.support(Capability::SessionEnforcement), Support::Unsupported);
        assert_eq!(a.support(Capability::UdpEnforcement), Support::Unsupported);
        // telemetry completeness is the spool's, not netfilter's
        assert_eq!(a.support(Capability::TelemetryCompleteness), Support::Supported);
    }

    #[test]
    fn no_socket_match_downgrades_sessions_only() {
        let f = HostFacts {
            kernel: "5.4".into(),
            cgroup2: true,
            nft_binary: true,
            netfilter_usable: true,
            socket_cgroupv2: false,
            cgroup_kill: false,
            probe_error: None,
        };
        let a = advertise(&f);
        assert_eq!(a.support(Capability::SessionEnforcement), Support::Unsupported);
        assert_eq!(a.support(Capability::UserEnforcement), Support::Supported);
    }
}
