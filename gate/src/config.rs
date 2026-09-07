use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, path::Path};

#[derive(Clone, Copy, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    pub per_second: f64,
    pub burst: f64,
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn status_capacity_is_optional_and_bounded_by_prelogin() {
        let mut raw:serde_json::Value=serde_json::from_str(include_str!("../../config/gate.json")).unwrap();
        raw["limits"].as_object_mut().unwrap().remove("status_connections");
        let mut c:Config=serde_json::from_value(raw).unwrap();
        assert_eq!(c.limits.status_connections,0); assert!(c.validate().is_ok());
        c.limits.status_connections=c.limits.prelogin;
        assert!(c.validate().is_ok());
        c.limits.status_connections+=1;
        assert!(c.validate().is_err());
    }
    #[test] fn upload_and_pending_limits_validate_without_arithmetic_overflow() {
        let mut c:Config=serde_json::from_str(include_str!("../../config/gate.json")).unwrap();
        c.upload=Upload {bytes_per_second:1,burst_bytes:0,enforce:true}; assert!(c.validate().is_err());
        c.upload.burst_bytes=1; assert!(c.validate().is_ok());
        c.limits.prelogin_ip=c.limits.prelogin+1; assert!(c.validate().is_err());
        c.limits.prelogin_ip=0; c.limits.admitted=usize::MAX; assert!(c.validate().is_err());
    }
    #[test] fn status_fairness_is_backward_compatible_and_bounded() {
        let mut raw:serde_json::Value=serde_json::from_str(include_str!("../../config/gate.json")).unwrap();
        for key in ["status_ip","separate_status_budget","preserve_burst"] {
            raw["limits"].as_object_mut().unwrap().remove(key);
        }
        let mut c:Config=serde_json::from_value(raw).unwrap();
        assert_eq!(c.limits.status_ip,0);
        assert!(!c.limits.separate_status_budget); assert!(!c.limits.preserve_burst);
        assert!(c.validate().is_ok());
        c.limits.status_ip=c.limits.status_connections; assert!(c.validate().is_ok());
        c.limits.status_ip+=1; assert!(c.validate().is_err());
        c.limits.status_connections=0; c.limits.status_ip=c.limits.prelogin;
        assert!(c.validate().is_ok());
        c.limits.status_ip+=1; assert!(c.validate().is_err());
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Rates {
    pub connect: Rate,
    pub handshake: Rate,
    pub status: Rate,
    pub login: Rate,
}
impl Rates {
    pub fn list(&self) -> [Rate; 4] { [self.connect, self.handshake, self.status, self.login] }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub total_sockets: usize,
    pub prelogin: usize,
    #[serde(default)]
    pub status_connections: usize,
    #[serde(default)]
    pub status_ip: usize,
    #[serde(default)]
    pub separate_status_budget: bool,
    #[serde(default)]
    pub preserve_burst: bool,
    pub admitted: usize,
    pub backend: usize,
    pub connections_ip: usize,
    pub connections_prefix: usize,
    #[serde(default)]
    pub prelogin_ip: usize,
    #[serde(default)]
    pub prelogin_prefix: usize,
    pub ip_entries: usize,
    pub prefix_entries: usize,
    pub idle_entry_seconds: u64,
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
    pub ip: Rates,
    pub prefix: Rates,
    pub global: Rates,
    pub mode_multipliers: [f64; 4],
    pub churn_score_threshold: f64,
    #[serde(default)]
    pub churn_prefix_score_threshold: f64,
    pub churn_half_life_seconds: u64,
    pub churn_window_seconds: u64,
    pub penalty_seconds: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    pub first_progress_ms: u64,
    pub progress_ms: u64,
    pub handshake_ms: u64,
    pub login_ms: u64,
    pub status_ms: u64,
    pub backend_ms: u64,
    pub shutdown_seconds: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    pub max_frame: usize,
    pub max_initial_bytes: usize,
    pub max_host_bytes: usize,
    pub allow_host_suffix: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub strict_username: bool,
    pub login_schemas: BTreeMap<i32, String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    pub host: String,
    pub port: u16,
    pub protocol: i32,
    pub ttl_seconds: u64,
    pub max_response_bytes: usize,
    pub fallback: serde_json::Value,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub backend: SocketAddr,
    pub metrics: SocketAddr,
    pub proxy_v2: bool,
    pub allow_backend_identity_loss: bool,
    pub ipv6: bool,
    pub observe: bool,
    pub runtime_file: String,
    pub workers: usize,
    pub relay_buffer: usize,
    #[serde(default)]
    pub upload: Upload,
    pub limits: Limits,
    pub timeouts: Timeouts,
    pub protocol: Protocol,
    pub cache: Cache,
}
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    pub bytes_per_second: u64,
    pub burst_bytes: u64,
    #[serde(default)]
    pub enforce: bool,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = std::fs::read(path)?;
        if raw.len() > 262144 { return Err("config too large".into()); }
        let c: Self = serde_json::from_slice(&raw)?;
        c.validate().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<(), String> {
        let l = &self.limits;
        if self.upload.bytes_per_second > 1_000_000_000 || self.upload.burst_bytes > 1_000_000_000 ||
            (self.upload.bytes_per_second == 0) != (self.upload.burst_bytes == 0) {
            return Err("upload rate/burst must both be zero or positive and <=1e9".into());
        }
        if self.workers == 0 || self.workers > 64 || !(1024..=65536).contains(&self.relay_buffer) {
            return Err("invalid workers/relay_buffer".into());
        }
        if !self.metrics.ip().is_loopback() || self.listen == self.backend || self.listen == self.metrics {
            return Err("metrics must be loopback; listen/backend/metrics must differ".into());
        }
        if self.listen.port() == 0 || self.backend.port() == 0 || self.metrics.port() == 0 {
            return Err("ports must be nonzero".into());
        }
        if !self.ipv6 && (self.listen.is_ipv6() || self.backend.is_ipv6()) {
            return Err("IPv6 address requires ipv6=true".into());
        }
        if !self.proxy_v2 && !self.allow_backend_identity_loss {
            return Err("enable PROXY v2 on trusted backend or explicitly allow identity loss".into());
        }
        if self.proxy_v2 && self.listen.is_ipv4() != self.backend.is_ipv4() {
            return Err("PROXY v2 requires matching listener/backend address families in this gate".into());
        }
        if l.total_sockets < 4 || l.total_sockets > 100000 || l.prelogin == 0 ||
            l.status_connections > l.prelogin ||
            l.status_ip > if l.status_connections == 0 { l.prelogin } else { l.status_connections } ||
            l.prelogin_ip > l.prelogin || l.prelogin_prefix > l.prelogin ||
            l.prelogin > l.total_sockets || l.admitted > l.total_sockets || l.backend > l.total_sockets ||
            l.admitted == 0 || l.backend < 2 || l.prelogin + l.admitted + l.backend > l.total_sockets ||
            l.ip_entries < 64 || l.ip_entries > 1_000_000 || l.prefix_entries < 64 ||
            l.prefix_entries > 1_000_000 || l.ip_entries % 64 != 0 || l.prefix_entries % 64 != 0 ||
            l.ipv4_prefix > 32 || l.ipv6_prefix > 128 || l.idle_entry_seconds == 0 ||
            l.churn_half_life_seconds == 0 || l.churn_window_seconds > 60 || l.penalty_seconds > 3600 ||
            !l.churn_score_threshold.is_finite() || l.churn_score_threshold < 0.0 ||
            !l.churn_prefix_score_threshold.is_finite() || l.churn_prefix_score_threshold < 0.0 {
            return Err("invalid resource/identity/penalty limits".into());
        }
        for rates in [&l.ip, &l.prefix, &l.global] {
            for r in rates.list() {
                if !r.per_second.is_finite() || !r.burst.is_finite() || r.per_second < 0.0 ||
                    r.per_second > 1e9 || r.burst < 0.0 || r.burst > 1e9 ||
                    (r.per_second == 0.0) != (r.burst == 0.0) ||
                    (r.burst > 0.0 && r.burst < 1.0) {
                    return Err("rates must be disabled (0/0) or finite positive rate/burst >=1".into());
                }
            }
        }
        if l.mode_multipliers.iter().any(|x| !x.is_finite() || *x <= 0.0 || *x > 1.0) ||
            l.mode_multipliers.windows(2).any(|x| x[1] > x[0]) {
            return Err("mode multipliers must be positive, <=1, non-increasing".into());
        }
        let p = &self.protocol;
        if !(64..=65536).contains(&p.max_frame) || p.max_initial_bytes < p.max_frame + 5 ||
            p.max_initial_bytes > 131072 || !(1..=4096).contains(&p.max_host_bytes) ||
            p.max_host_bytes > p.max_frame || p.allowed_ports.contains(&0) ||
            p.allowed_hosts.len() > 256 || p.login_schemas.len() > 1024 ||
            p.login_schemas.values().any(|x| !matches!(x.as_str(), "legacy"|"signed"|"signed_uuid"|"optional_uuid"|"uuid")) {
            return Err("invalid protocol bounds/schema".into());
        }
        for ms in [self.timeouts.first_progress_ms, self.timeouts.progress_ms,
                   self.timeouts.handshake_ms, self.timeouts.login_ms,
                   self.timeouts.status_ms, self.timeouts.backend_ms] {
            if ms == 0 || ms > 120000 { return Err("phase deadlines must be 1..120000 ms".into()); }
        }
        if self.timeouts.shutdown_seconds > 3600 || self.cache.ttl_seconds == 0 ||
            self.cache.ttl_seconds > 300 || !(256..=65536).contains(&self.cache.max_response_bytes) ||
            self.cache.host.is_empty() || self.cache.host.len() > 255 || self.cache.port == 0 ||
            !self.cache.fallback.is_object() ||
            serde_json::to_vec(&self.cache.fallback).map_err(|e| e.to_string())?.len() + 10 > self.cache.max_response_bytes {
            return Err("invalid cache/deadline configuration".into());
        }
        Ok(())
    }
}
