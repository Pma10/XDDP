use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, sync::Semaphore, time::{timeout, Duration}};

pub const NAMES: &[&str] = &[
    "tcp_accepts", "active_connections", "active_prelogin", "backend_connections",
    "handshake_ok", "handshake_invalid", "status_requests", "login_starts",
    "invalid_varint", "oversized_packet", "unsupported_protocol", "handshake_timeout",
    "slow_connection", "close_before_handshake", "rate_limited_ip", "rate_limited_prefix",
    "rate_limited_global", "backend_connect_failures", "prelogin_duration_microseconds_sum",
    "prelogin_duration_count", "resource_limited", "identity_table_full", "churn",
    "status_refresh_failures", "status_cache_fallback", "relay_errors", "accept_errors",
    "observed_rate_limit", "new_ip_entries", "new_prefix_entries", "admitted_clients",
    "backend_connect_attempts", "ip_entries", "prefix_entries", "mode", "observe",
    "active_status", "status_capacity_limited",
];
pub struct Metrics { values: Vec<AtomicU64> }
impl Metrics {
    pub fn new() -> Self { Self { values: NAMES.iter().map(|_| AtomicU64::new(0)).collect() } }
    pub fn inc(&self, n: usize) { self.add(n, 1); }
    pub fn add(&self, n: usize, value: u64) { self.values[n].fetch_add(value, Ordering::Relaxed); }
    pub fn dec(&self, n: usize) { self.values[n].fetch_sub(1, Ordering::Relaxed); }
    pub fn set(&self, n: usize, value: u64) { self.values[n].store(value, Ordering::Relaxed); }
    pub fn get(&self, n: usize) -> u64 { self.values[n].load(Ordering::Relaxed) }
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(4096);
        for (i, name) in NAMES.iter().enumerate() {
            let kind = if [1,2,3,30,32,33,34,35,36].contains(&i) { "gauge" } else { "counter" };
            let _ = writeln!(out, "# TYPE xddp_gate_{name} {kind}\nxddp_gate_{name} {}", self.get(i));
        }
        let count = self.get(19);
        let avg = if count == 0 { 0.0 } else { self.get(18) as f64 / count as f64 / 1e6 };
        let _ = writeln!(out, "xddp_gate_average_prelogin_duration_seconds {avg}");
        out
    }
}
pub struct Gauge { metrics: Arc<Metrics>, n: usize }
impl Gauge { pub fn new(metrics: Arc<Metrics>, n: usize) -> Self { metrics.inc(n); Self { metrics, n } } }
impl Drop for Gauge { fn drop(&mut self) { self.metrics.dec(self.n); } }

pub async fn serve(listener: TcpListener, metrics: Arc<Metrics>) {
    let slots = Arc::new(Semaphore::new(8));
    loop {
        let Ok((mut s, _)) = listener.accept().await else { tokio::time::sleep(Duration::from_millis(100)).await; continue; };
        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
        let m = metrics.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = timeout(Duration::from_secs(2), async {
                let mut request = [0; 2048]; let mut used = 0;
                loop {
                    if used == request.len() { return Ok::<(), std::io::Error>(()); }
                    let n = s.read(&mut request[used..]).await?;
                    if n == 0 { return Ok(()); }
                    used += n;
                    if request[..used].windows(4).any(|w| w == b"\r\n\r\n") { break; }
                }
                let ok = request[..used].starts_with(b"GET /metrics HTTP/1.");
                let body = if ok { m.render() } else { "not found\n".into() };
                let status = if ok { "200 OK" } else { "404 Not Found" };
                s.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await
            }).await;
        });
    }
}
