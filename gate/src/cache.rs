use crate::{config::Config, metrics::{Gauge, Metrics}, protocol::{self, Cursor}};
use std::{net::SocketAddr, sync::{Arc, RwLock}, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Semaphore, time::{timeout, Instant}};

struct Cached { value: Arc<serde_json::Value>, at: Instant }
pub struct StatusCache {
    value: RwLock<Option<Cached>>, fallback: Arc<serde_json::Value>, ttl: Duration,
    max_response_bytes: usize,
}
impl StatusCache {
    pub fn new(c: &Config) -> Arc<Self> {
        Arc::new(Self {
            value:RwLock::new(None), fallback:Arc::new(c.cache.fallback.clone()),
            ttl:Duration::from_secs(c.cache.ttl_seconds), max_response_bytes:c.cache.max_response_bytes,
        })
    }
    pub fn get(&self, m: &Metrics, requested_protocol: i32) -> Arc<Vec<u8>> {
        let r = self.value.read().unwrap();
        let value = if let Some(c) = r.as_ref() {
            if c.at.elapsed() < self.ttl { c.value.clone() } else { m.inc(24); self.fallback.clone() }
        } else { m.inc(24); self.fallback.clone() };
        Arc::new(render(&value, requested_protocol, self.max_response_bytes)
            .unwrap_or_else(|| render(&self.fallback, -1, self.max_response_bytes)
                .expect("validated fallback status exceeds response limit")))
    }
    pub async fn refresh(self: Arc<Self>, cfg: Arc<Config>, sockets: Arc<Semaphore>, metrics: Arc<Metrics>) {
        loop {
            // Exactly one cache task; one backend slot is reserved outside player slots.
            if let Ok(permit) = sockets.clone().try_acquire_owned() {
                let _permit = permit;
                let _gauge = Gauge::new(metrics.clone(), 3);
                metrics.inc(31);
                match timeout(Duration::from_millis(cfg.timeouts.backend_ms), poll(&cfg)).await {
                    Ok(Ok(value)) => *self.value.write().unwrap() = Some(Cached { value:Arc::new(value), at:Instant::now() }),
                    _ => metrics.inc(23),
                }
            } else { metrics.inc(23); }
            // No client can trigger an extra refresh, including cache misses.
            tokio::time::sleep((self.ttl / 2).max(Duration::from_millis(500))).await;
        }
    }
}
fn render(value: &serde_json::Value, requested_protocol: i32, max_response_bytes: usize) -> Option<Vec<u8>> {
    let mut value = value.clone();
    // ViaVersion can accept multiple client protocols. Match the status
    // version field to the requesting handshake so modern clients do not show
    // a false incompatibility (red X) while the cached MOTD/player data stays
    // shared. Protocol -1 is discovery and preserves the backend value.
    if requested_protocol >= 0 {
        if let Some(version) = value.get_mut("version").and_then(|v| v.as_object_mut()) {
            version.insert("protocol".into(), serde_json::Value::Number(requested_protocol.into()));
        }
    }
    let text = serde_json::to_vec(&value).ok()?;
    if text.len().saturating_add(5) > max_response_bytes { return None; }
    let mut body = vec![0];
    protocol::put_varint(text.len() as i32, &mut body);
    body.extend(text);
    Some(protocol::frame(&body))
}
async fn poll(c: &Config) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut s = TcpStream::connect(c.backend).await?; s.set_nodelay(true)?;
    if c.proxy_v2 { s.write_all(&proxy_header(s.local_addr()?, c.backend)?).await?; }
    s.write_all(&protocol::status_handshake(&c.cache.host, c.cache.port, c.cache.protocol)).await?;
    s.write_all(&[1,0]).await?;
    let mut left = c.cache.max_response_bytes + 5;
    let duration = Duration::from_millis(c.timeouts.backend_ms);
    let f = protocol::read_frame(&mut s, c.cache.max_response_bytes, &mut left, Instant::now()+duration, duration, duration).await?;
    let mut cursor = Cursor::new(f.body());
    if cursor.int()? != 0 { return Err("invalid backend status id".into()); }
    let text = cursor.string(c.cache.max_response_bytes)?;
    let value: serde_json::Value = serde_json::from_str(text)?;
    if !value.is_object() { return Err("backend status must be JSON object".into()); }
    cursor.finish()?;
    Ok(value)
}
pub fn proxy_header(src: SocketAddr, dst: SocketAddr) -> std::io::Result<Vec<u8>> {
    let mut b = b"\r\n\r\n\0\r\nQUIT\n".to_vec(); b.push(0x21);
    match (src,dst) {
        (SocketAddr::V4(s),SocketAddr::V4(d)) => { b.push(0x11); b.extend_from_slice(&12u16.to_be_bytes());
            b.extend_from_slice(&s.ip().octets()); b.extend_from_slice(&d.ip().octets()); },
        (SocketAddr::V6(s),SocketAddr::V6(d)) => { b.push(0x21); b.extend_from_slice(&36u16.to_be_bytes());
            b.extend_from_slice(&s.ip().octets()); b.extend_from_slice(&d.ip().octets()); },
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"PROXY address family mismatch")),
    }
    b.extend_from_slice(&src.port().to_be_bytes()); b.extend_from_slice(&dst.port().to_be_bytes()); Ok(b)
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn proxy_v2_lengths_and_endianness() {
        let b = proxy_header("192.0.2.7:12345".parse().unwrap(), "198.51.100.1:25565".parse().unwrap()).unwrap();
        assert_eq!(b.len(),28); assert_eq!(&b[14..16],&[0,12]); assert_eq!(&b[24..],&[48,57,99,221]);
        assert_eq!(proxy_header("[::1]:1".parse().unwrap(),"[::1]:2".parse().unwrap()).unwrap().len(),52);
    }
    #[test] fn status_protocol_matches_client_without_mutating_cached_value() {
        let value=serde_json::json!({"version":{"name":"ViaVersion","protocol":47},"description":{"text":"ok"}});
        let modern=render(&value,767,32768).unwrap();
        let legacy=render(&value,-1,32768).unwrap();
        assert!(String::from_utf8_lossy(&modern).contains("\"protocol\":767"));
        assert!(String::from_utf8_lossy(&legacy).contains("\"protocol\":47"));
        assert_eq!(value["version"]["protocol"],47);
    }
}
