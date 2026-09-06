use crate::{config::Config, metrics::{Gauge, Metrics}, protocol::{self, Cursor}};
use std::{net::SocketAddr, sync::{Arc, RwLock}, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Semaphore, time::{timeout, Instant}};

struct Cached { wire: Arc<Vec<u8>>, at: Instant }
pub struct StatusCache { value: RwLock<Option<Cached>>, fallback: Arc<Vec<u8>>, ttl: Duration }
impl StatusCache {
    pub fn new(c: &Config) -> Arc<Self> {
        let text = serde_json::to_vec(&c.cache.fallback).expect("validated JSON");
        let mut b = vec![0]; protocol::put_varint(text.len() as i32, &mut b); b.extend(text);
        Arc::new(Self { value:RwLock::new(None), fallback:Arc::new(protocol::frame(&b)), ttl:Duration::from_secs(c.cache.ttl_seconds) })
    }
    pub fn get(&self, m: &Metrics) -> Arc<Vec<u8>> {
        let r = self.value.read().unwrap();
        if let Some(c) = r.as_ref() { if c.at.elapsed() < self.ttl { return c.wire.clone(); } }
        m.inc(24); self.fallback.clone()
    }
    pub async fn refresh(self: Arc<Self>, cfg: Arc<Config>, sockets: Arc<Semaphore>, metrics: Arc<Metrics>) {
        loop {
            // Exactly one cache task; one backend slot is reserved outside player slots.
            if let Ok(permit) = sockets.clone().try_acquire_owned() {
                let _permit = permit;
                let _gauge = Gauge::new(metrics.clone(), 3);
                metrics.inc(31);
                match timeout(Duration::from_millis(cfg.timeouts.backend_ms), poll(&cfg)).await {
                    Ok(Ok(wire)) => *self.value.write().unwrap() = Some(Cached { wire:Arc::new(wire), at:Instant::now() }),
                    _ => metrics.inc(23),
                }
            } else { metrics.inc(23); }
            // No client can trigger an extra refresh, including cache misses.
            tokio::time::sleep((self.ttl / 2).max(Duration::from_millis(500))).await;
        }
    }
}
async fn poll(c: &Config) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut s = TcpStream::connect(c.backend).await?; s.set_nodelay(true)?;
    if c.proxy_v2 { s.write_all(&proxy_header(s.local_addr()?, c.backend)?).await?; }
    s.write_all(&protocol::status_handshake(&c.cache.host, c.cache.port, c.cache.protocol)).await?;
    s.write_all(&[1,0]).await?;
    let mut left = c.cache.max_response_bytes + 5;
    let duration = Duration::from_millis(c.timeouts.backend_ms);
    let f = protocol::read_frame(&mut s, c.cache.max_response_bytes, &mut left, Instant::now()+duration, duration, duration).await?;
    let mut cursor = Cursor::new(&f.body);
    if cursor.int()? != 0 { return Err("invalid backend status id".into()); }
    let text = cursor.string(c.cache.max_response_bytes)?;
    let value: serde_json::Value = serde_json::from_str(text)?;
    if !value.is_object() { return Err("backend status must be JSON object".into()); }
    cursor.finish()?;
    Ok(f.wire)
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
}
