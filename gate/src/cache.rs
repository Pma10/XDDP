use crate::{config::Config, metrics::{Gauge, Metrics}, protocol::{self, Cursor}};
use std::{net::SocketAddr, sync::{Arc, RwLock}, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Semaphore, time::{timeout, Instant}};

struct Cached { value: Arc<Prepared>, at: Instant }
// JSON is serialized only on refresh, never in response to a client-selected key.
// At most one canonical response and one prefix/suffix pair are retained.
struct Prepared { original: Arc<Vec<u8>>, parts: Option<(Vec<u8>,Vec<u8>)> }
impl Prepared {
    fn new(value: &serde_json::Value, max: usize) -> Option<Self> {
        let text=serde_json::to_vec(value).ok()?;
        if text.len().checked_add(5)? > max { return None; }
        let original=Arc::new(status_frame(&text));
        let parts=if let Some(version)=value.get("version").and_then(|v|v.as_object()) {
            let prefix=b"{\"version\":{\"protocol\":".to_vec();
            let mut suffix=Vec::new();
            for (key,val) in version.iter().filter(|(k,_)|k.as_str()!="protocol") {
                suffix.push(b','); suffix.extend(serde_json::to_vec(key).ok()?);
                suffix.push(b':'); suffix.extend(serde_json::to_vec(val).ok()?);
            }
            suffix.push(b'}');
            for (key,val) in value.as_object()?.iter().filter(|(k,_)|k.as_str()!="version") {
                suffix.push(b','); suffix.extend(serde_json::to_vec(key).ok()?);
                suffix.push(b':'); suffix.extend(serde_json::to_vec(val).ok()?);
            }
            suffix.push(b'}');
            // Reserve space for any nonnegative i32 client version and framing.
            if prefix.len()+10+suffix.len()+5 > max { return None; }
            Some((prefix,suffix))
        } else { None };
        Some(Self {original,parts})
    }
    fn render(&self, version:i32) -> Arc<Vec<u8>> {
        if version<0 { return self.original.clone(); }
        let Some((prefix,suffix))=&self.parts else { return self.original.clone(); };
        let number=version.to_string();
        let length=prefix.len()+number.len()+suffix.len();
        let mut body=Vec::with_capacity(length+5);
        body.push(0); protocol::put_varint(length as i32,&mut body);
        body.extend_from_slice(prefix); body.extend_from_slice(number.as_bytes()); body.extend_from_slice(suffix);
        Arc::new(protocol::frame(&body))
    }
}
fn status_frame(text:&[u8])->Vec<u8> {
    let mut body=vec![0]; protocol::put_varint(text.len() as i32,&mut body);
    body.extend_from_slice(text); protocol::frame(&body)
}
pub fn valid_status(value:&serde_json::Value,max:usize)->bool { Prepared::new(value,max).is_some() }
pub struct StatusCache {
    value: RwLock<Option<Cached>>, fallback: Arc<Prepared>, ttl: Duration,
}
impl StatusCache {
    pub fn new(c: &Config) -> Arc<Self> {
        Arc::new(Self {
            value:RwLock::new(None), fallback:Arc::new(Prepared::new(&c.cache.fallback,c.cache.max_response_bytes).expect("validated fallback")),
            ttl:Duration::from_secs(c.cache.ttl_seconds),
        })
    }
    pub fn get(&self, m: &Metrics, requested_protocol: i32) -> Arc<Vec<u8>> {
        let r = self.value.read().unwrap();
        let value = if let Some(c) = r.as_ref() {
            if c.at.elapsed() < self.ttl { c.value.clone() } else { m.inc(24); self.fallback.clone() }
        } else { m.inc(24); self.fallback.clone() };
        drop(r);
        value.render(requested_protocol)
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
async fn poll(c: &Config) -> Result<Prepared, Box<dyn std::error::Error + Send + Sync>> {
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
    Prepared::new(&value,c.cache.max_response_bytes).ok_or_else(||"rendered backend status exceeds limit".into())
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
    fn decoded(wire:&[u8])->serde_json::Value {
        let mut c=Cursor::new(wire); let _length=c.int().unwrap(); assert_eq!(c.int().unwrap(),0);
        let result=serde_json::from_str(c.string(65536).unwrap()).unwrap(); c.finish().unwrap(); result
    }
    #[test] fn prepared_response_preserves_components_and_has_no_client_key_growth() {
        let value=serde_json::json!({"version":{"name":"multi","protocol":47},
            "description":{"text":"","extra":[{"text":"A","color":"#aabbcc"},{"text":"B","bold":true}]},
            "players":{"max":100,"online":2},"favicon":"fixture","custom":{"version":{"protocol":123}}});
        let p=Prepared::new(&value,32768).unwrap();
        for version in [0,47,774,i32::MAX,-1] {
            let mut expected=value.clone(); if version>=0 {expected["version"]["protocol"]=version.into();}
            assert_eq!(decoded(&p.render(version)),expected);
        }
        let sizes=(p.original.len(),p.parts.as_ref().unwrap().0.len(),p.parts.as_ref().unwrap().1.len());
        for version in 0..10000 {p.render(version);}
        assert_eq!(sizes,(p.original.len(),p.parts.as_ref().unwrap().0.len(),p.parts.as_ref().unwrap().1.len()));
        assert!(Prepared::new(&value,32).is_none());
        let plain=serde_json::json!({"description":"plain"});
        let p=Prepared::new(&plain,256).unwrap(); assert_eq!(decoded(&p.render(774)),plain);
    }
    #[test] fn proxy_v2_lengths_and_endianness() {
        let b = proxy_header("192.0.2.7:12345".parse().unwrap(), "198.51.100.1:25565".parse().unwrap()).unwrap();
        assert_eq!(b.len(),28); assert_eq!(&b[14..16],&[0,12]); assert_eq!(&b[24..],&[48,57,99,221]);
        assert_eq!(proxy_header("[::1]:1".parse().unwrap(),"[::1]:2".parse().unwrap()).unwrap().len(),52);
    }
    #[test] fn status_protocol_matches_client_without_mutating_cached_value() {
        let value=serde_json::json!({
            "version":{"name":"ViaVersion","protocol":47},
            "description":{"text":"<gradient:blue>ok</gradient>","extra":[{"text":"!","color":"gold"}]},
            "favicon":"data:image/png;base64,fixture"
        });
        let prepared=Prepared::new(&value,32768).unwrap();
        let modern=prepared.render(767);
        let legacy=prepared.render(-1);
        assert!(String::from_utf8_lossy(&modern).contains("\"protocol\":767"));
        assert!(String::from_utf8_lossy(&legacy).contains("\"protocol\":47"));
        assert!(String::from_utf8_lossy(&modern).contains("<gradient:blue>ok</gradient>"));
        assert!(String::from_utf8_lossy(&modern).contains("\"color\":\"gold\""));
        assert!(String::from_utf8_lossy(&modern).contains("data:image/png;base64,fixture"));
        assert_eq!(value["version"]["protocol"],47);
    }
}
