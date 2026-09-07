use crate::limiter::{Policy, normalize};
use ipnet::IpNet;
use serde::Deserialize;
use std::{net::IpAddr, sync::{Arc, RwLock, atomic::{AtomicU64,Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tokio::io::AsyncReadExt;

const MAX_DOCUMENT_BYTES: usize = 262144;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire { generation: u64, expires_unix: u64, mode: usize, observe: bool, allow: Vec<IpNet>, block: Vec<IpNet> }
struct Snapshot { wire: Wire, received: Instant }
pub struct Runtime { value: RwLock<Option<Snapshot>>, default_observe: bool, rejected:AtomicU64 }
impl Runtime {
    pub fn new(default_observe: bool) -> Arc<Self> { Arc::new(Self { value: RwLock::new(None), default_observe, rejected:AtomicU64::new(0) }) }
    pub fn telemetry(&self) -> (u64,u64) {
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let state=self.value.read().unwrap();
        let generation=state.as_ref().filter(|s|s.received.elapsed()<=Duration::from_secs(15) && now<s.wire.expires_unix)
            .map(|s|s.wire.generation).unwrap_or(0);
        (generation,self.rejected.load(Ordering::Relaxed))
    }
    fn apply(&self,b:&[u8]) -> bool {
        if b.len()>MAX_DOCUMENT_BYTES { return false; }
        let Ok(w)=serde_json::from_slice::<Wire>(b) else { return false; };
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if w.mode>3 || w.expires_unix>now.saturating_add(30) || w.allow.len()>4096 || w.block.len()>4096 {
            return false;
        }
        let mut state=self.value.write().unwrap();
        if state.as_ref().map(|x|x.wire.generation)!=Some(w.generation) {
            // Explicit expired publications retire the previous policy immediately.
            *state=Some(Snapshot {wire:w,received:Instant::now()});
        }
        true
    }
    pub fn policy(&self, ip: IpAddr) -> (Policy, bool) {
        let default = (Policy { mode:0, observe:true, exempt:false }, false);
        let r = self.value.read().unwrap();
        let Some(s) = r.as_ref() else {
            // With no controller ever observed, standalone config is authoritative.
            return (Policy { observe:self.default_observe, ..default.0 }, false);
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if s.received.elapsed() > Duration::from_secs(15) || now >= s.wire.expires_unix { return default; }
        let ip = normalize(ip);
        let exempt = s.wire.allow.iter().any(|n| n.contains(&ip));
        let p = Policy { mode:s.wire.mode, observe:s.wire.observe, exempt };
        (p, !p.observe && !exempt && s.wire.block.iter().any(|n| n.contains(&ip)))
    }
    pub async fn watch(self: Arc<Self>, path: String) {
        if path.is_empty() { return; }
        loop {
            let mut accepted=false;
            if let Ok(file)=tokio::fs::File::open(&path).await {
                let mut b=Vec::new();
                if file.take((MAX_DOCUMENT_BYTES+1) as u64).read_to_end(&mut b).await.is_ok() {
                    accepted=self.apply(&b);
                }
            }
            if !accepted { self.rejected.fetch_add(1,Ordering::Relaxed); }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn explicit_expiry_and_rejected_documents_preserve_bounded_policy() {
        let r=Runtime::new(true);
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let wire=serde_json::json!({"generation":1,"expires_unix":now+10,"mode":2,"observe":false,"allow":[],"block":[]});
        let bytes=serde_json::to_vec(&wire).unwrap(); assert!(r.apply(&bytes));
        assert_eq!(r.telemetry().0,1);
        assert!(!r.apply(&vec![b' ';MAX_DOCUMENT_BYTES+1]));
        assert!(!r.apply(b"invalid json")); assert_eq!(r.telemetry().0,1);
        r.value.write().unwrap().as_mut().unwrap().received=Instant::now()-Duration::from_secs(16);
        assert!(r.apply(&bytes)); assert_eq!(r.telemetry().0,0); // Same generation cannot renew.
        let mut expired=wire.clone(); expired["generation"]=2.into(); expired["expires_unix"]=0.into();
        assert!(r.apply(&serde_json::to_vec(&expired).unwrap()));
        assert!(r.policy("192.0.2.1".parse().unwrap()).0.observe);
        assert_eq!(r.telemetry().0,0);
    }
    #[test] fn expired_and_unrenewed_lease_fail_to_observation() {
        let r=Runtime::new(true); let ip="192.0.2.4".parse().unwrap();
        assert!(r.policy(ip).0.observe);
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        *r.value.write().unwrap()=Some(Snapshot {wire:Wire {generation:1,expires_unix:now+10,mode:3,observe:false,
            allow:vec![],block:vec!["192.0.2.0/24".parse().unwrap()]},received:Instant::now()});
        assert!(r.policy(ip).1); assert_eq!(r.policy(ip).0.mode,3);
        r.value.write().unwrap().as_mut().unwrap().received=Instant::now()-Duration::from_secs(16);
        let (p,blocked)=r.policy(ip); assert!(p.observe); assert_eq!(p.mode,0); assert!(!blocked);
    }
    #[test] fn allow_precedes_block() {
        let r=Runtime::new(true); let ip="192.0.2.4".parse().unwrap();
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        *r.value.write().unwrap()=Some(Snapshot {wire:Wire {generation:1,expires_unix:now+10,mode:2,observe:false,
            allow:vec!["192.0.2.4/32".parse().unwrap()],block:vec!["192.0.2.0/24".parse().unwrap()]},received:Instant::now()});
        let (p,blocked)=r.policy(ip); assert!(p.exempt); assert!(!blocked);
    }
}
