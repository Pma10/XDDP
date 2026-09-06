use crate::limiter::{Policy, normalize};
use ipnet::IpNet;
use serde::Deserialize;
use std::{net::IpAddr, sync::{Arc, RwLock}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire { generation: u64, expires_unix: u64, mode: usize, observe: bool, allow: Vec<IpNet>, block: Vec<IpNet> }
struct Snapshot { wire: Wire, received: Instant }
pub struct Runtime { value: RwLock<Option<Snapshot>>, default_observe: bool }
impl Runtime {
    pub fn new(default_observe: bool) -> Arc<Self> { Arc::new(Self { value: RwLock::new(None), default_observe }) }
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
        loop {
            if let Ok(meta) = tokio::fs::metadata(&path).await {
                if meta.len() <= 262144 {
                    if let Ok(b) = tokio::fs::read(&path).await {
                        if let Ok(w) = serde_json::from_slice::<Wire>(&b) {
                            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                            if w.mode <= 3 && w.expires_unix > now && w.expires_unix <= now.saturating_add(30) &&
                                w.allow.len() <= 4096 && w.block.len() <= 4096 {
                                let mut state = self.value.write().unwrap();
                                if state.as_ref().map(|x| x.wire.generation) != Some(w.generation) {
                                    *state = Some(Snapshot { wire:w, received:Instant::now() });
                                }
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)] mod tests {
    use super::*;
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
