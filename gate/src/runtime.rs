use crate::limiter::{Policy, normalize};
use ipnet::IpNet;
use serde::Deserialize;
use std::{collections::{BTreeMap,HashSet}, io, net::IpAddr, sync::{Arc, RwLock, atomic::{AtomicU64,Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tokio::io::AsyncReadExt;

const MAX_DOCUMENT_BYTES: usize = 262144;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire { generation: u64, expires_unix: u64, mode: usize, observe: bool, allow: Vec<IpNet>, block: Vec<IpNet> }
// Tiny ACLs are faster to scan; large ACLs should not require thousands of
// linear CIDR comparisons on every incoming TCP connection.
struct PrefixIndex {
    small: Vec<IpNet>,
    v4: Vec<(u32,HashSet<u32>)>,
    v6: Vec<(u128,HashSet<u128>)>,
}
impl PrefixIndex {
    fn new(nets:&[IpNet])->Self {
        if nets.len()<=8 {
            return Self {small:nets.to_vec(),v4:Vec::new(),v6:Vec::new()};
        }
        let mut v4:BTreeMap<u8,HashSet<u32>>=BTreeMap::new();
        let mut v6:BTreeMap<u8,HashSet<u128>>=BTreeMap::new();
        for net in nets {
            match net {
                IpNet::V4(v) => {v4.entry(v.prefix_len()).or_default().insert(u32::from(v.network()));},
                IpNet::V6(v) => {v6.entry(v.prefix_len()).or_default().insert(u128::from(v.network()));},
            }
        }
        Self {
            small:Vec::new(),
            v4:v4.into_iter().map(|(bits,values)| {
                (u32::MAX.checked_shl(32-u32::from(bits)).unwrap_or(0),values)
            }).collect(),
            v6:v6.into_iter().map(|(bits,values)| {
                (u128::MAX.checked_shl(128-u32::from(bits)).unwrap_or(0),values)
            }).collect(),
        }
    }
    fn contains(&self,ip:IpAddr)->bool {
        if !self.small.is_empty() {return self.small.iter().any(|n|n.contains(&ip));}
        match ip {
            IpAddr::V4(v) => {
                let raw=u32::from(v);
                self.v4.iter().any(|(mask,nets)|nets.contains(&(raw & mask)))
            }
            IpAddr::V6(v) => {
                let raw=u128::from(v);
                self.v6.iter().any(|(mask,nets)|nets.contains(&(raw & mask)))
            }
        }
    }
}
struct Snapshot { wire: Wire, received: Instant, allow_index:PrefixIndex, block_index:PrefixIndex }
pub struct Runtime { value: RwLock<Option<Snapshot>>, default_observe: bool, rejected:AtomicU64, missing:AtomicU64 }
impl Runtime {
    pub fn new(default_observe: bool) -> Arc<Self> { Arc::new(Self { value: RwLock::new(None), default_observe, rejected:AtomicU64::new(0), missing:AtomicU64::new(0) }) }
    pub fn telemetry(&self) -> (u64,u64,u64) {
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let state=self.value.read().unwrap();
        let generation=state.as_ref().filter(|s|s.received.elapsed()<=Duration::from_secs(15) && now<s.wire.expires_unix)
            .map(|s|s.wire.generation).unwrap_or(0);
        (generation,self.rejected.load(Ordering::Relaxed),self.missing.load(Ordering::Relaxed))
    }
    fn apply(&self,b:&[u8]) -> bool {
        if b.len()>MAX_DOCUMENT_BYTES { return false; }
        let Ok(w)=serde_json::from_slice::<Wire>(b) else { return false; };
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if w.mode>3 || w.expires_unix>now.saturating_add(30) || w.allow.len()>4096 || w.block.len()>4096 {
            return false;
        }
        let mut state=self.value.write().unwrap();
        if let Some(previous)=state.as_ref() {
            // Never let a stale or replayed generation restore an older policy.
            // Identical generations cannot renew a lease or replace contents.
            if w.generation < previous.wire.generation { return false; }
            if w.generation == previous.wire.generation { return true; }
        }
        // Explicit expired publications retire the previous policy immediately.
        let allow_index=PrefixIndex::new(&w.allow);
        let block_index=PrefixIndex::new(&w.block);
        *state=Some(Snapshot {wire:w,received:Instant::now(),allow_index,block_index});
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
        let exempt = s.allow_index.contains(ip);
        let p = Policy { mode:s.wire.mode, observe:s.wire.observe, exempt };
        (p, !p.observe && !exempt && s.block_index.contains(ip))
    }
    fn record_open_error(&self, kind: io::ErrorKind) {
        if kind == io::ErrorKind::NotFound {
            self.missing.fetch_add(1,Ordering::Relaxed);
        } else {
            self.rejected.fetch_add(1,Ordering::Relaxed);
        }
    }
    pub async fn watch(self: Arc<Self>, path: String) {
        if path.is_empty() { return; }
        loop {
            match tokio::fs::File::open(&path).await {
                Ok(file) => {
                    let mut b=Vec::new();
                    let accepted=file.take((MAX_DOCUMENT_BYTES+1) as u64)
                        .read_to_end(&mut b).await.is_ok() && self.apply(&b);
                    if !accepted { self.rejected.fetch_add(1,Ordering::Relaxed); }
                }
                Err(e) => self.record_open_error(e.kind()),
            }
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
    #[test] fn replayed_old_generation_cannot_reenable_expired_or_blocking_policy() {
        let r=Runtime::new(true);
        let ip="192.0.2.4".parse().unwrap();
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let enforced=serde_json::json!({"generation":7,"expires_unix":now+10,
            "mode":2,"observe":false,"allow":[],"block":["192.0.2.0/24"]});
        assert!(r.apply(&serde_json::to_vec(&enforced).unwrap()));
        assert!(r.policy(ip).1);
        let newer=serde_json::json!({"generation":8,"expires_unix":now+10,
            "mode":0,"observe":true,"allow":[],"block":[]});
        assert!(r.apply(&serde_json::to_vec(&newer).unwrap()));
        assert!(!r.policy(ip).1);
        assert!(!r.apply(&serde_json::to_vec(&enforced).unwrap()));
        assert_eq!(r.telemetry().0,8);
        assert!(!r.policy(ip).1);
        let expired=serde_json::json!({"generation":9,"expires_unix":0,
            "mode":2,"observe":false,"allow":[],"block":["192.0.2.0/24"]});
        assert!(r.apply(&serde_json::to_vec(&expired).unwrap()));
        assert!(r.policy(ip).0.observe);
        assert!(!r.apply(&serde_json::to_vec(&enforced).unwrap()));
        assert!(r.policy(ip).0.observe);
    }
    #[test] fn expired_and_unrenewed_lease_fail_to_observation() {
        let r=Runtime::new(true); let ip="192.0.2.4".parse().unwrap();
        assert!(r.policy(ip).0.observe);
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let wire=Wire {generation:1,expires_unix:now+10,mode:3,observe:false,
            allow:vec![],block:vec!["192.0.2.0/24".parse().unwrap()]};
        let allow_index=PrefixIndex::new(&wire.allow); let block_index=PrefixIndex::new(&wire.block);
        *r.value.write().unwrap()=Some(Snapshot {wire,received:Instant::now(),allow_index,block_index});
        assert!(r.policy(ip).1); assert_eq!(r.policy(ip).0.mode,3);
        r.value.write().unwrap().as_mut().unwrap().received=Instant::now()-Duration::from_secs(16);
        let (p,blocked)=r.policy(ip); assert!(p.observe); assert_eq!(p.mode,0); assert!(!blocked);
    }
    #[test] fn indexed_cidrs_match_linear_ipv4_ipv6_and_overlap() {
        let mut nets=vec!["0.0.0.0/0".parse::<IpNet>().unwrap(),
            "192.0.2.0/24".parse().unwrap(),"2001:db8::/32".parse().unwrap(),
            "2001:db8:1::/48".parse().unwrap(), "::1/128".parse().unwrap()];
        for n in 1..20 {
            nets.push(format!("198.51.{}.0/24",n).parse().unwrap());
            nets.push(format!("2001:db8:{:x}::/48",n+200).parse().unwrap());
        }
        let matcher=PrefixIndex::new(&nets);
        for ip in ["192.0.2.1", "203.0.113.3", "::1",
                   "2001:db8:1::7", "2001:db8:cafe::1", "2001:4860::1"] {
            let ip=ip.parse::<IpAddr>().unwrap();
            assert_eq!(matcher.contains(ip),nets.iter().any(|n|n.contains(&ip)), "{ip}");
        }
        let no_match=PrefixIndex::new(&["2001:db8::/32".parse().unwrap(),
            "2001:db8:1::/48".parse().unwrap(),"::1/128".parse().unwrap()]);
        assert!(!no_match.contains("192.0.2.1".parse().unwrap()));
        let universal=PrefixIndex::new(&["::/0".parse().unwrap()]);
        assert!(universal.contains("2001:4860::1".parse().unwrap()));
        let small=PrefixIndex::new(&["192.0.2.0/24".parse().unwrap()]);
        assert!(small.contains("192.0.2.40".parse().unwrap()));
        assert!(!small.contains("192.0.3.1".parse().unwrap()));
    }
    #[test] fn missing_policy_file_is_not_invalid_policy() {
        let r=Runtime::new(true);
        r.record_open_error(io::ErrorKind::NotFound);
        r.record_open_error(io::ErrorKind::NotFound);
        r.record_open_error(io::ErrorKind::PermissionDenied);
        assert_eq!(r.telemetry(), (0,1,2));
        assert!(r.policy("192.0.2.1".parse().unwrap()).0.observe);
    }
    #[test] fn allow_precedes_block() {
        let r=Runtime::new(true); let ip="192.0.2.4".parse().unwrap();
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let wire=Wire {generation:1,expires_unix:now+10,mode:2,observe:false,
            allow:vec!["192.0.2.4/32".parse().unwrap()],block:vec!["192.0.2.0/24".parse().unwrap()]};
        let allow_index=PrefixIndex::new(&wire.allow); let block_index=PrefixIndex::new(&wire.block);
        *r.value.write().unwrap()=Some(Snapshot {wire,received:Instant::now(),allow_index,block_index});
        let (p,blocked)=r.policy(ip); assert!(p.exempt); assert!(!blocked);
    }
}
