use crate::{config::{Limits, Rate, Rates}, metrics::Metrics};
use std::{collections::{HashMap, hash_map::RandomState}, hash::{BuildHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr}, sync::{Arc, Mutex}, time::{Duration, Instant}};

const SHARDS: usize = 64;
#[derive(Clone, Copy)]
pub enum Event { Connect = 0, Handshake = 1, Status = 2, Login = 3 }
#[derive(Clone, Copy)]
pub struct Policy { pub mode: usize, pub observe: bool, pub exempt: bool }

#[derive(Clone)]
struct Bucket { tokens: f64, last: Instant, rate: Rate }
impl Bucket {
    fn new(rate: Rate, now: Instant) -> Self { Self { tokens: rate.burst, last: now, rate } }
    fn available(&mut self, now: Instant, factor: f64) -> bool {
        if self.rate.per_second == 0.0 { return true; }
        let cap = (self.rate.burst * factor).max(1.0);
        self.tokens = (self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * self.rate.per_second * factor).min(cap);
        self.last = self.last.max(now);
        self.tokens >= 1.0
    }
    fn consume(&mut self) {
        if self.rate.per_second > 0.0 { self.tokens -= 1.0; }
    }
    fn take(&mut self, now: Instant, factor: f64) -> bool {
        if !self.available(now, factor) { return false; }
        self.consume(); true
    }
}
struct Entry {
    active: usize, pending: usize, touched: Instant, buckets: [Bucket;4],
    score: f64, score_at: Instant, penalty_until: Instant,
}
impl Entry {
    fn new(r: &Rates, now: Instant) -> Self { Self { active: 0, pending: 0, touched: now,
        buckets: r.list().map(|x| Bucket::new(x, now)), score: 0.0,
        score_at: now, penalty_until: now } }
    fn decay(&mut self, now: Instant, half_life: u64) {
        self.score *= 2f64.powf(-now.saturating_duration_since(self.score_at).as_secs_f64() / half_life as f64);
        self.score_at = now;
    }
}
struct Table { shards: Vec<Mutex<HashMap<IpAddr,Entry>>>, hash: RandomState, capacity: usize }
impl Table {
    fn new(capacity: usize) -> Self { Self { shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        hash: RandomState::new(), capacity: capacity / SHARDS } }
    fn shard(&self, ip: IpAddr) -> usize { let mut h = self.hash.build_hasher(); ip.hash(&mut h); h.finish() as usize % SHARDS }
}
pub struct Limiter { ip: Table, prefix: Table, global: Mutex<[Bucket;4]>, cfg: Limits, metrics: Arc<Metrics> }
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip { IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip), _ => ip }
}
fn subnet(ip: IpAddr, v4: u8, v6: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => IpAddr::V4(Ipv4Addr::from(u32::from(v) & if v4 == 0 {0} else {u32::MAX << (32-v4)})),
        IpAddr::V6(v) => IpAddr::V6(Ipv6Addr::from(u128::from(v) & if v6 == 0 {0} else {u128::MAX << (128-v6)})),
    }
}
pub struct Ticket { limiter: Arc<Limiter>, ip: IpAddr, prefix: IpAddr,
    pub handshake: bool, pub admitted: bool, pub status_complete: bool, pub server_rejected: bool }
impl Ticket {
    pub fn mark_admitted(&mut self) {
        if self.admitted { return; }
        for (table,key) in [(&self.limiter.ip,self.ip),(&self.limiter.prefix,self.prefix)] {
            let mut map=table.shards[table.shard(key)].lock().unwrap();
            if let Some(e)=map.get_mut(&key) { e.pending-=1; }
        }
        self.admitted=true;
    }
}
pub fn state_sizes() -> (usize,usize,usize) {
    (std::mem::size_of::<IpAddr>(),std::mem::size_of::<Entry>(),std::mem::size_of::<Ticket>())
}
impl Drop for Ticket {
    fn drop(&mut self) {
        let now = Instant::now();
        // Once relaying, a short close could be backend/BotSentry policy. Do not
        // infer client fault from an opaque stream's lifetime or EOF direction.
        let churn = !self.server_rejected && !self.status_complete && !self.admitted;
        if churn { self.limiter.metrics.inc(22); }
        if !self.handshake { self.limiter.metrics.inc(13); }
        for (table, key, threshold) in [(&self.limiter.ip, self.ip, self.limiter.cfg.churn_score_threshold),
            (&self.limiter.prefix, self.prefix, self.limiter.cfg.churn_prefix_score_threshold)] {
            let mut map = table.shards[table.shard(key)].lock().unwrap();
            if let Some(e) = map.get_mut(&key) {
                e.active -= 1; e.touched = now;
                if !self.admitted { e.pending -= 1; }
                if churn {
                    e.decay(now, self.limiter.cfg.churn_half_life_seconds);
                    e.score = (e.score + if self.handshake {0.25} else {1.0}).min(1e6);
                    if threshold > 0.0 && e.score >= threshold {
                        e.penalty_until = now + Duration::from_secs(self.limiter.cfg.penalty_seconds);
                    }
                }
            }
        }
    }
}
impl Limiter {
    pub fn new(cfg: Limits, metrics: Arc<Metrics>) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self { ip: Table::new(cfg.ip_entries), prefix: Table::new(cfg.prefix_entries),
            global: Mutex::new(cfg.global.list().map(|r| Bucket::new(r, now))), cfg, metrics })
    }
    fn judged(&self, allowed: bool, reason: usize, p: Policy) -> bool {
        if allowed || p.exempt { return true; }
        if p.observe { self.metrics.inc(27); true } else { self.metrics.inc(reason); false }
    }
    pub fn global(&self, event: Event, p: Policy) -> bool {
        let allowed = self.global.lock().unwrap()[event as usize].take(Instant::now(), self.cfg.mode_multipliers[p.mode]);
        self.judged(allowed, 16, Policy { exempt: false, ..p })
    }
    pub fn accept(self: &Arc<Self>, ip: IpAddr, p: Policy) -> Option<Ticket> {
        let ip = normalize(ip); let prefix = subnet(ip, self.cfg.ipv4_prefix, self.cfg.ipv6_prefix);
        let now = Instant::now();
        let mut ips = self.ip.shards[self.ip.shard(ip)].lock().unwrap();
        let mut prefixes = self.prefix.shards[self.prefix.shard(prefix)].lock().unwrap();
        if (!ips.contains_key(&ip) && ips.len() >= self.ip.capacity) ||
            (!prefixes.contains_key(&prefix) && prefixes.len() >= self.prefix.capacity) {
            self.metrics.inc(21); return None;
        }
        let i = ips.entry(ip).or_insert_with(|| { self.metrics.inc(28); self.metrics.inc(32); Entry::new(&self.cfg.ip, now) });
        let net = prefixes.entry(prefix).or_insert_with(|| { self.metrics.inc(29); self.metrics.inc(33); Entry::new(&self.cfg.prefix, now) });
        i.touched = now; net.touched = now;
        if (self.cfg.connections_ip > 0 && i.active >= self.cfg.connections_ip) ||
           (self.cfg.connections_prefix > 0 && net.active >= self.cfg.connections_prefix) {
            self.metrics.inc(20); return None;
        }
        if (self.cfg.prelogin_ip > 0 && i.pending >= self.cfg.prelogin_ip) ||
            (self.cfg.prelogin_prefix > 0 && net.pending >= self.cfg.prelogin_prefix) {
            self.metrics.inc(20); self.metrics.inc(38); return None;
        }
        let factor = self.cfg.mode_multipliers[p.mode];
        let ip_ok = i.buckets[0].available(now, factor) && now >= i.penalty_until;
        let prefix_ok = net.buckets[0].available(now, factor) && now >= net.penalty_until;
        if !self.judged(ip_ok, 14, p) || !self.judged(prefix_ok, 15, p) { return None; }
        if !p.exempt {
            if ip_ok { i.buckets[0].consume(); }
            if prefix_ok { net.buckets[0].consume(); }
        }
        i.active += 1; net.active += 1; i.pending += 1; net.pending += 1;
        Some(Ticket { limiter: self.clone(), ip, prefix, handshake: false, admitted: false,
            status_complete: false, server_rejected: false })
    }
    pub fn event(&self, t: &Ticket, event: Event, p: Policy) -> bool {
        let now = Instant::now(); let factor = self.cfg.mode_multipliers[p.mode];
        // Stable lock order: IP -> prefix -> global. No await or relay I/O here.
        // Commit tokens only after every scope accepts, so a rejected identity
        // cannot drain its CGNAT prefix or other clients' global login budget.
        let mut ips = self.ip.shards[self.ip.shard(t.ip)].lock().unwrap();
        let mut prefixes = self.prefix.shards[self.prefix.shard(t.prefix)].lock().unwrap();
        let (Some(ip), Some(prefix)) = (ips.get_mut(&t.ip), prefixes.get_mut(&t.prefix)) else { return false; };
        ip.touched = now; prefix.touched = now;
        let index = event as usize;
        let ip_ok = ip.buckets[index].available(now, factor) && now >= ip.penalty_until;
        if !self.judged(ip_ok, 14, p) { return false; }
        let prefix_ok = prefix.buckets[index].available(now, factor) && now >= prefix.penalty_until;
        if !self.judged(prefix_ok, 15, p) { return false; }
        let mut global = self.global.lock().unwrap();
        let global_ok = global[index].available(now, factor);
        if !self.judged(global_ok, 16, Policy { exempt:false, ..p }) { return false; }
        if !p.exempt {
            if ip_ok { ip.buckets[index].consume(); }
            if prefix_ok { prefix.buckets[index].consume(); }
        }
        if global_ok { global[index].consume(); }
        true
    }
    pub fn sweep(&self, shard: usize) {
        let now = Instant::now();
        for (table, gauge) in [(&self.ip,32), (&self.prefix,33)] {
            let mut m = table.shards[shard % SHARDS].lock().unwrap();
            m.retain(|_, e| {
                let keep = e.active > 0 || now < e.penalty_until ||
                    now.saturating_duration_since(e.touched).as_secs() < self.cfg.idle_entry_seconds;
                if !keep { self.metrics.dec(gauge); } keep
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn bursts_refill_and_clock_safety() {
        let now = Instant::now();
        let mut b = Bucket::new(Rate { per_second: 2.0, burst: 3.0 }, now);
        for _ in 0..3 { assert!(b.take(now, 1.0)); }
        assert!(!b.take(now, 1.0));
        assert!(b.take(now + Duration::from_millis(500), 1.0));
        assert!(!b.take(now, 1.0));
        assert!(!b.take(now + Duration::from_millis(500), 1.0));
    }
    #[test] fn prefix_and_mapped_identity() {
        assert_eq!(normalize("::ffff:192.0.2.4".parse().unwrap()), "192.0.2.4".parse::<IpAddr>().unwrap());
        assert_eq!(subnet("192.0.2.4".parse().unwrap(),24,64), "192.0.2.0".parse::<IpAddr>().unwrap());
        assert_eq!(subnet("2001:db8::1234".parse().unwrap(),24,64), "2001:db8::".parse::<IpAddr>().unwrap());
    }
    fn config() -> Limits {
        let c: crate::config::Config = serde_json::from_str(include_str!("../../config/gate.json")).unwrap();
        c.limits
    }
    #[test] fn concurrency_release_observation_and_prefix_bursts() {
        let mut cfg = config(); cfg.connections_ip = 1; cfg.connections_prefix = 2;
        cfg.ip.connect = Rate { per_second:1.0,burst:1.0 };
        let metrics = Arc::new(Metrics::new()); let l = Limiter::new(cfg,metrics.clone());
        let observe = Policy { mode:0,observe:true,exempt:false };
        let ip = "192.0.2.1".parse().unwrap();
        let first = l.accept(ip,observe).unwrap();
        assert!(l.accept(ip,observe).is_none()); // Safety caps also apply in observation.
        let second = l.accept("192.0.2.2".parse().unwrap(),observe).unwrap();
        assert!(l.accept("192.0.2.3".parse().unwrap(),observe).is_none());
        drop(first); drop(second);
        let third = l.accept(ip,observe).unwrap(); // Rate candidate, allowed during observation.
        assert!(metrics.get(27)>0); drop(third);
        assert!(l.accept(ip,Policy {observe:false,..observe}).is_none());
    }
    #[test] fn rotating_sources_cannot_exceed_shard_capacity() {
        let mut cfg = config(); cfg.ip_entries=64; cfg.prefix_entries=64;
        let m = Arc::new(Metrics::new()); let l=Limiter::new(cfg,m.clone());
        let p=Policy {mode:0,observe:true,exempt:false};
        let first:IpAddr="192.0.2.1".parse().unwrap(); let shard=l.ip.shard(first);
        let ticket=l.accept(first,p).unwrap();
        let collision=(2..=254).map(|n|IpAddr::V4(Ipv4Addr::new(192,0,2,n)))
            .find(|ip| l.ip.shard(*ip)==shard);
        // Search a larger address space if the random hash happens to have no /24 collision.
        let collision=collision.or_else(|| (0..65536u32).map(|n|IpAddr::V4(Ipv4Addr::from(0xc6330000+n)))
            .find(|ip|l.ip.shard(*ip)==shard)).unwrap();
        assert!(l.accept(collision,p).is_none()); assert_eq!(m.get(21),1);
        l.sweep(shard); assert_eq!(l.ip.shards[shard].lock().unwrap().len(),1);
        drop(ticket);
    }
    #[test] fn valid_status_and_short_backend_closes_do_not_accrue_churn() {
        let m=Arc::new(Metrics::new()); let l=Limiter::new(config(),m.clone());
        let p=Policy {mode:0,observe:true,exempt:false};
        let mut t=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        t.handshake=true; t.status_complete=true; drop(t); assert_eq!(m.get(22),0);
        let mut t=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        t.handshake=true; t.mark_admitted(); drop(t); assert_eq!(m.get(22),0);
        let mut t=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        t.handshake=true; drop(t); assert_eq!(m.get(22),1);
    }
    #[test] fn rejected_ip_cannot_spend_shared_login_tokens() {
        let mut cfg=config();
        cfg.ip.login=Rate {per_second:0.001,burst:1.0};
        cfg.prefix.login=Rate {per_second:0.001,burst:2.0};
        cfg.global.login=Rate {per_second:0.001,burst:2.0};
        let l=Limiter::new(cfg,Arc::new(Metrics::new()));
        let p=Policy {mode:0,observe:false,exempt:false};
        let a=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        let b=l.accept("192.0.2.2".parse().unwrap(),p).unwrap();
        assert!(l.event(&a,Event::Login,p));
        for _ in 0..20 { assert!(!l.event(&a,Event::Login,p)); }
        assert!(l.event(&b,Event::Login,p));
    }
    #[test] fn pending_cap_excludes_relays_and_releases_on_drop() {
        let mut cfg=config(); cfg.prelogin_ip=1; cfg.prelogin_prefix=2;
        let l=Limiter::new(cfg,Arc::new(Metrics::new()));
        let p=Policy {mode:0,observe:true,exempt:false};
        let mut relay=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        assert!(l.accept("192.0.2.1".parse().unwrap(),p).is_none());
        relay.mark_admitted(); relay.mark_admitted();
        let mut a=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        let mut b=l.accept("192.0.2.2".parse().unwrap(),p).unwrap();
        assert!(l.accept("192.0.2.3".parse().unwrap(),p).is_none());
        a.server_rejected=true; drop(a);
        let mut c=l.accept("192.0.2.3".parse().unwrap(),p).unwrap();
        b.server_rejected=true; c.server_rejected=true; drop(b); drop(c); drop(relay);
        assert_eq!(l.prefix.shards[l.prefix.shard("192.0.2.0".parse().unwrap())].lock().unwrap()[&"192.0.2.0".parse::<IpAddr>().unwrap()].pending,0);
    }
    #[test] fn ip_penalty_does_not_implicitly_penalize_shared_prefix() {
        let mut cfg=config(); cfg.churn_score_threshold=0.1; cfg.churn_prefix_score_threshold=0.0;
        let l=Limiter::new(cfg,Arc::new(Metrics::new()));
        let p=Policy {mode:0,observe:false,exempt:false};
        drop(l.accept("192.0.2.1".parse().unwrap(),p).unwrap());
        assert!(l.accept("192.0.2.1".parse().unwrap(),p).is_none());
        assert!(l.accept("192.0.2.2".parse().unwrap(),p).is_some());
    }
    #[test] fn server_rejection_releases_counts_without_cgnat_penalty() {
        let mut cfg=config(); cfg.churn_score_threshold=0.1;
        let m=Arc::new(Metrics::new()); let l=Limiter::new(cfg,m.clone());
        let p=Policy {mode:0,observe:false,exempt:false};
        for _ in 0..20 {
            let mut t=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
            t.handshake=true; t.server_rejected=true; drop(t);
        }
        assert_eq!(m.get(22),0);
        let mut t=l.accept("192.0.2.2".parse().unwrap(),p).unwrap();
        let ips=l.ip.shards[l.ip.shard(t.ip)].lock().unwrap();
        let prefixes=l.prefix.shards[l.prefix.shard(t.prefix)].lock().unwrap();
        assert_eq!(ips[&t.ip].active,1); assert_eq!(prefixes[&t.prefix].active,1);
        assert_eq!(prefixes[&t.prefix].score,0.0);
        drop(prefixes); drop(ips); t.status_complete=true;
    }
    #[test] fn rejected_prefix_preserves_ip_and_global_tokens() {
        let mut cfg=config();
        cfg.ip.login=Rate {per_second:0.001,burst:2.0};
        cfg.prefix.login=Rate {per_second:0.001,burst:1.0};
        cfg.global.login=Rate {per_second:0.001,burst:3.0};
        let l=Limiter::new(cfg,Arc::new(Metrics::new()));
        let p=Policy {mode:0,observe:false,exempt:false};
        let a=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        assert!(l.event(&a,Event::Login,p));
        assert!(!l.event(&a,Event::Login,p));
        assert!(l.ip.shards[l.ip.shard(a.ip)].lock().unwrap()[&a.ip].buckets[3].tokens>=1.0);
        assert!(l.global.lock().unwrap()[3].tokens>=2.0);
    }
    #[test] fn rejected_connect_preserves_cgnat_prefix_burst() {
        let mut cfg=config();
        cfg.ip.connect=Rate {per_second:0.001,burst:1.0};
        cfg.prefix.connect=Rate {per_second:0.001,burst:2.0};
        let l=Limiter::new(cfg,Arc::new(Metrics::new()));
        let p=Policy {mode:0,observe:false,exempt:false};
        let _a=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        for _ in 0..20 { assert!(l.accept("192.0.2.1".parse().unwrap(),p).is_none()); }
        assert!(l.accept("192.0.2.2".parse().unwrap(),p).is_some());
    }
    #[test] fn exempt_identity_does_not_consume_prefix_budget_but_obeys_global() {
        let mut cfg=config();
        cfg.prefix.login=Rate {per_second:0.001,burst:1.0};
        cfg.global.login=Rate {per_second:0.001,burst:2.0};
        let l=Limiter::new(cfg,Arc::new(Metrics::new()));
        let p=Policy {mode:0,observe:false,exempt:false};
        let a=l.accept("192.0.2.1".parse().unwrap(),p).unwrap();
        let b=l.accept("192.0.2.2".parse().unwrap(),p).unwrap();
        assert!(l.event(&a,Event::Login,Policy {exempt:true,..p}));
        assert!(l.event(&b,Event::Login,p));
        assert!(!l.event(&a,Event::Login,Policy {exempt:true,..p}));
    }
}
