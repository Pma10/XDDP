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
    fn take(&mut self, now: Instant, factor: f64) -> bool {
        if self.rate.per_second == 0.0 { return true; }
        let cap = (self.rate.burst * factor).max(1.0);
        self.tokens = (self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * self.rate.per_second * factor).min(cap);
        self.last = now;
        if self.tokens < 1.0 { false } else { self.tokens -= 1.0; true }
    }
}
struct Entry {
    active: usize, touched: Instant, buckets: [Bucket;4],
    score: f64, score_at: Instant, penalty_until: Instant,
}
impl Entry {
    fn new(r: &Rates, now: Instant) -> Self { Self { active: 0, touched: now,
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
pub struct Ticket { limiter: Arc<Limiter>, ip: IpAddr, prefix: IpAddr, pub handshake: bool, pub admitted: bool }
impl Drop for Ticket {
    fn drop(&mut self) {
        let now = Instant::now();
        let churn = !self.admitted;
        if churn { self.limiter.metrics.inc(22); }
        if !self.handshake { self.limiter.metrics.inc(13); }
        for (table, key) in [(&self.limiter.ip, self.ip), (&self.limiter.prefix, self.prefix)] {
            let mut map = table.shards[table.shard(key)].lock().unwrap();
            if let Some(e) = map.get_mut(&key) {
                e.active -= 1; e.touched = now;
                if churn {
                    e.decay(now, self.limiter.cfg.churn_half_life_seconds);
                    e.score = (e.score + if self.handshake {0.25} else {1.0}).min(1e6);
                    let threshold = self.limiter.cfg.churn_score_threshold;
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
        let factor = self.cfg.mode_multipliers[p.mode];
        let ip_ok = i.buckets[0].take(now, factor) && now >= i.penalty_until;
        let prefix_ok = net.buckets[0].take(now, factor) && now >= net.penalty_until;
        if !self.judged(ip_ok, 14, p) || !self.judged(prefix_ok, 15, p) { return None; }
        i.active += 1; net.active += 1;
        Some(Ticket { limiter: self.clone(), ip, prefix, handshake: false, admitted: false })
    }
    pub fn event(&self, t: &Ticket, event: Event, p: Policy) -> bool {
        // Consume the global budget first; admission-phase operations are bounded.
        if !self.global(event, p) { return false; }
        let now = Instant::now(); let factor = self.cfg.mode_multipliers[p.mode];
        for (table, key, reason) in [(&self.ip,t.ip,14), (&self.prefix,t.prefix,15)] {
            let mut shard = table.shards[table.shard(key)].lock().unwrap();
            let Some(e) = shard.get_mut(&key) else { return false; };
            e.touched = now;
            let ok = e.buckets[event as usize].take(now, factor) && now >= e.penalty_until;
            if !self.judged(ok, reason, p) { return false; }
        }
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
    }
    #[test] fn prefix_and_mapped_identity() {
        assert_eq!(normalize("::ffff:192.0.2.4".parse().unwrap()), "192.0.2.4".parse::<IpAddr>().unwrap());
        assert_eq!(subnet("192.0.2.4".parse().unwrap(),24,64), "192.0.2.0".parse::<IpAddr>().unwrap());
        assert_eq!(subnet("2001:db8::1234".parse().unwrap(),24,64), "2001:db8::".parse::<IpAddr>().unwrap());
    }
}
