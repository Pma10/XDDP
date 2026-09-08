use crate::{config::BackendProtection,metrics::Metrics};
use std::{sync::{Arc,Mutex},time::{Duration,Instant}};
use tokio::sync::{Semaphore,OwnedSemaphorePermit};

struct State { failures:u32, generation:u64, retry_at:Option<Instant>, probing:bool, tokens:f64, last:Instant }
pub struct Protection { cfg:BackendProtection,state:Mutex<State>,slots:Arc<Semaphore>,metrics:Arc<Metrics> }
pub struct Attempt { owner:Arc<Protection>,generation:u64,_slot:OwnedSemaphorePermit,finished:bool }
impl Protection {
    pub fn new(cfg:BackendProtection,backend_slots:usize,metrics:Arc<Metrics>)->Arc<Self> {
        Arc::new(Self {cfg,state:Mutex::new(State {failures:0,generation:0,retry_at:None,probing:false,
                tokens:cfg.attempts.burst,last:Instant::now()}),
            slots:Arc::new(Semaphore::new(if cfg.max_connecting==0 {backend_slots} else {cfg.max_connecting})),metrics})
    }
    pub fn enter(self:&Arc<Self>,now:Instant)->Option<Attempt> {
        let slot=self.slots.clone().try_acquire_owned().ok()?;
        let mut state=self.state.lock().unwrap();
        if let Some(at)=state.retry_at {
            if now<at || state.probing { return None; }
        }
        // Debit only an actual player dial, after circuit and concurrency checks.
        // Closing a healthy connection cannot refund tokens or reset its burst.
        let rate=self.cfg.attempts;
        if rate.per_second>0.0 {
            state.tokens=(state.tokens+now.saturating_duration_since(state.last).as_secs_f64()*rate.per_second).min(rate.burst);
            state.last=state.last.max(now);
            if state.tokens<1.0 { self.metrics.inc(50); return None; }
            state.tokens-=1.0;
        }
        if state.retry_at.is_some() {state.probing=true;}
        Some(Attempt {owner:self.clone(),generation:state.generation,_slot:slot,finished:false})
    }
    fn finish(&self,generation:u64,ok:bool,now:Instant) {
        if self.cfg.failure_threshold==0 { return; }
        let mut state=self.state.lock().unwrap();
        // A completion from an older wave cannot reopen/close the current circuit.
        if generation!=state.generation { return; }
        if ok { state.failures=0; state.retry_at=None; state.probing=false; }
        else {
            state.failures=state.failures.saturating_add(1);
            if state.probing || state.failures>=self.cfg.failure_threshold {
                state.generation=state.generation.wrapping_add(1);
                state.retry_at=Some(now+Duration::from_millis(self.cfg.cooldown_ms));
                state.probing=false; self.metrics.inc(48);
            }
        }
    }
}
impl Attempt {
    pub fn finish(mut self,ok:bool,now:Instant) { self.owner.finish(self.generation,ok,now); self.finished=true; }
}
impl Drop for Attempt {
    fn drop(&mut self) { if !self.finished { self.owner.finish(self.generation,false,Instant::now()); } }
}

#[cfg(test)] mod tests {
    use super::*;
    use crate::config::Rate;
    #[test] fn successful_reconnects_do_not_reset_dial_budget() {
        let m=Arc::new(Metrics::new());
        let p=Protection::new(BackendProtection {max_connecting:1,attempts:Rate {per_second:2.0,burst:2.0},..Default::default()},4,m.clone());
        let now=p.state.lock().unwrap().last;
        let first=p.enter(now).unwrap(); assert!(p.enter(now).is_none()); // Cap rejection must not spend credit.
        first.finish(true,now);
        p.enter(now).unwrap().finish(true,now);
        assert!(p.enter(now).is_none());
        let later=now+Duration::from_millis(501);
        p.enter(later).unwrap().finish(true,later);
        assert!(p.enter(now).is_none()); // Clock reversal never refills.
        assert_eq!(m.get(50),2); assert_eq!(m.get(48),0);
    }
    #[test] fn circuit_rejections_do_not_spend_recovery_dial_credit() {
        let m=Arc::new(Metrics::new());
        let p=Protection::new(BackendProtection {max_connecting:1,failure_threshold:1,cooldown_ms:100,
            attempts:Rate {per_second:0.001,burst:2.0}},4,m);
        let now=p.state.lock().unwrap().last;
        p.enter(now).unwrap().finish(false,now);
        for _ in 0..10 {assert!(p.enter(now).is_none());}
        p.enter(now+Duration::from_millis(101)).unwrap().finish(true,now+Duration::from_millis(101));
    }
    #[test] fn outage_has_single_probe_and_ignores_old_completions() {
        let now=Instant::now(); let m=Arc::new(Metrics::new());
        let p=Protection::new(BackendProtection {max_connecting:3,failure_threshold:1,cooldown_ms:100,..Default::default()},4,m.clone());
        let old=p.enter(now).unwrap(); let failed=p.enter(now).unwrap();
        failed.finish(false,now);
        old.finish(true,now); // Late successful connect must not clear the failure wave.
        assert!(p.enter(now).is_none());
        let later=now+Duration::from_millis(101);
        let probe=p.enter(later).unwrap(); assert!(p.enter(later).is_none());
        probe.finish(false,later); assert!(p.enter(later).is_none());
        let later=later+Duration::from_millis(101);
        p.enter(later).unwrap().finish(true,later);
        p.enter(later).unwrap().finish(true,later); assert_eq!(m.get(48),2);
    }
    #[test] fn connecting_cap_and_cancelled_attempt_release_permits() {
        let now=Instant::now(); let m=Arc::new(Metrics::new());
        let p=Protection::new(BackendProtection {max_connecting:1,..Default::default()},4,m);
        let a=p.enter(now).unwrap(); assert!(p.enter(now).is_none()); drop(a);
        assert!(p.enter(now).is_some());
    }
}
