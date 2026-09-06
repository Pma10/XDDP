mod cache;
mod config;
mod limiter;
mod metrics;
mod protocol;
mod runtime;

use config::Config;
use limiter::{Event, Limiter, Ticket};
use metrics::{Gauge, Metrics};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::{TcpListener,TcpStream}, sync::{OwnedSemaphorePermit,Semaphore},
    task::JoinSet, time::{timeout,Instant}};

struct State {
    cfg:Arc<Config>, metrics:Arc<Metrics>, limiter:Arc<Limiter>, runtime:Arc<runtime::Runtime>,
    cache:Arc<cache::StatusCache>, sockets:Arc<Semaphore>, prelogin:Arc<Semaphore>,
    admitted:Arc<Semaphore>, backend:Arc<Semaphore>,
}
struct PreloginTime { start:Instant, metrics:Arc<Metrics> }
impl Drop for PreloginTime {
    fn drop(&mut self) { self.metrics.add(18,self.start.elapsed().as_micros().min(u64::MAX as u128) as u64); self.metrics.inc(19); }
}
struct Admission { slot:OwnedSemaphorePermit, gauge:Gauge, duration:PreloginTime }
impl Drop for Admission { fn drop(&mut self) { let _ = (&self.slot,&self.gauge,&self.duration); } }

fn main() -> Result<(),Box<dyn std::error::Error>> {
    let args:Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--state-sizes" {
        let (key,value,ticket) = limiter::state_sizes();
        println!("{{\"identity_key_bytes\":{key},\"identity_value_bytes\":{value},\"connection_ticket_bytes\":{ticket}}}");
        return Ok(());
    }
    if args.len() < 2 || args.len() > 3 || (args.len() == 3 && args[2] != "--check") {
        return Err("usage: xddp-gate CONFIG.json [--check]".into());
    }
    let cfg = Config::load(Path::new(&args[1]))?;
    if args.len() == 3 { println!("configuration valid"); return Ok(()); }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(cfg.workers).enable_all().build()?;
    rt.block_on(run(cfg))
}
async fn run(cfg:Config) -> Result<(),Box<dyn std::error::Error>> {
    // Bind both before accepting any player or starting backend polling.
    let listener = TcpListener::bind(cfg.listen).await?;
    let metrics_listener = TcpListener::bind(cfg.metrics).await?;
    let m = Arc::new(Metrics::new());
    let s = Arc::new(State {
        limiter:Limiter::new(cfg.limits.clone(),m.clone()), runtime:runtime::Runtime::new(if cfg.runtime_file.is_empty() {cfg.observe} else {true}),
        cache:cache::StatusCache::new(&cfg), sockets:Arc::new(Semaphore::new(cfg.limits.total_sockets)),
        prelogin:Arc::new(Semaphore::new(cfg.limits.prelogin)), admitted:Arc::new(Semaphore::new(cfg.limits.admitted)),
        backend:Arc::new(Semaphore::new(cfg.limits.backend-1)), cfg:Arc::new(cfg), metrics:m.clone(),
    });
    tokio::spawn(metrics::serve(metrics_listener,m));
    tokio::spawn(s.runtime.clone().watch(s.cfg.runtime_file.clone()));
    let refresh = tokio::spawn(s.cache.clone().refresh(s.cfg.clone(),s.sockets.clone(),s.metrics.clone()));
    let maintenance = s.clone();
    tokio::spawn(async move {
        let mut shard = 0;
        loop { maintenance.limiter.sweep(shard); shard = (shard+1)%64;
            let (p,_) = maintenance.runtime.policy(maintenance.cfg.listen.ip());
            maintenance.metrics.set(34,p.mode as u64); maintenance.metrics.set(35,u64::from(p.observe));
            tokio::time::sleep(Duration::from_millis(100)).await; }
    });
    eprintln!("xddp-gate ready on {}; observation={}",s.cfg.listen,s.runtime.policy(s.cfg.listen.ip()).0.observe);
    let mut tasks = JoinSet::new();
    let shutdown = shutdown_signal(); tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (client,peer) = match accepted { Ok(x)=>x, Err(_)=> {
                    s.metrics.inc(26); tokio::time::sleep(Duration::from_millis(100)).await; continue; } };
                s.metrics.inc(0);
                let (policy,blocked) = s.runtime.policy(peer.ip());
                if blocked || (!policy.observe && policy.mode == 3) || !s.limiter.global(Event::Connect,policy) { continue; }
                let (Ok(socket),Ok(pre)) = (s.sockets.clone().try_acquire_owned(),s.prelogin.clone().try_acquire_owned()) else {
                    s.metrics.inc(20); continue;
                };
                let Some(ticket) = s.limiter.accept(peer.ip(),policy) else { continue; };
                let state = s.clone();
                let active = Gauge::new(s.metrics.clone(),1);
                let admission = Admission { slot:pre,gauge:Gauge::new(s.metrics.clone(),2),
                    duration:PreloginTime { start:Instant::now(),metrics:s.metrics.clone() } };
                tasks.spawn(async move {
                    let (_socket,_active) = (socket,active);
                    if let Err(e) = handle(client,peer,state.clone(),ticket,admission).await {
                        record_error(&state.metrics,e);
                    }
                });
            }
        }
    }
    drop(listener); refresh.abort();
    eprintln!("stopping admission; draining active relays for {} seconds",s.cfg.timeouts.shutdown_seconds);
    if timeout(Duration::from_secs(s.cfg.timeouts.shutdown_seconds),async { while tasks.join_next().await.is_some() {} }).await.is_err() {
        tasks.abort_all(); while tasks.join_next().await.is_some() {}
    }
    Ok(())
}
async fn shutdown_signal() {
    #[cfg(unix)] {
        use tokio::signal::unix::{signal,SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! { _=term.recv()=>{}, _=tokio::signal::ctrl_c()=>{} }
    }
    #[cfg(not(unix))] { let _ = tokio::signal::ctrl_c().await; }
}
fn record_error(m:&Metrics,e:protocol::Error) {
    use protocol::Error::*;
    match e { VarInt=>m.inc(8), Oversized=>m.inc(9), Unsupported=>m.inc(10),
        Deadline=>m.inc(11), Slow=>m.inc(12), Invalid=>m.inc(5), Eof|Io=>{} }
}
async fn phase(client:&mut TcpStream,s:&State,left:&mut usize,ms:u64,first_ms:u64) -> Result<protocol::Frame,protocol::Error> {
    protocol::read_frame(client,s.cfg.protocol.max_frame,left,Instant::now()+Duration::from_millis(ms),
        Duration::from_millis(s.cfg.timeouts.progress_ms),Duration::from_millis(first_ms)).await
}
async fn handle(mut client:TcpStream,peer:SocketAddr,s:Arc<State>,mut ticket:Ticket,admission:Admission) -> Result<(),protocol::Error> {
    use protocol::Error;
    client.set_nodelay(true).map_err(|_|Error::Io)?;
    let mut left = s.cfg.protocol.max_initial_bytes;
    // Start the absolute handshake deadline at accept, not when a task gets CPU.
    let handshake = protocol::read_frame(&mut client,s.cfg.protocol.max_frame,&mut left,
        admission.duration.start+Duration::from_millis(s.cfg.timeouts.handshake_ms),
        Duration::from_millis(s.cfg.timeouts.progress_ms),Duration::from_millis(s.cfg.timeouts.first_progress_ms)).await?;
    let h = protocol::handshake(&handshake.body,&s.cfg.protocol)?;
    ticket.handshake = true; s.metrics.inc(4);
    let (p,blocked) = s.runtime.policy(peer.ip());
    if blocked || !s.limiter.event(&ticket,Event::Handshake,p) { return Ok(()); }
    if h.state == 1 {
        let request = phase(&mut client,&s,&mut left,s.cfg.timeouts.status_ms,s.cfg.timeouts.progress_ms).await?;
        protocol::status_request(&request.body)?; s.metrics.inc(6);
        let (p,blocked) = s.runtime.policy(peer.ip());
        if blocked || !s.limiter.event(&ticket,Event::Status,p) { return Ok(()); }
        let response = s.cache.get(&s.metrics);
        timeout(Duration::from_millis(s.cfg.timeouts.status_ms),client.write_all(&response)).await.map_err(|_|Error::Deadline)?.map_err(|_|Error::Io)?;
        // A successful status-only client may close without a ping; do not score it as churn.
        ticket.status_complete = true;
        let ping = phase(&mut client,&s,&mut left,s.cfg.timeouts.status_ms,s.cfg.timeouts.progress_ms).await?;
        protocol::ping(&ping.body)?;
        timeout(Duration::from_millis(s.cfg.timeouts.status_ms),client.write_all(&ping.wire)).await.map_err(|_|Error::Deadline)?.map_err(|_|Error::Io)?;
        return Ok(());
    }
    let login = phase(&mut client,&s,&mut left,s.cfg.timeouts.login_ms,s.cfg.timeouts.progress_ms).await?;
    protocol::login(&login.body,h.version,&s.cfg.protocol)?; s.metrics.inc(7);
    let (p,blocked) = s.runtime.policy(peer.ip());
    if blocked || (!p.observe && p.mode == 3) || !s.limiter.event(&ticket,Event::Login,p) { return Ok(()); }
    let (Ok(admitted),Ok(backend_slot),Ok(backend_socket)) = (s.admitted.clone().try_acquire_owned(),
        s.backend.clone().try_acquire_owned(),s.sockets.clone().try_acquire_owned()) else { s.metrics.inc(20); return Ok(()); };
    let (_admitted,_backend_slot,_backend_socket) = (admitted,backend_slot,backend_socket);
    let _backend_gauge = Gauge::new(s.metrics.clone(),3);
    s.metrics.inc(31);
    let backend = timeout(Duration::from_millis(s.cfg.timeouts.backend_ms),async {
        let mut backend = TcpStream::connect(s.cfg.backend).await?;
        backend.set_nodelay(true)?;
        if s.cfg.proxy_v2 { backend.write_all(&cache::proxy_header(peer,client.local_addr()?)?).await?; }
        backend.write_all(&handshake.wire).await?; backend.write_all(&login.wire).await?;
        Ok::<_,std::io::Error>(backend)
    }).await;
    let mut backend = match backend { Ok(Ok(b))=>b, _=>{s.metrics.inc(17); return Ok(());} };
    let _admitted_gauge = Gauge::new(s.metrics.clone(),30);
    ticket.admitted = true;
    // Keep identity concurrency accounting until relay ends; no hot-path limiter locks.
    drop(admission); drop(handshake); drop(login);
    if tokio::io::copy_bidirectional_with_sizes(&mut client,&mut backend,s.cfg.relay_buffer,s.cfg.relay_buffer).await.is_err() {
        s.metrics.inc(25);
    }
    Ok(())
}
