use crate::{config::Upload, metrics::Metrics};
use std::{future::Future, io, pin::Pin, sync::{Arc,atomic::{AtomicU64,Ordering}}, task::{Context, Poll}, time::{Duration, Instant}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::{sync::Notify, time::Sleep};

struct Activity { start:tokio::time::Instant,last_ms:AtomicU64 }
impl Activity {
    fn new()->Self {Self {start:tokio::time::Instant::now(),last_ms:AtomicU64::new(0)}}
    fn touch(&self) {
        self.last_ms.store(self.start.elapsed().as_millis().min(u64::MAX as u128) as u64,Ordering::Relaxed);
    }
    async fn expired(&self,ms:u64) {
        loop {
            let last=self.last_ms.load(Ordering::Relaxed);
            tokio::time::sleep_until(self.start+Duration::from_millis(last.saturating_add(ms))).await;
            if self.start.elapsed().as_millis()>=self.last_ms.load(Ordering::Relaxed) as u128+ms as u128 {return;}
        }
    }
}

// A deadline exists only while an actual write/flush/shutdown is blocked.
// Idle but healthy gameplay does not start a timer. Each direction is independent.
struct Guarded<R> {
    inner:R, stall_ms:u64, timer:Option<Pin<Box<Sleep>>>,
    eof:Arc<Notify>, metrics:Arc<Metrics>,
    activity:Option<Arc<Activity>>,
}
impl<R> Guarded<R> {
    fn check<T>(&mut self,result:Poll<io::Result<T>>,cx:&mut Context<'_>)->Poll<io::Result<T>> {
        if result.is_ready() { self.timer=None; return result; }
        if self.stall_ms==0 { return result; }
        let timer=self.timer.get_or_insert_with(||Box::pin(tokio::time::sleep(Duration::from_millis(self.stall_ms))));
        if timer.as_mut().poll(cx).is_ready() {
            self.metrics.inc(45);
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut,"relay write stalled")));
        }
        Poll::Pending
    }
}
impl<R:AsyncRead+Unpin> AsyncRead for Guarded<R> {
    fn poll_read(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<io::Result<()>> {
        let this=self.get_mut(); let before=buf.filled().len(); let space=buf.remaining();
        let result=Pin::new(&mut this.inner).poll_read(cx,buf);
        if matches!(result,Poll::Ready(Ok(()))) && space>0 && buf.filled().len()==before { this.eof.notify_one(); }
        if matches!(result,Poll::Ready(Ok(()))) && buf.filled().len()>before {
            if let Some(activity)=&this.activity {activity.touch();}
        }
        result
    }
}
impl<R:AsyncWrite+Unpin> AsyncWrite for Guarded<R> {
    fn poll_write(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<io::Result<usize>> {
        let this=self.get_mut(); let r=Pin::new(&mut this.inner).poll_write(cx,buf); this.check(r,cx)
    }
    fn poll_flush(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {
        let this=self.get_mut(); let r=Pin::new(&mut this.inner).poll_flush(cx); this.check(r,cx)
    }
    fn poll_shutdown(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {
        let this=self.get_mut(); let r=Pin::new(&mut this.inner).poll_shutdown(cx); this.check(r,cx)
    }
}
pub async fn protected_copy<C,S>(client:&mut C,server:&mut S,size:usize,cfg:Upload,
    stall_ms:u64,half_close_ms:u64,client_idle_ms:u64,metrics:Arc<Metrics>)->io::Result<(u64,u64)>
where C:AsyncRead+AsyncWrite+Unpin,S:AsyncRead+AsyncWrite+Unpin {
    if stall_ms==0 && half_close_ms==0 && client_idle_ms==0 { return copy(client,server,size,cfg,metrics).await; }
    let eof=Arc::new(Notify::new());
    let activity=Arc::new(Activity::new());
    let mut client=Guarded {inner:client,stall_ms,timer:None,eof:eof.clone(),metrics:metrics.clone(),
        activity:if client_idle_ms>0 {Some(activity.clone())} else {None}};
    let mut server=Guarded {inner:server,stall_ms,timer:None,eof:eof.clone(),metrics:metrics.clone(),activity:None};
    let transfer=copy(&mut client,&mut server,size,cfg,metrics.clone());
    tokio::pin!(transfer);
    let drain=async {
        tokio::select! {
            result=&mut transfer=>result,
            _=eof.notified(), if half_close_ms>0=> {
                match tokio::time::timeout(Duration::from_millis(half_close_ms),transfer).await {
                    Ok(result)=>result,
                    Err(_)=> { metrics.inc(46); Err(io::Error::new(io::ErrorKind::TimedOut,"half-close deadline")) }
                }
            }
        }
    };
    tokio::select! {
        result=drain=>result,
        _=activity.expired(client_idle_ms), if client_idle_ms>0=> {
            metrics.inc(49); Err(io::Error::new(io::ErrorKind::TimedOut,"client relay idle"))
        }
    }
}

const SECOND: u128 = 1_000_000_000;
struct Budget { credit: u128, last: Instant, cfg: Upload }
impl Budget {
    fn new(cfg: Upload, now: Instant) -> Self {
        Self { credit:cfg.burst_bytes as u128 * SECOND, last:now, cfg }
    }
    fn take(&mut self, bytes: usize, now: Instant) -> bool {
        let cap=self.cfg.burst_bytes as u128 * SECOND;
        let refill=now.saturating_duration_since(self.last).as_nanos()
            .saturating_mul(self.cfg.bytes_per_second as u128);
        self.credit=self.credit.saturating_add(refill).min(cap);
        self.last=self.last.max(now);
        let cost=bytes as u128 * SECOND;
        if cost>self.credit { self.credit=0; false } else { self.credit-=cost; true }
    }
}

// Only used when an upload budget is configured. No shared rate lock, packet
// decoding, sleep, growing queue or IP penalty on the opaque relay byte path.
struct Monitored<R> { inner:R, budget:Budget, metrics:Arc<Metrics>, flagged:bool }
impl<R:AsyncRead+Unpin> AsyncRead for Monitored<R> {
    fn poll_read(self:Pin<&mut Self>, cx:&mut Context<'_>, buf:&mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this=self.get_mut();
        let before=buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx,buf) {
            Poll::Ready(Ok(())) => {
                let n=buf.filled().len()-before;
                this.metrics.add(40,n as u64);
                if n>0 && !this.budget.take(n,Instant::now()) {
                    if !this.flagged { this.metrics.inc(39); this.flagged=true; }
                    if this.budget.cfg.enforce {
                        // Discard the over-budget chunk rather than forwarding it.
                        buf.set_filled(before);
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::PermissionDenied,"upload budget exceeded")));
                    }
                }
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}
impl<R:AsyncWrite+Unpin> AsyncWrite for Monitored<R> {
    fn poll_write(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<io::Result<usize>> {
        let this=self.get_mut();
        let result=Pin::new(&mut this.inner).poll_write(cx,buf);
        if let Poll::Ready(Ok(n))=result { this.metrics.add(41,n as u64); }
        result
    }
    fn poll_write_vectored(self:Pin<&mut Self>,cx:&mut Context<'_>,bufs:&[io::IoSlice<'_>])->Poll<io::Result<usize>> {
        let this=self.get_mut();
        let result=Pin::new(&mut this.inner).poll_write_vectored(cx,bufs);
        if let Poll::Ready(Ok(n))=result { this.metrics.add(41,n as u64); }
        result
    }
    fn is_write_vectored(&self)->bool { self.inner.is_write_vectored() }
    fn poll_flush(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
pub async fn copy<C,S>(client:&mut C,server:&mut S,size:usize,cfg:Upload,metrics:Arc<Metrics>)->io::Result<(u64,u64)>
where C:AsyncRead+AsyncWrite+Unpin, S:AsyncRead+AsyncWrite+Unpin {
    if cfg.bytes_per_second==0 {
        return tokio::io::copy_bidirectional_with_sizes(client,server,size,size).await;
    }
    let mut client=Monitored { inner:client,budget:Budget::new(cfg,Instant::now()),metrics,flagged:false };
    tokio::io::copy_bidirectional_with_sizes(&mut client,server,size,size).await
}

#[cfg(test)] mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    #[tokio::test(start_paused = true)] async fn backend_output_cannot_keep_silent_client_alive() {
        let (mut player,mut client)=tokio::io::duplex(128);
        let (mut server,mut backend)=tokio::io::duplex(128);
        let m=Arc::new(Metrics::new()); let evidence=m.clone();
        let task=tokio::spawn(async move {protected_copy(&mut client,&mut server,16,Upload::default(),0,0,50,m).await});
        let mut b=[0;1];
        for _ in 0..3 {
            backend.write_all(b"s").await.unwrap(); player.read_exact(&mut b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(task.await.unwrap().unwrap_err().kind(),io::ErrorKind::TimedOut);
        assert_eq!(evidence.get(49),1);
    }
    #[tokio::test(start_paused = true)] async fn client_activity_refreshes_idle_deadline_without_per_packet_timers() {
        let (mut player,mut client)=tokio::io::duplex(128);
        let (mut server,mut backend)=tokio::io::duplex(128);
        let m=Arc::new(Metrics::new()); let evidence=m.clone();
        let task=tokio::spawn(async move {protected_copy(&mut client,&mut server,16,Upload::default(),0,100,50,m).await});
        let mut b=[0;1];
        for _ in 0..6 {
            player.write_all(b"c").await.unwrap(); backend.read_exact(&mut b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(!task.is_finished());
        }
        player.shutdown().await.unwrap(); backend.shutdown().await.unwrap();
        assert_eq!(task.await.unwrap().unwrap(),(6,0)); assert_eq!(evidence.get(49),0);
    }
    #[tokio::test(start_paused = true)] async fn stalled_reader_times_out_without_unbounded_buffering() {
        let (mut player,mut client)=tokio::io::duplex(16);
        let (mut server,mut backend)=tokio::io::duplex(16);
        let m=Arc::new(Metrics::new()); let evidence=m.clone();
        let task=tokio::spawn(async move {protected_copy(&mut client,&mut server,16,Upload::default(),30,0,0,m).await});
        let sender=tokio::spawn(async move {backend.write_all(&[7;1024]).await});
        let error=task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(),io::ErrorKind::TimedOut); assert_eq!(evidence.get(45),1);
        assert!(sender.await.unwrap().is_err());
        // Only bounded already-forwarded bytes may remain; the client side closes.
        let mut remaining=Vec::new(); player.read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.len()<=16);
    }
    #[tokio::test(start_paused = true)] async fn healthy_idle_and_half_close_reply_are_preserved() {
        let (mut player,mut client)=tokio::io::duplex(128);
        let (mut server,mut backend)=tokio::io::duplex(128);
        let m=Arc::new(Metrics::new()); let evidence=m.clone();
        let task=tokio::spawn(async move {protected_copy(&mut client,&mut server,16,Upload::default(),30,100,0,m).await});
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!task.is_finished()); // Idle time is not a stalled write.
        player.write_all(b"hello").await.unwrap(); player.shutdown().await.unwrap();
        let mut request=Vec::new(); backend.read_to_end(&mut request).await.unwrap(); assert_eq!(request,b"hello");
        backend.write_all(b"reply").await.unwrap(); backend.shutdown().await.unwrap();
        let mut reply=Vec::new(); player.read_to_end(&mut reply).await.unwrap(); assert_eq!(reply,b"reply");
        assert_eq!(task.await.unwrap().unwrap(),(5,5)); assert_eq!(evidence.get(45)+evidence.get(46),0);
    }
    #[tokio::test(start_paused = true)] async fn half_close_deadline_is_absolute_despite_reverse_traffic() {
        let (mut player,mut client)=tokio::io::duplex(128);
        let (mut server,mut backend)=tokio::io::duplex(128);
        let m=Arc::new(Metrics::new()); let evidence=m.clone();
        let task=tokio::spawn(async move {protected_copy(&mut client,&mut server,16,Upload::default(),0,50,0,m).await});
        player.shutdown().await.unwrap();
        let mut b=[0;1]; assert_eq!(backend.read(&mut b).await.unwrap(),0);
        for _ in 0..3 {
            backend.write_all(b"x").await.unwrap(); player.read_exact(&mut b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(task.await.unwrap().unwrap_err().kind(),io::ErrorKind::TimedOut);
        assert_eq!(evidence.get(46),1); assert_eq!(evidence.get(45),0);
    }
    #[test] fn byte_budget_burst_refill_and_clock_order() {
        let now=Instant::now(); let cfg=Upload {bytes_per_second:10,burst_bytes:10,enforce:true};
        let mut b=Budget::new(cfg,now);
        assert!(b.take(10,now)); assert!(!b.take(1,now));
        assert!(b.take(5,now+Duration::from_millis(500)));
        assert!(!b.take(1,now)); assert!(!b.take(1,now+Duration::from_millis(500)));
        assert!(!b.take(11,now+Duration::from_secs(100)));
    }
    #[tokio::test] async fn exceeds_budget_closes_only_monitored_stream() {
        let (mut sender,reader)=tokio::io::duplex(64);
        sender.write_all(&[1;32]).await.unwrap(); sender.shutdown().await.unwrap();
        let m=Arc::new(Metrics::new());
        let mut guarded=Monitored {inner:reader,budget:Budget::new(Upload {bytes_per_second:1,burst_bytes:8,enforce:true},Instant::now()),metrics:m.clone(),flagged:false};
        let mut out=Vec::new();
        assert_eq!(guarded.read_to_end(&mut out).await.unwrap_err().kind(),io::ErrorKind::PermissionDenied);
        assert!(out.is_empty()); assert_eq!(m.get(39),1);
    }
    #[tokio::test] async fn monitor_only_preserves_bytes_half_close_and_unlimited_download() {
        let (mut player,mut client)=tokio::io::duplex(1024);
        let (mut server,mut backend)=tokio::io::duplex(1024);
        let m=Arc::new(Metrics::new()); let evidence=m.clone();
        let relay=tokio::spawn(async move {copy(&mut client,&mut server,64,
            Upload {bytes_per_second:1,burst_bytes:8,enforce:false},m).await});
        let reply=tokio::spawn(async move {
            let mut b=Vec::new(); backend.read_to_end(&mut b).await.unwrap(); assert_eq!(b,vec![3;64]);
            backend.write_all(&[7;512]).await.unwrap(); backend.shutdown().await.unwrap();
        });
        player.write_all(&[3;64]).await.unwrap(); player.shutdown().await.unwrap();
        let mut b=Vec::new();
        tokio::time::timeout(Duration::from_secs(2),player.read_to_end(&mut b)).await.unwrap().unwrap();
        assert_eq!(b,vec![7;512]); reply.await.unwrap();
        assert_eq!(relay.await.unwrap().unwrap(),(64,512));
        assert_eq!(evidence.get(39),1); assert_eq!(evidence.get(40),64); assert_eq!(evidence.get(41),512);
    }
}
