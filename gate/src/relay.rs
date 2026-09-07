use crate::{config::Upload, metrics::Metrics};
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll}, time::Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
