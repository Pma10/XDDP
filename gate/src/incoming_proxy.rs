//! Bounded, fail-closed HAProxy PROXY protocol v2 receiver.
//! Only configured trusted TCP peers may assert client identity.
use crate::{config::IncomingProxyV2, protocol::Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::{io::{AsyncRead, AsyncReadExt}, time::{timeout_at, Instant}};

const SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const MAX_ADDRESS_AND_TLVS: usize = 4096;

pub async fn read<R: AsyncRead + Unpin>(
    stream: &mut R, socket_peer: SocketAddr, cfg: &IncomingProxyV2, deadline: Instant,
) -> Result<(SocketAddr, SocketAddr), Error> {
    // Reject untrusted peers before accepting any client-provided identity bytes.
    if !cfg.trusted_proxies.iter().any(|net| net.contains(&socket_peer.ip())) {
        return Err(Error::Invalid);
    }
    let mut header = [0u8; 16];
    timeout_at(deadline, stream.read_exact(&mut header)).await
        .map_err(|_| Error::Deadline)?.map_err(|_| Error::Io)?;
    if &header[..12] != SIGNATURE || header[12] != 0x21 {
        return Err(Error::Invalid); // v2 PROXY command only; LOCAL is never trusted.
    }
    let min = match header[13] {
        0x11 => 12usize, // TCP over IPv4
        0x21 => 36usize, // TCP over IPv6
        _ => return Err(Error::Invalid), // reject UDP/UNSPEC/unknown families
    };
    let len = u16::from_be_bytes([header[14], header[15]]) as usize;
    if len < min || len > MAX_ADDRESS_AND_TLVS {
        return Err(Error::Oversized);
    }
    let mut body = vec![0u8; len];
    timeout_at(deadline, stream.read_exact(&mut body)).await
        .map_err(|_| Error::Deadline)?.map_err(|_| Error::Io)?;
    let (src, dst) = if min == 12 {
        let src = IpAddr::V4(Ipv4Addr::new(body[0], body[1], body[2], body[3]));
        let dst = IpAddr::V4(Ipv4Addr::new(body[4], body[5], body[6], body[7]));
        let src_port = u16::from_be_bytes([body[8], body[9]]);
        let dst_port = u16::from_be_bytes([body[10], body[11]]);
        (SocketAddr::new(src, src_port), SocketAddr::new(dst, dst_port))
    } else {
        let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&body[0..16]).map_err(|_| Error::Invalid)?));
        let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&body[16..32]).map_err(|_| Error::Invalid)?));
        let src_port = u16::from_be_bytes([body[32], body[33]]);
        let dst_port = u16::from_be_bytes([body[34], body[35]]);
        (SocketAddr::new(src, src_port), SocketAddr::new(dst, dst_port))
    };
    if src.ip().is_unspecified() || src.ip().is_multicast() || src.port() == 0 ||
        dst.ip().is_unspecified() || dst.port() == 0 {
        return Err(Error::Invalid);
    }
    // TLVs, if supplied, are consumed but never trusted for identity.
    Ok((src, dst))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use tokio::io::{duplex, AsyncWriteExt};
    fn cfg() -> IncomingProxyV2 {
        IncomingProxyV2 {
            enabled: true,
            trusted_proxies: vec!["192.0.2.0/24".parse::<IpNet>().unwrap()],
        }
    }
    fn header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        crate::cache::proxy_header(src, dst).unwrap()
    }
    async fn parse(payload: &[u8], peer: &str) -> Result<(SocketAddr, SocketAddr), Error> {
        let (mut w, mut r) = duplex(8192);
        w.write_all(payload).await.unwrap();
        drop(w);
        read(&mut r, peer.parse().unwrap(), &cfg(),
            Instant::now() + std::time::Duration::from_millis(100)).await
    }
    #[tokio::test]
    async fn accepts_v4_and_tlv_and_consumes_exact_header() {
        let src = "203.0.113.7:1234".parse().unwrap();
        let dst = "198.51.100.5:25565".parse().unwrap();
        let mut frame = header(src, dst);
        frame[14..16].copy_from_slice(&15u16.to_be_bytes());
        frame.extend_from_slice(&[0xee, 0, 0]); // ignored TLV bytes
        assert_eq!(parse(&frame, "192.0.2.5:456").await.unwrap(), (src, dst));
    }
    #[tokio::test]
    async fn accepts_ipv6_identity_over_ipv4_transport() {
        let src = "[2001:db8::10]:4444".parse().unwrap();
        let dst = "[2001:db8::20]:25565".parse().unwrap();
        assert_eq!(parse(&header(src,dst),"192.0.2.5:456").await.unwrap(),(src,dst));
    }
    #[tokio::test]
    async fn rejects_untrusted_spoofed_and_invalid_headers() {
        let src = "203.0.113.7:1234".parse().unwrap();
        let dst = "198.51.100.5:25565".parse().unwrap();
        let frame = header(src,dst);
        assert_eq!(parse(&frame,"198.51.100.8:9999").await,Err(Error::Invalid));
        let mut local = frame.clone(); local[12] = 0x20;
        assert_eq!(parse(&local,"192.0.2.5:456").await,Err(Error::Invalid));
        let mut udp = frame.clone(); udp[13] = 0x12;
        assert_eq!(parse(&udp,"192.0.2.5:456").await,Err(Error::Invalid));
        let mut oversized = frame.clone(); oversized[14..16].copy_from_slice(&4097u16.to_be_bytes());
        assert_eq!(parse(&oversized,"192.0.2.5:456").await,Err(Error::Oversized));
        let mut truncated = frame.clone(); truncated.pop();
        assert_eq!(parse(&truncated,"192.0.2.5:456").await,Err(Error::Io));
        let mut sig = frame; sig[0] = b'!';
        assert_eq!(parse(&sig,"192.0.2.5:456").await,Err(Error::Invalid));
    }
}
