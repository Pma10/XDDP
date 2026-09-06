use crate::config::Protocol;
use std::{fmt, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt}, time::{timeout_at, Instant}};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error { Eof, Io, VarInt, Oversized, Invalid, Unsupported, Deadline, Slow }
impl fmt::Display for Error { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") } }
impl std::error::Error for Error {}

pub fn varint(data: &[u8]) -> Result<Option<(i32, usize)>, Error> {
    let mut value = 0u32;
    for i in 0..5 {
        let Some(&b) = data.get(i) else { return Ok(None); };
        if i == 4 && b & 0xf0 != 0 { return Err(Error::VarInt); }
        value |= ((b & 0x7f) as u32) << (7 * i);
        if b & 0x80 == 0 {
            if i > 0 && b == 0 { return Err(Error::VarInt); }
            return Ok(Some((value as i32, i + 1)));
        }
    }
    Err(Error::VarInt)
}
pub fn put_varint(value: i32, out: &mut Vec<u8>) {
    let mut v = value as u32;
    loop {
        let mut b = (v & 127) as u8;
        v >>= 7;
        if v != 0 { b |= 128; }
        out.push(b);
        if v == 0 { break; }
    }
}
pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    put_varint(body.len() as i32, &mut out);
    out.extend_from_slice(body);
    out
}
pub struct Frame { pub body: Vec<u8>, pub wire: Vec<u8> }

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize,
    remaining: &mut usize, deadline: Instant, progress: Duration,
    first_progress: Duration) -> Result<Frame, Error>
{
    let mut prefix = Vec::with_capacity(5);
    let len;
    loop {
        let mut b = [0];
        let wait = if prefix.is_empty() { first_progress } else { progress };
        read_bounded(r, &mut b, deadline, wait).await?;
        if *remaining == 0 { return Err(Error::Oversized); }
        *remaining -= 1;
        prefix.push(b[0]);
        if let Some((n, _)) = varint(&prefix)? {
            if n <= 0 { return Err(Error::Invalid); }
            len = n as usize;
            break;
        }
    }
    if len > max || len > *remaining { return Err(Error::Oversized); }
    *remaining -= len;
    let mut body = vec![0; len];
    read_bounded(r, &mut body, deadline, progress).await?;
    let mut wire = prefix;
    wire.extend_from_slice(&body);
    Ok(Frame { body, wire })
}
async fn read_bounded<R: AsyncRead + Unpin>(r: &mut R, mut out: &mut [u8],
    absolute: Instant, progress: Duration) -> Result<(), Error>
{
    while !out.is_empty() {
        let now = Instant::now();
        if now >= absolute { return Err(Error::Deadline); }
        let until = absolute.min(now + progress);
        let n = timeout_at(until, r.read(out)).await
            .map_err(|_| if until == absolute { Error::Deadline } else { Error::Slow })?
            .map_err(|_| Error::Io)?;
        if n == 0 { return Err(Error::Eof); }
        out = &mut out[n..];
    }
    Ok(())
}
pub struct Cursor<'a> { data: &'a [u8], pos: usize }
impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
    pub fn int(&mut self) -> Result<i32, Error> {
        let (n, used) = varint(&self.data[self.pos..])?.ok_or(Error::Invalid)?;
        self.pos += used;
        Ok(n)
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.data.len() - self.pos { return Err(Error::Invalid); }
        let b = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }
    pub fn boolean(&mut self) -> Result<bool, Error> {
        match self.bytes(1)?[0] { 0 => Ok(false), 1 => Ok(true), _ => Err(Error::Invalid) }
    }
    pub fn blob(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = self.int()?;
        if n < 0 || n as usize > max { return Err(Error::Oversized); }
        self.bytes(n as usize)
    }
    pub fn string(&mut self, max: usize) -> Result<&'a str, Error> {
        std::str::from_utf8(self.blob(max)?).map_err(|_| Error::Invalid)
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.pos == self.data.len() { Ok(()) } else { Err(Error::Invalid) }
    }
}
#[derive(Debug)]
pub struct Handshake { pub version: i32, pub state: i32 }
pub fn handshake(data: &[u8], cfg: &Protocol) -> Result<Handshake, Error> {
    let mut c = Cursor::new(data);
    if c.int()? != 0 { return Err(Error::Invalid); }
    let version = c.int()?;
    let host = c.string(cfg.max_host_bytes)?;
    let base = host.split('\0').next().unwrap_or("");
    if base.is_empty() || base.chars().any(char::is_control) ||
        (!cfg.allow_host_suffix && host.contains('\0')) ||
        (!cfg.allowed_hosts.is_empty() && !cfg.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(base))) {
        return Err(Error::Invalid);
    }
    let b = c.bytes(2)?;
    let port = u16::from_be_bytes([b[0], b[1]]);
    if port == 0 || (!cfg.allowed_ports.is_empty() && !cfg.allowed_ports.contains(&port)) { return Err(Error::Invalid); }
    let state = c.int()?;
    if state != 1 && state != 2 { return Err(Error::Invalid); }
    if state == 2 && version < 0 { return Err(Error::Unsupported); }
    c.finish()?;
    Ok(Handshake { version, state })
}
pub fn login(data: &[u8], version: i32, cfg: &Protocol) -> Result<(), Error> {
    let mut c = Cursor::new(data);
    if c.int()? != 0 { return Err(Error::Invalid); }
    let name = c.string(64)?;
    if name.is_empty() || name.encode_utf16().count() > 16 || name.chars().any(char::is_control) ||
        (cfg.strict_username && !name.bytes().all(|x| x.is_ascii_alphanumeric() || x == b'_')) {
        return Err(Error::Invalid);
    }
    let schema = match cfg.login_schemas.get(&version) {
        Some(schema) => schema.as_str(),
        None => match version {
            4..=758 => "legacy", 759 => "signed", 760 => "signed_uuid",
            761..=763 => "optional_uuid", 764..=775 => "uuid", _ => return Err(Error::Unsupported),
        },
    };
    if schema == "signed" || schema == "signed_uuid" {
        if c.boolean()? { c.bytes(8)?; c.blob(4096)?; c.blob(4096)?; }
    }
    if schema == "signed_uuid" || schema == "optional_uuid" {
        if c.boolean()? { c.bytes(16)?; }
    } else if schema == "uuid" { c.bytes(16)?; }
    c.finish()
}
pub fn status_request(data: &[u8]) -> Result<(), Error> {
    let mut c = Cursor::new(data);
    if c.int()? != 0 { return Err(Error::Invalid); }
    c.finish()
}
pub fn ping(data: &[u8]) -> Result<(), Error> {
    let mut c = Cursor::new(data);
    if c.int()? != 1 { return Err(Error::Invalid); }
    c.bytes(8)?;
    c.finish()
}
pub fn status_handshake(host: &str, port: u16, version: i32) -> Vec<u8> {
    let mut b = vec![0];
    put_varint(version, &mut b); put_varint(host.len() as i32, &mut b);
    b.extend_from_slice(host.as_bytes()); b.extend_from_slice(&port.to_be_bytes()); b.push(1);
    frame(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cfg() -> Protocol { Protocol { max_frame: 16384, max_initial_bytes: 32768,
        max_host_bytes: 1024, allow_host_suffix: true, allowed_hosts: vec![],
        allowed_ports: vec![], strict_username: false, login_schemas: Default::default() } }
    #[test] fn varints() {
        for n in [0, 1, 127, 128, 255, i32::MAX, -1, i32::MIN] {
            let mut b = vec![]; put_varint(n, &mut b);
            assert_eq!(varint(&b), Ok(Some((n, b.len()))));
            for i in 0..b.len() { assert_eq!(varint(&b[..i]), Ok(None)); }
        }
        for b in [vec![128, 0], vec![128; 5], vec![255,255,255,255,31]] {
            assert_eq!(varint(&b), Err(Error::VarInt));
        }
    }
    #[test] fn handshake_and_login_schemas() {
        let wire = status_handshake("localhost\0FML3\0", 25565, -1);
        let (_, off) = varint(&wire).unwrap().unwrap();
        assert_eq!(handshake(&wire[off..], &cfg()).unwrap().state, 1);
        for (v, tail) in [(47, vec![]), (759, vec![0]), (760, vec![0,0]),
                          (761, vec![0]), (764, vec![0;16]), (770, vec![0;16]),
                          (774, vec![0;16]), (775, vec![0;16])] {
            let mut b = vec![0,3,b'a',b'b',b'c']; b.extend(tail);
            assert!(login(&b, v, &cfg()).is_ok());
            b.push(0); assert!(login(&b, v, &cfg()).is_err());
        }
        assert_eq!(login(&[0,1,b'a'], 9999, &cfg()), Err(Error::Unsupported));
        let mut custom=cfg(); custom.login_schemas.insert(9999,"legacy".into());
        assert!(login(&[0,1,b'a'],9999,&custom).is_ok());
        assert!(status_request(&[0,0]).is_err());
        assert!(ping(&[1;8]).is_err());
    }
    #[tokio::test] async fn split_coalesced_and_oversize() {
        use tokio::io::AsyncWriteExt;
        let (mut tx, mut rx) = tokio::io::duplex(1024);
        let body = vec![7;130]; let a = frame(&body); let expected = a.clone();
        tokio::spawn(async move { for b in a { tx.write_all(&[b]).await.unwrap(); tokio::task::yield_now().await; }
            tx.write_all(&[1,0]).await.unwrap(); });
        let mut remaining = 512;
        let deadline = Instant::now() + Duration::from_secs(2);
        let f = read_frame(&mut rx, 256, &mut remaining, deadline, Duration::from_secs(1), Duration::from_secs(1)).await.unwrap();
        assert_eq!(f.wire, expected);
        assert_eq!(read_frame(&mut rx, 256, &mut remaining, deadline, Duration::from_secs(1), Duration::from_secs(1)).await.unwrap().body, [0]);
        let mut huge = &[255,255,127][..];
        assert!(matches!(read_frame(&mut huge, 256, &mut remaining, deadline, Duration::from_secs(1), Duration::from_secs(1)).await, Err(Error::Oversized)));
    }
    #[tokio::test] async fn absolute_and_progress_deadlines() {
        let (_tx, mut rx) = tokio::io::duplex(64);
        let mut n = 128;
        assert!(matches!(read_frame(&mut rx, 64, &mut n, Instant::now() + Duration::from_millis(15),
            Duration::from_secs(1), Duration::from_secs(1)).await, Err(Error::Deadline)));
        assert!(matches!(read_frame(&mut rx, 64, &mut n, Instant::now() + Duration::from_secs(1),
            Duration::from_millis(15), Duration::from_millis(15)).await, Err(Error::Slow)));
    }
}
