use crate::config::{log_debug, log_warn, STATS};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{ready, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;
const SESSION_ID_LEN: usize = 32;

const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;

const READ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_RECORD_TIMEOUT: Duration = Duration::from_secs(10);
const MASKING_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const SH_RANDOM_OFF: usize = 11;
const SH_SESSID_OFF: usize = 44;
const SH_PUBKEY_OFF: usize = 89;

type HmacSha256 = Hmac<Sha256>;

pub struct FakeTlsStream {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    pub write: Box<dyn AsyncWrite + Send + Unpin>,
}

fn server_hello_template() -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x7a]);
    v.extend_from_slice(&[0x02, 0x00, 0x00, 0x76]);
    v.extend_from_slice(&[0x03, 0x03]);
    v.extend_from_slice(&[0u8; 32]);
    v.push(0x20);
    v.extend_from_slice(&[0u8; 32]);
    v.extend_from_slice(&[0x13, 0x01, 0x00]);
    v.extend_from_slice(&[0x00, 0x2e, 0x00]);
    v.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    v.extend_from_slice(&[0u8; 32]);
    v.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    v
}

fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<([u8; 32], [u8; 32], i64)> {
    if data.len() < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random
        .copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    for b in &mut zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] {
        *b = 0;
    }

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    if expected[..28] != client_random[..28] {
        return None;
    }

    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes) as i64;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; 32];
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id
            .copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some((client_random, session_id, timestamp))
}

fn build_server_hello(secret: &[u8], client_random: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut sh = server_hello_template();
    debug_assert_eq!(sh.len(), 128);
    sh[SH_SESSID_OFF..SH_SESSID_OFF + 32].copy_from_slice(session_id);

    let mut pubkey = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut pubkey);
    sh[SH_PUBKEY_OFF..SH_PUBKEY_OFF + 32].copy_from_slice(&pubkey);

    let mut response = Vec::with_capacity(128 + 6 + 5 + 2100);
    response.extend_from_slice(&sh);
    response.extend_from_slice(&CCS_FRAME);

    let encrypted_size = 1900 + (rand::thread_rng().next_u32() % 201) as usize;
    let mut encrypted_data = vec![0u8; encrypted_size];
    rand::thread_rng().fill_bytes(&mut encrypted_data);
    response.push(TLS_RECORD_APPDATA);
    response.push(0x03);
    response.push(0x03);
    response.push((encrypted_size >> 8) as u8);
    response.push(encrypted_size as u8);
    response.extend_from_slice(&encrypted_data);

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_random);
    mac.update(&response);
    let server_random = mac.finalize().into_bytes();

    let mut final_bytes = response;
    final_bytes[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    final_bytes
}

fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / TLS_APPDATA_MAX + 1));
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + TLS_APPDATA_MAX, data.len());
        let chunk = &data[offset..end];
        out.push(TLS_RECORD_APPDATA);
        out.push(0x03);
        out.push(0x03);
        out.push((chunk.len() >> 8) as u8);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        offset = end;
    }
    out
}

// Читатель TLS-записей как явная машина состояний. Раньше на каждый poll
// создавался новый future c read_exact и выбрасывался на Pending: частично
// прочитанный 5-байтный заголовок терялся, и поток рассинхронизировался.
struct TlsRecordReader {
    inner: ReadHalf<TcpStream>,
    hdr: [u8; 5],
    hdr_len: usize,
    skip_left: usize,
    read_left: usize,
}

impl TlsRecordReader {
    fn new(inner: ReadHalf<TcpStream>) -> Self {
        TlsRecordReader {
            inner,
            hdr: [0u8; 5],
            hdr_len: 0,
            skip_left: 0,
            read_left: 0,
        }
    }
}

fn faketls_eof() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "faketls eof")
}

impl AsyncRead for TlsRecordReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_left > 0 {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                let max = this.read_left.min(buf.remaining());
                let n = {
                    let mut sub = buf.take(max);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                    sub.filled().len()
                };
                if n == 0 {
                    return Poll::Ready(Err(faketls_eof()));
                }
                // SAFETY: inner заполнил n байт в незаполненной части buf.
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                this.read_left -= n;
                return Poll::Ready(Ok(()));
            }

            if this.skip_left > 0 {
                let mut scratch = [0u8; 512];
                let max = this.skip_left.min(scratch.len());
                let mut rb = ReadBuf::new(&mut scratch[..max]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                let n = rb.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(faketls_eof()));
                }
                this.skip_left -= n;
                continue;
            }

            while this.hdr_len < 5 {
                let mut rb = ReadBuf::new(&mut this.hdr[this.hdr_len..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                let n = rb.filled().len();
                if n == 0 {
                    if this.hdr_len == 0 {
                        return Poll::Ready(Ok(())); // чистый EOF между записями
                    }
                    return Poll::Ready(Err(faketls_eof()));
                }
                this.hdr_len += n;
            }
            this.hdr_len = 0;
            let rec_len = u16::from_be_bytes([this.hdr[3], this.hdr[4]]) as usize;
            match this.hdr[0] {
                TLS_RECORD_CCS => this.skip_left = rec_len,
                TLS_RECORD_APPDATA => this.read_left = rec_len,
                // Как раньше: чужой тип записи = конец потока.
                _ => return Poll::Ready(Ok(())),
            }
        }
    }
}

// Писатель TLS-записей. Раньше при частичной записи в сокет (TG в фоне не
// читает, буфер полон) на провод уходил обрывок записи, а вызывающему
// возвращалось «записано n байт» — следующий вызов оборачивал хвост в новую
// запись, и поток ломался. Теперь запись досылается целиком, прежде чем
// её байты считаются принятыми.
struct TlsRecordWriter {
    inner: WriteHalf<TcpStream>,
    pending: Vec<u8>,
    pos: usize,
    pending_src: usize,
}

impl TlsRecordWriter {
    fn new(inner: WriteHalf<TcpStream>) -> Self {
        TlsRecordWriter {
            inner,
            pending: Vec::new(),
            pos: 0,
            pending_src: 0,
        }
    }

    fn poll_drain(&mut self, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pos < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.pos += n;
        }
        self.pending.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TlsRecordWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(TLS_APPDATA_MAX);
            this.pending = wrap_tls_record(&buf[..n]);
            this.pos = 0;
            this.pending_src = n;
        }
        // При Pending вызывающий (write_all) повторит с тем же buf, и мы
        // просто дошлём начатую запись.
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(this.pending_src))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub async fn server_handshake(
    mut conn: TcpStream,
    first: u8,
    secret: &[u8],
    masking: &str,
    label: &str,
) -> Option<FakeTlsStream> {
    let mut hdr_rest = [0u8; 4];
    match tokio::time::timeout(READ_HANDSHAKE_TIMEOUT, conn.read_exact(&mut hdr_rest)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record header", label));
            return None;
        }
    }

    let mut tls_header = [0u8; 5];
    tls_header[0] = first;
    tls_header[1..5].copy_from_slice(&hdr_rest);
    let record_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;

    let mut body = vec![0u8; record_len];
    match tokio::time::timeout(READ_RECORD_TIMEOUT, conn.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record body", label));
            return None;
        }
    }

    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.extend_from_slice(&tls_header);
    client_hello.extend_from_slice(&body);

    match verify_client_hello(&client_hello, secret) {
        Some((client_random, session_id, ts)) => {
            log_debug(&format!("[{}] Fake TLS handshake ok (ts={})", label, ts));
            let server_hello = build_server_hello(secret, &client_random, &session_id);
            if conn.write_all(&server_hello).await.is_err() {
                return None;
            }
            let _ = conn.flush().await;

            let (r, w) = tokio::io::split(conn);
            Some(FakeTlsStream {
                read: Box::new(TlsRecordReader::new(r)),
                write: Box::new(TlsRecordWriter::new(w)),
            })
        }
        None => {
            log_debug(&format!(
                "[{}] Fake TLS verify failed (size={} rec={}) -> masking",
                label,
                client_hello.len(),
                record_len
            ));
            proxy_to_masking_domain(conn, client_hello, masking, label).await;
            None
        }
    }
}

async fn proxy_to_masking_domain(conn: TcpStream, initial: Vec<u8>, domain: &str, label: &str) {
    let upstream = match tokio::time::timeout(
        MASKING_CONNECT_TIMEOUT,
        TcpStream::connect((domain, 443u16)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            log_warn(&format!(
                "[{}] masking: cannot connect to {}:443",
                label, domain
            ));
            return;
        }
    };

    log_debug(&format!("[{}] masking -> {}:443", label, domain));
    STATS
        .connections_masked
        .fetch_add(1, Ordering::Relaxed);

    let mut upstream = upstream;
    if upstream.write_all(&initial).await.is_err() {
        return;
    }

    let (mut c_read, mut c_write) = tokio::io::split(conn);
    let (mut u_read, mut u_write) = tokio::io::split(upstream);

    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut c_read, &mut u_write).await;
        let _ = u_write.shutdown().await;
    });
    let down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut u_read, &mut c_write).await;
        let _ = c_write.shutdown().await;
    });

    let _ = tokio::join!(up, down);
}
