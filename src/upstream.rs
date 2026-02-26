use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// Forward a DNS query to the upstream server using the same protocol
/// (UDP or TCP) as the incoming request.
///
/// This is the Rust equivalent of the Go `forwardUpstream` function.
pub async fn forward_upstream(
    request: &Message,
    upstream: &str,
    protocol: &str,
) -> Result<Message> {
    let request_bytes = request.to_vec().context("failed to serialize DNS request")?;

    match protocol {
        "udp" => forward_udp(&request_bytes, upstream).await,
        "tcp" => forward_tcp(&request_bytes, upstream).await,
        _ => anyhow::bail!("unsupported protocol: {}", protocol),
    }
}

/// Forward via UDP: bind ephemeral socket, send query, receive response.
async fn forward_udp(request_bytes: &[u8], upstream: &str) -> Result<Message> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind UDP socket for upstream")?;

    socket
        .send_to(request_bytes, upstream)
        .await
        .context("failed to send to upstream")?;

    let mut buf = vec![0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .context("upstream UDP timeout")?
        .context("upstream UDP recv failed")?;

    Message::from_vec(&buf[..len]).context("failed to parse upstream UDP response")
}

/// Forward via TCP: connect, send length-prefixed query, read length-prefixed response.
async fn forward_tcp(request_bytes: &[u8], upstream: &str) -> Result<Message> {
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(upstream))
        .await
        .context("upstream TCP connect timeout")?
        .context("upstream TCP connect failed")?;

    // DNS over TCP uses a 2-byte length prefix.
    let len_prefix = (request_bytes.len() as u16).to_be_bytes();
    stream
        .write_all(&len_prefix)
        .await
        .context("failed to write TCP length prefix")?;
    stream
        .write_all(request_bytes)
        .await
        .context("failed to write TCP request")?;

    // Read response length prefix.
    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .context("upstream TCP read timeout")?
        .context("upstream TCP read length failed")?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    // Read response body.
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .await
        .context("upstream TCP read body failed")?;

    Message::from_vec(&resp_buf).context("failed to parse upstream TCP response")
}
