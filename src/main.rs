use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use macos_dns_proxy::handler;
use macos_dns_proxy::resolver::{Resolver, SystemResolver};

/// A lightweight DNS forwarding proxy for macOS.
///
/// Exposes the macOS system resolver (mDNSResponder) to other machines
/// on local network interfaces (VMs, containers, other devices).
#[derive(Parser, Debug)]
#[command(name = "macos-dns-proxy")]
struct Cli {
    /// Address and port to listen on (e.g., 192.168.99.1:53)
    #[arg(long)]
    listen: String,

    /// Upstream DNS server for unsupported query types (e.g., SOA, CAA)
    #[arg(long, default_value = "127.0.0.1:53")]
    upstream: String,

    /// Log each DNS query
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let listen_addr = cli.listen.clone();
    let upstream = Arc::new(cli.upstream.clone());
    let verbose = cli.verbose;
    let resolver: Arc<dyn Resolver> = Arc::new(SystemResolver);

    tracing::info!("starting UDP listener on {}", listen_addr);
    tracing::info!("starting TCP listener on {}", listen_addr);
    tracing::info!(
        "using system resolver for A, AAAA, CNAME, MX, TXT, SRV, NS, PTR queries"
    );
    tracing::info!("fallback upstream {} for other query types", cli.upstream);

    // Launch UDP and TCP servers concurrently, shut down on signal.
    tokio::select! {
        result = run_udp_server(&listen_addr, resolver.clone(), upstream.clone(), verbose) => {
            if let Err(e) = result {
                tracing::error!("UDP server failed: {}", e);
            }
        },
        result = run_tcp_server(&listen_addr, resolver.clone(), upstream.clone(), verbose) => {
            if let Err(e) = result {
                tracing::error!("TCP server failed: {}", e);
            }
        },
        _ = shutdown_signal() => {
            tracing::info!("received shutdown signal, shutting down");
        },
    }

    tracing::info!("shutdown complete");
    Ok(())
}

/// Run the UDP DNS server loop.
async fn run_udp_server(
    addr: &str,
    resolver: Arc<dyn Resolver>,
    upstream: Arc<String>,
    verbose: bool,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(addr)
            .await
            .with_context(|| format!("failed to bind UDP on {}", addr))?,
    );

    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await.context("UDP recv failed")?;

        let request = match Message::from_vec(&buf[..len]) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::debug!("failed to parse UDP message from {}: {}", src, e);
                continue;
            }
        };

        // Spawn a task to handle the request concurrently.
        let socket = socket.clone();
        let resolver = resolver.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let response =
                handler::handle_dns(&request, resolver.as_ref(), &upstream, "udp", src, verbose)
                    .await;

            match response.to_vec() {
                Ok(bytes) => {
                    if let Err(e) = socket.send_to(&bytes, src).await {
                        tracing::debug!("failed to send UDP response to {}: {}", src, e);
                    }
                }
                Err(e) => {
                    tracing::debug!("failed to serialize UDP response: {}", e);
                }
            }
        });
    }
}

/// Run the TCP DNS server loop.
async fn run_tcp_server(
    addr: &str,
    resolver: Arc<dyn Resolver>,
    upstream: Arc<String>,
    verbose: bool,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind TCP on {}", addr))?;

    loop {
        let (stream, src) = listener.accept().await.context("TCP accept failed")?;

        let resolver = resolver.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_tcp_connection(stream, src, resolver, upstream, verbose).await
            {
                tracing::debug!("TCP connection from {} error: {}", src, e);
            }
        });
    }
}

/// Handle a single TCP DNS connection. DNS over TCP uses 2-byte length-prefixed
/// messages.
async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    src: SocketAddr,
    resolver: Arc<dyn Resolver>,
    upstream: Arc<String>,
    verbose: bool,
) -> Result<()> {
    // Read 2-byte length prefix.
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("failed to read TCP length prefix")?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    // Read the DNS message.
    let mut msg_buf = vec![0u8; msg_len];
    stream
        .read_exact(&mut msg_buf)
        .await
        .context("failed to read TCP message body")?;

    let request = Message::from_vec(&msg_buf).context("failed to parse TCP DNS message")?;

    let response =
        handler::handle_dns(&request, resolver.as_ref(), &upstream, "tcp", src, verbose).await;

    let response_bytes = response.to_vec().context("failed to serialize TCP response")?;

    // Write 2-byte length prefix + response.
    let len_prefix = (response_bytes.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).await?;
    stream.write_all(&response_bytes).await?;

    Ok(())
}

/// Wait for SIGINT (ctrl-c) or SIGTERM shutdown signal.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for ctrl-c");
    }
}
