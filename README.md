# macos-dns-proxy

A lightweight DNS forwarding proxy for macOS. It listens on a specified network
interface and resolves DNS queries using the macOS system resolver
(`getaddrinfo` -> `mDNSResponder`), which automatically handles VPN split-DNS
routing as configured in `scutil --dns`.

## Why

macOS's built-in `mDNSResponder` handles all DNS resolution including VPN
split-DNS rules. When a VPN connects and advertises domain-specific resolvers
(visible via `scutil --dns`), `mDNSResponder` automatically routes matching
queries to those resolvers.

This proxy exposes that capability to other machines on local network
interfaces -- virtual machines, containers, or other devices that need DNS
resolution routed through the macOS host.

## Architecture

```
Client (e.g., VM at 192.168.x.x)
    |
    | DNS query to <listen-addr>:53
    v
macos-dns-proxy (on macOS host)
    |
    |-- A, AAAA queries:
    |       |
    |       v
    |   getaddrinfo (dns-lookup crate) -> mDNSResponder via Mach IPC
    |       |
    |       |-- LAN DNS servers (default)
    |       |-- VPN DNS servers (when connected, for VPN-specific domains)
    |       |-- /etc/resolver/* entries
    |
    |-- CNAME, MX, TXT, SRV, NS, PTR queries:
    |       |
    |       v
    |   res_query (libresolv FFI) -> system resolver
    |       |
    |       |-- Returns full DNS wire-format responses with real TTLs
    |
    |-- All other query types (SOA, CAA, etc.):
            |
            v
        Upstream DNS server (--upstream, default 127.0.0.1:53)
```

For A and AAAA queries, the proxy uses `getaddrinfo()` (via the `dns-lookup`
crate), which on macOS communicates with `mDNSResponder` via Mach IPC (not via
port 53). This path **always** respects `scutil --dns` configuration, VPN
split-DNS routing, and `/etc/resolver/*` files.

For CNAME, MX, TXT, SRV, NS, and PTR queries, the proxy calls `res_query()`
via libresolv FFI, which queries through the system's configured DNS resolver
and returns full DNS wire-format responses with real TTLs.

For less common query types (SOA, CAA, NAPTR, etc.) that aren't handled by the
system resolver paths above, the proxy falls back to raw DNS forwarding to the
`--upstream` server.

## Requirements

- macOS (for the launchd service; the binary itself is portable)
- Rust toolchain (cargo, edition 2021) to build from source

## Build

```bash
make build
```

Or directly:

```bash
cargo build --release
```

## Install as a launchd Service

The install target will prompt for the listen address if not provided:

```bash
# Interactive -- prompts for listen address
make install

# Non-interactive -- provide the address directly
make install LISTEN=192.168.99.1:53
```

This will:
1. Build the binary
2. Copy it to `/usr/local/bin/macos-dns-proxy`
3. Generate and install a launchd plist to `/Library/LaunchDaemons/`
4. Start the service

### Uninstall

```bash
make uninstall
```

## Standalone Usage

```
macos-dns-proxy --listen <addr:port> [--upstream <addr:port>] [--verbose]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--listen` | *(required)* | Address and port to listen on (e.g., `192.168.99.1:53`) |
| `--upstream` | `127.0.0.1:53` | Upstream DNS server for unsupported query types (SOA, CAA, etc.) |
| `--verbose` | `false` | Log each query name, type, resolution method, response code, and latency |

### Example

```bash
sudo ./macos-dns-proxy --listen 192.168.99.1:53 --verbose
```

Root/sudo is required for binding to port 53.

## Client Configuration

Point your client's DNS at the proxy's listen address.

**Linux** (`/etc/resolv.conf` or NetworkManager/systemd-resolved):
```
nameserver 192.168.99.1
```

**Windows**: Set DNS server in network adapter properties.

**macOS**: Use System Settings > Network or `networksetup`.

## Verification

```bash
# Check the proxy is listening (on the macOS host)
sudo lsof -i :53 -n | grep macos-dns

# Test basic resolution (from a client)
dig @<listen-addr> google.com

# Test VPN domain resolution (while VPN is connected)
dig @<listen-addr> internal.corp.example.com

# Check active macOS resolvers
scutil --dns
```

## How It Works

The proxy handles DNS queries in three ways depending on the record type:

1. **getaddrinfo path** (A, AAAA):
   Uses `getaddrinfo()` via the `dns-lookup` crate. On macOS this communicates
   with `mDNSResponder` via Mach IPC, which is the same path native macOS
   applications use. This ensures VPN split-DNS, `/etc/resolver/*` entries, and
   all `scutil --dns` configuration is respected. This path does **not** require
   anything listening on port 53. Since `getaddrinfo()` doesn't expose TTL
   information, a synthetic TTL of 60 seconds is used.

2. **res_query path** (CNAME, MX, TXT, SRV, NS, PTR):
   Uses `res_query()` via libresolv FFI, which queries through the system's
   configured DNS resolver and returns full DNS wire-format responses. This
   preserves real TTLs from the authoritative response.

3. **Upstream fallback** (SOA, CAA, NAPTR, and other types):
   Forwards the raw DNS message to the `--upstream` server.

Verbose mode logs which path was used for each query:
```
query example.com. A from 192.168.99.10:12345 -> NOERROR [system] (1.234ms)
query example.com. SOA from 192.168.99.10:12345 -> NOERROR [upstream] (2.345ms)
```

## Tests

```bash
make test
```

## Edge Cases

- **Network interface not up**: If the listen interface isn't available, the
  proxy will fail to bind. The launchd `KeepAlive` directive will restart it
  automatically until the interface comes up.
- **Port 53 conflict**: If another process is bound to the same address and
  port, the proxy won't start. Check with `sudo lsof -i :53`.
- **DNS-over-TCP**: Both UDP and TCP are supported. Truncated UDP responses
  that cause TCP retry will work correctly.
- **TTLs**: The `getaddrinfo` path (A, AAAA) uses a synthetic TTL of 60 seconds
  since `getaddrinfo()` doesn't expose TTL information. The `res_query` path
  (CNAME, MX, TXT, SRV, NS, PTR) and the upstream fallback path both preserve
  original TTLs.
- **DNSSEC**: Not preserved through the `getaddrinfo` path (A, AAAA) since
  `getaddrinfo` doesn't expose DNSSEC data. The `res_query` and upstream
  fallback paths preserve DNSSEC transparently.
- **macOS firewall**: If the application firewall is enabled, you may need to
  allow the `macos-dns-proxy` binary. The built-in `pf` firewall typically
  doesn't block loopback or vmnet traffic by default.

## License

MIT
