# OHTTP Relay

A rust implementation of an [Oblivious
HTTP](https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html) relay resource.

This work is undergoing active revision in the IETF and so are these
implementations. Use at your own risk.

## Usage

Run ohttp-relay by setting `PORT` (or `UNIX_SOCKET`):

```console
PORT=3000 cargo run
```

Alternatively, set `UNIX_SOCKET` to bind to a unix socket path instead of a TCP port.

`GATEWAY_URI` is deprecated and, if set, must remain `https://payjo.in`.

This crate is intended to run behind a reverse proxy such as NGINX for inbound
TLS handling. Tests cover this integration using `nginx.conf.template`.

## Outbound Proxy (Tor Egress)

To route relay egress (relay -> directory/gateway) through Tor, set a SOCKS5h
proxy:

```console
OUTBOUND_PROXY='socks5h://127.0.0.1:9050' cargo run
```

Optional connect timeout (seconds):

```console
OUTBOUND_PROXY='socks5h://127.0.0.1:9050' \
OUTBOUND_CONNECT_TIMEOUT_SECS=10 \
cargo run
```

Notes:

- `OUTBOUND_PROXY` must use the `socks5h://` scheme to ensure remote DNS
  resolution by the proxy.
- This configuration applies to both OHTTP request forwarding and bootstrap
  CONNECT/WebSocket tunnels.

## Tor Native Deployment Notes

For relay -> directory onion routing:

- Set `OUTBOUND_PROXY=socks5h://127.0.0.1:9050`
- Keep relay and directory as separate services/operators when possible
- Expose relay and directory on distinct onion addresses

Using `socks5h` is required to avoid local DNS resolution for onion targets.

## Bootstrap Feature

The Oblivious HTTP specification requires clients obtain a [Key Configuration](https://www.ietf.org/rfc/rfc9458.html#name-key-configuration) from the OHTTP Gateway but leaves a mechanism for doing so explicitly unspecified. This feature hosts HTTPS-in-WebSocket and HTTPS-in-CONNECT proxies to allow web clients to GET a gateway's ohttp-keys via [Direct Discovery](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-key-consistency-01#name-direct-discovery) in an end-to-end-encrypted, authenticated manner using the OHTTP relay as a tunnel so as not to reveal their IP address. The `bootstrap` feature to host these proxies is enabled by default. The `ws-bootstrap` and `connect-bootstrap` features enable each proxy individually.

### How does it work?

Both bootstrap features enable the server to forward packets directly to and from the OHTTP Gateway's TCP socket to negotiate a TLS session between the client and gateway. By doing so, the OHTTP Relay is prevented from conducting a [man-in-the-middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) to compromise the TLS session.
