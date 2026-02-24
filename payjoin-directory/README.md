# Payjoin Directory

[BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md) Async Payjoin (v2)
peers store and forward HTTP client messages via a directory server in order to
make asynchronous Payjoin transactions. This is a reference implementation of
such a server

V2 clients encapsulate requests using
[Oblivious HTTP](https://www.ietf.org/rfc/rfc9458.html) (OHTTP) which allows
them to make payjoins without the directory being able to link payjoins to
specific client IP. Payjoin Directory is therefore an [Oblivious Gateway
Resource](https://www.ietf.org/rfc/rfc9458.html#dfn-gateway).

Payjoin Directory also behaves as an [unsecured public-facing HTTP
server](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#unsecured-payjoin-server)
in order to provide backwards-compatible support for [BIP
78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) Payjoin (v1)
clients.

## Tor Native Operation

For Tor-native BIP77 deployments:

- Expose the directory as an onion service
- Keep relay and directory logically separate (service/process/operator)
- Route relay egress to directory through SOCKS5h on the relay side

Clients can bootstrap keys directly from the directory over Tor using
`/.well-known/ohttp-gateway` as defined by RFC 9540.

## OHTTP Key Management

Operational guidance:

- Keep OHTTP key storage on persistent disk
- Plan key rotations with overlap windows so active clients can complete
  sessions during rollout
- Monitor bootstrap and decapsulation failures during rotation windows
