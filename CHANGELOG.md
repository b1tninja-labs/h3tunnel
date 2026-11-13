# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- `varint`: QUIC variable-length integers against the vectors of RFC 9000 Appendix A.1.
- `capsule`: `Capsule`, `encode_capsule`, `decode_capsule`, an incremental `CapsuleParser` with a
  value-length cap, and `parse_capsule_protocol_header` (reads the header with the sibling `sfields`).
- `httpdatagram`, `ctx`, `limits`: UDP Proxying datagrams, HTTP/3 Quarter Stream IDs, the
  SETTINGS_H3_DATAGRAM check, Context ID allocation, the 65527 limit, and the RFC 9931 sec. 6.3
  optimistic-send rule.
- `template`, `connect_udp`: the RFC 9298 sec. 2 template subset, request builders for HTTP/1.1,
  HTTP/2 and HTTP/3, and response checks.
- `connect_ip`: target URIs with RFC 9484 erratum 8444 applied and the ADDRESS_ASSIGN,
  ADDRESS_REQUEST and ROUTE_ADVERTISEMENT capsules.
- Changed: `connect_ip.target_uri` takes the template; `clamp_payload` and `allocate_context` are real.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for h3tunnel.
- `h3tunnel.apps` namespace reserved for composition that is not protocol behaviour.
