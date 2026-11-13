# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation h3tunnel could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `varint.encode_varint()` | RFC 9000 sec. 16, Appendix A.1 | `[ok]` | `tests/test_varint.py::test_rfc9000_a1_vectors_reencode_to_the_shortest_form`, `tests/test_varint.py::test_boundaries` | M1 |
| `varint.decode_varint()` | RFC 9000 sec. 16, Appendix A.1 | `[ok]` | `tests/test_varint.py::test_rfc9000_a1_vectors_decode`, `tests/test_varint.py::test_decode_nonminimal_accepted`, `tests/test_varint.py::test_decode_truncated` | M1 |
| `capsule.encode_capsule()` | RFC 9297 sec. 3.2, 3.5 | `[ok]` | `tests/test_capsule.py::test_encode_roundtrip`, `tests/test_capsule.py::test_zero_length_capsule` | M1 |
| `capsule.decode_capsule()` | RFC 9297 sec. 3.2, 3.3 | `[ok]` | `tests/test_capsule.py::test_decode_capsule_incomplete`, `tests/test_capsule.py::test_decode_capsule_leaves_trailing_bytes_to_the_caller` | M1 |
| `capsule.parse_capsule_protocol_header()` | RFC 9297 sec. 3.4 (an Item Structured Field, RFC 9651, from the sibling sfields) | `[ok]` | `tests/test_capsule.py::test_capsule_protocol_header` | M1 |
| `httpdatagram.encode_datagram()` | RFC 9298 sec. 5 paragraphs 2 to 6 | `[ok]` | `tests/test_httpdatagram.py::test_context_zero_roundtrip`, `tests/test_httpdatagram.py::test_payload_65527_ok_65528_refused` | M1 |
| `httpdatagram.decode_h3_datagram()` | RFC 9297 sec. 2.1 paragraphs 4 and 6 | `[ok]` | `tests/test_httpdatagram.py::test_quarter_stream_id_limits`, `tests/test_httpdatagram.py::test_h3_datagram_roundtrip_and_stream_id_rules` | M1 |
| `httpdatagram.validate_h3_datagram_setting()` | RFC 9297 sec. 2.1.1 paragraphs 2 to 4; H3_SETTINGS_ERROR 0x0109 from RFC 9114 sec. 8.1 | `[ok]` | `tests/test_httpdatagram.py::test_settings_h3_datagram` | M1 |
| `ctx.allocate_context()` | RFC 9298 sec. 4 paragraph 2 | `[ok]` | `tests/test_httpdatagram.py::test_allocator_parity_and_no_reuse`, `tests/test_httpdatagram.py::test_allocator_exhaustion` | M2 |
| `limits.clamp_payload()` | RFC 9298 sec. 6.1 (the 65527 rule is sec. 5 paragraph 6, `limits.check_udp_payload()`) | `[ok]` | `tests/test_httpdatagram.py::test_clamp_payload`, `tests/test_httpdatagram.py::test_payload_65527_ok_65528_refused` | M1 |
| `limits.optimistic_send_allowed()` | RFC 9931 sec. 6.3, replacing RFC 9298 sec. 5 paragraph 9 | `[ok]` | `tests/test_rfc9931_optimistic.py::test_http1_clients_must_not_send_optimistically`, `tests/test_connect_udp.py::test_http11_never_optimistic` | M2 |
| `template.parse_template()` | RFC 6570 sec. 2 and 3.2 (level 3 subset), erratum 6937; RFC 9298 sec. 2 paragraphs 5, 10, 11 | `[ok]` | `tests/test_connect_udp.py::test_template_rejections`, `tests/test_connect_udp.py::test_expansion_encodes_every_reserved_character_in_a_value` | M2 |
| `connect_udp.validate_template()` | RFC 9298 sec. 2 paragraphs 5 to 12 | `[ok]` | `tests/test_connect_udp.py::test_template_rejections` | M2 |
| `connect_udp.build_request()` | RFC 9298 sec. 3, 3.2, 3.4 | `[ok]` | `tests/test_connect_udp.py::test_default_template_example`, `tests/test_connect_udp.py::test_request_shapes_h2_h3` | M2 |
| `connect_udp.check_response()` | RFC 9298 sec. 3.3, 3.5; RFC 9297 sec. 3.2 paragraph 16 | `[ok]` | `tests/test_connect_udp.py::test_response_http11`, `tests/test_connect_udp.py::test_response_h2_h3` | M2 |
| `connect_ip.target_uri()` | RFC 9484 sec. 4.6, erratum 8444 | `[ok]` | `tests/test_connect_ip.py::test_wildcard_percent_encoded`, `tests/test_connect_ip.py::test_ipv6_prefix_encoding` | M5 |
| `connect_ip.encode_address_assign()` | RFC 9484 sec. 4.7.1 | `[ok]` | `tests/test_connect_ip.py::test_assign_roundtrip_and_empty_means_remove` | M5 |
| `connect_ip.decode_address_request()` | RFC 9484 sec. 4.7.2 | `[ok]` | `tests/test_connect_ip.py::test_request_zero_entries_aborts`, `tests/test_connect_ip.py::test_request_id_zero_refused` | M5 |
| `connect_ip.validate_routes()` | RFC 9484 sec. 4.7.3 paragraphs 14 to 19 | `[ok]` | `tests/test_connect_ip.py::test_route_order_violations`, `tests/test_connect_ip.py::test_route_order_violations_on_the_wire_abort_the_stream` | M5 |
| `connect_ip.decode_route_advertisement()` | RFC 9484 sec. 4.7.3; RFC 9297 sec. 3.3 paragraph 2 | `[ok]` | `tests/test_connect_ip.py::test_route_roundtrip`, `tests/test_connect_ip.py::test_trailing_bytes_malformed` | M5 |
| `connect_ip.datagram-payload` (`ip_datagram.encode_ip_datagram`, `decode_ip_datagram`: Context ID zero carries the packet from the IP Version field on; others are unknown; sec. 6 and sec. 4.8 read 2026-11-13) | RFC 9484 sec. 6, sec. 4.8 | `[ok]` | `tests/test_connect_ip_datagram.py::test_datagram_payload_is_context_zero_then_the_packet` | M5 |
| `ip_datagram.outermost_protocol()` (IPv6 extension header walk to the number scoping matches; IANA registry 0, 43, 44, 50, 51, 60, 135, 140, 253, 254; stops at ESP and the experimental numbers, `None` for a non-first fragment or a cut chain) | RFC 9484 sec. 4.8, RFC 8200 sec. 4 | `[ok]` | `tests/test_connect_ip_datagram.py::test_ipv6_extension_header_chain_is_walked` | M5 |
| `ip_datagram.decrement_hop_limit()` (decrement on encapsulation, IPv4 checksum recomputed, `None` at zero) | RFC 9484 sec. 7.2 paragraph 4 | `[ok]` | `tests/test_connect_ip_datagram.py::test_decrement_hop_limit_on_encapsulation` | M5 |
| `ip_datagram.check_ipv6_link_mtu()` (at least 1280 or abort; the ICMPv6 echo probe of sec. 7.2 paragraph 7 is not built) | RFC 9484 sec. 7.2 paragraphs 6 to 8 | `[part]` | `tests/test_connect_ip_datagram.py::test_ipv6_link_mtu_minimum` | M5 |
| `sansio.on_datagram()` (`Tunnel`: unknown Context ID or datagram before the request buffered for a window, count and size limits, newest dropped when full, 65527 abort, closed receive side drops; the cited paragraphs were wrong, the rules are RFC 9298 sec. 5 paragraphs 3, 5, 6, 7 and RFC 9297 sec. 2.1 paragraphs 5 and 6) | RFC 9298 sec. 5, RFC 9297 sec. 2.1 | `[ok]` | `tests/test_sansio.py::test_on_datagram`, `tests/test_sansio.py::test_unknown_context_is_buffered_then_released_on_registration`, `tests/test_sansio.py::test_buffer_limits_drop_the_newest_not_the_oldest`, `tests/test_sansio.py::test_oversize_udp_payload_aborts_the_stream` | M2 |
| `proxy.rules` (`h3tunnel.proxy`, sans-IO: `plan_target` says a name must be resolved before the reply, `reject_dns_error` 502 and `reject_dns_timeout` 504 and `reject_prohibited` 502 carry a RFC 9209 `Proxy-Status`, `ProxySession` discards packets whose source address or port differs from the request unless the socket is connected, drops datagrams that would need IP fragmentation at the path MTU and never above 65527, sets DF for IPv4, closes the stream on a socket error, and closes an idle socket after two minutes unless `allow_short_idle` says otherwise) | RFC 9298 sec. 3.1; RFC 9209 sec. 2, sec. 2.3.1, sec. 2.3.2, sec. 2.3.5 | `[ok]` | `tests/test_proxy_rules.py::test_proxy_rules`, `tests/test_proxy_rules.py::test_source_validation_discards_packets_that_do_not_match_the_request`, `tests/test_proxy_rules.py::test_idle_close_floor_and_socket_errors` | M4 |
| `proxy.proxy-status-sfields` (`proxy.proxy_status` writes the few RFC 9209 shapes by hand; it should serialise through `sfields` once h3tunnel may depend on it) | RFC 9209 sec. 2; RFC 8941 sec. 4 | `[ ]` | `tests/test_proxy_rules.py::test_proxy_status_serialisation` | M4 |
| `aio.open_udp_tunnel()` (M3a: HTTP/1.1 Upgrade over asyncio and `ssl`, standard library only: request from `build_request`, 101 checked by `check_response`, DATAGRAM capsules both ways through `sansio.Tunnel`; header size cap, line folding and bad status lines refused, unknown capsules skipped; QUIC and HTTP/3 stay `[no]` behind the owner decision below) | RFC 9298 sec. 3.2, sec. 3.3; RFC 9297 sec. 3.5 | `[ok]` | `tests/test_aio.py::test_open_udp_tunnel_roundtrip_and_request_shape`, `tests/test_aio.py::test_a_response_that_does_not_establish_the_tunnel_is_refused` | M3 |
| `aio.serve_proxy()` (the asyncio server over `ssl`: HTTP/1.1 Upgrade parse, template match, `getaddrinfo` before the 101, a UDP socket per stream driven by `proxy.ProxySession`; the rules are built and tested, the socket glue is not, and the function is still a loud stub) | RFC 9298 sec. 3.1 | `[ ]` | `tests/test_aio.py` (to be written) | M4 |

## 2. Milestones

- M1 codecs first: varint, capsule and HTTP Datagram framing against byte-exact vectors (done 2026-11-13)
- M2 sans-IO client state machine including context identifier lifecycle (request builder, template, context allocator, optimistic-send rule and `sansio.Tunnel` done)
- M3 asyncio client: HTTP/1.1 Upgrade over `ssl` done and verified against a local loopback proxy double (M3a); the QUIC adapter (M3b) is `[no]` until the owner decision below
- M4 proxy server: RFC 9298 sec. 3.1 handling, limits, graceful teardown
- M5 CONNECT-IP with erratum 8444 percent-encoding and an IP packet codec (target URI, the three capsules and the datagram payload with the extension header walk done)
- M6 publication: 0.1.0 with an interoperability trace against a non-Python proxy

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 9484 verified erratum 8444, sec. 4.6: the wildcard value for target and ipproto MUST be percent-encoded, so it travels as %2A. Examples in sec. 4.2 and 4.4 are corrected too. Get this wrong and CONNECT-IP does not interoperate.
- RFC 9931 (2026-03) sec. 6.3 replaces the optimistic-sending text of RFC 9298 sec. 5: a client MAY send UDP packets in HTTP Datagrams before the response only on HTTP/2 or later, and MUST NOT on HTTP/1.x.
- Section citations corrected 2026-11-13: the unknown-Context-ID, pre-request and buffering-limit rules are RFC 9298 sec. 5 paragraphs 3, 6 and 7 (not 4, 7 and 8; paragraph 8 is optimistic sending), and RFC 9297 sec. 2.1 paragraphs 5 and 6 (paragraph 7 is the stream-limit H3_ID_ERROR, a SHOULD this library does not implement because the QUIC stream limit is unknown to it). RFC 9484 sec. 6 is a restatement of the same datagram rule; its Context ID text is identical to RFC 9298's. RFC 9484 sec. 4.8 (read in full): scoping by protocol number MUST walk the extension chain, and number 0 in ROUTE_ADVERTISEMENT means all protocols, not Hop-by-Hop. RFC 9484 has 1 verified erratum (8444, sec. 4.6, already applied); none on sec. 4.8, 6 or 7.
- RFC 9297, RFC 9298 and RFC 9931 report no errata (rfclib, re-read 2026-11-13).
- Added 2026-11-13. RFC 9000 has 6 verified errata, none on sec. 16 or Appendix A.1 (the varint). RFC 6570 has verified erratum 6937 on sec. 2.1: the literals ABNF wrongly excludes the apostrophe, and `template.py` follows the corrected rule. RFC 9114 has 3 verified errata; 7014 (sec. 4.3.1) says `:path` is an absolute-path and may start with `//`, which `build_request` preserves (`test_path_may_start_with_two_slashes`).
- RFC 9931 sec. 6.3 paragraph 4 is the replacement text and RFC 9298 sec. 5 paragraph 9 the replaced one, both confirmed by reading. RFC 9931 sec. 6.4 says RFC 9484 sec. 11 already forbids optimistic sending in CONNECT-IP on HTTP/1.1. RFC 9931 sec. 8 (CONNECT proxy clients wait for a 2xx or send Connection: close; proxy servers close the connection on a rejected CONNECT) applies to a future CONNECT-TCP, not to this project.
- Review claims corrected: RFC 6570 sec. 3.2.8 and 3.2.9 were listed as unread and are read now. The review said the wildcard may be left out when the variable is absent; with the default template an omitted variable would leave an empty path segment, which RFC 9484 sec. 3 paragraph 10 forbids, so `target_uri(None)` sends `%2A`. The review also expected the raw RFC 9298 examples to match byte for byte; they do (`test_default_template_example`).

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a QUIC implementation: aioquic and qh3 already are one, and this is not a third | `[no]` | a named document requires it |
| WARP's proprietary L4 mode or its authentication scheme | `[no]` | a named document requires it |
| a full VPN: CONNECT-IP moves packets, it does not negotiate an address with a peer | `[no]` | a named document requires it |

## 5. Open questions

- OWNER DECISION, "adapter or cut": QUIC and HTTP/3 transport are neither in the standard library nor in `cryptography`, so M3b and the HTTP/3 half of M4 need either an adapter or a cut. The choice: keep the first-party code transport-free (everything above, plus a sans-IO machine and an HTTP/1.1 Upgrade client over `asyncio` and `ssl`, which needs no third-party code) and let an adapter to aioquic or qh3 be a separate optional distribution, or mark the QUIC transport `[no]`, which PORTFOLIO section 9 already says for now. This pass built the transport-free part.
- Which adapter lands first, if adapter: qh3 or aioquic, given both expose datagrams today.
- Does the proxy side need CONNECT-TCP before users ask for it.
- OWNER DECISION: the interoperability trace of M6 needs a named non-Python peer (a Go or Rust MASQUE proxy); none is chosen.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
