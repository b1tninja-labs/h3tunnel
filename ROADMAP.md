# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation h3tunnel could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `capsule.encode_capsule()` | RFC 9297 | `[ ]` | `tests/test_obligations.py::encode_capsule` |
| `capsule.decode_capsule()` | RFC 9297 | `[ ]` | `tests/test_obligations.py::decode_capsule` |
| `httpdatagram.encode_datagram()` | RFC 9298 sec. 5 | `[ ]` | `tests/test_obligations.py::encode_datagram` |
| `ctx.allocate_context()` | RFC 9298 sec. 4 | `[ ]` | `tests/test_obligations.py::allocate_context` |
| `connect_udp.build_request()` | RFC 9298 sec. 3 | `[ ]` | `tests/test_obligations.py::build_request` |
| `connect_ip.target_uri()` | RFC 9484 sec. 4.6 | `[ ]` | `tests/test_obligations.py::target_uri` |
| `limits.clamp_payload()` | RFC 9298 sec. 6.1 | `[ ]` | `tests/test_obligations.py::clamp_payload` |
| `sansio.on_datagram()` | RFC 9298 | `[ ]` | `tests/test_obligations.py::on_datagram` |
| `aio.open_udp_tunnel()` | RFC 9298 | `[ ]` | `tests/test_obligations.py::open_udp_tunnel` |
| `aio.serve_proxy()` | RFC 9298 sec. 3.1 | `[ ]` | `tests/test_obligations.py::serve_proxy` |

## 2. Milestones

- M1 signed codecs first: capsule and HTTP Datagram framing against byte-exact vectors
- M2 sans-IO client state machine including context identifier lifecycle
- M3 asyncio client over the qh3 adapter, verified against a local proxy
- M4 proxy server: RFC 9298 sec. 3.1 handling, limits, graceful teardown
- M5 CONNECT-IP with erratum 8444 percent-encoding and an IP packet codec
- M6 publication: 0.1.0 with an interoperability trace against a non-Python proxy

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 9484 verified erratum 8444, sec. 4.6: the wildcard value for target and ipproto MUST be percent-encoded, so it travels as %2A. Examples in sec. 4.2 and 4.4 are corrected too. Get this wrong and CONNECT-IP does not interoperate.
- RFC 9931 updates RFC 9298 sec. 5: optimistic sending before the response is allowed in HTTP/2 and HTTP/3 but not in HTTP/1.1.
- RFC 9297 and RFC 9298 report no errata as of 2026-10-29.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a QUIC implementation: aioquic and qh3 already are one, and this is not a third | `[no]` | a named document requires it |
| WARP's proprietary L4 mode or its authentication scheme | `[no]` | a named document requires it |
| a full VPN: CONNECT-IP moves packets, it does not negotiate an address with a peer | `[no]` | a named document requires it |

## 5. Open questions

- which adapter lands first: qh3 or aioquic, given both expose datagrams today
- does the proxy side need CONNECT-TCP before users ask for it

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
