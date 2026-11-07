# h3tunnel

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

h3tunnel -- CONNECT-UDP and CONNECT-IP in Python

MASQUE is how UDP is proxied over HTTP today, and Python cannot speak it. The closest thing on PyPI is pymasque (0.1.2, 2026-11-04), which implements Cloudflare WARP's undocumented L4 mode from a gist: TCP only, client only, no proxy side, and compliant with neither RFC 9298 nor RFC 9484. The transport problem is already solved twice over, since aioquic 1.7.2 (2026-11-02) and qh3 2.1.0 (2026-10-25) both ship sans-IO and asyncio APIs with QUIC DATAGRAM support. What is missing is precisely the layer above them: capsules, context identifiers and the two CONNECT profiles. h3tunnel keeps that layer sans-IO, so it is testable with no QUIC stack at all and the transport stays an adapter.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| pymasque | 0.1.2 | 2026-11-04 | Cloudflare WARP L4 mode only: TCP only, client only |
| aioquic | 1.7.2 | 2026-11-02 | the transport underneath, sans-IO plus asyncio; not a tunnel |
| qh3 | 2.1.0 | 2026-10-25 | maintained aioquic fork, Rust core, datagrams and WebTransport |
| connect-udp, masque-proxy, capsule | - | - | all absent from PyPI (2026-11-05) |

What this project intends to add:

- CONNECT-UDP client and proxy in one library, including the server duties of RFC 9298 sec. 3.1
- CONNECT-IP with the erratum-correct URI template (RFC 9484)
- the Capsule Protocol, so one tunnel works over HTTP/1.1 and HTTP/2 as well (RFC 9297)
- context identifier demultiplexing under the MTU and ECN rules of RFC 9298 sec. 6
- a transport-neutral core: qh3 and aioquic as adapters, never as the design centre

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 9297 | Proposed Standard | 2022-08 | HTTP Datagrams and the Capsule Protocol, the framing everything else uses |
| RFC 9298 | Proposed Standard | 2022-08 | CONNECT-UDP: request syntax, context identifiers, proxy behaviour |
| RFC 9484 | Proposed Standard | 2023-10 | CONNECT-IP: whole IP packets through the same tunnel |
| RFC 9221 | Proposed Standard | 2022-03 | the QUIC DATAGRAM extension HTTP Datagrams ride on |
| RFC 9114 | Proposed Standard | 2022-06 | HTTP/3 stream and setting rules the tunnels live inside |
| RFC 9220 | Proposed Standard | 2022-06 | extended CONNECT over HTTP/3, the pattern this reuses |
| RFC 9931 | Proposed Standard | 2026-03 | what may be sent optimistically before the response arrives |

### Errata watch

- RFC 9484 verified erratum 8444, sec. 4.6: the wildcard value for target and ipproto MUST be percent-encoded, so it travels as %2A. Examples in sec. 4.2 and 4.4 are corrected too. Get this wrong and CONNECT-IP does not interoperate.
- RFC 9931 (2026-03) sec. 6.3 replaces the optimistic-sending text of RFC 9298 sec. 5: a client MAY send UDP packets in HTTP Datagrams before the response only on HTTP/2 or later, and MUST NOT on HTTP/1.x.
- RFC 9297, RFC 9298 and RFC 9931 report no errata as of the 2026-10-29 errata feed (rfclib, read 2026-11-06).

## Module layout

| Module | Responsibility |
|---|---|
| `capsule` | capsule framing and the registered capsule types (RFC 9297) |
| `httpdatagram` | HTTP Datagram payload with the context identifier (RFC 9298 sec. 5) |
| `ctx` | context identifier allocation and demultiplexing (RFC 9298 sec. 4) |
| `connect_udp` | CONNECT-UDP request and response construction (RFC 9298 sec. 3) |
| `connect_ip` | CONNECT-IP URI template and IP packet framing (RFC 9484) |
| `limits` | MTU, ECN and optimistic-send rules (RFC 9298 sec. 6, RFC 9931 sec. 6.3) |
| `sansio` | transport-neutral tunnel state machine |
| `aio` | asyncio client and proxy server over a pluggable QUIC adapter |

## What it does not do

- a QUIC implementation: aioquic and qh3 already are one, and this is not a third
- WARP's proprietary L4 mode or its authentication scheme
- a full VPN: CONNECT-IP moves packets, it does not negotiate an address with a peer


## Install

```bash
git clone https://github.com/b1tninja/h3tunnel.git
cd h3tunnel
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy h3tunnel
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
