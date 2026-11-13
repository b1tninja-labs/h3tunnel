# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 9297 | Proposed Standard | 2022-08 | 2026-11-05 |
| RFC 9298 | Proposed Standard | 2022-08 | 2026-11-05 |
| RFC 9484 | Proposed Standard | 2023-10 | 2026-11-05 |
| RFC 9221 | Proposed Standard | 2022-03 | 2026-11-05 |
| RFC 9114 | Proposed Standard | 2022-06 | 2026-11-05 |
| RFC 9220 | Proposed Standard | 2022-06 | 2026-11-05 |
| RFC 9931 | Proposed Standard, updates RFC 9112 and RFC 9298 | 2026-03 | 2026-11-13 |
| RFC 9000 | Proposed Standard, current, 6 verified errata (none on sec. 16 or Appendix A.1) | 2021-05 | 2026-11-13 |
| RFC 6570 | Proposed Standard, current, verified erratum 6937 (sec. 2.1) | 2012-03 | 2026-11-13 |
| RFC 9651 | Proposed Standard, obsoletes RFC 8941 (the sibling `sfields`) | 2024-09 | 2026-11-13 |
| RFC 3986 | Internet Standard (STD 66): the unreserved set used by RFC 6570 expansion | 2005-01 | not re-checked |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

## What each document supplies

- RFC 9000 sec. 16 and Appendix A.1: the variable-length integer, used by every length, type, Context ID and Quarter Stream ID here. The five sample encodings of A.1 paragraph 5 are the vectors in `tests/test_varint.py`.
- RFC 9297: sec. 2.1 (HTTP/3 Datagram, Quarter Stream ID, H3_DATAGRAM_ERROR 0x33, SETTINGS_H3_DATAGRAM), sec. 3.2 to 3.5 (capsules, error handling, the Capsule-Protocol header, the DATAGRAM capsule). No errata.
- RFC 9298 (updated by RFC 9484 and RFC 9931): sec. 2 (the template rules), 3.2 to 3.5 (request and response shapes), 4 (Context IDs), 5 (payload format, the 65527 limit, buffering), 6.1 (MTU). No errata. Paragraph 9 of sec. 5, the optimistic-send MAY, is replaced by RFC 9931 sec. 6.3.
- RFC 9484: sec. 3 (template rules), 4.6 (target and ipproto, erratum 8444: the wildcard travels as %2A), 4.7 (the three capsules). Sec. 4.8 and 6 are not read yet.
- RFC 9931 sec. 6.3, 6.4, 7 and 8: sec. 6.3 is the hostile test of `tests/test_rfc9931_optimistic.py`; sec. 8 concerns a CONNECT-TCP client this project does not have.
- RFC 6570 sec. 2 (syntax, with erratum 6937 on the literals) and 3.2.1, 3.2.2, 3.2.8, 3.2.9 (expansion): the subset in `template.py`. RFC 3986 appendix A supplies `unreserved`.
- RFC 9114 sec. 8.1 (H3_SETTINGS_ERROR 0x0109) and verified erratum 7014 on sec. 4.3.1 (`:path` may start with `//`).
- RFC 9651 and sfields: only for reading a received Capsule-Protocol header.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
