"""asyncio client and proxy server over a pluggable QUIC adapter.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ProxyPolicy = Any  # placeholder: give it a real type in the milestone that needs it
    UdpTunnel = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "open_udp_tunnel",
    "serve_proxy",
]


async def open_udp_tunnel(proxy: str, target: tuple) -> UdpTunnel:
    """Pending behaviour defined by RFC 9298.

    Not implemented yet. See the ``aio.open_udp_tunnel()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("open_udp_tunnel() is not implemented: RFC 9298")


async def serve_proxy(host: str, port: int, policy: ProxyPolicy) -> None:
    """Pending behaviour defined by RFC 9298 sec. 3.1.

    Not implemented yet. See the ``aio.serve_proxy()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("serve_proxy() is not implemented: RFC 9298 sec. 3.1")
