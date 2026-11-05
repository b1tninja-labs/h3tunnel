"""h3tunnel -- CONNECT-UDP and CONNECT-IP in Python.

MASQUE is how UDP is proxied over HTTP today, and Python cannot speak it.
"""

from __future__ import annotations

from . import aio, apps, capsule, cli, connect_ip, connect_udp, ctx, httpdatagram, limits, sansio
from .aio import open_udp_tunnel, serve_proxy
from .capsule import decode_capsule, encode_capsule
from .connect_ip import target_uri
from .connect_udp import build_request
from .ctx import allocate_context
from .httpdatagram import encode_datagram
from .limits import clamp_payload
from .sansio import on_datagram

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "aio",
    "allocate_context",
    "apps",
    "build_request",
    "capsule",
    "clamp_payload",
    "cli",
    "connect_ip",
    "connect_udp",
    "ctx",
    "decode_capsule",
    "encode_capsule",
    "encode_datagram",
    "httpdatagram",
    "limits",
    "on_datagram",
    "open_udp_tunnel",
    "sansio",
    "serve_proxy",
    "target_uri",
]
