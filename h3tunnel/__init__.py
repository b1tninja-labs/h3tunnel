"""h3tunnel -- CONNECT-UDP and CONNECT-IP in Python.

MASQUE is how UDP is proxied over HTTP today, and Python cannot speak it.
"""

from __future__ import annotations

from . import (
    aio,
    apps,
    capsule,
    cli,
    connect_ip,
    connect_udp,
    ctx,
    errors,
    httpdatagram,
    ip_datagram,
    limits,
    proxy,
    sansio,
    template,
    varint,
)
from .aio import open_udp_tunnel, serve_proxy
from .capsule import Capsule, CapsuleParser, decode_capsule, encode_capsule
from .connect_ip import target_uri
from .connect_udp import build_request
from .ctx import ContextAllocator, allocate_context
from .httpdatagram import decode_datagram, encode_datagram
from .limits import clamp_payload
from .sansio import on_datagram
from .varint import decode_varint, encode_varint

__version__ = "0.1.0"

__all__ = [
    "Capsule",
    "CapsuleParser",
    "ContextAllocator",
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
    "decode_datagram",
    "decode_varint",
    "encode_capsule",
    "encode_datagram",
    "encode_varint",
    "errors",
    "httpdatagram",
    "ip_datagram",
    "limits",
    "on_datagram",
    "open_udp_tunnel",
    "proxy",
    "sansio",
    "serve_proxy",
    "target_uri",
    "template",
    "varint",
]
