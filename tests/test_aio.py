"""The HTTP/1.1 Upgrade client over asyncio and ssl against a loopback server (RFC 9298 sec. 3.2)."""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import ssl

import pytest

from h3tunnel.aio import open_udp_tunnel, serve_proxy
from h3tunnel.capsule import DATAGRAM, CapsuleParser, encode_capsule
from h3tunnel.errors import TunnelRefused
from h3tunnel.varint import encode_varint

x509 = pytest.importorskip("cryptography.x509")


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("tls")
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def contexts(certificate):
    cert_path, key_path = certificate
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(cert_path))
    return server, client


RESPONSE_OK = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Connection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"
)


async def serve(server_context, respond, *, requests=None, hangup=False):
    """A proxy double: read the request header, write ``respond``, then echo reversed payloads."""

    async def handle(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        if requests is not None:
            requests.append(head)
        writer.write(respond)
        await writer.drain()
        if hangup:
            writer.close()
            return
        parser = CapsuleParser()
        try:
            while data := await reader.read(65536):
                for capsule in parser.feed(data):
                    if capsule.type == DATAGRAM and capsule.value[:1] == b"\x00":
                        echoed = b"\x00" + capsule.value[1:][::-1]
                        writer.write(encode_capsule(DATAGRAM, echoed))
                        writer.write(encode_capsule(0x7777, b"unknown capsule type"))
                        await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    listener = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_context)
    return listener, listener.sockets[0].getsockname()[1]


async def test_open_udp_tunnel_roundtrip_and_request_shape(certificate):
    server_context, client_context = contexts(certificate)
    requests: list[bytes] = []
    listener, port = await serve(server_context, RESPONSE_OK, requests=requests)
    async with listener:
        tunnel = await open_udp_tunnel(
            f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
        )
        await tunnel.send(b"hello")
        assert await tunnel.recv() == b"olleh"  # the unknown capsule that follows is skipped
        await tunnel.send(b"")
        assert await tunnel.recv() == b""
        await tunnel.send(b"x" * 65527)
        assert await tunnel.recv() == b"x" * 65527
        with pytest.raises(ValueError, match="65527"):
            await tunnel.send(b"x" * 65528)
        await tunnel.close()
    request = requests[0].decode("ascii")
    assert request.startswith(
        f"GET https://127.0.0.1:{port}/.well-known/masque/udp/192.0.2.6/53/ HTTP/1.1\r\n"
    )
    for line in ("Connection: Upgrade", "Upgrade: connect-udp", "Capsule-Protocol: ?1"):
        assert line in request


async def test_bytes_after_the_101_in_the_same_segment_are_not_lost(certificate):
    server_context, client_context = contexts(certificate)
    early = encode_capsule(DATAGRAM, b"\x00early")
    listener, port = await serve(server_context, RESPONSE_OK + early)
    async with listener:
        tunnel = await open_udp_tunnel(
            f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
        )
        assert await tunnel.recv() == b"early"
        await tunnel.close()


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 403 Forbidden\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: connect-udp\r\n\r\n",
        b"HTTP/1.0 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n",
        b"HTTP/1.1 101 X\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n folded\r\n\r\n",
        b"HTTP/1.1 101 X\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nContent-Length: 3\r\n\r\n",
        b"garbage\r\n\r\n",
    ],
)
async def test_a_response_that_does_not_establish_the_tunnel_is_refused(certificate, response):
    server_context, client_context = contexts(certificate)
    listener, port = await serve(server_context, response)
    async with listener:
        with pytest.raises(TunnelRefused):
            await open_udp_tunnel(
                f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
            )


async def test_oversize_and_truncated_responses_and_hostile_capsules(certificate):
    server_context, client_context = contexts(certificate)
    big = b"HTTP/1.1 101 X\r\n" + b"X-Pad: " + b"a" * 20000 + b"\r\n\r\n"
    listener, port = await serve(server_context, big)
    async with listener:
        with pytest.raises(TunnelRefused, match="16384"):
            await open_udp_tunnel(
                f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
            )
    listener, port = await serve(
        server_context, b"HTTP/1.1 101 Sw", hangup=True
    )  # closes mid header
    async with listener:
        with pytest.raises(TunnelRefused, match="closed"):
            await open_udp_tunnel(
                f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
            )
    # a capsule that declares a huge value is refused before it is buffered
    hostile = RESPONSE_OK + encode_varint(DATAGRAM) + encode_varint(1 << 30)
    listener, port = await serve(server_context, hostile)
    async with listener:
        tunnel = await open_udp_tunnel(
            f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
        )
        with pytest.raises(ValueError, match="limit"):
            await tunnel.recv()
        await tunnel.close()
    # a datagram too long for Context ID zero aborts the tunnel
    over = RESPONSE_OK + encode_capsule(DATAGRAM, b"\x00" + b"x" * 65528)
    listener, port = await serve(server_context, over)
    async with listener:
        tunnel = await open_udp_tunnel(
            f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
        )
        # the capsule value is 65529 octets: over the parser's 65535 cap is not reached, the machine aborts
        with pytest.raises(ConnectionError, match="aborted"):
            await tunnel.recv()
        await tunnel.close()


async def test_clean_close_returns_none_and_a_truncated_capsule_is_an_error(certificate):
    server_context, client_context = contexts(certificate)
    listener, port = await serve(server_context, RESPONSE_OK)
    async with listener:
        tunnel = await open_udp_tunnel(
            f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
        )
        listener.close()
        await tunnel.close()
        with pytest.raises(ConnectionError, match="closed"):
            await tunnel.send(b"late")
    listener, port = await serve(
        server_context, RESPONSE_OK + encode_capsule(DATAGRAM, b"\x00abc")[:-2], hangup=True
    )
    async with listener:
        tunnel = await open_udp_tunnel(
            f"127.0.0.1:{port}", ("192.0.2.6", 53), ssl_context=client_context
        )
        with pytest.raises(ValueError, match="inside a capsule"):
            await tunnel.recv()
        await tunnel.close()


async def test_verification_failure_and_timeout(certificate):
    server_context, _ = contexts(certificate)
    listener, port = await serve(server_context, RESPONSE_OK)
    async with listener:
        with pytest.raises(ssl.SSLError):  # the default context does not trust the test CA
            await open_udp_tunnel(f"127.0.0.1:{port}", ("192.0.2.6", 53))

    async def hold(reader, writer):
        await asyncio.sleep(1.0)  # accept and say nothing
        writer.close()

    silent = await asyncio.start_server(hold, "127.0.0.1", 0)
    async with silent:
        with pytest.raises(TimeoutError):
            await open_udp_tunnel(
                f"127.0.0.1:{silent.sockets[0].getsockname()[1]}",
                ("192.0.2.6", 53),
                ssl_context=ssl.create_default_context(),
                timeout=0.3,
            )


async def test_serve_proxy_is_still_a_loud_stub():
    with pytest.raises(NotImplementedError):
        await serve_proxy("127.0.0.1", 0, None)
