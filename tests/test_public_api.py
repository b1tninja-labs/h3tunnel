"""The shell contract: the surface exists, is documented, and refuses to lie.

These are the tests that must fail loudly if a stub ever starts returning a plausible
empty value instead of raising. That is how a protocol library quietly becomes wrong: a
decoder learns to return an empty object rather than refuse, and every caller downstream
reads confidence where there was only silence.
"""

from __future__ import annotations

import importlib

import pytest

import h3tunnel as package

SURFACE = [
    ("capsule", "encode_capsule", "RFC 9297 sec. 3.2"),
    ("capsule", "decode_capsule", "RFC 9297 sec. 3.2"),
    ("httpdatagram", "encode_datagram", "RFC 9298 sec. 5"),
    ("ctx", "allocate_context", "RFC 9298 sec. 4"),
    ("connect_udp", "build_request", "RFC 9298 sec. 3"),
    ("connect_ip", "target_uri", "RFC 9484 sec. 4.6"),
    ("limits", "clamp_payload", "RFC 9298 sec. 6.1"),
    ("sansio", "on_datagram", "RFC 9298"),
    ("aio", "open_udp_tunnel", "RFC 9298"),
    ("aio", "serve_proxy", "RFC 9298 sec. 3.1"),
]


def test_version_is_a_string():
    assert isinstance(package.__version__, str)


def test_public_names_all_exist():
    missing = [name for name in package.__all__ if not hasattr(package, name)]
    assert not missing, "__all__ names things that do not exist: " + ", ".join(missing)


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_surface_is_documented(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    assert target.__doc__, fn + " needs a docstring"
    # Docstrings are wrapped, so a long citation can span a line break; compare words, not layout.
    assert " ".join(cite.split()) in " ".join(target.__doc__.split()), (
        fn + " must cite the document that defines it"
    )


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_stubs_are_loud(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    if "Not implemented yet" not in (target.__doc__ or ""):
        pytest.skip(fn + " is implemented; pin it with a real vector test now")
    with pytest.raises((NotImplementedError, TypeError)):
        target()
