"""Command line entry point for h3tunnel.

The CLI is how most people meet a protocol library, so it is part of the public surface and
gets the same typing and testing discipline as the rest of the package.
"""

from __future__ import annotations

import argparse
import sys

USAGE = """\
Examples:
  h3tunnel udp --proxy https://proxy:4433 --listen 127.0.0.1:5354 --target 1.1.1.1:53"""


def build_parser():
    return argparse.ArgumentParser(
        prog="h3tunnel",
        description="MASQUE tunnels: HTTP Datagrams and the Capsule Protocol, CONNECT-UDP and CONNECT-IP clients, and the proxy side that terminates them",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv=None):
    """Parse arguments, then refuse to pretend the protocol works.

    Exiting non-zero is the correct behaviour for a shell. A CLI that printed a friendly
    banner and exited 0 would be indistinguishable from one that actually did something.
    """
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_usage(sys.stderr)
    print(
        "h3tunnel: no tunnel is implemented yet (only the codecs are); see ROADMAP.md",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
