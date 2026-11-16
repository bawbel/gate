"""A pytest plugin that blocks and records every attempt to reach a non-loopback address.

Loaded from tests/conftest.py, so it is active for the whole suite. It exists so that a
change which makes the gate reach the network fails the suite, and so the README can say
what the gate does on the network and have CI hold it to that.

What it patches, in the test process only:

- `socket.socket.connect`, `connect_ex` and `sendto`: allowed for loopback addresses and
  Unix sockets, blocked for anything else
- `socket.getaddrinfo`, `gethostbyname` and `gethostbyname_ex`: allowed for loopback
  addresses and `localhost`, blocked for any other name or address

What it does not cover:

- child processes: the upstream MCP servers that tests spawn run unguarded
- code paths the suite does not execute
- sockets that are only bound or listened on
- gRPC, which opens its own sockets below Python's `socket` module. The optional OTLP
  exporter in ops/otel.py is gRPC, so with the `ops` extra installed and
  OTEL_EXPORTER_OTLP_ENDPOINT set, tests can export spans while this guard records nothing.
  tests/test_network_surface.py watches for that import instead.

A blocked attempt raises OSError. Code that catches the error still leaves the attempt in
the record, and the session then exits non-zero even if every test passed.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
from collections.abc import Callable, Iterator
from typing import Any

import pytest

# (kind, target, test id). kind is "connect", "sendto" or "dns".
Attempt = tuple[str, str, str]
ATTEMPTS: list[Attempt] = []

_SOCKET_METHODS = ("connect", "connect_ex", "sendto")
_SOCKET_FUNCTIONS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex")

# The unpatched callables. Filled by _install, read at call time so a test can swap one.
_REAL: dict[str, Callable[..., Any]] = {}
_installed = False


def _is_loopback(host: object) -> bool:
    if host is None:
        return True  # getaddrinfo(None, port): the local host, no lookup on the network
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host in ("", "localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _record(kind: str, target: object) -> None:
    test = os.environ.get("PYTEST_CURRENT_TEST", "(outside a test)")
    ATTEMPTS.append((kind, str(target), test))


def _address_host(sock: socket.socket, address: object) -> tuple[bool, object]:
    """(is this address allowed, what to name it in a message)."""
    if hasattr(socket, "AF_UNIX") and sock.family == socket.AF_UNIX:
        return True, address
    if isinstance(address, tuple) and address:
        return _is_loopback(address[0]), address[0]
    return False, address  # an address form this guard does not understand: refuse it


def _guard_socket_method(name: str):
    def guarded(self, *args):
        # connect(address), connect_ex(address), sendto(data, address),
        # or sendto(data, flags, address): the address is always the last argument
        address = args[-1] if args else None
        allowed, shown = _address_host(self, address)
        if not allowed:
            kind = "sendto" if name == "sendto" else "connect"
            _record(kind, shown)
            raise OSError(f"netguard: blocked {kind} to {shown}")
        return _REAL[name](self, *args)

    guarded.__name__ = name
    return guarded


def _guard_name_lookup(name: str):
    def guarded(host, *args, **kwargs):
        if not _is_loopback(host):
            _record("dns", host)
            raise OSError(f"netguard: blocked DNS lookup of {host}")
        return _REAL[name](host, *args, **kwargs)

    guarded.__name__ = name
    return guarded


def _install() -> None:
    global _installed
    if _installed:
        return
    for name in _SOCKET_METHODS:
        _REAL[name] = getattr(socket.socket, name)
        setattr(socket.socket, name, _guard_socket_method(name))
    for name in _SOCKET_FUNCTIONS:
        _REAL[name] = getattr(socket, name)
        setattr(socket, name, _guard_name_lookup(name))
    _installed = True


def _uninstall() -> None:
    global _installed
    if not _installed:
        return
    for name in _SOCKET_METHODS:
        setattr(socket.socket, name, _REAL[name])
    for name in _SOCKET_FUNCTIONS:
        setattr(socket, name, _REAL[name])
    _installed = False


@contextlib.contextmanager
def expected_attempts() -> Iterator[list[Attempt]]:
    """For the guard's own tests: attempts made inside the block are returned, not kept.

    Without this, a test that checks the guard blocks something would leave an attempt in
    the record and fail the session.
    """
    start = len(ATTEMPTS)
    seen: list[Attempt] = []
    try:
        yield seen
    finally:
        seen.extend(ATTEMPTS[start:])
        del ATTEMPTS[start:]


def pytest_configure(config: pytest.Config) -> None:
    _install()


def pytest_unconfigure(config: pytest.Config) -> None:
    _uninstall()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if ATTEMPTS and session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter) -> None:
    terminalreporter.write_line(f"NETGUARD external attempts: {len(ATTEMPTS)}")
    for kind, target, test in ATTEMPTS:
        terminalreporter.write_line(f"  {kind} {target} from {test}")
