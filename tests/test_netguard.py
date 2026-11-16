"""Tests for tests/_netguard.py: it blocks what it says it blocks and lets loopback through.

Every name or address used for a blocked attempt is reserved (192.0.2.1 is TEST-NET-1, and
`.invalid` never resolves), so a broken guard would not reach a real host.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tests import _netguard
from tests._netguard import expected_attempts

REPO_ROOT = Path(__file__).resolve().parent.parent
RESERVED = "192.0.2.1"
NO_SUCH_HOST = "telemetry.example.invalid"


class TestIsLoopback:
    @pytest.mark.parametrize(
        "host", ["127.0.0.1", "127.255.0.9", "::1", "localhost", "", None, b"127.0.0.1"]
    )
    def test_loopback_forms_are_allowed(self, host):
        assert _netguard._is_loopback(host) is True

    @pytest.mark.parametrize(
        "host",
        ["192.0.2.1", "8.8.8.8", "10.0.0.1", "0.0.0.0", "example.com", "localhost.example.com", 7],
    )
    def test_everything_else_is_not(self, host):
        assert _netguard._is_loopback(host) is False


class TestBlocksNonLoopback:
    def test_connect_is_blocked_and_recorded_with_the_test_that_made_it(self):
        with socket.socket() as sock:
            sock.settimeout(0.5)
            with expected_attempts() as seen:
                with pytest.raises(OSError, match=f"netguard: blocked connect to {RESERVED}"):
                    sock.connect((RESERVED, 9))
        assert [(kind, target) for kind, target, _ in seen] == [("connect", RESERVED)]
        assert "test_netguard.py" in seen[0][2]

    def test_connect_ex_is_blocked_too(self):
        with socket.socket() as sock:
            sock.settimeout(0.5)
            with expected_attempts() as seen:
                with pytest.raises(OSError, match="netguard: blocked connect"):
                    sock.connect_ex((RESERVED, 9))
        assert len(seen) == 1

    def test_udp_sendto_is_blocked(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            with expected_attempts() as seen:
                with pytest.raises(OSError, match=f"netguard: blocked sendto to {RESERVED}"):
                    sock.sendto(b"x", (RESERVED, 9))
        assert [(kind, target) for kind, target, _ in seen] == [("sendto", RESERVED)]

    def test_an_address_form_the_guard_does_not_understand_is_refused(self):
        with socket.socket() as sock:
            with expected_attempts() as seen:
                with pytest.raises(OSError, match="netguard: blocked connect"):
                    sock.connect("not-an-address-tuple")
        assert len(seen) == 1

    @pytest.mark.parametrize("name", ["getaddrinfo", "gethostbyname", "gethostbyname_ex"])
    def test_a_lookup_of_a_non_loopback_name_is_blocked_before_the_resolver(
        self, name, monkeypatch
    ):
        def resolver_must_not_run(*args, **kwargs):
            raise AssertionError("the real resolver was reached")

        monkeypatch.setitem(_netguard._REAL, name, resolver_must_not_run)
        args = (NO_SUCH_HOST, 443) if name == "getaddrinfo" else (NO_SUCH_HOST,)
        with expected_attempts() as seen:
            with pytest.raises(OSError, match=f"netguard: blocked DNS lookup of {NO_SUCH_HOST}"):
                getattr(socket, name)(*args)
        assert [(kind, target) for kind, target, _ in seen] == [("dns", NO_SUCH_HOST)]

    def test_create_connection_is_blocked_at_the_lookup(self):
        with expected_attempts() as seen:
            with pytest.raises(OSError, match="netguard: blocked DNS lookup"):
                socket.create_connection((NO_SUCH_HOST, 80), timeout=0.5)
        assert [kind for kind, _, _ in seen] == ["dns"]

    def test_urlopen_fails_with_the_guards_message(self):
        """The path the gate uses in `enroll`: urllib.request.urlopen."""
        with expected_attempts() as seen:
            with pytest.raises(urllib.error.URLError, match="netguard: blocked DNS lookup"):
                urllib.request.urlopen(f"http://{NO_SUCH_HOST}/", timeout=0.5)  # noqa: S310
        assert [(kind, target) for kind, target, _ in seen] == [("dns", NO_SUCH_HOST)]


class TestAllowsLoopback:
    def test_a_tcp_connection_to_a_local_listener_passes_and_is_not_recorded(self):
        before = list(_netguard.ATTEMPTS)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                accepted, _ = listener.accept()
                accepted.close()
        assert _netguard.ATTEMPTS == before

    def test_udp_to_a_local_socket_passes(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(2)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(b"ping", receiver.getsockname())
            assert receiver.recvfrom(16)[0] == b"ping"

    @pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no Unix sockets on this platform")
    def test_a_unix_socket_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "s")
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(path)
                listener.listen(1)
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(path)
                    accepted, _ = listener.accept()
                    accepted.close()

    @pytest.mark.parametrize("name", ["getaddrinfo", "gethostbyname", "gethostbyname_ex"])
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
    def test_a_loopback_lookup_reaches_the_real_resolver(self, name, host, monkeypatch):
        sentinel = object()
        monkeypatch.setitem(_netguard._REAL, name, lambda *args, **kwargs: sentinel)
        args = (host, 80) if name == "getaddrinfo" else (host,)
        assert getattr(socket, name)(*args) is sentinel


class TestExpectedAttempts:
    def test_it_removes_only_the_attempts_made_inside_the_block(self):
        earlier = ("connect", "earlier", "some test")
        _netguard.ATTEMPTS.append(earlier)
        try:
            with expected_attempts() as seen:
                _netguard._record("dns", "inside.example.invalid")
            assert [target for _, target, _ in seen] == ["inside.example.invalid"]
            assert _netguard.ATTEMPTS == [earlier]
        finally:
            _netguard.ATTEMPTS.remove(earlier)


class TestInstall:
    def test_uninstall_restores_the_originals_and_install_puts_the_guard_back(self):
        try:
            _netguard._uninstall()
            assert socket.getaddrinfo is _netguard._REAL["getaddrinfo"]
            assert socket.socket.connect is _netguard._REAL["connect"]
        finally:
            _netguard._install()
        assert socket.getaddrinfo is not _netguard._REAL["getaddrinfo"]
        assert socket.socket.connect is not _netguard._REAL["connect"]

    def test_installing_twice_does_not_record_the_guard_as_the_original(self):
        _netguard._install()
        _netguard._install()
        for real in _netguard._REAL.values():
            assert getattr(real, "__module__", None) != _netguard.__name__


def _run_pytest(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    """Run a one-file pytest session in a child process with the guard loaded as a plugin."""
    (tmp_path / "test_probe.py").write_text(body, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(REPO_ROOT), env.get("PYTHONPATH")]))
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell
        [sys.executable, "-m", "pytest", "-p", "tests._netguard", "-p", "no:cacheprovider",
         "test_probe.py"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120, check=False,
    )


class TestSessionOutcome:
    def test_a_clean_session_exits_zero_and_reports_zero_attempts(self, tmp_path):
        result = _run_pytest(tmp_path, "def test_ok():\n    assert True\n")
        assert result.returncode == 0, result.stdout
        assert "NETGUARD external attempts: 0" in result.stdout

    def test_a_test_that_calls_urlopen_on_a_non_loopback_host_fails(self, tmp_path):
        body = (
            "import urllib.request\n"
            "def test_phone_home():\n"
            f"    urllib.request.urlopen('http://{NO_SUCH_HOST}/', timeout=1)\n"
        )
        result = _run_pytest(tmp_path, body)
        assert result.returncode == 1, result.stdout
        assert "netguard: blocked DNS lookup" in result.stdout
        assert "NETGUARD external attempts: 1" in result.stdout

    def test_a_swallowed_attempt_still_fails_the_session(self, tmp_path):
        body = (
            "import socket\n"
            "def test_swallows_the_error():\n"
            "    try:\n"
            f"        socket.getaddrinfo('{NO_SUCH_HOST}', 443)\n"
            "    except OSError:\n"
            "        pass\n"
        )
        result = _run_pytest(tmp_path, body)
        assert "1 passed" in result.stdout, result.stdout
        assert result.returncode == 1, result.stdout
        assert "NETGUARD external attempts: 1" in result.stdout
        assert "test_probe.py::test_swallows_the_error" in result.stdout
