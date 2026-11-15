"""The modules under src/ that can open, accept, or hand off network connections.

The README's "Network behavior" section says what the gate does on the network. This test
keeps that section and the code together: a new import that can reach the network fails
here even when no test runs the code, and removing a documented command's description from
the README fails here too.

The scan reads every import, including the ones inside functions. A grep for top-level
`import` lines misses `cli.py`'s `import urllib.request` inside `enroll()`, which is the one
place the gate opens an outbound connection.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from tests.i6_scan import SRC_ROOT

README = Path(__file__).resolve().parent.parent / "README.md"

# urllib.parse and urllib.error do not connect, so they are not listed.
NETWORK_MODULES = (
    "urllib.request", "urllib3", "http.client", "http.server", "socketserver", "socket", "ssl",
    "smtplib", "ftplib", "telnetlib", "imaplib", "poplib", "xmlrpc", "requests", "httpx",
    "aiohttp", "websockets", "grpc", "opentelemetry", "subprocess", "multiprocessing",
    "webbrowser",
)

# file (relative to src/) -> the network-capable modules it imports. Change this list and the
# README section together.
EXPECTED = {
    "bawbel_gate/cli.py": {"urllib.request"},  # `enroll`: one outbound HTTP POST
    "bawbel_gate/console/server.py": {"http.server"},  # `serve --console`: a listener
    "bawbel_gate/hub/server.py": {"http.server"},  # `hub serve`: a listener
    "bawbel_gate/mux/proxy.py": {"subprocess"},  # waits on and ends the upstream processes
    "bawbel_gate/mux/transport.py": {"subprocess"},  # starts the upstream MCP servers
    "bawbel_gate/ops/otel.py": {"opentelemetry"},  # the optional OTLP exporter (`ops` extra)
}

# A phrase the README section must contain for each file above.
DOCUMENTED_AS = {
    "bawbel_gate/cli.py": "bawbel-gate enroll",
    "bawbel_gate/console/server.py": "serve --console",
    "bawbel_gate/hub/server.py": "hub serve",
    "bawbel_gate/mux/proxy.py": "upstream MCP servers",
    "bawbel_gate/mux/transport.py": "upstream MCP servers",
    "bawbel_gate/ops/otel.py": "OTEL_EXPORTER_OTLP_ENDPOINT",
}


def find_network_imports(src_root: Path = SRC_ROOT) -> dict[str, set[str]]:
    """File (relative to src_root) -> the NETWORK_MODULES it imports, anywhere in the file."""
    files = sorted(src_root.rglob("*.py"))
    assert files, f"no .py files under {src_root}: the scan would pass without scanning"
    found: dict[str, set[str]] = {}
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for name in names:
                for module in NETWORK_MODULES:
                    if name == module or name.startswith(module + "."):
                        found.setdefault(path.relative_to(src_root).as_posix(), set()).add(module)
    return found


def _readme_section() -> str:
    text = README.read_text(encoding="utf-8")
    match = re.search(r"^## Network behavior\n(.*?)(?=^## )", text, re.DOTALL | re.MULTILINE)
    assert match, "README.md has no '## Network behavior' section"
    return match.group(1)


class TestTheDocumentedSurfaceMatchesTheCode:
    def test_the_modules_that_can_reach_the_network_are_exactly_the_documented_list(self):
        assert find_network_imports() == EXPECTED, (
            "The set of modules under src/ that can open or accept network connections "
            "changed. Update EXPECTED and the README 'Network behavior' section together, "
            "and say in the pull request what the new code connects to."
        )

    def test_every_file_in_the_list_is_described_in_the_readme_section(self):
        section = _readme_section()
        missing = sorted({p for p in DOCUMENTED_AS.values() if p not in section})
        assert not missing, f"README 'Network behavior' does not mention: {missing}"

    def test_documented_as_covers_every_expected_file(self):
        assert set(DOCUMENTED_AS) == set(EXPECTED)


class TestTheScan:
    def _tree(self, root: Path, files: dict[str, str]) -> Path:
        src = root / "src"
        for rel, content in files.items():
            target = src / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return src

    def test_it_finds_an_import_inside_a_function(self, tmp_path):
        src = self._tree(tmp_path, {"pkg/a.py": "def f():\n    import urllib.request as r\n"})
        assert find_network_imports(src) == {"pkg/a.py": {"urllib.request"}}

    @pytest.mark.parametrize(
        ("line", "module"),
        [
            ("import socket", "socket"),
            ("from urllib import request", "urllib.request"),
            ("from http import client", "http.client"),
            ("from http.server import HTTPServer", "http.server"),
            ("import requests", "requests"),
            ("from opentelemetry.sdk.trace import TracerProvider", "opentelemetry"),
        ],
    )
    def test_it_finds_each_import_form(self, tmp_path, line, module):
        src = self._tree(tmp_path, {"pkg/a.py": line + "\n"})
        assert find_network_imports(src) == {"pkg/a.py": {module}}

    def test_it_ignores_modules_that_do_not_connect(self, tmp_path):
        src = self._tree(
            tmp_path,
            {"pkg/a.py": "import urllib.parse, urllib.error, json\nimport socketstuff\n"},
        )
        assert find_network_imports(src) == {}

    def test_a_tree_with_no_python_files_is_an_error_not_a_pass(self, tmp_path):
        (tmp_path / "src").mkdir()
        with pytest.raises(AssertionError, match="no .py files"):
            find_network_imports(tmp_path / "src")
