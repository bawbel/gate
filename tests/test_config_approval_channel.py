"""GATE-33b: an approval channel that is not implemented is refused, not ignored.

`approval.channel` accepted `webhook` and `slack`, and nothing read them: the gate started and
handled approvals as if `terminal` had been set. A gate that silently ignores an approval
channel is the defect. These tests were committed failing, before the change.

Decided by the maintainer on 2026-11-26 (option R in #235): refuse to start with a config error.
A non-null `webhook_url` with the terminal channel is accepted and warns on stderr.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from bawbel_gate.cli import main
from bawbel_gate.mux.config import ApprovalConfig, ConfigError, load_config

SECRET_URL = "https://hooks.example.invalid/services/T000/B000/s3cretvalue"


def _write(tmp_path: Path, approval_block: str) -> Path:
    (tmp_path / "m.cap.yaml").write_text("placeholder", encoding="utf-8")
    path = tmp_path / "gate.yaml"
    path.write_text(
        "schema: bawbel/gate-config/v1\n"
        f"{approval_block}"
        "servers:\n  - name: a\n    command: x\n    args: []\n    manifest: m.cap.yaml\n",
        encoding="utf-8",
    )
    return path


class TestAChannelThatIsNotImplementedIsRefused:
    @pytest.mark.parametrize("channel", ["webhook", "slack"])
    def test_load_config_refuses_it_and_says_what_is_available(self, tmp_path, channel):
        path = _write(tmp_path, f"approval:\n  channel: {channel}\n")
        with pytest.raises(ConfigError) as exc:
            load_config(path)
        message = str(exc.value)
        assert channel in message
        assert "not implemented" in message
        assert "terminal" in message

    @pytest.mark.parametrize("channel", ["webhook", "slack"])
    def test_the_dataclass_refuses_it_too(self, channel):
        with pytest.raises(ConfigError, match="not implemented"):
            ApprovalConfig(channel=channel)

    def test_terminal_is_still_accepted(self, tmp_path):
        cfg = load_config(_write(tmp_path, "approval:\n  channel: terminal\n"))
        assert cfg.approval.channel == "terminal"

    def test_the_default_is_still_terminal(self, tmp_path):
        assert load_config(_write(tmp_path, "")).approval.channel == "terminal"

    def test_an_unknown_channel_is_still_refused_with_its_own_message(self, tmp_path):
        """A control: this is refused today, and the message for it does not change."""
        with pytest.raises(ConfigError, match="must be terminal"):
            load_config(_write(tmp_path, "approval:\n  channel: pagerduty\n"))

    @pytest.mark.parametrize("channel", ["webhook", "slack"])
    def test_serve_stops_with_a_config_error_and_exit_1(self, tmp_path, channel):
        path = _write(tmp_path, f"approval:\n  channel: {channel}\n")
        result = CliRunner().invoke(main, ["serve", "--config", str(path)])
        assert result.exit_code == 1
        assert "config error" in result.output
        assert "not implemented" in result.output
        assert "enforcement mode active" not in result.output


class TestAWebhookUrlWithTheTerminalChannelWarns:
    def test_it_loads_and_warns_on_stderr(self, tmp_path, capsys):
        path = _write(
            tmp_path, f"approval:\n  channel: terminal\n  webhook_url: {SECRET_URL}\n"
        )
        cfg = load_config(path)
        assert cfg.approval.channel == "terminal"
        err = capsys.readouterr().err
        assert "warning" in err
        assert "webhook_url" in err

    def test_the_warning_never_contains_the_url(self, tmp_path, capsys):
        path = _write(
            tmp_path, f"approval:\n  channel: terminal\n  webhook_url: {SECRET_URL}\n"
        )
        load_config(path)
        captured = capsys.readouterr()
        assert "s3cretvalue" not in captured.err
        assert "s3cretvalue" not in captured.out
        assert "hooks.example.invalid" not in captured.err

    def test_no_url_no_warning(self, tmp_path, capsys):
        load_config(_write(tmp_path, "approval:\n  channel: terminal\n"))
        load_config(_write(tmp_path, "approval:\n  channel: terminal\n  webhook_url: null\n"))
        assert capsys.readouterr().err == ""

    def test_a_webhook_url_does_not_make_a_webhook_channel_acceptable(self, tmp_path):
        path = _write(
            tmp_path, f"approval:\n  channel: webhook\n  webhook_url: {SECRET_URL}\n"
        )
        with pytest.raises(ConfigError, match="not implemented") as exc:
            load_config(path)
        assert "s3cretvalue" not in str(exc.value)
