"""gate.yaml config loader and validated config dataclasses.

Schema per DESIGN.md 3.1. Fails fast on validation errors — the gate
never starts with a broken config.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bawbel_gate._const import (
    APPROVAL_TIMEOUT_DEFAULT_S,
    EFFECT_DENY,
    SCHEMA_GATE_CONFIG_V1,
)


@dataclass(frozen=True)
class ServerConfig:
    name: str
    command: str
    args: list[str]
    manifest: Path


@dataclass(frozen=True)
class ApprovalConfig:
    channel: str = "terminal"
    webhook_url: str | None = None
    timeout_seconds: int = APPROVAL_TIMEOUT_DEFAULT_S
    on_timeout: str = EFFECT_DENY   # fail-closed; only valid value

    def __post_init__(self) -> None:
        if self.channel not in ("terminal", "webhook", "slack"):
            raise ConfigError(
                f"approval.channel must be terminal|webhook|slack, got {self.channel!r}"
            )
        if self.on_timeout != EFFECT_DENY:
            raise ConfigError("approval.on_timeout must be 'deny'; fail-open is not supported")
        if self.timeout_seconds < 5 or self.timeout_seconds > 3600:
            raise ConfigError(
                f"approval.timeout_seconds must be 5..3600, got {self.timeout_seconds}"
            )


@dataclass(frozen=True)
class GateConfig:
    audit_log: Path
    servers: list[ServerConfig]
    approval: ApprovalConfig = field(default_factory=ApprovalConfig)

    def __post_init__(self) -> None:
        if not self.servers:
            raise ConfigError("gate.yaml must define at least one server")
        names = [s.name for s in self.servers]
        if len(names) != len(set(names)):
            raise ConfigError(f"duplicate server names in gate.yaml: {names}")


class ConfigError(ValueError):
    """Raised when gate.yaml fails schema or semantic validation."""


def load_config(path: Path) -> GateConfig:
    """Parse and validate gate.yaml. Raises ConfigError on any problem."""
    raw = _read_yaml(path)
    _check_schema_id(raw)
    approval = _parse_approval(raw.get("approval", {}))
    servers = _parse_servers(raw.get("servers", []), path.parent)
    audit = Path(raw.get("audit_log", "gate.audit.jsonl"))
    return GateConfig(audit_log=audit, servers=servers, approval=approval)


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"gate.yaml parse error: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("gate.yaml must be a YAML mapping")
    return data


def _check_schema_id(raw: dict[str, Any]) -> None:
    got = raw.get("schema")
    if got != SCHEMA_GATE_CONFIG_V1:
        raise ConfigError(
            f"gate.yaml schema must be {SCHEMA_GATE_CONFIG_V1!r}, got {got!r}"
        )


def _parse_approval(raw: dict[str, Any]) -> ApprovalConfig:
    return ApprovalConfig(
        channel=raw.get("channel", "terminal"),
        webhook_url=raw.get("webhook_url"),
        timeout_seconds=int(raw.get("timeout_seconds", APPROVAL_TIMEOUT_DEFAULT_S)),
        on_timeout=raw.get("on_timeout", EFFECT_DENY),
    )


def _parse_servers(raw: list[Any], config_dir: Path) -> list[ServerConfig]:
    if not isinstance(raw, list):
        raise ConfigError("gate.yaml 'servers' must be a list")
    servers = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ConfigError(f"each server entry must be a mapping, got {type(entry)}")
        try:
            manifest_path = Path(entry["manifest"])
            if not manifest_path.is_absolute():
                manifest_path = config_dir / manifest_path
            servers.append(ServerConfig(
                name=entry["name"],
                command=entry["command"],
                args=entry.get("args", []),
                manifest=manifest_path,
            ))
        except KeyError as exc:
            raise ConfigError(f"server entry missing required field: {exc}") from exc
    return servers
