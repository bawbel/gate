"""bawbel-gate CLI entry point. See DESIGN.md 11.5 for the full command surface."""

from __future__ import annotations

import sys
from pathlib import Path

import click



@click.group()
@click.version_option(package_name="bawbel-gate")
def main() -> None:
    """bawbel-gate: runtime enforcement proxy for MCP agents."""


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

@main.command()
@click.option("--config", "-c", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to gate.yaml.")
@click.option("--learn", "learn_mode", is_flag=True, default=False,
              help="Observe-only mode: enforce nothing, record everything.")
def serve(config: Path, learn_mode: bool) -> None:
    """Start the gate proxy (or in learning mode, a transparent recorder)."""
    from bawbel_gate.mux.config import load_config, ConfigError
    try:
        cfg = load_config(config)
    except ConfigError as exc:
        click.echo(f"bawbel-gate: config error: {exc}", err=True)
        sys.exit(1)

    if learn_mode:
        click.echo("bawbel-gate: learning mode active — enforcing NOTHING, recording everything")
        _run_learn_serve(cfg)
    else:
        click.echo("bawbel-gate: enforcement mode active")
        _run_enforce_serve(cfg)


def _run_learn_serve(cfg) -> None:  # type: ignore[no-untyped-def]
    """Transparent proxy with learning recorder. Full multiplexer in M1."""
    click.echo("bawbel-gate: [learn] proxy started (M1 multiplexer wires this up)")


def _run_enforce_serve(cfg) -> None:  # type: ignore[no-untyped-def]
    """Full enforcement proxy. Wired up in M2."""
    click.echo("bawbel-gate: [enforce] proxy started (M2 enforcement wires this up)")


# ---------------------------------------------------------------------------
# learn subgroup
# ---------------------------------------------------------------------------

@main.group("learn")
def learn_group() -> None:
    """Learning mode commands."""


@learn_group.command("report")
@click.option("--obs", default="learn.observations.jsonl", type=click.Path(path_type=Path),
              help="Observations JSONL file written by learning mode.")
def learn_report(obs: Path) -> None:
    """Print per-server tool usage report from learning mode observations."""
    from bawbel_gate.learn.report import render_report
    render_report(obs, sys.stdout)


@learn_group.command("synthesize")
@click.option("--obs", default="learn.observations.jsonl", type=click.Path(path_type=Path),
              help="Observations JSONL file.")
@click.option("--out", required=True, type=click.Path(file_okay=False, path_type=Path),
              help="Output directory for draft manifests.")
def learn_synthesize(obs: Path, out: Path) -> None:
    """Generate draft capability manifests from learning mode observations."""
    from bawbel_gate.learn.synthesize import synthesize_manifests
    synthesize_manifests(obs, out)


# ---------------------------------------------------------------------------
# audit subgroup
# ---------------------------------------------------------------------------

@main.group("audit")
def audit_group() -> None:
    """Audit log commands."""


@audit_group.command("verify")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
def audit_verify(file: Path) -> None:
    """Verify hash chain integrity of an audit log file."""
    from bawbel_gate.audit.writer import verify_chain
    result = verify_chain(file)
    if result.ok:
        click.echo(f"ok: {result.records} records, chain intact")
        click.echo(f"chain verified: {file}")
    else:
        click.echo(f"FAIL: {result.error}", err=True)
        sys.exit(1)


@audit_group.command("tail")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--follow", "-f", is_flag=True, default=False,
              help="Follow log (like tail -f).")
@click.option("--lines", "-n", default=20, show_default=True)
def audit_tail(file: Path, follow: bool, lines: int) -> None:
    """Print the last N records from an audit log."""
    import time
    all_lines = file.read_text(encoding="utf-8").splitlines()
    for line in all_lines[-lines:]:
        if line.strip():
            click.echo(line)
    if follow:
        with file.open(encoding="utf-8") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if line:
                    click.echo(line.rstrip())
                else:
                    time.sleep(0.1)


# ---------------------------------------------------------------------------
# clear
# ---------------------------------------------------------------------------

@main.command("clear")
@click.option("--session", required=True, help="Session ID to clear.")
@click.option("--confirm", is_flag=True, required=True,
              help="Required explicit confirmation flag.")
@click.option("--audit-log", default="bawbel-audit.jsonl", type=click.Path(path_type=Path),
              help="Audit log file to append the SESSION_CLEAR record to.")
def clear_session(session: str, confirm: bool, audit_log: Path) -> None:
    """Reset taint for a session (operator action, audited). See DESIGN.md 6.1."""
    import datetime
    from bawbel_gate.audit.writer import AuditWriter
    from bawbel_gate._const import EVENT_SESSION_CLEAR

    if not confirm:
        click.echo("bawbel-gate: --confirm flag required for SESSION_CLEAR", err=True)
        sys.exit(1)

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    writer = AuditWriter.from_existing(audit_log)
    record_hash = writer.append({
        "ts": ts,
        "event": EVENT_SESSION_CLEAR,
        "session": session,
        "operator": "cli",
    })
    click.echo(f"bawbel-gate: SESSION_CLEAR written for session {session}")
    click.echo(f"  audit record: {record_hash}")
    click.echo(f"  log: {audit_log}")


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------

@main.command("lint")
@click.argument("manifest_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--schema", default="capability-manifest/v1", show_default=True)
@click.option("--forbid-effect", default=None,
              help="Fail if any grant has this effect (e.g. 'allow' for prod check).")
@click.option("--tools-with", default=None,
              help="Scope --forbid-effect to tools with this trifecta flag.")
def lint(
    manifest_dir: Path, schema: str, forbid_effect: str | None, tools_with: str | None
) -> None:
    """Validate manifests in MANIFEST_DIR against the capability-manifest schema."""
    import yaml as _yaml
    from bawbel_gate._schemas import schema_capability_manifest
    import jsonschema

    cap_schema = schema_capability_manifest()
    validator = jsonschema.Draft202012Validator(cap_schema)
    errors_found = False

    for manifest_file in sorted(manifest_dir.rglob("*.yaml")):
        raw = _yaml.safe_load(manifest_file.read_text(encoding="utf-8"))
        errs = list(validator.iter_errors(raw))
        if errs:
            errors_found = True
            click.echo(f"FAIL {manifest_file.name}: {len(errs)} schema error(s)")
            for e in errs:
                click.echo(f"  {e.json_path}: {e.message}")
            continue

        if forbid_effect:
            for grant in raw.get("grants", {}).get("tools", []):
                if (
                    grant.get("effect") == forbid_effect
                    and (tools_with is None or raw.get("trifecta", {}).get(tools_with))
                ):
                    click.echo(
                        f"FAIL {manifest_file.name}: grant '{grant['name']}'"
                        f" has forbidden effect '{forbid_effect}'"
                    )
                    errors_found = True
                    break
            else:
                click.echo(f"ok   {manifest_file.name}")
        else:
            click.echo(f"ok   {manifest_file.name}")

    if errors_found:
        sys.exit(1)


# ---------------------------------------------------------------------------
# harden (stub — implemented in M3)
# ---------------------------------------------------------------------------

@main.command("harden")
@click.option("--ave", "ave_id", required=True, help="AVE ID to harden against.")
@click.option("--manifest", default=None, type=click.Path(path_type=Path),
              help="Target manifest file to merge into.")
@click.option("--allow-unreviewed", is_flag=True, default=False,
              help="Proceed even if the stanza review_status is not 'reviewed'.")
def harden(ave_id: str, manifest: Path | None, allow_unreviewed: bool) -> None:
    """Merge an AVE mitigation stanza into a capability manifest. Implemented in M3."""
    click.echo(f"bawbel-gate: harden --ave {ave_id} (implemented in M3)")
