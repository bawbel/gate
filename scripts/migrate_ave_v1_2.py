"""migrate_ave_v1_2.py - Migrate AVE records from schema 1.1 to 1.2.

Null-insert migration per DESIGN.md 9.2:
  - Bumps schema_version to "1.2"
  - Adds provenance_vector, trifecta_profile, capability_mitigation as null
  - Adds triage.provenance = "unclassified" if absent
  - Validates each output record against ave-1.2.json
  - Idempotent: skips records already at 1.2 unless --force
  - Output is git-diffable (2-space indent, LF, trailing newline)

Usage:
    python scripts/migrate_ave_v1_2.py --in records/ --out records/
    python scripts/migrate_ave_v1_2.py --in records/ --out records/ \
        --schema schemas/ave-1.2.json --force
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import jsonschema

# Fields added by the 1.2 migration, in insertion order
_NEW_FIELDS: tuple[str, ...] = (
    "provenance_vector",
    "trifecta_profile",
    "capability_mitigation",
)

_TARGET_VERSION = "1.2"
_SOURCE_VERSION = "1.1"


def migrate_record(record: dict) -> tuple[dict, bool]:
    """Return (migrated_record, was_changed).

    Idempotent: if schema_version is already 1.2 and all new fields present,
    returns the record unchanged and was_changed=False.
    """
    version = record.get("schema_version")
    already_migrated = (
        version == _TARGET_VERSION
        and all(k in record for k in _NEW_FIELDS)
        and "provenance" in record.get("triage", {})
    )
    if already_migrated:
        return record, False

    out = dict(record)
    out["schema_version"] = _TARGET_VERSION

    triage = dict(out.get("triage", {}))
    if "provenance" not in triage:
        triage["provenance"] = "unclassified"
    out["triage"] = triage

    for field in _NEW_FIELDS:
        if field not in out:
            out[field] = None

    return out, True


def validate_record(record: dict, schema: dict) -> None:
    """Validate record against the given JSON Schema. Raises ValidationError on failure."""
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(record), key=lambda e: list(e.path))
    if errors:
        raise jsonschema.ValidationError(
            f"{len(errors)} validation error(s):\n"
            + "\n".join(f"  {e.json_path}: {e.message}" for e in errors)
        )


def _load_schema(schema_path: Path) -> dict:
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _dump_record(record: dict) -> str:
    return json.dumps(record, indent=2, ensure_ascii=False) + "\n"


@click.command()
@click.option(
    "--in", "in_dir",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Directory containing AVE record JSON files.",
)
@click.option(
    "--out", "out_dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Output directory (may be the same as --in for in-place migration).",
)
@click.option(
    "--schema",
    "schema_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to ave-1.2.json (default: schemas/ave-1.2.json relative to repo root).",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Re-migrate records already at schema 1.2.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate and report without writing any files.",
)
def migrate(
    in_dir: Path,
    out_dir: Path,
    schema_path: Path | None,
    force: bool,
    dry_run: bool,
) -> None:
    """Migrate AVE records from schema 1.1 to 1.2."""
    if schema_path is None:
        schema_path = Path(__file__).parent.parent / "schemas" / "ave-1.2.json"
    if not schema_path.exists():
        click.echo(f"error: schema not found: {schema_path}", err=True)
        sys.exit(1)

    schema = _load_schema(schema_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    records = sorted(in_dir.glob("*.json"))
    if not records:
        click.echo(f"warning: no .json files found in {in_dir}", err=True)
        sys.exit(0)

    migrated = skipped = errors = 0

    for src in records:
        raw = src.read_text(encoding="utf-8")
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            click.echo(f"error: {src.name}: invalid JSON: {exc}", err=True)
            errors += 1
            continue

        if record.get("schema_version") == _TARGET_VERSION and not force:
            click.echo(f"skip  {src.name} (already 1.2; use --force to re-migrate)")
            skipped += 1
            continue

        try:
            out_record, changed = migrate_record(record)
            validate_record(out_record, schema)
        except jsonschema.ValidationError as exc:
            click.echo(f"error: {src.name}: validation failed: {exc.message}", err=True)
            errors += 1
            continue

        dest = out_dir / src.name
        content = _dump_record(out_record)
        if not dry_run:
            dest.write_text(content, encoding="utf-8", newline="\n")

        action = "migrate" if changed else "rewrite"
        flag = " (dry-run)" if dry_run else ""
        click.echo(f"{action} {src.name}{flag}")
        migrated += 1

    click.echo(
        f"\ndone: {migrated} migrated, {skipped} skipped, {errors} errors"
        + (" (dry-run, no files written)" if dry_run else "")
    )
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    migrate()
