"""Schema loading utilities.

All JSON Schemas live in the top-level schemas/ directory. Load them via
load_schema() rather than constructing paths or reading files inline.
Override the directory at runtime with the BAWBEL_SCHEMAS_DIR env var.
"""

import json
import os
from functools import lru_cache
from pathlib import Path

from bawbel_gate._const import (
    SCHEMA_FILE_AVE_12,
    SCHEMA_FILE_AVE_MITIGATIONS,
    SCHEMA_FILE_CAPABILITY_MANIFEST,
)

# Two levels up from src/bawbel_gate/ -> repo root -> schemas/
_DEFAULT_SCHEMA_DIR = Path(__file__).parent.parent.parent / "schemas"
SCHEMAS_DIR = Path(os.environ.get("BAWBEL_SCHEMAS_DIR", _DEFAULT_SCHEMA_DIR))


@lru_cache(maxsize=16)
def load_schema(filename: str) -> dict:
    """Load and cache a JSON Schema by filename from SCHEMAS_DIR."""
    path = SCHEMAS_DIR / filename
    return json.loads(path.read_text(encoding="utf-8"))


def schema_ave_12() -> dict:
    return load_schema(SCHEMA_FILE_AVE_12)


def schema_capability_manifest() -> dict:
    return load_schema(SCHEMA_FILE_CAPABILITY_MANIFEST)


def schema_ave_mitigations() -> dict:
    return load_schema(SCHEMA_FILE_AVE_MITIGATIONS)
