"""Shared pytest fixtures for all test modules."""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas"
CORPUS_DIR = REPO_ROOT / "tests" / "corpus"
AVE_V1_1 = CORPUS_DIR / "ave" / "v1_1"
AVE_V1_2 = CORPUS_DIR / "ave" / "v1_2"


@pytest.fixture(scope="session")
def schema_dir() -> Path:
    return SCHEMA_DIR


@pytest.fixture(scope="session")
def ave_12_schema(schema_dir: Path) -> dict:
    return json.loads((schema_dir / "ave-1.2.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def cap_manifest_schema(schema_dir: Path) -> dict:
    return json.loads((schema_dir / "capability-manifest-v1.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def ave_mitigations_schema(schema_dir: Path) -> dict:
    return json.loads((schema_dir / "bawbel-ave-mitigations-v1.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def ave_v1_1_records() -> dict[str, dict]:
    return {
        p.stem: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(AVE_V1_1.glob("*.json"))
    }


@pytest.fixture(scope="session")
def ave_v1_2_records() -> dict[str, dict]:
    return {
        p.stem: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(AVE_V1_2.glob("*.json"))
    }
