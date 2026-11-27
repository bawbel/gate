"""The first-run report form, and the README link to it, stay in step.

The form is read as YAML. Nothing is fetched and no network is used.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FORM = REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "first-run-report.yml"
README = REPO_ROOT / "README.md"
LINK = "https://github.com/bawbel/gate/issues/new?template=first-run-report.yml"

# What the maintainer asked the form to collect, by the label on each field.
REQUIRED_LABELS = {
    "Operating system",
    "Python version",
    "bawbel-gate version",
    "MCP client",
    "Install method",
    "The README step where you stopped",
    "Time taken",
    "What broke",
    "What was confusing",
    "May we quote this?",
}


def _fields() -> list[dict]:
    form = yaml.safe_load(FORM.read_text(encoding="utf-8"))
    return [item for item in form["body"] if item["type"] != "markdown"]


def test_the_form_asks_for_every_requested_field_and_each_is_required():
    by_label = {f["attributes"]["label"]: f for f in _fields()}
    missing = REQUIRED_LABELS - set(by_label)
    assert not missing, f"fields missing from the form: {sorted(missing)}"
    for label in REQUIRED_LABELS:
        assert by_label[label].get("validations", {}).get("required") is True, label


def test_the_form_collects_no_email_and_no_telemetry():
    # An email field, or any field that asks for contact details, is not allowed.
    for field in _fields():
        attributes = field["attributes"]
        text = (attributes["label"] + " " + attributes.get("description", "")).lower()
        assert "email" not in text and "e-mail" not in text, field["attributes"]["label"]
        assert "telemetry" not in text, field["attributes"]["label"]
    body = yaml.safe_load(FORM.read_text(encoding="utf-8"))["body"]
    banner = next(item for item in body if item["type"] == "markdown")
    assert "no email field" in banner["attributes"]["value"]


def test_every_field_has_an_id_and_a_label_as_github_requires():
    ids = [f["id"] for f in _fields()]
    assert len(ids) == len(set(ids)), "field ids must be unique"
    for field in _fields():
        assert field["attributes"]["label"].strip()


def test_the_step_options_are_the_readme_headings():
    step = next(f for f in _fields() if f["id"] == "step")
    options = step["attributes"]["options"]
    readme = README.read_text(encoding="utf-8")
    headings = re.findall(r"^### (\d+\. .+)$", readme, flags=re.MULTILINE)
    assert headings, "no numbered step headings found in the README"
    assert "Install" in options
    for heading in headings:
        assert heading in options, f"the README step {heading!r} is not an option in the form"


def test_the_readme_links_to_the_form_in_its_start_section():
    text = README.read_text(encoding="utf-8")
    assert LINK in text
    assert text.index(LINK) < text.index("## Status:"), "the link must be before the Status section"
    assert FORM.name == LINK.rsplit("=", 1)[1]
