from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

TEMPLATE_DIR = Path("templates")
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
REQUIRED_FIELDS = ["id", "name", "severity"]


def load_templates():
    files = sorted(TEMPLATE_DIR.rglob("*.yaml")) + sorted(TEMPLATE_DIR.rglob("*.yml"))
    return [(f, yaml.safe_load(f.read_text())) for f in files]


TEMPLATES = load_templates()
IDS = [str(path) for path, _ in TEMPLATES]


def test_templates_are_found():
    assert len(TEMPLATES) > 0


@pytest.mark.parametrize("path,data", TEMPLATES, ids=IDS)
def test_template_has_required_fields(path, data):
    assert isinstance(data, dict), f"{path} is not a YAML mapping"
    for field in REQUIRED_FIELDS:
        assert field in data, f"{path} is missing '{field}'"


@pytest.mark.parametrize("path,data", TEMPLATES, ids=IDS)
def test_template_severity_is_valid(path, data):
    assert str(data.get("severity")).upper() in VALID_SEVERITIES


def test_template_ids_are_unique():
    ids = [data["id"] for _, data in TEMPLATES if isinstance(data, dict) and "id" in data]
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, f"Duplicate template IDs: {duplicates}"


def test_no_template_is_missing_its_yaml_extension():
    for f in TEMPLATE_DIR.rglob("*"):
        if f.is_file() and f.suffix not in (".yaml", ".yml", ".gitkeep"):
            try:
                text = f.read_text()
            except UnicodeDecodeError:
                continue
            assert not text.startswith("id:"), f"{f} looks like a template but has no .yaml extension"
