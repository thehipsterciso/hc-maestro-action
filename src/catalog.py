"""
Loads and indexes the maestro-spec.yaml threat catalog.
"""
import yaml
from pathlib import Path

_BUNDLED_SPEC = Path(__file__).parent.parent / "maestro-spec.yaml"


def load_catalog(spec_path=None, layers=None):
    """
    Load threats from maestro-spec.yaml.

    spec_path: path to a custom spec YAML; None uses the bundled spec.
    layers: list of int layer IDs to include; None includes all layers.
    Returns list of threat dicts.
    """
    path = Path(spec_path) if spec_path else _BUNDLED_SPEC
    if not path.exists():
        raise FileNotFoundError(
            f"maestro-spec.yaml not found at {path}. "
            "Provide HC_SPEC_PATH or ensure the bundled spec is present."
        )

    with open(path) as f:
        spec = yaml.safe_load(f)

    threats = spec.get("threats", [])
    if layers is not None:
        threats = [t for t in threats if t.get("layer") in layers]

    return threats


def get_threat_by_id(catalog, threat_id):
    """Return a single threat dict by ID, or None if not found."""
    for t in catalog:
        if t.get("id") == threat_id:
            return t
    return None


def catalog_summary(catalog):
    """
    Return a compact string summary of the catalog for LLM context injection.
    Each line: ID [SEVERITY] Name: description (first 220 chars).
    """
    lines = []
    for t in catalog:
        desc = t.get("description", "").replace("\n", " ").strip()[:220]
        lines.append(
            f"{t['id']} [{t['severity'].upper()}] {t['name']}: {desc}"
        )
    return "\n".join(lines)
