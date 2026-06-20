"""
Converts hc-maestro findings to SARIF 2.1.0 format.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

SARIF is the GitHub Code Scanning ingestion format. When uploaded via the
GitHub API or the codeql-action/upload-sarif action, findings appear in the
Security > Code scanning tab and are annotated on the diff.
"""
from catalog import get_threat_by_id

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_TOOL_VERSION = "0.1.0"
_TOOL_URI = "https://github.com/thehipsterciso/hc-maestro-action"
_SPEC_URI = "https://github.com/thehipsterciso/hc-maestro-spec/blob/main/maestro-spec.yaml"

_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "none",
}

_SEVERITY_TO_RANK = {
    "critical": 100.0,
    "high": 80.0,
    "medium": 50.0,
    "low": 25.0,
    "informational": 5.0,
}


def findings_to_sarif(findings, catalog):
    """Convert a findings list to a SARIF 2.1.0 document (dict, JSON-serializable)."""
    rules = _build_rules(findings, catalog)
    results = [_finding_to_result(f, catalog) for f in findings]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hc-maestro",
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _build_rules(findings, catalog):
    seen = set()
    rules = []
    for f in findings:
        tid = f["threat_id"]
        if tid in seen:
            continue
        seen.add(tid)
        threat = get_threat_by_id(catalog, tid)
        if not threat:
            continue

        severity = threat.get("severity", "medium")
        description = threat.get("description", "").replace("\n", " ").strip()
        mitigations = threat.get("mitigations", [])
        help_text = description
        if mitigations:
            help_text += "\n\nMitigations:\n" + "\n".join(f"• {m}" for m in mitigations)

        tags = [f"maestro-layer-{threat.get('layer', '?')}", f"severity/{severity}"]
        tags += [f"stride/{s}" for s in threat.get("stride", [])]
        tags += threat.get("owasp_asi_ids", [])

        rules.append({
            "id": tid,
            "name": _to_pascal_case(threat["name"]),
            "shortDescription": {"text": threat["name"]},
            "fullDescription": {"text": description[:1000]},
            "helpUri": _SPEC_URI,
            "help": {"text": help_text[:3000], "markdown": help_text[:3000]},
            "properties": {
                "tags": tags,
                "security-severity": str(_SEVERITY_TO_RANK.get(severity, 50.0)),
            },
            "defaultConfiguration": {
                "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")
            },
        })
    return rules


def _finding_to_result(finding, catalog):
    tid = finding["threat_id"]
    severity = finding.get("severity", "medium")
    file_path = finding.get("file", "") or "."
    line = max(1, int(finding.get("line", 1) or 1))

    message = finding.get("title", tid)
    description = finding.get("description", "")
    if description:
        message = f"{message}: {description}"

    return {
        "ruleId": tid,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
        "message": {"text": message[:2048]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": line},
                }
            }
        ],
        "properties": {
            "severity": severity,
            "threat_id": tid,
            "evidence": finding.get("evidence", "")[:500],
            "recommendation": finding.get("recommendation", "")[:500],
        },
    }


def _to_pascal_case(name):
    return "".join(
        w.capitalize()
        for w in name.replace("-", " ").replace("/", " ").replace("(", " ").replace(")", " ").split()
    )
