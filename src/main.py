"""
hc-maestro GitHub Action — main entry point.

Orchestrates: diff extraction → MAESTRO threat analysis → SARIF output → PR comment.
"""
import base64
import fnmatch
import gzip
import json
import os
import subprocess
import sys

from catalog import load_catalog
from analyze import analyze_diff
from sarif import findings_to_sarif
from comment import findings_to_comment

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def main():
    layers = [int(x.strip()) for x in os.environ.get("HC_LAYERS", "3,4").split(",")]
    severity_threshold = os.environ.get("HC_SEVERITY_THRESHOLD", "medium")
    sarif_output = os.environ.get("HC_SARIF_OUTPUT", "hc-maestro-findings.sarif")
    post_comment = os.environ.get("HC_POST_PR_COMMENT", "true").lower() == "true"
    fail_on_severity = os.environ.get("HC_FAIL_ON_SEVERITY", "high")
    spec_path = os.environ.get("HC_SPEC_PATH", "").strip() or None
    suppressions_path = os.environ.get("HC_SUPPRESSIONS_PATH", ".maestro-suppressions.yml")

    print("[hc-maestro] Loading threat catalog...")
    catalog = load_catalog(spec_path=spec_path, layers=layers)
    print(f"[hc-maestro] Loaded {len(catalog)} threats (layers {layers})")

    print("[hc-maestro] Extracting PR diff...")
    diff = _get_pr_diff()
    if not diff.strip():
        print("[hc-maestro] No diff found. Nothing to analyze.")
        _write_sarif(sarif_output, [], catalog)
        _write_step_outputs(sarif_output, [])
        return

    print(f"[hc-maestro] Analyzing {len(diff):,} chars of diff against {len(catalog)} threats...")
    findings = analyze_diff(diff=diff, catalog=catalog, layers=layers)
    print(f"[hc-maestro] Raw findings: {len(findings)}")

    # Acknowledged baseline: matching findings are excluded from the gate but still
    # reported (with their reason) in the PR comment — an auditable accept, not a mask.
    suppressions = _load_suppressions(suppressions_path)
    findings, suppressed = _partition_suppressed(findings, suppressions)
    if suppressed:
        print(
            f"[hc-maestro] Suppressed {len(suppressed)} finding(s) via "
            f"'{suppressions_path}' (acknowledged; excluded from the gate)."
        )

    threshold_idx = (
        _SEVERITY_ORDER.index(severity_threshold)
        if severity_threshold in _SEVERITY_ORDER else 99
    )
    filtered = [
        f for f in findings
        if _SEVERITY_ORDER.index(f.get("severity", "informational")) <= threshold_idx
    ]
    print(f"[hc-maestro] Findings at or above '{severity_threshold}': {len(filtered)}")

    _write_sarif(sarif_output, filtered, catalog)
    _upload_sarif(sarif_output)

    if post_comment:
        pr_desc = _get_pr_description()
        if filtered:
            comment = findings_to_comment(filtered, catalog, pr_desc=pr_desc)
        else:
            comment = (
                f"### hc-maestro Threat Analysis\n\n"
                f"✅ No MAESTRO threats detected at or above `{severity_threshold}` severity."
            )
        if suppressed:
            comment += _suppressed_section(suppressed)
        _post_pr_comment(comment)

    _write_step_outputs(sarif_output, filtered)

    critical_n = sum(1 for f in filtered if f.get("severity") == "critical")
    high_n = sum(1 for f in filtered if f.get("severity") == "high")

    print(f"\n[hc-maestro] Complete. {len(filtered)} findings ({critical_n} critical, {high_n} high).")

    if fail_on_severity != "none":
        fail_idx = (
            _SEVERITY_ORDER.index(fail_on_severity)
            if fail_on_severity in _SEVERITY_ORDER else 99
        )
        blockers = [
            f for f in filtered
            if _SEVERITY_ORDER.index(f.get("severity", "informational")) <= fail_idx
        ]
        if blockers:
            print(
                f"[hc-maestro] FAILED: {len(blockers)} finding(s) at or above "
                f"fail-on-severity='{fail_on_severity}'."
            )
            sys.exit(1)


def _load_suppressions(path):
    """Load an acknowledged-findings baseline. Each entry requires threat_id + reason."""
    if not path or not os.path.exists(path):
        return []
    try:
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[hc-maestro] Could not read suppressions '{path}': {e}")
        return []
    if isinstance(data, dict):
        entries = data.get("suppressions", [])
    elif isinstance(data, list):
        entries = data
    else:
        entries = []
    valid = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        if not e.get("threat_id") or not e.get("reason"):
            print(f"[hc-maestro] Ignoring suppression without threat_id + reason: {e}")
            continue
        valid.append(e)
    return valid


def _matching_suppression(finding, suppressions):
    for s in suppressions:
        if s.get("threat_id") != finding.get("threat_id"):
            continue
        file_glob = s.get("file")
        if file_glob and not fnmatch.fnmatch(finding.get("file", ""), file_glob):
            continue
        return s
    return None


def _partition_suppressed(findings, suppressions):
    """Split findings into (active, suppressed) using the baseline."""
    if not suppressions:
        return findings, []
    active, suppressed = [], []
    for f in findings:
        match = _matching_suppression(f, suppressions)
        if match:
            suppressed.append({**f, "_reason": match["reason"]})
        else:
            active.append(f)
    return active, suppressed


def _suppressed_section(suppressed):
    """Markdown section listing acknowledged findings + reasons (auditable, not hidden)."""
    lines = [
        "",
        "---",
        "",
        f"#### 🔕 Suppressed (acknowledged) — {len(suppressed)}",
        "",
        "Excluded from the gate via the suppressions baseline:",
        "",
    ]
    for f in suppressed:
        tid = f.get("threat_id", "")
        sev = f.get("severity", "informational")
        loc = f.get("file", "")
        line = f.get("line", "")
        title = f.get("title", "")
        reason = str(f.get("_reason", "")).strip()
        lines.append(f"- **{tid}** ({sev}) `{loc}:{line}` — {title}")
        lines.append(f"  - _Reason:_ {reason}")
    return "\n".join(lines)


def _get_pr_diff():
    base = os.environ.get("GITHUB_BASE_REF", "")
    if base:
        try:
            result = subprocess.run(
                ["git", "diff", f"origin/{base}...HEAD"],
                capture_output=True, text=True, check=True
            )
            if result.stdout.strip():
                return result.stdout
        except subprocess.CalledProcessError:
            pass

    try:
        result = subprocess.run(
            ["git", "diff", "HEAD~1"],
            capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[hc-maestro] Warning: could not extract diff: {e}")
        return ""


def _get_pr_description():
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path or not os.path.exists(event_path):
        return ""
    try:
        with open(event_path) as f:
            event = json.load(f)
        pr = event.get("pull_request", {})
        title = pr.get("title", "")
        body = pr.get("body", "") or ""
        return f"{title}\n\n{body}".strip()
    except Exception:
        return ""


def _post_pr_comment(comment_text):
    import requests

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")

    if not all([token, repo, event_path]) or not os.path.exists(event_path):
        print("[hc-maestro] Skipping PR comment: missing token, repo, or event file")
        return

    try:
        with open(event_path) as f:
            event = json.load(f)
        pr_number = event.get("pull_request", {}).get("number")
    except Exception:
        pr_number = None

    if not pr_number:
        print("[hc-maestro] Skipping PR comment: not in a PR context")
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        resp = requests.post(url, headers=headers, json={"body": comment_text}, timeout=30)
        if resp.status_code in (200, 201):
            print(f"[hc-maestro] PR comment posted: {resp.json().get('html_url', '')}")
        else:
            print(f"[hc-maestro] PR comment failed: {resp.status_code}")
    except Exception as e:
        print(f"[hc-maestro] PR comment error: {e}")


def _write_sarif(sarif_output, findings, catalog):
    import json as _json
    sarif_doc = findings_to_sarif(findings, catalog)
    with open(sarif_output, "w") as f:
        _json.dump(sarif_doc, f, indent=2)
    print(f"[hc-maestro] SARIF written: {sarif_output}")


def _upload_sarif(sarif_path):
    import requests

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    ref = os.environ.get("GITHUB_REF", "refs/heads/main")

    if not all([token, repo, sha]):
        return

    try:
        with open(sarif_path, "rb") as f:
            sarif_bytes = f.read()
        encoded = base64.b64encode(gzip.compress(sarif_bytes)).decode()

        url = f"https://api.github.com/repos/{repo}/code-scanning/sarifs"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        resp = requests.post(
            url, headers=headers,
            json={"commit_sha": sha, "ref": ref, "sarif": encoded, "tool_name": "hc-maestro"},
            timeout=30,
        )
        if resp.status_code in (200, 201, 202):
            print("[hc-maestro] SARIF uploaded to Code Scanning")
        elif resp.status_code == 403:
            print("[hc-maestro] SARIF upload skipped: Code Security not enabled (requires GitHub Advanced Security or public repo)")
        else:
            print(f"[hc-maestro] SARIF upload response: {resp.status_code}")
    except Exception as e:
        print(f"[hc-maestro] SARIF upload error: {e}")


def _write_step_outputs(sarif_path, findings):
    output_file = os.environ.get("GITHUB_OUTPUT", "")
    if not output_file:
        return
    critical_n = sum(1 for f in findings if f.get("severity") == "critical")
    high_n = sum(1 for f in findings if f.get("severity") == "high")
    with open(output_file, "a") as f:
        f.write(f"sarif-path={os.path.abspath(sarif_path)}\n")
        f.write(f"finding-count={len(findings)}\n")
        f.write(f"critical-count={critical_n}\n")
        f.write(f"high-count={high_n}\n")


if __name__ == "__main__":
    main()
