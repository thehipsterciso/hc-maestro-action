"""
LLM-based MAESTRO threat analysis for PR diffs.

Two-pass design (arXiv:2603.18740 — confirmation bias in LLM code review):
  Pass 1: analyze the raw diff before seeing PR description or title.
  Pass 2: reserved for future context-enriched verification pass.

Analyzing diff before PR context prevents the model from rationalizing
the author's stated intent instead of evaluating actual code evidence.
"""
import json
import os

from catalog import catalog_summary

_SEVERITY_LEVELS = {"critical", "high", "medium", "low", "informational"}

_SYSTEM_PROMPT = """\
You are a security analyst applying the MAESTRO threat framework to agentic AI system code changes.
Your job is to identify concrete security threats in git diffs — not theoretical risks.
Only report findings that are directly evidenced by code visible in the diff.
Return valid JSON only. No markdown, no prose outside the JSON array.\
"""

_USER_TEMPLATE = """\
MAESTRO THREAT CATALOG (these are the only valid threat IDs):
{catalog}

INSTRUCTIONS:
1. Read the diff carefully.
2. For each changed file or code block, check whether the change introduces,
   removes, or modifies a threat surface from the catalog above.
3. Report ONLY findings with specific code evidence from this diff.
4. Do NOT report threats not evidenced by the actual code changes.
5. If the diff removes a threat (e.g., adds a missing provenance gate), do not report it.

GIT DIFF:
```diff
{diff}
```

OUTPUT: JSON array of findings. Empty array [] if none found.
Each finding must have all these fields:
{{
  "threat_id": "MAESTRO-L3-001",   // must be a valid ID from the catalog above
  "severity": "high",              // critical|high|medium|low|informational
  "title": "Short finding title",
  "description": "Specific description with file and code context.",
  "file": "path/to/file.py",       // file where the issue was found
  "line": 42,                      // approximate line number (integer)
  "evidence": "exact code snippet or pattern",
  "recommendation": "Specific remediation for this exact finding."
}}
"""

_MAX_DIFF_CHARS = 14000


def analyze_diff(diff, catalog, layers=None):
    """
    Analyze a git diff against the MAESTRO threat catalog.
    Returns list of validated finding dicts.
    """
    model = os.environ.get("HC_MODEL", "claude-sonnet-4-6")
    client_fn = _get_client(model)

    summary = catalog_summary(catalog)
    truncated_diff = diff[:_MAX_DIFF_CHARS]
    if len(diff) > _MAX_DIFF_CHARS:
        truncated_diff += f"\n... [diff truncated at {_MAX_DIFF_CHARS} chars]"

    prompt = _USER_TEMPLATE.format(catalog=summary, diff=truncated_diff)
    response_text = client_fn(prompt, model)

    return _parse_findings(response_text, catalog)


def _get_client(model):
    """Return a callable(prompt, model) -> str based on configured backend."""
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "")

    if model.startswith("ollama/"):
        actual_model = model[len("ollama/"):]
        base_url = ollama_url or "http://localhost:11434"
        return _ollama_client(base_url, actual_model)
    elif anthropic_key:
        return _anthropic_client(anthropic_key)
    elif ollama_url:
        return _ollama_client(ollama_url, model)
    else:
        raise RuntimeError(
            "No inference backend configured. "
            "Set ANTHROPIC_API_KEY for Claude API or OLLAMA_BASE_URL for local inference."
        )


def _anthropic_client(api_key):
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)

    def call(prompt, model):
        msg = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    return call


def _ollama_client(base_url, model):
    import requests

    def call(prompt, _model):
        resp = requests.post(
            f"{base_url.rstrip('/')}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 4096},
            },
            timeout=180,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    return call


def _parse_findings(response_text, catalog):
    """Parse and validate the LLM JSON response into a findings list."""
    text = response_text.strip()

    if text.startswith("```"):
        lines = text.split("\n")
        inner = lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
        text = "\n".join(inner)

    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        print(f"[hc-maestro] Warning: could not parse LLM response as JSON.")
        print(f"[hc-maestro] Response (first 400 chars): {response_text[:400]}")
        return []

    if not isinstance(raw, list):
        return []

    valid_ids = {t["id"] for t in catalog}
    findings = []

    for item in raw:
        if not isinstance(item, dict):
            continue

        threat_id = item.get("threat_id", "")
        if threat_id not in valid_ids:
            print(f"[hc-maestro] Skipping finding with unrecognized threat_id '{threat_id}'")
            continue

        severity = item.get("severity", "medium")
        if severity not in _SEVERITY_LEVELS:
            severity = "medium"

        try:
            line = int(item.get("line", 1))
        except (TypeError, ValueError):
            line = 1

        findings.append({
            "threat_id": threat_id,
            "severity": severity,
            "title": str(item.get("title", "Untitled Finding"))[:200],
            "description": str(item.get("description", ""))[:2000],
            "file": str(item.get("file", ""))[:500],
            "line": max(1, line),
            "evidence": str(item.get("evidence", ""))[:1000],
            "recommendation": str(item.get("recommendation", ""))[:1000],
        })

    return findings
