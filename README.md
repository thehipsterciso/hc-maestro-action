# hc-maestro-action

**MAESTRO-as-Code CI gate** — threat-models every PR to your agentic AI repo using the [MAESTRO framework](https://cloudsecurityalliance.org/research/topics/ai-safety-initiative).

**Attribution:** Thomas Jones (thehipsterciso)  
**License:** Apache-2.0 (code) + CC BY 4.0 (bundled spec — see NOTICE)  
**Version:** 0.1.0

---

## What It Does

On every PR:
1. Extracts the diff (before reading the PR title or description — prevents confirmation bias per arXiv:2603.18740)
2. Analyzes the diff against the [hc-maestro-spec](https://github.com/thehipsterciso/hc-maestro-spec) threat catalog using Claude or Ollama
3. Uploads findings as SARIF 2.1.0 to GitHub Code Scanning
4. Posts a structured PR review comment with threat IDs, severity, evidence, and mitigations
5. Fails the workflow if any finding at or above `fail-on-severity` is detected

---

## Quick Start

```yaml
# .github/workflows/maestro.yml
name: MAESTRO Threat Model

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write   # required for SARIF upload

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required for diff extraction
      - uses: thehipsterciso/hc-maestro-action@v0.1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          fail-on-severity: high
```

Add `ANTHROPIC_API_KEY` to your repository secrets. Done.

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `anthropic-api-key` | — | Anthropic API key. Use this or `ollama-base-url`. |
| `ollama-base-url` | — | Ollama URL for local inference (e.g., `http://localhost:11434`) |
| `model` | `claude-sonnet-4-6` | Model to use. Also accepts `claude-haiku-4-5-20251001`, `ollama/qwen3:14b`, etc. |
| `layers` | `3,4` | Comma-separated MAESTRO layers to analyze |
| `severity-threshold` | `medium` | Minimum severity to include in output |
| `fail-on-severity` | `high` | Fail the step if any finding is at or above this level. Set `none` for report-only. |
| `post-pr-comment` | `true` | Post findings as a PR review comment |
| `sarif-output` | `hc-maestro-findings.sarif` | SARIF output file path |
| `spec-path` | — | Path to a custom `maestro-spec.yaml`. Uses bundled v0.1.0 if empty. |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-path` | Absolute path to the generated SARIF file |
| `finding-count` | Total findings at or above `severity-threshold` |
| `critical-count` | Critical-severity finding count |
| `high-count` | High-severity finding count |

---

## Inference Backends

### Claude API (recommended for CI)

```yaml
- uses: thehipsterciso/hc-maestro-action@v0.1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    model: claude-sonnet-4-6
```

### Ollama (local / air-gapped)

```yaml
- uses: thehipsterciso/hc-maestro-action@v0.1
  with:
    ollama-base-url: http://your-ollama-host:11434
    model: ollama/qwen3:14b
```

---

## SARIF + Code Scanning

The action uses `github/codeql-action/upload-sarif` to upload findings. This requires:

- **Public repos:** no additional setup
- **Private repos:** GitHub Advanced Security ($30/committer/month) or GitHub Code Security

If Code Security is not enabled, the SARIF upload is skipped with a warning and the PR comment is still posted.

---

## Threat Coverage (v0.1.0)

| Layer | Name | Threats |
|-------|------|---------|
| L3 | Agent Frameworks | 7 |
| L4 | Deployment and Infrastructure | 7 |

Full threat catalog: [hc-maestro-spec](https://github.com/thehipsterciso/hc-maestro-spec/blob/main/maestro-spec.yaml)

---

## Semgrep Rules

The `rules/semgrep-l3-l4.yaml` file contains static Semgrep rules for the highest-confidence MAESTRO patterns:

- `maestro-l3-003-http-to-vector-store` — Zombie Agent taint: HTTP fetch → memory store
- `maestro-l3-005-safety-field-write` — Safety constraint modification
- `maestro-l3-006-unbounded-llm-loop` — Unbounded tool execution loop
- `maestro-l4-002-hardcoded-*-key` — Hardcoded API credentials
- `maestro-l4-006-debug-true` — Debug mode in production

Run them standalone:

```bash
semgrep --config rules/semgrep-l3-l4.yaml your-repo/
```

---

## Attribution (CC BY 4.0 requirement)

This action bundles the hc-maestro-spec threat catalog. Per the CC BY 4.0 license, any use must credit:

> "MAESTRO-as-Code by Thomas Jones (thehipsterciso) — https://github.com/thehipsterciso/hc-maestro-spec"

See [NOTICE](NOTICE) for full attribution requirements.
