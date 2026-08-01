"""Human-readable report.md writer.

Findings grouped severity → OWASP category, each with its verbatim snippet,
rule citation, and judge verdict; suppressed candidates and rejected inputs
get their own audit sections (PRD acceptance criterion 5).
"""

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from sentinel.report.builder import SEVERITY_ORDER

_OWASP_RE = re.compile(r"owasp:\s*(A\d{2}:2021)")

_OWASP_TITLES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}


def _owasp_category(finding: dict[str, Any]) -> str:
    match = _OWASP_RE.search(finding.get("grounded_in_rule_chunk", ""))
    if match:
        code = match.group(1)
        return f"{code} {_OWASP_TITLES.get(code, '')}".strip()
    return "Uncategorized"


def _fmt_score(score: Any) -> str:
    return f"{score:.3f}" if isinstance(score, (int, float)) else "n/a"


def _finding_block(f: dict[str, Any]) -> str:
    judge = f.get("judge") or {}
    lines = [
        f"#### `{f['file_path']}:{f['line_start']}"
        + (f"-{f['line_end']}`" if f["line_end"] != f["line_start"] else "`")
        + f" — {f['rule_id']}",
        "",
        f"**Severity:** {f['severity']}"
        + (
            f" *(model claimed {f['claimed_severity']})*"
            if f.get("claimed_severity") and f["claimed_severity"] != f["severity"]
            else ""
        )
        + f" · **Judge groundedness:** {_fmt_score(judge.get('groundedness_score'))}",
        "",
        "```",
        f["code_snippet"],
        "```",
        "",
        f["explanation"],
        "",
        "<details><summary>Grounding rule (verbatim from corpus)</summary>",
        "",
        "```yaml",
        f["grounded_in_rule_chunk"].rstrip(),
        "```",
        "",
        "</details>",
        "",
    ]
    return "\n".join(lines)


def render_markdown(report: dict[str, Any]) -> str:
    run = report["run"]
    summary = report["summary"]
    out: list[str] = [
        "# Sentinel Security Review",
        "",
        f"**Target:** `{run['target']}`  ",
        f"**Reviewed:** {run['timestamp']} · sentinel {run['sentinel_version']} · "
        f"{run['wall_seconds']}s  ",
        f"**Files:** {summary['files_reviewed']} "
        f"({', '.join(f'{v} {k}' for k, v in summary['file_status_counts'].items())})  ",
        f"**Findings:** {summary['findings']} · "
        f"**Suppressed candidates:** {summary['suppressed_candidates']} · "
        f"**Rejected inputs:** {summary['rejected_inputs']}",
        "",
    ]

    # Every way a run can fail to account for its target must reach the reader.
    # Warning only on judge outages let an errored file render "No grounded
    # findings were emitted" with no caveat at all, which reads as a clean bill
    # of health for a target that was never fully reviewed.
    if not summary.get("complete", True):
        errored = summary.get("file_status_counts", {}).get("error", 0)
        causes = []
        if summary.get("judge_unavailable"):
            causes.append(
                f"the judge did not answer for {summary['judge_unavailable']} "
                f"candidate(s), quarantined below as unadjudicated rather than "
                f"judged unfounded"
            )
        if errored:
            causes.append(
                f"{errored} file(s) never finished review and were not assessed "
                f"at all (see the per-file status table)"
            )
        out += [
            f"> **WARNING — this review is INCOMPLETE: {'; and '.join(causes)}.** "
            f"Real vulnerabilities may be missing from this report. Precision and "
            f"recall computed from this run are not trustworthy.",
            "",
        ]

    if summary.get("judge_unavailable"):
        out += ["## ⚠️ Unadjudicated candidates (judge unavailable)", ""]
        for u in report.get("unadjudicated_candidates", []):
            cand = u.get("candidate") or {}
            out.append(
                f"- `{u.get('file_path')}`"
                f"{':' + str(cand['line_start']) if cand.get('line_start') else ''}"
                f" — {cand.get('rule_id', 'unknown rule')} — {u.get('reason')}"
            )
        out.append("")

    if report["rejected_inputs"]:
        out += ["## ⛔ Rejected inputs", ""]
        for r in report["rejected_inputs"]:
            out.append(f"- `{r['file_path']}` — guardrail category {r['category']}: {r['note']}")
        out.append("")

    if not report["findings"]:
        out += ["## Findings", "", "No grounded findings were emitted.", ""]
    else:
        out += ["## Findings", ""]
        by_sev: dict[str, list[dict]] = defaultdict(list)
        for f in report["findings"]:
            by_sev[f["severity"]].append(f)
        for severity in SEVERITY_ORDER:
            if severity not in by_sev:
                continue
            out += [f"### {severity.upper()} ({len(by_sev[severity])})", ""]
            by_owasp: dict[str, list[dict]] = defaultdict(list)
            for f in by_sev[severity]:
                by_owasp[_owasp_category(f)].append(f)
            for category in sorted(by_owasp):
                out += [f"#### {category}", ""]
                for f in by_owasp[category]:
                    out.append(_finding_block(f))

    if report["suppressed_candidates"]:
        out += [
            "## Suppressed candidates (audit trail)",
            "",
            "Candidates rejected by the deterministic validator or the",
            "groundedness judge. Listed for auditability — these are NOT findings.",
            "",
        ]
        for s in report["suppressed_candidates"]:
            candidate = s.get("candidate", {})
            judge = s.get("judge") or {}
            out.append(
                f"- **[{s['stage']}]** `{s.get('file_path', '?')}` "
                f"rule `{candidate.get('rule_id', '?')}` — {s['reason']}"
                + (
                    f" (judge score {judge.get('groundedness_score')}; "
                    f"reasoning: {str(judge.get('reasoning', ''))[:200]})"
                    if judge
                    else ""
                )
            )
        out.append("")

    out += [
        "---",
        "",
        "*Every finding above cites a rule from the local corpus (shown verbatim in its",
        "details block) and passed a groundedness check by a local judge model. Models:*",
        "",
    ]
    for alias, m in run["models"].items():
        out.append(f"- *{alias}: {m['hf_repo']} ({m['developer']}, {m['origin']})*")
    out.append("")
    return "\n".join(out)


def write_markdown_report(report: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.md"
    path.write_text(render_markdown(report), encoding="utf-8")
    return path
