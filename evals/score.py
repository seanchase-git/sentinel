"""Score a Sentinel report against adjudicated ground truth.

Two numbers matter and they are measured separately.

Precision and recall answer "is it right". Stability answers "does it say the
same thing twice", which is not a given: llama.cpp continuous batching reorders
floating point reductions between runs, so greedy decoding at temperature zero
still flips close calls. A real finding can appear in one run of an unchanged
file and be gone in the next. Any precision number carries that variance, so a
single run is a sample, not a measurement.

Usage:
    uv run python evals/score.py <ground_truth.yaml> <report.json> [more_reports...]

Passing several reports of the same target scores each and reports the stability
rate across them.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

# A finding matches a known vulnerability if it names the same file and lands
# within this many lines of the adjudicated location. Deep review reports the
# line it quoted, which drifts from the line a human would cite.
LINE_TOLERANCE = 40


def _norm(path: str) -> str:
    """Compare on the trailing path segments so a report scoped to a
    subdirectory still matches ground truth written repo-relative."""
    return path.replace("\\", "/").lstrip("./")


def _same_place(finding: dict, vuln: dict) -> bool:
    """Same file, near the same line, AND the same weakness class.

    The CWE check is load-bearing. Without it an unrelated finding that happens
    to land within LINE_TOLERANCE counts as detecting the vulnerability, which
    inflates both recall and true positives. That is not hypothetical: with a
    40-line tolerance, two unrelated defects in the same handler are routinely
    close enough that proximity alone credits the wrong one.
    """
    f_path, v_path = _norm(finding.get("file_path", "")), _norm(vuln["file"])
    if not (f_path.endswith(v_path) or v_path.endswith(f_path)):
        return False
    f_line = finding.get("line_start")
    if f_line is None:
        return False
    if min(abs(f_line - line) for line in _vuln_lines(vuln)) > LINE_TOLERANCE:
        return False
    return _cwe_matches(vuln.get("cwe", ""), _finding_cwes(finding))


def _vuln_lines(vuln: dict) -> list[int]:
    """Every line this ONE defect legitimately surfaces at.

    Some defects are a single omission that manifests at several places. A
    router registered without an auth hook is one mistake, and every route it
    carries is unauthenticated because of it, which can span hundreds of lines.
    Anchoring that to one line makes a correct detection at the far end score as
    a miss because it sits well outside LINE_TOLERANCE.

    It stays ONE entry rather than four, so recall is not inflated by counting
    one missing hook four times. `also_at` only widens where the single defect
    may be legitimately reported, never how much credit it earns.
    """
    lines = [vuln["line"], *vuln.get("also_at", [])]
    return [int(line) for line in lines]


# Substring matching is wrong here and silently generous: "cwe79" is a substring
# of "cwe798hardcodedsecrets", so a hardcoded-secret finding would be credited
# with detecting an XSS defect. Match the token, not the characters.
_CWE_TOKEN_RE = re.compile(r"(?:^|[^a-z0-9])cwe-?(\d+)(?:[^0-9]|$)", re.IGNORECASE)

# Last-resort scrape, used only when the rule body will not parse as YAML.
# Deliberately NOT the primary path: it is not scoped to the taxonomy block, so
# a line `cwe: CWE-798` sitting in a description would contribute a CWE the rule
# never declared, and an inline comment or a quoted value
# (`- cwe: CWE-78 # shell`) silently yields nothing at all. Both were verified
# against this pattern. Parse the document instead.
_TAXONOMY_CWE_RE = re.compile(r"^\s*-?\s*cwe:\s*[\"']?(CWE-\d+)", re.IGNORECASE | re.MULTILINE)

# CWE pairs where one is a documented specialization of the other, so a finding
# labelled with either is detecting the same defect. Kept explicit and small on
# purpose: a general "walk the whole CWE tree" rule would let distant ancestors
# match and quietly re-introduce the over-crediting the token check prevents.
# Each pair cites the MITRE relationship that justifies it.
_CWE_EQUIVALENT: dict[str, set[str]] = {
    # CWE-95 Eval Injection ChildOf CWE-94 Code Injection
    "94": {"95"},
    "95": {"94"},
    # CWE-321 Hard-coded Cryptographic Key ChildOf CWE-798 Hard-coded Credentials
    "798": {"321"},
    "321": {"798"},
    # CWE-201 Insertion of Sensitive Information Into Sent Data ChildOf CWE-200
    "200": {"201"},
    "201": {"200"},
    # CWE-306 Missing Authentication and CWE-862 Missing Authorization are NOT
    # listed. They are siblings describing different weaknesses, and conflating
    # them would credit an authentication rule with catching an authorization
    # defect. DVNA's /admin/usersapi is exactly that case.
}


def _finding_cwes(finding: dict) -> set[str]:
    """The CWE numbers a finding actually claims.

    Read the rule's declared taxonomy first, and fall back to the rule id.
    Deriving the CWE from the id alone was wrong: 8 of the 51 corpus rules are
    named by OWASP category (owasp-a03-command-injection-javascript-exec
    declares CWE-78 but carries no cwe token in its id), so every finding
    citing one could never be credited, however correct it was. That scored a
    verbatim, correctly grounded command-injection detection on DVNA as both a
    false positive and a miss.
    """
    chunk = finding.get("grounded_in_rule_chunk") or ""
    for cwe in (_taxonomy_cwes_parsed(chunk), _taxonomy_cwes_scraped(chunk)):
        if cwe:
            return cwe
    return {m.group(1) for m in _CWE_TOKEN_RE.finditer(finding.get("rule_id", ""))}


def _taxonomy_cwes_parsed(chunk: str) -> set[str]:
    """Read taxonomy[].cwe out of the rule body as YAML.

    The report carries the rule's complete yaml_body, verified unsliced from
    loader through writer, so this parses rather than pattern-matches. Scoping
    to the taxonomy key is the point: it cannot be fooled by prose elsewhere in
    the document, and it handles comments and quoting that a line regex drops.
    """
    try:
        doc = yaml.safe_load(chunk)
    except yaml.YAMLError:
        return set()
    if not isinstance(doc, dict):
        return set()
    entries = doc.get("taxonomy")
    if not isinstance(entries, list):
        return set()
    cwes = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        found = _CWE_TOKEN_RE.search(str(entry.get("cwe", "")))
        if found:
            cwes.add(found.group(1))
    return cwes


def _taxonomy_cwes_scraped(chunk: str) -> set[str]:
    return {m.group(1).split("-")[-1] for m in _TAXONOMY_CWE_RE.finditer(chunk)}


def _cwe_matches(vuln_cwe: str, finding_cwes: set[str]) -> bool:
    if not vuln_cwe:
        return True
    want = _CWE_TOKEN_RE.search(vuln_cwe)
    if want is None:
        return False
    accept = {want.group(1)} | _CWE_EQUIVALENT.get(want.group(1), set())
    return bool(accept & finding_cwes)


def load_report(path: Path) -> dict:
    return json.loads(path.read_text())


def scoreable_vulnerabilities(truth: dict) -> list[dict]:
    """Return confirmed, walker-eligible defects from either truth format."""
    if "adjudications" not in truth:
        return list(truth.get("vulnerabilities", []))
    return [
        case for case in truth.get("adjudications", [])
        if case.get("status") == "CONFIRMED" and case.get("walker_eligible") is True
    ]


def score_one(truth: dict, report: dict) -> dict:
    findings = report.get("findings", [])
    vulns = scoreable_vulnerabilities(truth)

    # One-to-one. Without it, three duplicate findings for one defect all count
    # as true positives and precision reports work the tool did not do, while a
    # single finding can also satisfy several ground-truth entries at once.
    # Greedy nearest-line assignment, each finding and each vulnerability used
    # at most once.
    unclaimed = list(range(len(findings)))
    matched, unmatched = [], []
    claimed_by: dict[int, dict] = {}
    for v in vulns:
        cands = [i for i in unclaimed if _same_place(findings[i], v)]
        if not cands:
            unmatched.append(v)
            continue
        best = min(cands, key=lambda i: abs((findings[i].get("line_start") or 0) - v["line"]))
        unclaimed.remove(best)
        claimed_by[best] = v
        matched.append(v)

    true_pos = [findings[i] for i in sorted(claimed_by)]
    exhaustive = bool(truth.get("exhaustive"))

    # Everything unclaimed is a false positive ONLY when the ground truth is
    # exhaustive. When it is not, these are unadjudicated, and calling them
    # false positives turns an incomplete label set into a precision claim.
    # The old code computed that claim anyway and published it under the name
    # `precision`, with the caveat living only in a printed note. A number
    # named precision gets quoted as precision. So under non-exhaustive truth
    # `precision` is now None and the same value is reported as what it
    # actually is: a lower bound that assumes every unadjudicated finding is
    # wrong. f1 follows precision, because an f1 built on a bound is a bound.
    unadjudicated = [findings[i] for i in unclaimed]
    false_pos = unadjudicated if exhaustive else []

    # None, not 0.0, when the denominator is empty. A target with no known
    # vulnerabilities has no recall to report, and printing 0.000 reads as
    # "found nothing it should have" rather than "nothing to find".
    bound = len(true_pos) / len(findings) if findings else None
    precision = bound if exhaustive else None
    recall = len(matched) / len(vulns) if vulns else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )

    # Recall over defects the corpus can actually reach. Raw recall conflates
    # "had a rule and missed it" with "no rule exists", and on a benchmark
    # dense with planted defects the second dominates. Only computed when the
    # ground truth annotates coverage; absent that, no claim is made.
    covered = [v for v in vulns if str(v.get("corpus_coverage", "")).strip() not in ("", "none")]
    covered_ids = {v["id"] for v in covered}
    recall_covered = (
        len([v for v in matched if v["id"] in covered_ids]) / len(covered) if covered else None
    )

    return {
        "findings": len(findings),
        "true_positives": len(true_pos),
        "false_positives": len(false_pos),
        "unadjudicated": len(unadjudicated),
        "known_vulns": len(vulns),
        "exhaustive": exhaustive,
        "detected": [v["id"] for v in matched],
        "missed": [v["id"] for v in unmatched],
        "precision": precision,
        "precision_lower_bound": bound,
        "recall": recall,
        "recall_covered": recall_covered,
        "covered_vulns": len(covered),
        "f1": f1,
        "suppressed": len(report.get("suppressed_candidates", [])),
    }


def finding_key(f: dict) -> tuple:
    return (_norm(f.get("file_path", "")), f.get("line_start"), f.get("rule_id"))


def stability(reports: list[dict]) -> dict:
    """How much of the output survives from run to run.

    Reported as the share of distinct findings that appear in every run. A tool
    you cannot reproduce cannot be gated on.
    """
    sets = [{finding_key(f) for f in r.get("findings", [])} for r in reports]
    if len(sets) < 2:
        return {}
    everywhere = set.intersection(*sets)
    anywhere = set.union(*sets)
    counts = Counter(k for s in sets for k in s)
    return {
        "runs": len(sets),
        "stable": len(everywhere),
        "union": len(anywhere),
        "stability_rate": len(everywhere) / len(anywhere) if anywhere else 1.0,
        "flapping": sorted(
            f"{k[0]}:{k[1]} {k[2]} ({counts[k]}/{len(sets)} runs)"
            for k in anywhere - everywhere
        ),
    }


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    truth = yaml.safe_load(Path(sys.argv[1]).read_text())
    report_paths = [Path(p) for p in sys.argv[2:]]
    reports = [load_report(p) for p in report_paths]

    # Scoring a report against the wrong target produces numbers that look fine
    # and mean nothing. Refuse rather than guess.
    for path, report in zip(report_paths, reports, strict=True):
        got = str((report.get("run") or {}).get("target", ""))
        if got and Path(got).resolve() != Path(truth["target"]).resolve():
            print(f"ERROR: {path} was produced for {got!r}, not {truth['target']!r}")
            return 2

    print(f"target: {truth['target']}")
    print(f"ground truth: {len(scoreable_vulnerabilities(truth))} known vulnerabilities")
    if not truth.get("exhaustive", False):
        print(
            "  NOTE: ground truth is not marked exhaustive. Unmatched findings are\n"
            "  UNADJUDICATED, not proven false positives, and recall is an upper\n"
            "  bound on what is known rather than a measurement of the tool."
        )
    print()

    for path, report in zip(report_paths, reports, strict=True):
        s = score_one(truth, report)
        print(f"--- {path.parent.name} ---")
        label, count = (
            ("FP ", s["false_positives"]) if s["exhaustive"] else ("unadj", s["unadjudicated"])
        )
        print(
            f"  findings {s['findings']:>3}  "
            f"TP {s['true_positives']:>2}  {label} {count:>3}  "
            f"suppressed {s['suppressed']:>3}"
        )

        def fmt(v: float | None) -> str:
            return "  n/a" if v is None else f"{v:.3f}"

        # Never print a bound under the name `precision`. Under non-exhaustive
        # truth the honest label is the only thing standing between a lower
        # bound and someone quoting it as a measurement.
        if s["exhaustive"]:
            print(f"  precision {fmt(s['precision'])}   ", end="")
        else:
            print(f"  precision >= {fmt(s['precision_lower_bound'])} (bound)   ", end="")
        print(f"recall {fmt(s['recall'])}   f1 {fmt(s['f1'])}")
        if s["recall_covered"] is not None:
            print(
                f"  recall over the {s['covered_vulns']} defects with corpus coverage: "
                f"{fmt(s['recall_covered'])}"
            )
        if s["missed"]:
            print(f"  MISSED: {', '.join(s['missed'])}")
        print()

    if len(reports) > 1:
        st = stability(reports)
        print(f"--- stability across {st['runs']} runs ---")
        print(
            f"  {st['stable']}/{st['union']} findings appear in every run "
            f"(stability {st['stability_rate']:.3f})"
        )
        for line in st["flapping"]:
            print(f"    FLAPPING  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
