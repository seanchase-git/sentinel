"""Risk-category vocabulary and taxonomy-derived category mapping.

The classifier node emits a subset of RISK_CATEGORIES; retrieval filters rules
whose risk_categories overlap. Rules may declare categories explicitly in YAML;
otherwise they are derived here from the rule's OWASP/CWE taxonomy.
"""

RISK_CATEGORIES: frozenset[str] = frozenset(
    {
        "auth",
        "data_access",
        "deserialization",
        "injection",
        "secrets",
        "crypto",
        "xss",
        "csrf",
        "ssrf",
        "path_traversal",
        "dependency",
        "config",
    }
)

# OWASP Top 10 2021 category → risk categories
_OWASP_MAP: dict[str, set[str]] = {
    "A01": {"auth", "data_access"},
    "A02": {"crypto", "secrets"},
    "A03": {"injection", "xss"},
    "A04": {"config"},
    "A05": {"config"},
    "A06": {"dependency"},
    "A07": {"auth"},
    "A08": {"deserialization"},
    "A09": {"config"},
    "A10": {"ssrf"},
}

# CWE id → risk categories (top CWEs relevant to py/js/ts; extended as corpus grows)
_CWE_MAP: dict[str, set[str]] = {
    "CWE-20": {"injection"},
    "CWE-22": {"path_traversal"},
    "CWE-78": {"injection"},
    "CWE-79": {"xss"},
    "CWE-89": {"injection"},
    "CWE-94": {"injection"},
    "CWE-95": {"injection"},
    "CWE-200": {"data_access"},
    "CWE-287": {"auth"},
    "CWE-295": {"crypto"},
    "CWE-306": {"auth"},
    "CWE-327": {"crypto"},
    "CWE-330": {"crypto"},
    "CWE-338": {"crypto"},
    "CWE-352": {"csrf"},
    "CWE-434": {"path_traversal", "config"},
    "CWE-502": {"deserialization"},
    "CWE-601": {"config"},
    "CWE-611": {"injection"},
    "CWE-639": {"auth", "data_access"},
    "CWE-798": {"secrets"},
    "CWE-829": {"dependency"},
    "CWE-915": {"data_access", "auth"},
    "CWE-918": {"ssrf"},
    "CWE-1321": {"injection"},
}


def derive_risk_categories(taxonomy: list[dict[str, str]]) -> set[str]:
    """Derive risk categories from a rule's taxonomy entries.

    CWE mappings are specific and take priority; the broad OWASP-category
    mapping is only a fallback when no CWE entry derives anything. (A03
    spans injection AND xss — tagging every A03 rule with both would let an
    xss classification pull SQL-injection rules into the top-K budget.)

    OWASP entries look like ``{"owasp": "A03:2021"}``; CWE entries like
    ``{"cwe": "CWE-89"}``. Unknown identifiers derive nothing (the rule can
    still declare risk_categories explicitly).
    """
    from_cwe: set[str] = set()
    from_owasp: set[str] = set()
    for entry in taxonomy:
        for kind, value in entry.items():
            if kind == "owasp":
                from_owasp |= _OWASP_MAP.get(value.split(":")[0].upper(), set())
            elif kind == "cwe":
                from_cwe |= _CWE_MAP.get(value.upper(), set())
    return from_cwe or from_owasp
