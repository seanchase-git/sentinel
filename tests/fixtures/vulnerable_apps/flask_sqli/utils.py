"""Benign helper module — should triage clean."""


def format_display_name(first: str, last: str) -> str:
    return f"{first.strip().title()} {last.strip().title()}".strip()


def paginate(items: list, page: int, per_page: int = 20) -> list:
    start = max(0, (page - 1) * per_page)
    return items[start : start + per_page]


def initials(name: str) -> str:
    return "".join(part[0].upper() for part in name.split() if part)
