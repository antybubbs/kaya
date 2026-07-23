from __future__ import annotations


def clean_name_part(value: str | None) -> str | None:
    """Trim a user-entered name while preserving words and punctuation."""
    clean = " ".join(str(value or "").split())
    return clean or None


def first_name_contains_last_name(first_name: str | None, last_name: str | None) -> bool:
    """Detect the common legacy mistake 'Anthony Hales' + 'Hales'."""
    first = clean_name_part(first_name)
    last = clean_name_part(last_name)
    if not first or not last:
        return False
    first_words = first.casefold().split()
    last_words = last.casefold().split()
    return len(first_words) > len(last_words) and first_words[-len(last_words):] == last_words


def user_display_name(first_name: str | None, last_name: str | None, fallback: str = "") -> str:
    first = clean_name_part(first_name)
    last = clean_name_part(last_name)
    if first_name_contains_last_name(first, last):
        return first or fallback
    return " ".join(part for part in (first, last) if part) or fallback
