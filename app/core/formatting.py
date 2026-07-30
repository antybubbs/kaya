"""Shared presentation formatters."""


def human_bytes(value: int | None, *, unknown: str = "unknown") -> str:
    """Format a byte count using unambiguous binary units."""
    if value is None:
        return unknown

    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(size) < 1024 or unit == "PiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    raise AssertionError("unreachable")

