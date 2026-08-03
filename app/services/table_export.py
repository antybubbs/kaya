from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable, Iterator, Sequence
from datetime import date

from fastapi import HTTPException
from fastapi.responses import StreamingResponse


SUPPORTED_FORMATS = {"csv", "text"}
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_SAFE_NAME = re.compile(r"[^a-z0-9]+")


def validate_export_format(value: str) -> str:
    clean = (value or "").strip().lower()
    if clean not in SUPPORTED_FORMATS:
        raise HTTPException(status_code=422, detail="Unsupported table export format")
    return clean


def validate_export_columns(requested: str, allowed: Sequence[str]) -> list[str]:
    allowed_set = set(allowed)
    if not requested.strip():
        return list(allowed)
    columns = [value.strip() for value in requested.split(",") if value.strip()]
    if not columns or len(columns) != len(set(columns)) or any(value not in allowed_set for value in columns):
        raise HTTPException(status_code=422, detail="Invalid table export columns")
    return columns


def validate_export_filters(requested: str, allowed: Sequence[str]) -> dict[str, str]:
    if not requested.strip():
        return {}
    try:
        payload = json.loads(requested)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Invalid table export filters") from exc
    if not isinstance(payload, dict) or len(payload) > len(allowed):
        raise HTTPException(status_code=422, detail="Invalid table export filters")
    allowed_set = set(allowed)
    clean = {}
    for key, value in payload.items():
        if key not in allowed_set or not isinstance(value, str) or len(value) > 100:
            raise HTTPException(status_code=422, detail="Invalid table export filters")
        if value.strip():
            clean[key] = value.strip().casefold()
    return clean


def export_row_matches(row: object, column_map: dict, filters: dict[str, str]) -> bool:
    return all(needle in str(column_map[key][1](row) or "").casefold() for key, needle in filters.items())


def safe_export_filename(table_name: str, export_format: str, today: date | None = None) -> str:
    clean = _SAFE_NAME.sub("-", (table_name or "table").strip().lower()).strip("-") or "table"
    extension = "csv" if export_format == "csv" else "txt"
    return f"kaya-{clean}-{today or date.today():%Y-%m-%d}.{extension}"


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    return f"'{text}" if text.startswith(FORMULA_PREFIXES) else text


def text_safe(value: object) -> str:
    return "" if value is None else re.sub(r"[\t\r\n]+", " ", str(value))


def _encoded_lines(
    headers: Sequence[str], rows: Iterable[Sequence[object]], export_format: str
) -> Iterator[bytes]:
    output = io.StringIO(newline="")
    if export_format == "csv":
        yield b"\xef\xbb\xbf"
        writer = csv.writer(output, lineterminator="\r\n")
        sanitise = csv_safe
    else:
        writer = csv.writer(output, delimiter="\t", lineterminator="\r\n")
        sanitise = text_safe
    for row in _with_header(headers, rows):
        writer.writerow([sanitise(value) for value in row])
        yield output.getvalue().encode("utf-8")
        output.seek(0)
        output.truncate(0)


def _with_header(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> Iterator[Sequence[object]]:
    yield headers
    yield from rows


def table_export_response(
    *, table_name: str, headers: Sequence[str], rows: Iterable[Sequence[object]], export_format: str
) -> StreamingResponse:
    clean_format = validate_export_format(export_format)
    filename = safe_export_filename(table_name, clean_format)
    media_type = "text/csv; charset=utf-8" if clean_format == "csv" else "text/plain; charset=utf-8"
    return StreamingResponse(
        _encoded_lines(headers, rows, clean_format),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
