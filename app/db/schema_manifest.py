"""Deterministic database schema manifests for cross-engine validation."""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.sql.schema import MetaData


def _sorted_rows(rows: Iterable[dict], *keys: str) -> list[dict]:
    return sorted(rows, key=lambda row: tuple(str(row.get(key, "")) for key in keys))


def schema_manifest(engine: Engine) -> dict:
    """Return actual database metadata, including dialect-specific objects."""
    inspector = inspect(engine)
    tables = []
    for table_name in sorted(inspector.get_table_names()):
        columns = []
        for column in inspector.get_columns(table_name):
            columns.append(
                {
                    "name": column["name"],
                    "type": str(column["type"]),
                    "nullable": bool(column["nullable"]),
                    "default": column.get("default"),
                }
            )
        tables.append(
            {
                "name": table_name,
                "columns": _sorted_rows(columns, "name"),
                "primary_key": inspector.get_pk_constraint(table_name),
                "foreign_keys": _sorted_rows(
                    inspector.get_foreign_keys(table_name),
                    "name",
                    "referred_table",
                ),
                "unique_constraints": _sorted_rows(
                    inspector.get_unique_constraints(table_name), "name"
                ),
                "check_constraints": _sorted_rows(
                    inspector.get_check_constraints(table_name), "name"
                ),
                "indexes": _sorted_rows(
                    inspector.get_indexes(table_name), "name"
                ),
            }
        )

    manifest = {"engine": engine.dialect.name, "tables": tables}
    with engine.connect() as connection:
        if engine.dialect.name == "postgresql":
            manifest["triggers"] = [
                dict(row)
                for row in connection.execute(
                    text(
                        """
                        SELECT n.nspname AS schema_name,
                               c.relname AS table_name,
                               t.tgname AS trigger_name,
                               pg_get_triggerdef(t.oid) AS definition,
                               pg_get_functiondef(t.tgfoid) AS function_definition
                        FROM pg_trigger t
                        JOIN pg_class c ON c.oid = t.tgrelid
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE NOT t.tgisinternal
                        ORDER BY n.nspname, c.relname, t.tgname
                        """
                    )
                ).mappings()
            ]
            manifest["sequences"] = [
                dict(row)
                for row in connection.execute(
                    text(
                        """
                        SELECT schemaname AS schema_name,
                               sequencename AS sequence_name,
                               start_value, increment_by, cycle, cache_size
                        FROM pg_sequences
                        WHERE schemaname = 'public'
                        ORDER BY sequencename
                        """
                    )
                ).mappings()
            ]
        else:
            manifest["triggers"] = [
                {"table_name": row[0], "trigger_name": row[1], "definition": row[2]}
                for row in connection.execute(
                    text(
                        "SELECT tbl_name, name, sql FROM sqlite_master "
                        "WHERE type = 'trigger' ORDER BY tbl_name, name"
                    )
                )
            ]
            manifest["sequences"] = []
    return manifest


def compare_manifest_to_models(manifest: dict, metadata: MetaData) -> dict[str, list[str]]:
    """Report model objects absent from an inspected database manifest."""
    actual = {table["name"]: table for table in manifest["tables"]}
    missing_tables = sorted(set(metadata.tables) - set(actual))
    missing_columns = []
    for table in metadata.tables.values():
        actual_columns = {column["name"] for column in actual.get(table.name, {}).get("columns", [])}
        missing_columns.extend(
            f"{table.name}.{column.name}"
            for column in table.columns
            if column.name not in actual_columns
        )
    return {"missing_tables": missing_tables, "missing_columns": sorted(missing_columns)}
