#!/usr/bin/env python3
"""Fail-closed ownership checks for disposable Kaya Docker validation resources."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

PROJECT_RE = re.compile(r"^kaya_phase(?:7d|8|9|10|11|12a?|13)_[a-z0-9][a-z0-9_-]*$")
SAFE_RESOURCE_RE = re.compile(r"^kaya_phase(?:7d|8|9|10|11|12a?|13)_[a-z0-9][a-z0-9_-]*$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
RUN_VALUE_RE = re.compile(r"^[0-9]+$")
PROTECTED_NAMES = frozenset(
    {
        "kaya_phase6_postgres_secret",
        "kaya_postgres_data",
        "kaya_postgres_secret",
        "kaya_postgres_data",
    }
)


def valid_project(project: str) -> bool:
    return bool(PROJECT_RE.fullmatch(project))


def phase12a_project_name(run_id: str, run_attempt: str) -> str:
    if run_id == "local":
        if run_attempt != "1":
            raise ValueError("local Phase 12A runs must use attempt 1")
    elif not RUN_VALUE_RE.fullmatch(run_id):
        raise ValueError("GITHUB_RUN_ID must contain decimal digits")
    if not RUN_VALUE_RE.fullmatch(run_attempt):
        raise ValueError("GITHUB_RUN_ATTEMPT must contain decimal digits")
    project = f"kaya_phase12a_{run_id}_{run_attempt}"
    if not valid_project(project):
        raise ValueError("generated Phase 12A project is not valid")
    return project


def validate_identifier(value: str, field: str = "resource identifier") -> None:
    if not IDENTIFIER_RE.fullmatch(value):
        raise RuntimeError(f"{field} contains an unsafe character: {value}")


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def labels(kind: str, name: str) -> dict[str, str]:
    raw = run("docker", kind, "inspect", name, "--format", "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}")
    return json.loads(raw) or {}


def validate_name(name: str, project: str) -> None:
    validate_identifier(name)
    if name in PROTECTED_NAMES:
        raise RuntimeError(f"protected resource name is in the Phase 12 mutable set: {name}")
    if not SAFE_RESOURCE_RE.fullmatch(name) or not name.startswith(project + "_"):
        raise RuntimeError(f"resource is not owned by the Phase 12 project: {name}")


def validate_config(config: dict[str, Any], project: str) -> dict[str, list[str]]:
    if not valid_project(project):
        raise RuntimeError("project name must be an exact run-scoped Phase 12 name")
    found = {"volumes": [], "networks": [], "containers": []}
    volume_actual = {
        name: definition.get("name", name)
        for name, definition in config.get("volumes", {}).items()
    }
    for service_name, service in config.get("services", {}).items():
        container_name = service.get("container_name")
        if container_name:
            validate_name(container_name, project)
            found["containers"].append(container_name)
        for mount in service.get("volumes", []):
            source = mount.get("source") if isinstance(mount, dict) else str(mount).split(":", 1)[0]
            mount_type = mount.get("type") if isinstance(mount, dict) else None
            if mount_type in {"bind", "tmpfs"}:
                continue
            if mount_type == "volume" and source not in volume_actual:
                raise RuntimeError(f"service {service_name} references undefined named volume: {source}")
            source = volume_actual.get(source, source)
            if source and not source.startswith(".") and not source.startswith("/") and not source.startswith("${"):
                validate_name(source, project)
                found["volumes"].append(source)
    for name, definition in config.get("volumes", {}).items():
        actual = definition.get("name", name)
        if definition.get("external"):
            raise RuntimeError(f"external volume is forbidden in disposable Phase 12 config: {actual}")
        validate_name(actual, project)
        found["volumes"].append(actual)
    for name, definition in config.get("networks", {}).items():
        actual = definition.get("name", f"{project}_{name}")
        if definition.get("external"):
            raise RuntimeError(f"external network is forbidden in disposable Phase 12 config: {actual}")
        validate_name(actual, project)
        found["networks"].append(actual)
    return {key: sorted(set(value)) for key, value in found.items()}


def write_manifest(path: Path, project: str, resources: dict[str, list[str]], fixture_paths: list[str] | None = None) -> None:
    path.write_text(
        json.dumps(
            {
                "project": project,
                "containers": resources.get("containers", []),
                "volumes": resources.get("volumes", []),
                "networks": resources.get("networks", []),
                "fixture_paths": fixture_paths or [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def cleanup(path: Path) -> None:
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    project = manifest["project"]
    if not valid_project(project):
        raise RuntimeError("manifest project is not a valid Phase 12 project")
    for kind, command in (("container", "rm"), ("volume", "rm"), ("network", "rm")):
        for name in manifest.get(f"{kind}s", []):
            validate_name(name, project)
            try:
                actual_labels = labels(kind, name)
            except subprocess.CalledProcessError:
                continue
            if actual_labels.get("com.kaya.validation.disposable") != "true":
                raise RuntimeError(f"refusing unlabelled cleanup target: {kind} {name}")
            if actual_labels.get("com.docker.compose.project") not in {project, None}:
                raise RuntimeError(f"refusing project-label mismatch: {kind} {name}")
            subprocess.run(
                ["docker", kind, command, "-f", name]
                if kind == "container"
                else ["docker", kind, command, name],
                check=True,
            )
    for raw_path in manifest.get("fixture_paths", []):
        target = Path(raw_path).resolve()
        if target.name.startswith(("phase12", "phase12a")) and target != Path.cwd().resolve() and Path.cwd().resolve() in target.parents:
            shutil.rmtree(target)


def cleanup_compose_project(project: str, dry_run: bool = False) -> list[str]:
    """Remove only volumes/networks bearing this exact Compose project label."""
    if not valid_project(project):
        raise RuntimeError("project name is not a validated disposable phase project")
    removed: list[str] = []
    for kind in ("container", "volume", "network"):
        try:
            list_args = ["docker", kind, "ls"]
            if kind == "container":
                list_args.append("-a")
            format_value = "{{.Names}}" if kind == "container" else "{{.Name}}"
            names = run(*list_args, "--filter", f"label=com.docker.compose.project={project}", "--format", format_value).splitlines()
        except subprocess.CalledProcessError:
            names = []
        for name in filter(None, names):
            validate_name(name, project)
            actual_labels = labels(kind, name)
            if actual_labels.get("com.docker.compose.project") != project:
                raise RuntimeError(f"refusing {kind} with mismatched project label: {name}")
            if name in PROTECTED_NAMES:
                raise RuntimeError(f"refusing protected cleanup target: {name}")
            if dry_run:
                removed.append(f"{kind}:{name}")
            else:
                subprocess.run(["docker", kind, "rm", name], check=True)
                removed.append(f"{kind}:{name}")
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    check = sub.add_parser("validate-config")
    check.add_argument("--project", required=True)
    check.add_argument("--config", type=Path, required=True)
    record = sub.add_parser("record")
    record.add_argument("--project", required=True)
    record.add_argument("--resources", type=Path, required=True)
    record.add_argument("--manifest", type=Path, required=True)
    clean = sub.add_parser("cleanup")
    clean.add_argument("--manifest", type=Path, required=True)
    compose_clean = sub.add_parser("cleanup-compose")
    compose_clean.add_argument("--project", required=True)
    compose_clean.add_argument("--dry-run", action="store_true")
    validate_project = sub.add_parser("validate-project")
    validate_project.add_argument("--project", required=True)
    name = sub.add_parser("phase12a-project")
    name.add_argument("--run-id", required=True)
    name.add_argument("--run-attempt", required=True)
    args = parser.parse_args()
    if args.action == "validate-project":
        if not valid_project(args.project):
            raise SystemExit("invalid disposable validation project")
    elif args.action == "phase12a-project":
        print(phase12a_project_name(args.run_id, args.run_attempt))
    elif args.action == "validate-config":
        resources = validate_config(json.loads(args.config.read_text(encoding="utf-8-sig")), args.project)
        print(json.dumps(resources, sort_keys=True))
    elif args.action == "record":
        resources = json.loads(args.resources.read_text(encoding="utf-8"))
        write_manifest(args.manifest, args.project, resources)
    elif args.action == "cleanup":
        cleanup(args.manifest)
    else:
        print(json.dumps(cleanup_compose_project(args.project, args.dry_run), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
