import re
from pathlib import Path


WORKFLOW = Path(".github/workflows/docker.yml").read_text(encoding="utf-8")
MAKEFILE = Path("Makefile").read_text(encoding="utf-8")
STABLE_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


def workflow_step(name: str) -> str:
    match = re.search(
        rf"      - name: {re.escape(name)}\n(?P<body>.*?)(?=\n      - name:|\Z)",
        WORKFLOW,
        re.DOTALL,
    )
    assert match is not None
    return match.group("body")


def test_publish_permissions_are_job_scoped_and_least_privilege():
    workflow_defaults, _, jobs = WORKFLOW.partition("jobs:")
    assert re.search(r"^permissions: \{\}$", workflow_defaults, re.MULTILINE)
    assert "packages: write" not in workflow_defaults

    publish_job = re.search(
        r"^  container:\n(?P<header>.*?)(?=^    steps:)",
        jobs,
        re.MULTILINE | re.DOTALL,
    )
    assert publish_job is not None
    assert "permissions:\n      contents: read\n      packages: write" in publish_job.group("header")
    assert WORKFLOW.count("packages: write") == 1
    assert "contents: write" not in WORKFLOW
    assert "actions: write" not in WORKFLOW
    assert "pull-requests: write" not in WORKFLOW


def test_only_published_releases_can_reach_the_latest_tag():
    trigger = WORKFLOW.partition("permissions:")[0]
    assert "release:" in trigger
    assert "- published" in trigger
    assert "tags:" not in trigger

    release = workflow_step("Build and push release image")
    assert "github.event_name == 'release'" in release
    assert "steps.meta.outputs.stable_release == 'true'" in release
    assert "${{ steps.meta.outputs.image }}:latest" in release

    assert WORKFLOW.count("${{ steps.meta.outputs.image }}:latest") == 1


def test_published_prereleases_get_version_images_without_latest():
    metadata = workflow_step("Set image metadata")
    prerelease = workflow_step("Build and push prerelease image")

    assert "RELEASE_PRERELEASE" in metadata
    assert "v[0-9]+\\.[0-9]+\\.[0-9]+-(dev|rc)\\.[0-9]+" in metadata
    assert "CHECKOUT_REF=\"$RELEASE_TAG\"" in metadata
    assert "github.event_name == 'release'" in prerelease
    assert "APP_VERSION=${{ steps.meta.outputs.version }}" in prerelease
    assert "${{ steps.meta.outputs.image }}:${{ steps.meta.outputs.version }}" in prerelease
    assert ":latest" not in prerelease


def test_branch_builds_cannot_publish_latest_and_keep_expected_versions():
    metadata = workflow_step("Set image metadata")
    main = workflow_step("Build and push main commit image")
    development = workflow_step("Build and push development branch image")
    kaya = workflow_step("Build and push Kaya branch image")

    assert 'VERSION="$SHORT_SHA"' in metadata
    assert "- dev" in WORKFLOW
    assert '[[ "$REF" == refs/heads/dev* ]]' in metadata
    assert 'VERSION="$REF_TAG"' in metadata

    assert "refs/heads/main" in main
    assert "APP_VERSION=${{ steps.meta.outputs.version }}" in main
    assert "${{ steps.meta.outputs.short_sha }}" in main

    assert "refs/heads/dev" in development
    assert "APP_VERSION=${{ steps.meta.outputs.version }}" in development
    assert "${{ steps.meta.outputs.ref_tag }}" in development
    assert "${{ steps.meta.outputs.ref_tag }}-${{ steps.meta.outputs.short_sha }}" in development

    assert "refs/heads/Kaya" in kaya
    assert "APP_VERSION=${{ steps.meta.outputs.version }}" in kaya
    assert kaya.count("${{ steps.meta.outputs.image }}:") == 1

    for step in (main, development, kaya):
        assert ":latest" not in step


def test_dev_branch_publishes_moving_and_commit_specific_tags_without_release():
    trigger = WORKFLOW.partition("permissions:")[0]
    development = workflow_step("Build and push development branch image")

    assert "      - dev\n" in trigger
    assert "startsWith(github.ref, 'refs/heads/dev')" in development
    assert "${{ steps.meta.outputs.image }}:${{ steps.meta.outputs.ref_tag }}" in development
    assert "${{ steps.meta.outputs.image }}:${{ steps.meta.outputs.ref_tag }}-${{ steps.meta.outputs.short_sha }}" in development
    assert ":latest" not in development
    assert "gh release" not in development


def test_stable_release_validation_is_strict_semver_without_suffixes():
    allowed = ["v0.25.1", "v0.26.0", "v1.0.0", "v10.12.3"]
    rejected = ["v0.26", "v0.26.0-dev", "v0.26.0-beta", "vtest", "version1", "dev0.26.0"]

    assert all(STABLE_TAG.fullmatch(tag) for tag in allowed)
    assert not any(STABLE_TAG.fullmatch(tag) for tag in rejected)
    assert "grep -Eq '^v[0-9]+\\.[0-9]+\\.[0-9]+$'" in WORKFLOW
    assert "LATEST_RELEASE_TAG" in WORKFLOW
    assert 'LATEST_RELEASE_TAG" != "$RELEASE_TAG' in WORKFLOW
    assert "VERSION=\"$RELEASE_TAG\"" in WORKFLOW


def test_release_lifecycle_tag_formats_are_distinct_and_ordered_by_semver():
    prerelease = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+-(dev|rc)\.[0-9]+$")
    assert all(prerelease.fullmatch(tag) for tag in (
        "v0.28.0-dev.1", "v0.28.0-dev.2", "v0.28.0-rc.1", "v0.28.0-rc.2",
    ))
    assert STABLE_TAG.fullmatch("v0.28.0")
    assert not prerelease.fullmatch("v0.28.0")
    assert not STABLE_TAG.fullmatch("v0.28.0-rc.1")


def test_release_command_creates_a_github_release_after_validating_version():
    assert "grep -Eq '^v[0-9]+\\.[0-9]+\\.[0-9]+$$'" in MAKEFILE
    assert 'gh release create "$(VERSION)" --verify-tag --generate-notes --title "$(VERSION)"' in MAKEFILE


def test_release_commands_mark_only_prereleases_as_prerelease():
    assert "release-dev:" in MAKEFILE
    assert "release-rc:" in MAKEFILE
    assert "^v[0-9]+\\.[0-9]+\\.[0-9]+-dev\\.[0-9]+$$" in MAKEFILE
    assert "^v[0-9]+\\.[0-9]+\\.[0-9]+-rc\\.[0-9]+$$" in MAKEFILE
    assert MAKEFILE.count("--prerelease") == 2


def test_production_deployments_stay_on_latest():
    expected = "ghcr.io/antybubbs/kaya:latest"
    assert expected in Path("docker-compose.yml").read_text(encoding="utf-8")
    assert expected in Path("install-kaya.sh").read_text(encoding="utf-8")
