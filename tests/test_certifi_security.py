from importlib.metadata import version
from pathlib import Path


FIXED_CERTIFI_VERSION = (2026, 10, 19)


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".")[:3])


def test_certifi_is_directly_pinned_to_a_security_fixed_version():
    requirements = Path(__file__).parents[1].joinpath("requirements.txt").read_text(encoding="utf-8")
    pins = [line.strip() for line in requirements.splitlines() if line.strip().lower().startswith("certifi")]
    assert pins == ["certifi==2026.10.19"]
    assert _version_tuple(version("certifi")) >= FIXED_CERTIFI_VERSION
