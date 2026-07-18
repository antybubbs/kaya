from dataclasses import dataclass


@dataclass(frozen=True)
class HAProvider:
    key: str
    name: str
    maturity: str
    description: str
    capabilities: tuple[str, ...]


SUPPORTED_HA_PROVIDERS = (
    HAProvider(
        key="pihole",
        name="Pi-hole",
        maturity="Beta",
        description="DNS filtering and local DNS high availability.",
        capabilities=("Health monitoring", "Configuration comparison", "Controlled synchronisation"),
    ),
)
