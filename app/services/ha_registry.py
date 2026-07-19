from dataclasses import dataclass


@dataclass(frozen=True)
class HAProvider:
    key: str
    name: str
    maturity: str
    description: str
    capabilities: tuple[str, ...]
    category: str
    selectable: bool = True


SUPPORTED_HA_PROVIDERS = (
    HAProvider(
        key="pihole",
        name="Pi-hole",
        maturity="Beta",
        description="DNS filtering and local DNS high availability.",
        capabilities=("Health monitoring", "Configuration comparison", "Controlled synchronisation"),
        category="DNS and DHCP",
    ),
)


def provider_for_key(key: str) -> HAProvider | None:
    return next((provider for provider in SUPPORTED_HA_PROVIDERS if provider.key == key), None)
