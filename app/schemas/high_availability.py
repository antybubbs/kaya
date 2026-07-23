from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class HAAgentMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HAAgentRegister(HAAgentMessage):
    cluster_id: str = Field(min_length=36, max_length=36)
    node_id: str = Field(min_length=36, max_length=36)
    bootstrap_token: str = Field(min_length=32, max_length=200)
    public_key: str = Field(min_length=40, max_length=100)
    agent_version: str = Field(min_length=1, max_length=80)
    protocol_version: int = Field(default=1, ge=1, le=1)


class HAAgentHeartbeat(HAAgentMessage):
    observed_role: str = Field(pattern="^(ACTIVE|STANDBY|FAULT|UNKNOWN)$")
    observed_generation: int = Field(ge=0)
    vip_owned: bool
    dhcp_running: bool
    dns_healthy: bool
    peer_reachable: bool
    lease_generation: int = Field(default=0, ge=0)
    config_generation: int = Field(default=0, ge=0)
    agent_version: str = Field(min_length=1, max_length=80)
    keepalived_runtime_state: str = Field(default="UNKNOWN", pattern="^(RUNNING|STOPPED|FAULT|UNKNOWN)$")


class HAAgentActionResult(HAAgentMessage):
    action_id: str = Field(min_length=20, max_length=180, pattern=r"^[A-Za-z0-9._:-]+$")
    action_type: str = Field(pattern="^(KEEPALIVED_APPLY|LEASE_SNAPSHOT_STAGE|DHCP_DEMOTE|DHCP_PROMOTE)$")
    generation: int = Field(ge=1)
    status: str = Field(pattern="^(APPLIED|FAILED)$")
    checksum: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    backup_reference: str | None = Field(default=None, max_length=255, pattern=r"^[A-Za-z0-9._:-]+$")
    message: str = Field(min_length=1, max_length=1000)


class HAAgentEventItem(HAAgentMessage):
    event_id: str = Field(min_length=8, max_length=80, pattern=r"^[A-Za-z0-9._:-]+$")
    event_type: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_]+$")
    severity: str = Field(pattern="^(info|warning|error|critical)$")
    message: str = Field(min_length=1, max_length=1000)
    occurred_at: datetime
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class HAAgentEvents(HAAgentMessage):
    events: list[HAAgentEventItem] = Field(min_length=1, max_length=100)


class HANodeDraftCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    api_base_url: str = Field(min_length=1, max_length=500)
    secret: str | None = Field(default=None, max_length=2000)
    ssl_verify: bool = True


class HANodeUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    api_base_url: str = Field(min_length=1, max_length=500)
    secret: str | None = Field(default=None, max_length=2000)
    ssl_verify: bool = True
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    network_interface: str | None = Field(default=None, max_length=80)


class HAClusterDraftCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    provider_key: str = Field(default="pihole", min_length=1, max_length=40)
    primary: HANodeDraftCreate
    secondary: HANodeDraftCreate
    virtual_ip: str | None = None
    prefix_length: int | None = Field(default=None, ge=1, le=32)


class HANodeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    public_id: str
    display_name: str
    api_base_url: str
    integration_reference_id: int | None
    ha_connection_id: int | None
    role: str
    desired_role: str
    status: str
    provider_version: str | None
    capabilities_json: str | None
    configuration_checksum: str | None
    agent_version: str | None
    last_heartbeat_at: datetime | None
    observed_role: str | None
    observed_generation: int
    vip_owned: bool
    dhcp_running: bool
    config_generation: int
    network_interface: str | None
    vrrp_priority: int | None
    keepalived_status: str
    keepalived_config_checksum: str | None
    keepalived_last_error: str | None
    keepalived_reported_at: datetime | None
    keepalived_runtime_state: str


class HAHealthCheckRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    check_key: str
    status: str
    severity: str
    summary: str
    technical_detail_redacted: str | None
    remediation: str | None
    observed_at: datetime


class HAConfigurationDifferenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    group_key: str
    group_label: str
    primary_value: str
    secondary_value: str
    proposed_value: str
    source_of_truth: str
    risk: str


class HAClusterRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    public_id: str
    name: str
    description: str | None
    provider_key: str
    status: str
    virtual_ip: str | None
    prefix_length: int | None
    cluster_generation: int
    role_generation: int
    vrrp_router_id: int | None
    keepalived_generation: int
    keepalived_status: str
    keepalived_requested_at: datetime | None
    keepalived_deployed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    nodes: list[HANodeRead]
    health_checks: list[HAHealthCheckRead]
