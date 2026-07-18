from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class HAClusterDraftCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    provider_key: str = Field(default="pihole", pattern="^pihole$")
    primary_integration_id: int
    secondary_integration_id: int
    virtual_ip: str | None = None
    prefix_length: int | None = Field(default=None, ge=1, le=32)


class HANodeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    public_id: str
    display_name: str
    api_base_url: str
    integration_reference_id: int | None
    role: str
    desired_role: str
    status: str


class HAHealthCheckRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    check_key: str
    status: str
    severity: str
    summary: str
    technical_detail_redacted: str | None
    observed_at: datetime


class HAClusterRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    public_id: str
    name: str
    description: str | None
    provider_key: str
    status: str
    virtual_ip: str | None
    prefix_length: int | None
    created_at: datetime
    updated_at: datetime
    nodes: list[HANodeRead]
