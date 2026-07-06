from datetime import datetime
from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    first_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    role: Mapped[str] = mapped_column(String(30), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    user = relationship("User")


class AppSession(Base):
    __tablename__ = "app_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(80), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    user = relationship("User")


class Licence(Base):
    __tablename__ = "licences"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    licence_id: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    parent_program: Mapped[str | None] = mapped_column(String(255), nullable=True)
    organisation: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    product: Mapped[str] = mapped_column(String(500), index=True)
    vendor: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    encrypted_product_key: Mapped[str] = mapped_column(Text)
    licence_type: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    activations: Mapped[str | None] = mapped_column(String(120), nullable=True)
    seats: Mapped[int | None] = mapped_column(Integer, nullable=True)
    osa_status: Mapped[str | None] = mapped_column(String(120), nullable=True)
    expiry_date: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    is_favourite: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IPAddress(Base):
    __tablename__ = "ip_addresses"
    __table_args__ = (UniqueConstraint("vlan_id", "address", name="uq_ip_addresses_vlan_address"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vlan_id: Mapped[int | None] = mapped_column(ForeignKey("vlans.id"), nullable=True, index=True)
    address: Mapped[str] = mapped_column(String(80), index=True)
    category: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    name: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    assignment_type: Mapped[str] = mapped_column(String(20), default="Static")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    vlan = relationship("VLAN")


class VLAN(Base):
    __tablename__ = "vlans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class NetworkMonitor(Base):
    __tablename__ = "network_monitors"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address_id: Mapped[int] = mapped_column(ForeignKey("ip_addresses.id"), unique=True, index=True)
    check_type: Mapped[str] = mapped_column(String(30), default="icmp")
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    timeout_ms: Mapped[int] = mapped_column(Integer, default=2000)
    notify_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_status: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    last_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ip_address = relationship("IPAddress")


class NetworkMonitorCheck(Base):
    __tablename__ = "network_monitor_checks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitor_id: Mapped[int] = mapped_column(ForeignKey("network_monitors.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    monitor = relationship("NetworkMonitor")


class RemoteAccess(Base):
    __tablename__ = "remote_access"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address_id: Mapped[int] = mapped_column(ForeignKey("ip_addresses.id"), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    protocol: Mapped[str] = mapped_column(String(20), default="ssh", index=True)
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str | None] = mapped_column(String(120), nullable=True)
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(120), nullable=True)
    terminal_settings: Mapped[str | None] = mapped_column(Text, nullable=True)
    rdp_settings: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ip_address = relationship("IPAddress")


class RemoteManagerSetting(Base):
    __tablename__ = "remote_manager_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RemoteSessionRecording(Base):
    __tablename__ = "remote_session_recordings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    remote_access_id: Mapped[int | None] = mapped_column(ForeignKey("remote_access.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    remote_label: Mapped[str] = mapped_column(String(255), index=True)
    remote_address: Mapped[str | None] = mapped_column(String(80), nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), index=True)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    trigger: Mapped[str] = mapped_column(String(30), default="manual", index=True)
    status: Mapped[str] = mapped_column(String(30), default="complete", index=True)
    stored_filename: Mapped[str] = mapped_column(String(500))
    original_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    remote = relationship("RemoteAccess")
    user = relationship("User")


class DomainRecord(Base):
    __tablename__ = "domain_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    dns_provider: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    nameservers: Mapped[str | None] = mapped_column(Text, nullable=True)
    lookup_registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lookup_dns_provider: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lookup_status: Mapped[str | None] = mapped_column(String(120), nullable=True)
    lookup_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lookup_nameservers: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_records: Mapped[str | None] = mapped_column(Text, nullable=True)
    lookup_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_lookup_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DomainRecordHistory(Base):
    __tablename__ = "domain_record_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int | None] = mapped_column(ForeignKey("domain_records.id", ondelete="SET NULL"), nullable=True, index=True)
    domain_name: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(30), default="scheduled", index=True)
    changes: Mapped[str] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    domain = relationship("DomainRecord")


class DNSProviderConfig(Base):
    __tablename__ = "dns_providers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider_type: Mapped[str] = mapped_column(String(40), default="pihole", index=True)
    base_url: Mapped[str] = mapped_column(String(500))
    auth_method: Mapped[str] = mapped_column(String(40), default="password")
    encrypted_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssl_verify: Mapped[bool] = mapped_column(Boolean, default=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class HardwareAsset(Base):
    __tablename__ = "hardware_assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_tag: Mapped[str | None] = mapped_column(String(120), unique=True, index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    status: Mapped[str] = mapped_column(String(80), default="In use", index=True)
    manufacturer: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    purchase_date: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    purchase_cost: Mapped[str | None] = mapped_column(String(80), nullable=True)
    warranty_expires: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    supplier: Mapped[str | None] = mapped_column(String(255), nullable=True)
    photo_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class HardwareAssetAttachment(Base):
    __tablename__ = "hardware_asset_attachments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("hardware_assets.id"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    stored_filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    asset = relationship("HardwareAsset")

class Rack(Base):
    __tablename__ = "racks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    height_u: Mapped[int] = mapped_column(Integer, default=42)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    items = relationship("RackItem", back_populates="rack", cascade="all, delete-orphan")


class RackItem(Base):
    __tablename__ = "rack_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rack_id: Mapped[int] = mapped_column(ForeignKey("racks.id"), index=True)
    hardware_asset_id: Mapped[int | None] = mapped_column(ForeignKey("hardware_assets.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    start_u: Mapped[int] = mapped_column(Integer)
    height_u: Mapped[int] = mapped_column(Integer, default=1)
    mount_side: Mapped[str] = mapped_column(String(20), default="front", index=True)
    color: Mapped[str | None] = mapped_column(String(40), nullable=True)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    rack = relationship("Rack", back_populates="items")
    hardware_asset = relationship("HardwareAsset")

class CustomField(Base):
    __tablename__ = "custom_fields"
    __table_args__ = (UniqueConstraint("module", "field_key", name="uq_custom_fields_module_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    module: Mapped[str] = mapped_column(String(80), index=True)
    label: Mapped[str] = mapped_column(String(120))
    field_key: Mapped[str] = mapped_column(String(120), index=True)
    field_type: Mapped[str] = mapped_column(String(30), default="text")
    options: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_required: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CustomFieldValue(Base):
    __tablename__ = "custom_field_values"
    __table_args__ = (UniqueConstraint("field_id", "entity_type", "entity_id", name="uq_custom_field_values_entity"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    field_id: Mapped[int] = mapped_column(ForeignKey("custom_fields.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(80), index=True)
    entity_id: Mapped[int] = mapped_column(Integer, index=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    field = relationship("CustomField")


class ManagedListItem(Base):
    __tablename__ = "managed_list_items"
    __table_args__ = (UniqueConstraint("module", "list_key", "value", name="uq_managed_list_items_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    module: Mapped[str] = mapped_column(String(80), index=True)
    list_key: Mapped[str] = mapped_column(String(80), index=True)
    value: Mapped[str] = mapped_column(String(120), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RunbookSpace(Base):
    __tablename__ = "runbook_spaces"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RunbookPage(Base):
    __tablename__ = "runbook_pages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    space_id: Mapped[int | None] = mapped_column(ForeignKey("runbook_spaces.id"), nullable=True, index=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("runbook_pages.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), index=True)
    slug: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)
    is_pinned: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    space = relationship("RunbookSpace")
    parent = relationship("RunbookPage", remote_side=[id])
    created_by = relationship("User", foreign_keys=[created_by_id])
    updated_by = relationship("User", foreign_keys=[updated_by_id])


class RunbookPageHistory(Base):
    __tablename__ = "runbook_page_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    page_id: Mapped[int] = mapped_column(ForeignKey("runbook_pages.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(String(500), nullable=True)
    saved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    saved_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    page = relationship("RunbookPage")
    saved_by = relationship("User")


class ComputeHost(Base):
    __tablename__ = "compute_hosts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    platform: Mapped[str] = mapped_column(String(30), index=True)
    base_url: Mapped[str] = mapped_column(String(500))
    token_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True, index=True)
    # Retained only so startup can migrate tokens created by early agent builds.
    # New and regenerated tokens never write to this column.
    encrypted_agent_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, default=30)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    memory_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    storage_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    storage_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ComputeWorkload(Base):
    __tablename__ = "compute_workloads"
    __table_args__ = (UniqueConstraint("host_id", "kind", "external_id", name="uq_compute_workload_external"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("compute_hosts.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    node: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(30), default="unknown", index=True)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_total: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    memory_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    storage_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    storage_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uptime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    backup_policy: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    host = relationship("ComputeHost")


class ComputeInventoryItem(Base):
    __tablename__ = "compute_inventory_items"
    __table_args__ = (UniqueConstraint("host_id", "kind", "external_id", name="uq_compute_inventory_external"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("compute_hosts.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(500), index=True)
    name: Mapped[str] = mapped_column(String(500), index=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    host = relationship("ComputeHost")


class ComputeMetric(Base):
    __tablename__ = "compute_metrics"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("compute_hosts.id"), index=True)
    workload_id: Mapped[int | None] = mapped_column(ForeignKey("compute_workloads.id"), nullable=True, index=True)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    memory_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    storage_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    storage_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class ComputeEvent(Base):
    __tablename__ = "compute_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("compute_hosts.id"), index=True)
    workload_id: Mapped[int | None] = mapped_column(ForeignKey("compute_workloads.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    detail: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class BackupRecord(Base):
    __tablename__ = "backup_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    source_type: Mapped[str] = mapped_column(String(40), default="manual", index=True)
    source_ref: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)
    target: Mapped[str | None] = mapped_column(String(500), nullable=True)
    schedule: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    last_status: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BackupJob(Base):
    __tablename__ = "backup_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("compute_hosts.id"), index=True)
    workload_id: Mapped[int | None] = mapped_column(ForeignKey("compute_workloads.id"), nullable=True, index=True)
    operation: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(40), default="queued", index=True)
    encryption_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    encrypted_backup_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_path: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    log: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    host = relationship("ComputeHost")
    workload = relationship("ComputeWorkload")
    requested_by = relationship("User")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    entity: Mapped[str] = mapped_column(String(80), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(80), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(40), default="activity", index=True)
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    request_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    request_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    user = relationship("User")
