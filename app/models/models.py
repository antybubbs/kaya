from datetime import datetime
from uuid import uuid4
from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, LargeBinary, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base
from app.services.user_names import user_display_name


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    role: Mapped[str] = mapped_column(String(30), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    authentication_type: Mapped[str] = mapped_column(String(30), default="local", index=True)
    is_break_glass: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    role_source: Mapped[str] = mapped_column(String(30), default="local", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    external_identities = relationship("ExternalIdentity", foreign_keys="ExternalIdentity.user_id", back_populates="user")

    @property
    def display_name(self) -> str:
        return user_display_name(self.first_name, self.last_name, self.email)


class OIDCProvider(Base):
    __tablename__ = "oidc_providers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="OpenID Connect")
    issuer: Mapped[str] = mapped_column(String(1000), default="")
    client_id: Mapped[str] = mapped_column(String(500), default="")
    encrypted_client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    scopes: Mapped[str] = mapped_column(String(500), default="openid profile email")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    use_userinfo: Mapped[bool] = mapped_column(Boolean, default=True)
    require_verified_email: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_jit_provisioning: Mapped[bool] = mapped_column(Boolean, default=False)
    email_matching_mode: Mapped[str] = mapped_column(String(40), default="disabled")
    allowed_email_domains: Mapped[str | None] = mapped_column(Text, nullable=True)
    default_role: Mapped[str] = mapped_column(String(30), default="viewer")
    sync_roles_on_login: Mapped[bool] = mapped_column(Boolean, default=False)
    update_names_on_login: Mapped[bool] = mapped_column(Boolean, default=True)
    update_email_on_login: Mapped[bool] = mapped_column(Boolean, default=False)
    end_session_on_logout: Mapped[bool] = mapped_column(Boolean, default=False)
    email_claim: Mapped[str] = mapped_column(String(255), default="email")
    email_verified_claim: Mapped[str] = mapped_column(String(255), default="email_verified")
    name_claim: Mapped[str] = mapped_column(String(255), default="name")
    first_name_claim: Mapped[str] = mapped_column(String(255), default="given_name")
    last_name_claim: Mapped[str] = mapped_column(String(255), default="family_name")
    preferred_username_claim: Mapped[str] = mapped_column(String(255), default="preferred_username")
    group_claim: Mapped[str] = mapped_column(String(255), default="groups")
    role_mappings_json: Mapped[str] = mapped_column(Text, default="[]")
    group_matching_case_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    discovery_status: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    discovery_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_fetched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    test_login_succeeded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    identities = relationship("ExternalIdentity", back_populates="provider")


class ExternalIdentity(Base):
    __tablename__ = "external_identities"
    __table_args__ = (
        UniqueConstraint("provider_id", "issuer", "subject", name="uq_external_identity_security_key"),
        UniqueConstraint("provider_id", "user_id", name="uq_external_identity_provider_user"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("oidc_providers.id", ondelete="CASCADE"), index=True)
    issuer: Mapped[str] = mapped_column(String(1000), index=True)
    subject: Mapped[str] = mapped_column(String(500), index=True)
    email_at_link_time: Mapped[str | None] = mapped_column(String(255), nullable=True)
    current_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    preferred_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    claims_summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    role_management: Mapped[str] = mapped_column(String(30), default="local")
    linked_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    link_method: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    user = relationship("User", foreign_keys=[user_id], back_populates="external_identities")
    linked_by = relationship("User", foreign_keys=[linked_by_user_id])
    provider = relationship("OIDCProvider", back_populates="identities")


class OIDCTransaction(Base):
    __tablename__ = "oidc_transactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    transaction_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_nonce: Mapped[str] = mapped_column(Text)
    encrypted_code_verifier: Mapped[str] = mapped_column(Text)
    provider_id: Mapped[int] = mapped_column(ForeignKey("oidc_providers.id", ondelete="CASCADE"), index=True)
    flow_type: Mapped[str] = mapped_column(String(40), default="login", index=True)
    target_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    initiated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    return_path: Mapped[str] = mapped_column(String(500), default="/dashboard")
    validated_claims_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)


class OIDCLinkInvitation(Base):
    __tablename__ = "oidc_link_invitations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("oidc_providers.id", ondelete="CASCADE"), index=True)
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)


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
    encrypted_oidc_id_token: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    mac_address: Mapped[str | None] = mapped_column(String(17), index=True, nullable=True)
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
    subnet_cidr: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
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
    failure_threshold: Mapped[int] = mapped_column(Integer, default=3)
    latency_warning_ms: Mapped[int] = mapped_column(Integer, default=150)
    latency_critical_ms: Mapped[int] = mapped_column(Integer, default=500)
    packet_loss_warning_percent: Mapped[int] = mapped_column(Integer, default=20)
    packet_loss_critical_percent: Mapped[int] = mapped_column(Integer, default=60)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_status: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    last_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_packet_loss_percent: Mapped[int | None] = mapped_column(Integer, nullable=True)
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
    packet_loss_percent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    monitor = relationship("NetworkMonitor")


class NetworkMonitorEvent(Base):
    __tablename__ = "network_monitor_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitor_id: Mapped[int] = mapped_column(ForeignKey("network_monitors.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    message: Mapped[str] = mapped_column(String(500))
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    monitor = relationship("NetworkMonitor")


class NetworkMonitorOutage(Base):
    __tablename__ = "network_monitor_outages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitor_id: Mapped[int] = mapped_column(ForeignKey("network_monitors.id"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    failure_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    monitor = relationship("NetworkMonitor")


class NetworkMonitorStatistic(Base):
    __tablename__ = "network_monitor_statistics"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitor_id: Mapped[int] = mapped_column(ForeignKey("network_monitors.id"), index=True)
    bucket_start: Mapped[datetime] = mapped_column(DateTime, index=True)
    bucket_seconds: Mapped[int] = mapped_column(Integer, index=True)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    up_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    avg_packet_loss_percent: Mapped[int | None] = mapped_column(Integer, nullable=True)
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
    ha_cluster_id: Mapped[int | None] = mapped_column(ForeignKey("ha_clusters.id", ondelete="SET NULL"), nullable=True, index=True)
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
    ha_cluster = relationship("HACluster", foreign_keys=[ha_cluster_id], back_populates="dns_providers")


class DNSInvestigation(Base):
    __tablename__ = "dns_investigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[int | None] = mapped_column(ForeignKey("dns_providers.id", ondelete="SET NULL"), nullable=True, index=True)
    domain: Mapped[str] = mapped_column(String(500), index=True)
    client_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    client_ip: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    query_type: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(40), default="open", index=True)
    reply_type: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    reply_time: Mapped[str | None] = mapped_column(String(80), nullable=True)
    upstream: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[str | None] = mapped_column(String(80), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    provider = relationship("DNSProviderConfig")
    created_by = relationship("User")


class DNSInsight(Base):
    __tablename__ = "dns_insights"
    __table_args__ = (UniqueConstraint("provider_id", "insight_key", name="uq_dns_insights_provider_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("dns_providers.id", ondelete="CASCADE"), index=True)
    insight_key: Mapped[str] = mapped_column(String(500), index=True)
    rule_key: Mapped[str] = mapped_column(String(120), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(String(1000))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    entity_type: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    entity_identifier: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)
    current_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    comparison_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    percentage_change: Mapped[float | None] = mapped_column(Float, nullable=True)
    action_type: Mapped[str | None] = mapped_column(String(60), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    provider = relationship("DNSProviderConfig")
    acknowledged_by = relationship("User")


class DHCPRange(Base):
    __tablename__ = "dhcp_ranges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    vlan_id: Mapped[int | None] = mapped_column(ForeignKey("vlans.id", ondelete="SET NULL"), nullable=True, index=True)
    start_address: Mapped[str] = mapped_column(String(80), index=True)
    end_address: Mapped[str] = mapped_column(String(80), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    vlan = relationship("VLAN")


class DNSStatisticsSnapshot(Base):
    __tablename__ = "dns_statistics_snapshots"
    __table_args__ = (UniqueConstraint("provider_id", "period_start", name="uq_dns_snapshots_provider_period"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("dns_providers.id", ondelete="CASCADE"), index=True)
    period_start: Mapped[datetime] = mapped_column(DateTime, index=True)
    period_end: Mapped[datetime] = mapped_column(DateTime, index=True)
    total_queries: Mapped[int | None] = mapped_column(Integer, nullable=True)
    blocked_queries: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failed_queries: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cached_queries: Mapped[int | None] = mapped_column(Integer, nullable=True)
    forwarded_queries: Mapped[int | None] = mapped_column(Integer, nullable=True)
    active_clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    blocking_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    provider_connected: Mapped[bool] = mapped_column(Boolean, default=True)
    client_aggregates_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain_aggregates_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_aggregates_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    capabilities_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    provider = relationship("DNSProviderConfig")


class DNSRecognisedDevice(Base):
    __tablename__ = "dns_recognised_devices"
    __table_args__ = (UniqueConstraint("provider_id", "identity_type", "identity_value", name="uq_dns_devices_provider_identity"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("dns_providers.id", ondelete="CASCADE"), index=True)
    identity_type: Mapped[str] = mapped_column(String(30), index=True)
    identity_value: Mapped[str] = mapped_column(String(500), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    previous_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    current_ip: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    previous_ip: Mapped[str | None] = mapped_column(String(80), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    provider_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    provider_type: Mapped[str] = mapped_column(String(40), default="pihole", index=True)
    friendly_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    normalised_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    normalised_mac: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    is_known: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_ignored: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    linked_ip_record_id: Mapped[int | None] = mapped_column(ForeignKey("ip_addresses.id", ondelete="SET NULL"), nullable=True, index=True)
    suggested_ip_record_id: Mapped[int | None] = mapped_column(ForeignKey("ip_addresses.id", ondelete="SET NULL"), nullable=True, index=True)
    match_confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    match_method: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    observation_source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    query_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_query_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    hardware_asset_id: Mapped[int | None] = mapped_column(ForeignKey("hardware_assets.id", ondelete="SET NULL"), nullable=True, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    is_suppressed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    provider = relationship("DNSProviderConfig")
    hardware_asset = relationship("HardwareAsset")
    linked_ip_record = relationship("IPAddress", foreign_keys=[linked_ip_record_id])
    suggested_ip_record = relationship("IPAddress", foreign_keys=[suggested_ip_record_id])
    ip_history = relationship("DNSClientIPHistory", cascade="all, delete-orphan", back_populates="client")
    hostname_history = relationship("DNSClientHostnameHistory", cascade="all, delete-orphan", back_populates="client")
    events = relationship("DNSClientEvent", cascade="all, delete-orphan", back_populates="client")
    traffic_history = relationship("DNSClientTrafficEvent", cascade="all, delete-orphan", back_populates="client")


class DNSClientIPHistory(Base):
    __tablename__ = "dns_client_ip_history"
    __table_args__ = (UniqueConstraint("dns_client_id", "ip_address", name="uq_dns_client_ip_history"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dns_client_id: Mapped[int] = mapped_column(ForeignKey("dns_recognised_devices.id", ondelete="CASCADE"), index=True)
    ip_address: Mapped[str] = mapped_column(String(80), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    provider_id: Mapped[int | None] = mapped_column(ForeignKey("dns_providers.id", ondelete="SET NULL"), nullable=True, index=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    client = relationship("DNSRecognisedDevice", back_populates="ip_history")


class DNSClientHostnameHistory(Base):
    __tablename__ = "dns_client_hostname_history"
    __table_args__ = (UniqueConstraint("dns_client_id", "normalised_hostname", name="uq_dns_client_hostname_history"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dns_client_id: Mapped[int] = mapped_column(ForeignKey("dns_recognised_devices.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    normalised_hostname: Mapped[str] = mapped_column(String(255), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    provider_id: Mapped[int | None] = mapped_column(ForeignKey("dns_providers.id", ondelete="SET NULL"), nullable=True, index=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    client = relationship("DNSRecognisedDevice", back_populates="hostname_history")


class DNSClientEvent(Base):
    __tablename__ = "dns_client_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dns_client_id: Mapped[int] = mapped_column(ForeignKey("dns_recognised_devices.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    event_summary: Mapped[str] = mapped_column(String(500))
    old_value: Mapped[str | None] = mapped_column(String(500), nullable=True)
    new_value: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    provider_id: Mapped[int | None] = mapped_column(ForeignKey("dns_providers.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    client = relationship("DNSRecognisedDevice", back_populates="events")


class DNSClientTrafficEvent(Base):
    __tablename__ = "dns_client_traffic_events"
    __table_args__ = (UniqueConstraint("provider_id", "event_key", name="uq_dns_client_traffic_provider_event"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dns_client_id: Mapped[int] = mapped_column(ForeignKey("dns_recognised_devices.id", ondelete="CASCADE"), index=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("dns_providers.id", ondelete="CASCADE"), index=True)
    dhcp_lease_id: Mapped[int | None] = mapped_column(ForeignKey("dhcp_lease_history.id", ondelete="SET NULL"), nullable=True, index=True)
    event_key: Mapped[str] = mapped_column(String(64), index=True)
    client_ip: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    domain: Mapped[str] = mapped_column(String(500), index=True)
    query_type: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    status: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    reply_type: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    reply_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    upstream: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    client = relationship("DNSRecognisedDevice", back_populates="traffic_history")
    provider = relationship("DNSProviderConfig")


class HAProviderConnection(Base):
    """A provider connection created and managed from the HA module."""

    __tablename__ = "ha_provider_connections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), default=lambda: str(uuid4()), unique=True, index=True)
    provider_key: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    api_base_url: Mapped[str] = mapped_column(String(500))
    auth_method: Mapped[str] = mapped_column(String(40), default="password")
    encrypted_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssl_verify: Mapped[bool] = mapped_column(Boolean, default=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_by = relationship("User", foreign_keys=[created_by_user_id])


class HACluster(Base):
    __tablename__ = "ha_clusters"
    __table_args__ = (
        Index(
            "uq_ha_clusters_active_virtual_ip",
            "virtual_ip",
            unique=True,
            sqlite_where=text("virtual_ip IS NOT NULL AND deleted_at IS NULL"),
        ),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), default=lambda: str(uuid4()), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider_key: Mapped[str] = mapped_column(String(40), default="pihole", index=True)
    status: Mapped[str] = mapped_column(String(40), default="DRAFT", index=True)
    virtual_ip: Mapped[str | None] = mapped_column(String(80), nullable=True)
    prefix_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authoritative_node_id: Mapped[int | None] = mapped_column(ForeignKey("ha_nodes.id", ondelete="SET NULL"), nullable=True)
    current_active_node_id: Mapped[int | None] = mapped_column(ForeignKey("ha_nodes.id", ondelete="SET NULL"), nullable=True)
    automatic_failover_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    automatic_failback_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    sync_mode: Mapped[str] = mapped_column(String(40), default="active_authoritative")
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    drift_check_interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    maintenance_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    cluster_generation: Mapped[int] = mapped_column(Integer, default=1)
    role_generation: Mapped[int] = mapped_column(Integer, default=1)
    desired_sync_generation: Mapped[int] = mapped_column(Integer, default=0)
    vrrp_router_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    keepalived_generation: Mapped[int] = mapped_column(Integer, default=0)
    keepalived_status: Mapped[str] = mapped_column(String(40), default="NOT_CONFIGURED", index=True)
    keepalived_requested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    keepalived_deployed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_healthy_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_failover_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    nodes = relationship("HANode", foreign_keys="HANode.cluster_id", cascade="all, delete-orphan", back_populates="cluster")
    health_checks = relationship("HAHealthCheck", cascade="all, delete-orphan", back_populates="cluster")
    events = relationship("HAEvent", cascade="all, delete-orphan", back_populates="cluster")
    dns_providers = relationship("DNSProviderConfig", foreign_keys="DNSProviderConfig.ha_cluster_id", back_populates="ha_cluster")
    sync_runs = relationship("HASyncRun", cascade="all, delete-orphan", back_populates="cluster")
    lease_replication = relationship("HALeaseReplicationState", uselist=False, cascade="all, delete-orphan", back_populates="cluster")
    lease_snapshots = relationship("HALeaseSnapshot", cascade="all, delete-orphan", back_populates="cluster")
    created_by = relationship("User", foreign_keys=[created_by_user_id])


class HANode(Base):
    __tablename__ = "ha_nodes"
    __table_args__ = (
        UniqueConstraint("cluster_id", "integration_reference_id", name="uq_ha_nodes_cluster_integration"),
        UniqueConstraint("cluster_id", "ha_connection_id", name="uq_ha_nodes_cluster_connection"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("ha_clusters.id", ondelete="CASCADE"), index=True)
    public_id: Mapped[str] = mapped_column(String(36), default=lambda: str(uuid4()), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    management_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    api_base_url: Mapped[str] = mapped_column(String(500))
    integration_reference_id: Mapped[int | None] = mapped_column(ForeignKey("dns_providers.id", ondelete="SET NULL"), nullable=True, index=True)
    ha_connection_id: Mapped[int | None] = mapped_column(ForeignKey("ha_provider_connections.id", ondelete="SET NULL"), nullable=True, index=True)
    role: Mapped[str] = mapped_column(String(30), index=True)
    desired_role: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(40), default="UNVALIDATED", index=True)
    network_interface: Mapped[str | None] = mapped_column(String(80), nullable=True)
    vrrp_priority: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    agent_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    provider_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    capabilities_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    configuration_snapshot_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    configuration_checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_health_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    observed_role: Mapped[str | None] = mapped_column(String(30), nullable=True)
    observed_generation: Mapped[int] = mapped_column(Integer, default=0)
    vip_owned: Mapped[bool] = mapped_column(Boolean, default=False)
    dhcp_running: Mapped[bool] = mapped_column(Boolean, default=False)
    dns_healthy: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    peer_reachable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    lease_generation: Mapped[int] = mapped_column(Integer, default=0)
    config_generation: Mapped[int] = mapped_column(Integer, default=0)
    keepalived_status: Mapped[str] = mapped_column(String(40), default="NOT_CONFIGURED", index=True)
    keepalived_config_checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    keepalived_backup_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    keepalived_last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    keepalived_reported_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    keepalived_runtime_state: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    cluster = relationship("HACluster", foreign_keys=[cluster_id], back_populates="nodes")
    integration = relationship("DNSProviderConfig")
    ha_connection = relationship("HAProviderConnection")
    agent_credential = relationship("HAAgentCredential", uselist=False, cascade="all, delete-orphan", back_populates="node")


class HAAgentCredential(Base):
    __tablename__ = "ha_agent_credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True, unique=True)
    bootstrap_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True, index=True)
    bootstrap_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    node = relationship("HANode", back_populates="agent_credential")
    requests = relationship("HAAgentRequest", cascade="all, delete-orphan", back_populates="credential")


class HAAgentRequest(Base):
    __tablename__ = "ha_agent_requests"
    __table_args__ = (UniqueConstraint("credential_id", "request_id", name="uq_ha_agent_request_replay"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[int] = mapped_column(ForeignKey("ha_agent_credentials.id", ondelete="CASCADE"), index=True)
    request_id: Mapped[str] = mapped_column(String(80), index=True)
    request_timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    credential = relationship("HAAgentCredential", back_populates="requests")


class HAEvent(Base):
    __tablename__ = "ha_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("ha_clusters.id", ondelete="CASCADE"), index=True)
    node_id: Mapped[int | None] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    message: Mapped[str] = mapped_column(String(1000))
    details_json_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_event_id: Mapped[str | None] = mapped_column(String(80), nullable=True, unique=True, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    acknowledged_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cluster = relationship("HACluster", back_populates="events")
    node = relationship("HANode")
    acknowledged_by = relationship("User")


class HAAgentActionResult(Base):
    __tablename__ = "ha_agent_action_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_id: Mapped[str] = mapped_column(String(180), unique=True, index=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("ha_clusters.id", ondelete="CASCADE"), index=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), index=True)
    action_type: Mapped[str] = mapped_column(String(60), index=True)
    generation: Mapped[int] = mapped_column(Integer, index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    backup_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    message_redacted: Mapped[str] = mapped_column(String(1000))
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    cluster = relationship("HACluster")
    node = relationship("HANode")


class HALeaseReplicationState(Base):
    """Current lease staging state, deliberately separate from DNS Manager history."""

    __tablename__ = "ha_lease_replication_states"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("ha_clusters.id", ondelete="CASCADE"), unique=True, index=True)
    source_node_id: Mapped[int | None] = mapped_column(ForeignKey("ha_nodes.id", ondelete="SET NULL"), nullable=True, index=True)
    target_node_id: Mapped[int | None] = mapped_column(ForeignKey("ha_nodes.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(30), default="NOT_APPLICABLE", index=True)
    desired_generation: Mapped[int] = mapped_column(Integer, default=0)
    applied_generation: Mapped[int] = mapped_column(Integer, default=0)
    lease_count: Mapped[int] = mapped_column(Integer, default=0)
    difference_count: Mapped[int] = mapped_column(Integer, default=0)
    conflict_count: Mapped[int] = mapped_column(Integer, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_full_reconciliation_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_applied_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error_redacted: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    cluster = relationship("HACluster", back_populates="lease_replication")
    source_node = relationship("HANode", foreign_keys=[source_node_id])
    target_node = relationship("HANode", foreign_keys=[target_node_id])


class HALeaseSnapshot(Base):
    """Encrypted, validated HA lease snapshot; never used as DNS Manager history."""

    __tablename__ = "ha_lease_snapshots"
    __table_args__ = (UniqueConstraint("cluster_id", "generation", name="uq_ha_lease_snapshot_generation"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), default=lambda: str(uuid4()), unique=True, index=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("ha_clusters.id", ondelete="CASCADE"), index=True)
    source_node_id: Mapped[int] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), index=True)
    target_node_id: Mapped[int] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), index=True)
    generation: Mapped[int] = mapped_column(Integer, index=True)
    checksum: Mapped[str] = mapped_column(String(64), index=True)
    encrypted_payload: Mapped[str] = mapped_column(Text)
    lease_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(30), default="PENDING", index=True)
    validation_summary_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    staged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cluster = relationship("HACluster", back_populates="lease_snapshots")
    source_node = relationship("HANode", foreign_keys=[source_node_id])
    target_node = relationship("HANode", foreign_keys=[target_node_id])


class HASyncRun(Base):
    __tablename__ = "ha_sync_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), default=lambda: str(uuid4()), unique=True, index=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("ha_clusters.id", ondelete="CASCADE"), index=True)
    source_node_id: Mapped[int] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), index=True)
    target_node_id: Mapped[int] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="PLANNED", index=True)
    plan_json: Mapped[str] = mapped_column(Text)
    error_redacted: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    cluster = relationship("HACluster", back_populates="sync_runs")
    source_node = relationship("HANode", foreign_keys=[source_node_id])
    target_node = relationship("HANode", foreign_keys=[target_node_id])
    created_by = relationship("User")
    backups = relationship("HABackup", cascade="all, delete-orphan", back_populates="sync_run")
    drift_items = relationship("HADriftItem", cascade="all, delete-orphan", back_populates="sync_run")


class HABackup(Base):
    __tablename__ = "ha_backups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sync_run_id: Mapped[int] = mapped_column(ForeignKey("ha_sync_runs.id", ondelete="CASCADE"), index=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), index=True)
    encrypted_snapshot: Mapped[str] = mapped_column(Text)
    checksum: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    sync_run = relationship("HASyncRun", back_populates="backups")
    node = relationship("HANode")


class HADriftItem(Base):
    __tablename__ = "ha_drift_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sync_run_id: Mapped[int] = mapped_column(ForeignKey("ha_sync_runs.id", ondelete="CASCADE"), index=True)
    group_key: Mapped[str] = mapped_column(String(80), index=True)
    risk: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(30), default="DRIFT", index=True)
    source_checksum: Mapped[str] = mapped_column(String(64))
    target_checksum: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(String(1000))
    sync_run = relationship("HASyncRun", back_populates="drift_items")


class HAHealthCheck(Base):
    __tablename__ = "ha_health_checks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("ha_clusters.id", ondelete="CASCADE"), index=True)
    node_id: Mapped[int | None] = mapped_column(ForeignKey("ha_nodes.id", ondelete="CASCADE"), nullable=True, index=True)
    check_key: Mapped[str] = mapped_column(String(120), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(String(1000))
    technical_detail_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    cluster = relationship("HACluster", back_populates="health_checks")
    node = relationship("HANode")


class DHCPLeaseHistory(Base):
    """A time-bounded DHCP address assignment retained independently of the provider."""

    __tablename__ = "dhcp_lease_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[int | None] = mapped_column(ForeignKey("dns_providers.id", ondelete="SET NULL"), nullable=True, index=True)
    dns_client_id: Mapped[int | None] = mapped_column(ForeignKey("dns_recognised_devices.id", ondelete="SET NULL"), nullable=True, index=True)
    dhcp_range_id: Mapped[int | None] = mapped_column(ForeignKey("dhcp_ranges.id", ondelete="SET NULL"), nullable=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(80), index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    provider_lease_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    lease_started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    provider = relationship("DNSProviderConfig")
    client = relationship("DNSRecognisedDevice")
    dhcp_range = relationship("DHCPRange")


class DashboardPreference(Base):
    __tablename__ = "dashboard_preferences"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    preference_version: Mapped[int] = mapped_column(Integer, default=1)
    layout_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = relationship("User")


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
    view_count: Mapped[int] = mapped_column(Integer, default=0, index=True)
    last_viewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
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


class RunbookImage(Base):
    __tablename__ = "runbook_images"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    original_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_type: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    uploaded_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    uploaded_by = relationship("User")


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


# Secret Vault stores only encrypted user-facing values.  The small amount of
# plaintext metadata below is deliberately limited to identifiers, versions,
# sizes and access-control state needed before a vault is unlocked.
class Vault(Base):
    __tablename__ = "vaults"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    pin_hash: Mapped[str] = mapped_column(String(255))
    pin_salt: Mapped[str] = mapped_column(String(120))
    pin_wrapped_key: Mapped[str] = mapped_column(Text)
    recovery_hash: Mapped[str] = mapped_column(String(255))
    recovery_salt: Mapped[str] = mapped_column(String(120))
    recovery_wrapped_key: Mapped[str] = mapped_column(Text)
    app_wrapped_key: Mapped[str] = mapped_column(Text)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    auto_lock_minutes: Mapped[int] = mapped_column(Integer, default=10)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    recovery_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner = relationship("User")


class VaultSession(Base):
    __tablename__ = "vault_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vault_id: Mapped[int] = mapped_column(ForeignKey("vaults.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    app_session_id: Mapped[str] = mapped_column(String(120), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    nonce: Mapped[str] = mapped_column(String(120))
    authentication_method: Mapped[str] = mapped_column(String(40), default="pin_totp")
    unlocked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)


class VaultTotpUse(Base):
    __tablename__ = "vault_totp_uses"
    __table_args__ = (UniqueConstraint("user_id", "counter", name="uq_vault_totp_user_counter"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    counter: Mapped[int] = mapped_column(Integer, index=True)
    used_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class VaultCollection(Base):
    __tablename__ = "vault_collections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vault_id: Mapped[int] = mapped_column(ForeignKey("vaults.id", ondelete="CASCADE"), index=True)
    encrypted_payload: Mapped[str] = mapped_column(Text)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    is_private: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class VaultCollectionMember(Base):
    __tablename__ = "vault_collection_members"
    __table_args__ = (UniqueConstraint("collection_id", "user_id", name="uq_vault_collection_member"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    collection_id: Mapped[int] = mapped_column(ForeignKey("vault_collections.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    permission: Mapped[str] = mapped_column(String(40), default="viewer")
    encrypted_collection_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class VaultItem(Base):
    __tablename__ = "vault_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vault_id: Mapped[int] = mapped_column(ForeignKey("vaults.id", ondelete="CASCADE"), index=True)
    collection_id: Mapped[int | None] = mapped_column(ForeignKey("vault_collections.id", ondelete="SET NULL"), nullable=True, index=True)
    item_type: Mapped[str] = mapped_column(String(40), index=True)
    encrypted_payload: Mapped[str] = mapped_column(Text)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    is_favourite: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    updated_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class VaultItemVersion(Base):
    __tablename__ = "vault_item_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("vault_items.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    encrypted_payload: Mapped[str] = mapped_column(Text)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    saved_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class VaultAttachment(Base):
    __tablename__ = "vault_attachments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("vault_items.id", ondelete="CASCADE"), index=True)
    storage_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    encrypted_metadata: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    ciphertext_size: Mapped[int] = mapped_column(Integer, default=0)
    integrity_hash: Mapped[str] = mapped_column(String(64))
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class VaultBackupRecord(Base):
    __tablename__ = "vault_backup_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vault_id: Mapped[int] = mapped_column(ForeignKey("vaults.id", ondelete="CASCADE"), index=True)
    operation: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    format_version: Mapped[int] = mapped_column(Integer, default=1)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


# Secure Send retains only encrypted recipient/content metadata. Public URLs,
# PINs and passphrases are represented by hashes or encrypted recovery copies;
# sequential database identifiers are never exposed by recipient routes.
class SecureSendPackage(Base):
    __tablename__ = "secure_send_packages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    internal_recipient_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    recipient_type: Mapped[str] = mapped_column(String(20), default="external", index=True)
    access_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_access_token: Mapped[str] = mapped_column(Text)
    credential_hash: Mapped[str] = mapped_column(String(255))
    credential_salt: Mapped[str] = mapped_column(String(120))
    credential_wrapped_key: Mapped[str] = mapped_column(Text)
    app_wrapped_key: Mapped[str] = mapped_column(Text)
    encrypted_summary: Mapped[str] = mapped_column(Text)
    encrypted_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="active", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    one_download_only: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    allow_vault_save: Mapped[bool] = mapped_column(Boolean, default=False)
    notify_when_opened: Mapped[bool] = mapped_column(Boolean, default=True)
    download_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    opened_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    authenticated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    expired_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    cleaned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    sender = relationship("User", foreign_keys=[sender_id])
    internal_recipient = relationship("User", foreign_keys=[internal_recipient_id])


class SecureSendFile(Base):
    __tablename__ = "secure_send_files"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("secure_send_packages.id", ondelete="CASCADE"), index=True)
    storage_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    encrypted_metadata: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    ciphertext_size: Mapped[int] = mapped_column(Integer, default=0)
    integrity_hash: Mapped[str] = mapped_column(String(64))
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class SecureSendRecipientSession(Base):
    __tablename__ = "secure_send_recipient_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("secure_send_packages.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)


class SecureSendActivity(Base):
    __tablename__ = "secure_send_activities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("secure_send_packages.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    encrypted_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
