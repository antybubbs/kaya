from datetime import datetime
from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base


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
