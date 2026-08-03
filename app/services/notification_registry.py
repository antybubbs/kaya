"""Single, reviewable catalogue of notification event contracts."""

from dataclasses import dataclass


@dataclass(frozen=True)
class NotificationType:
    identifier: str
    module: str
    category: str
    display_name: str
    default_severity: str
    default_channels: tuple[str, ...] = ("in_app",)
    user_configurable: bool = True
    recovery: bool = False
    sensitive_payload: bool = False
    supported_channels: tuple[str, ...] = ("in_app", "push", "email")
    recipient_strategy: str = "module_access"
    deduplication_strategy: str = "operation_specific"
    implemented_publisher: str | None = None
    automated_test_present: bool = False


_ROWS = (
    (
        "system.notification.test",
        "system",
        "system",
        "Notification diagnostic",
        "info",
    ),
    (
        "system.web_push.keys_rotated",
        "system",
        "security",
        "Web Push keys rotated",
        "warning",
    ),
    ("system.update.available", "system", "system", "Kaya update available", "info"),
    (
        "system.background_task.failed",
        "system",
        "system",
        "Background task failure",
        "critical",
    ),
    ("system.security.warning", "system", "security", "Security warning", "critical"),
    (
        "ipwan.host.offline",
        "network_monitor",
        "host_status",
        "Host offline",
        "critical",
    ),
    (
        "ipwan.host.recovered",
        "network_monitor",
        "host_status",
        "Host recovered",
        "success",
    ),
    ("ipwan.wan.offline", "network_monitor", "wan_status", "WAN offline", "critical"),
    (
        "ipwan.wan.recovered",
        "network_monitor",
        "wan_status",
        "WAN recovered",
        "success",
    ),
    (
        "ipwan.latency.threshold_exceeded",
        "network_monitor",
        "performance",
        "High latency",
        "warning",
    ),
    (
        "ipwan.packet_loss.threshold_exceeded",
        "network_monitor",
        "performance",
        "Packet loss threshold exceeded",
        "warning",
    ),
    (
        "ipwan.monitoring.failed",
        "network_monitor",
        "monitoring",
        "Monitoring failure",
        "critical",
    ),
    ("backup.job.failed", "backup_manager", "backup", "Backup failed", "critical"),
    (
        "backup.job.warning",
        "backup_manager",
        "backup",
        "Backup completed with warnings",
        "warning",
    ),
    ("backup.job.overdue", "backup_manager", "backup", "Backup overdue", "warning"),
    (
        "pihole.cluster.degraded",
        "high_availability",
        "pihole",
        "Pi-hole cluster degraded",
        "warning",
    ),
    (
        "pihole.cluster.recovered",
        "high_availability",
        "pihole",
        "Pi-hole cluster recovered",
        "success",
    ),
    (
        "pihole.node.unreachable",
        "high_availability",
        "pihole",
        "Pi-hole node unreachable",
        "critical",
    ),
    (
        "pihole.failover.started",
        "high_availability",
        "pihole",
        "Failover started",
        "warning",
    ),
    (
        "pihole.failover.completed",
        "high_availability",
        "pihole",
        "Failover completed",
        "success",
    ),
    (
        "pihole.failover.failed",
        "high_availability",
        "pihole",
        "Failover failed",
        "critical",
    ),
    (
        "pihole.failback.started",
        "high_availability",
        "pihole",
        "Failback started",
        "warning",
    ),
    (
        "pihole.failback.completed",
        "high_availability",
        "pihole",
        "Failback completed",
        "success",
    ),
    (
        "pihole.failback.failed",
        "high_availability",
        "pihole",
        "Failback failed",
        "critical",
    ),
    (
        "pihole.sync.failed",
        "high_availability",
        "pihole",
        "Synchronisation failed",
        "critical",
    ),
    (
        "certificate.expiring",
        "domain_manager",
        "certificate",
        "Certificate expiring",
        "warning",
    ),
    (
        "certificate.expired",
        "domain_manager",
        "certificate",
        "Certificate expired",
        "critical",
    ),
    ("licence.expiring", "licence_manager", "licence", "Licence expiring", "warning"),
    ("licence.expired", "licence_manager", "licence", "Licence expired", "critical"),
    (
        "secure_vault.security_event",
        "secret_vault",
        "vault_security",
        "Vault security event",
        "critical",
    ),
    (
        "secure_vault.backup_failed",
        "secret_vault",
        "vault_security",
        "Vault backup failed",
        "critical",
    ),
    (
        "secure_send.item.accessed",
        "secure_send",
        "secure_send",
        "Secure item accessed",
        "info",
    ),
    (
        "secure_send.item.expired",
        "secure_send",
        "secure_send",
        "Secure item expired",
        "info",
    ),
    (
        "secure_send.item.revoked",
        "secure_send",
        "secure_send",
        "Secure item revoked",
        "warning",
    ),
)

_IMPLEMENTED_PUBLISHERS = {
    "system.notification.test": "notification_outbox",
    "system.web_push.keys_rotated": "notification_service",
    "system.background_task.failed": "notification_supervisor_outbox",
    "ipwan.host.offline": "network_monitor_transition_outbox",
    "ipwan.host.recovered": "network_monitor_transition_outbox",
    "backup.job.failed": "backup_job_outbox",
    "pihole.cluster.degraded": "ha_outbox",
    "pihole.cluster.recovered": "ha_outbox",
    "pihole.node.unreachable": "ha_outbox",
    "pihole.failover.started": "ha_outbox",
    "pihole.failover.completed": "ha_outbox",
    "pihole.failover.failed": "ha_outbox",
    "pihole.failback.started": "ha_outbox",
    "pihole.failback.completed": "ha_outbox",
    "pihole.failback.failed": "ha_outbox",
    "pihole.sync.failed": "ha_outbox",
}
_ACTIVE_CONDITION_EVENTS = {
    "ipwan.host.offline",
    "ipwan.wan.offline",
    "pihole.cluster.degraded",
    "pihole.node.unreachable",
    "backup.job.overdue",
    "certificate.expiring",
    "certificate.expired",
    "licence.expiring",
    "licence.expired",
}


EVENT_TYPES = {
    row[0]: NotificationType(
        *row,
        recovery=row[0].endswith(".recovered"),
        sensitive_payload=row[0].startswith(("secure_vault.", "secure_send.")),
        recipient_strategy="administrators" if row[1] == "system" else "module_access",
        deduplication_strategy=(
            "active_condition"
            if row[0] in _ACTIVE_CONDITION_EVENTS
            else "operation_specific"
        ),
        implemented_publisher=_IMPLEMENTED_PUBLISHERS.get(row[0]),
        automated_test_present=row[0] in _IMPLEMENTED_PUBLISHERS,
    )
    for row in _ROWS
}
SEVERITY_ORDER = {"info": 0, "success": 1, "warning": 2, "critical": 3}


def event_type(identifier: str) -> NotificationType:
    try:
        return EVENT_TYPES[identifier]
    except KeyError as exc:
        raise ValueError("Unknown notification event type") from exc
