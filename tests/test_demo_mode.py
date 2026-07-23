import unittest
from types import SimpleNamespace
from unittest.mock import patch
import sys
import types

config_stub = types.ModuleType("app.core.config")
config_stub.get_settings = lambda: SimpleNamespace(demo_mode=False)
sys.modules.setdefault("app.core.config", config_stub)
from app.core.demo import demo_request_is_blocked


class DemoModeSafetyTests(unittest.TestCase):
    def blocked(self, method: str, path: str) -> bool:
        settings = SimpleNamespace(demo_mode=True)
        with patch("app.core.demo.get_settings", return_value=settings):
            return demo_request_is_blocked(method, path)

    def test_blocks_backup_manager_mutations(self):
        self.assertTrue(self.blocked("POST", "/infrastructure/backup-manager/manual"))
        self.assertTrue(self.blocked("POST", "/infrastructure/backup-manager/docker/1/backup"))
        self.assertTrue(self.blocked("GET", "/infrastructure/backup-manager/api/agent/jobs"))

    def test_blocks_dns_investigation_mutation(self):
        self.assertTrue(self.blocked("POST", "/networking/dns-manager/investigations"))
        self.assertTrue(self.blocked("POST", "/networking/dns-manager/known-hostnames"))
        self.assertTrue(self.blocked("POST", "/networking/dns-manager/blocklists/update"))
        self.assertTrue(self.blocked("POST", "/networking/dns-manager/insights/analyse"))
        self.assertTrue(self.blocked("POST", "/networking/dns-manager/insights/42/acknowledge"))

    def test_blocks_security_network_checks(self):
        self.assertTrue(self.blocked("GET", "/system/site-administration/security/public-ip"))
        self.assertTrue(self.blocked("GET", "/system/site-administration/security/inbound"))

    def test_blocks_all_destructive_delete_routes(self):
        paths = (
            "/networking/vlan-ip-manager/ip-addresses/1/delete",
            "/security/license-keys/1/delete",
            "/infrastructure/hardware-assets/1/delete",
            "/infrastructure/hardware-assets/1/attachments/2/delete",
            "/network-monitor/1/delete",
            "/networking/dns-manager/investigations/1/delete",
            "/infrastructure/backup-manager/manual/1/delete",
            "/documentation/runbook-manager/pages/1/delete",
            "/documentation/runbook-manager/spaces/1/delete",
            "/infrastructure/rack-manager/racks/1/delete",
            "/infrastructure/vm-docker-manager/hosts/1/delete",
            "/networking/domains/1/delete",
            "/system/site-administration/custom-fields/1/delete",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(self.blocked("POST", path))

    def test_blocks_shared_dashboard_preference_changes(self):
        self.assertTrue(self.blocked("PUT", "/api/dashboard/preferences"))
        self.assertTrue(self.blocked("POST", "/api/dashboard/preferences/reset"))
        self.assertFalse(self.blocked("GET", "/api/dashboard/snapshot"))

    def test_blocks_oidc_provider_flows_in_public_demo(self):
        self.assertTrue(self.blocked("GET", "/auth/oidc/login"))
        self.assertTrue(self.blocked("GET", "/auth/oidc/callback"))

    def test_blocks_high_availability_network_and_mutating_paths(self):
        paths = (
            "/high-availability/clusters/test-connection",
            "/high-availability/clusters",
            "/high-availability/clusters/demo/validate",
            "/high-availability/clusters/demo/deployment",
            "/high-availability/clusters/demo/synchronisation/plan",
            "/high-availability/clusters/demo/synchronisation/automatic",
            "/high-availability/clusters/demo/synchronisation/apply",
            "/high-availability/clusters/demo/testing/start",
            "/high-availability/clusters/demo/nodes/node/agent/bootstrap",
            "/high-availability/clusters/demo/nodes/node/agent/revoke",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(self.blocked("POST", path))
        self.assertFalse(self.blocked("GET", "/high-availability/clusters/demo"))
        self.assertFalse(self.blocked("GET", "/high-availability/clusters/demo/live"))

    def test_blocks_all_high_availability_agent_api_paths(self):
        self.assertTrue(self.blocked("GET", "/api/ha/agent/v1/install.sh"))
        self.assertTrue(self.blocked("GET", "/api/ha/agent/v1/files/update.sh"))
        self.assertTrue(self.blocked("POST", "/api/ha/agent/v1/register"))
        self.assertTrue(self.blocked("POST", "/api/ha/agent/v1/heartbeat"))

    def test_allows_read_only_module_pages(self):
        self.assertFalse(self.blocked("GET", "/networking/dns-manager"))
        self.assertFalse(self.blocked("GET", "/infrastructure/backup-manager"))


if __name__ == "__main__":
    unittest.main()
