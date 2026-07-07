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

    def test_blocks_security_network_checks(self):
        self.assertTrue(self.blocked("GET", "/system/site-administration/security/public-ip"))
        self.assertTrue(self.blocked("GET", "/system/site-administration/security/inbound"))

    def test_allows_read_only_module_pages(self):
        self.assertFalse(self.blocked("GET", "/networking/dns-manager"))
        self.assertFalse(self.blocked("GET", "/infrastructure/backup-manager"))


if __name__ == "__main__":
    unittest.main()
