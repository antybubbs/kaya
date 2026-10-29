import dns.exception
import dns.name
import pytest

import app.services.domain_lookup as domain_lookup


def test_dns_parser_rejects_forward_compression_pointers():
    with pytest.raises(dns.exception.DNSException):
        dns.name.from_wire(b"\xc0\x02\x00", 0)


def test_lookup_dns_converts_resolver_timeout_to_safe_record_errors(monkeypatch):
    class TimeoutResolver:
        timeout = None
        lifetime = None

        def resolve(self, domain, record_type):
            raise dns.exception.Timeout("synthetic timeout")

    monkeypatch.setattr(domain_lookup.dns.resolver, "Resolver", TimeoutResolver)

    records = domain_lookup.lookup_dns("example.com")

    assert set(records) == set(domain_lookup.DNS_TYPES)
    assert all(value == ["Lookup failed: synthetic timeout"] for value in records.values())


def test_lookup_dns_preserves_empty_results_for_nonexistent_records(monkeypatch):
    class Resolver:
        timeout = None
        lifetime = None

        def resolve(self, domain, record_type):
            if record_type in {"A", "AAAA"}:
                raise dns.resolver.NXDOMAIN()
            raise dns.resolver.NoAnswer()

    monkeypatch.setattr(domain_lookup.dns.resolver, "Resolver", Resolver)

    assert domain_lookup.lookup_dns("example.com") == {
        record_type: [] for record_type in domain_lookup.DNS_TYPES
    }
