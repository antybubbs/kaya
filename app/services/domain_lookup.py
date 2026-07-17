import json
import re
import socket
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from app.core.performance import external_call

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - dependency is installed in the app image
    dns = None


DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_rdap_bootstrap: dict | None = None
WHOIS_FIELD_MAP = {
    "registrar": {"registrar", "sponsoring registrar"},
    "expires_at": {"registry expiry date", "registrar registration expiration date", "expiration date", "expiry date", "paid-till", "renewal date"},
    "status": {"domain status", "status"},
    "nameservers": {"name server", "nserver", "nameserver"},
}
WHOIS_FALLBACK_SERVERS = {
    "za": "whois.registry.net.za",
}


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    domain = domain.removeprefix("http://").removeprefix("https://").split("/")[0].split(":")[0]
    if not DOMAIN_PATTERN.match(domain):
        raise ValueError("Enter a valid domain name.")
    return domain


def parse_rdap_date(value: str | None) -> datetime | None:
    if not value:
        return None
    clean = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(clean).replace(tzinfo=None)
    except ValueError:
        return None


def parse_whois_date(value: str | None) -> datetime | None:
    if not value:
        return None
    clean = value.strip().replace("Z", "+00:00")
    for pattern in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(clean, pattern).replace(tzinfo=None)
        except ValueError:
            continue
    return parse_rdap_date(clean)


def rdap_event_date(data: dict, actions: set[str]) -> datetime | None:
    for event in data.get("events", []):
        if event.get("eventAction") in actions:
            parsed = parse_rdap_date(event.get("eventDate"))
            if parsed:
                return parsed
    return None


def entity_name(entity: dict) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            value = str(item[3]).strip()
            if value:
                return value
    return None


def registrar_from_rdap(data: dict) -> str | None:
    for entity in data.get("entities", []):
        roles = set(entity.get("roles", []))
        if "registrar" in roles:
            return entity_name(entity)
    return None


def nameservers_from_rdap(data: dict) -> list[str]:
    nameservers = []
    for row in data.get("nameservers", []):
        name = str(row.get("ldhName") or row.get("unicodeName") or "").strip().lower().rstrip(".")
        if name and name not in nameservers:
            nameservers.append(name)
    return nameservers


def infer_dns_provider(nameservers: list[str]) -> str | None:
    if not nameservers:
        return None
    nameserver = nameservers[0].lower().rstrip(".")
    if "ui-dns." in nameserver:
        return "IONOS"
    parts = [part for part in nameserver.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return nameserver


def fetch_json(url: str) -> dict:
    request = Request(url, headers={"Accept": "application/rdap+json, application/json"})
    with external_call():
        with urlopen(request, timeout=8) as response:
            return json.loads(response.read().decode("utf-8"))


def rdap_bootstrap() -> dict:
    global _rdap_bootstrap
    if _rdap_bootstrap is None:
        _rdap_bootstrap = fetch_json(RDAP_BOOTSTRAP_URL)
    return _rdap_bootstrap


def rdap_urls_for(domain: str) -> list[str]:
    labels = domain.split(".")
    candidates = [".".join(labels[index:]) for index in range(len(labels))]
    services = rdap_bootstrap().get("services", [])
    matches: list[tuple[int, str]] = []
    for suffix in candidates:
        for service_labels, urls in services:
            if suffix in service_labels:
                matches.extend((suffix.count("."), url.rstrip("/") + f"/domain/{domain}") for url in urls)
    matches.sort(reverse=True)
    return [url for _, url in matches]


def lookup_rdap(domain: str) -> dict:
    errors = []
    try:
        urls = rdap_urls_for(domain)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        urls = []
        errors.append(f"IANA RDAP bootstrap failed: {exc}")

    urls.append(f"https://rdap.org/domain/{domain}")
    for url in dict.fromkeys(urls):
        try:
            return fetch_json(url)
        except HTTPError as exc:
            errors.append(f"{url} returned HTTP {exc.code}")
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            errors.append(f"{url} failed: {exc}")
    raise LookupError("; ".join(errors) or "No RDAP service returned registration data.")


def query_whois(server: str, query: str) -> str:
    with external_call():
        with socket.create_connection((server, 43), timeout=8) as sock:
            sock.sendall((query + "\r\n").encode("utf-8"))
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def whois_server_for(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1]
    response = query_whois("whois.iana.org", tld)
    for line in response.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "whois":
            server = value.strip()
            if server:
                return server
    return WHOIS_FALLBACK_SERVERS.get(tld)


def parse_whois_response(response: str) -> dict:
    result: dict[str, object] = {"nameservers": []}
    for line in response.splitlines():
        if not line or line.startswith("%") or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        clean_key = key.strip().lower()
        clean_value = value.strip()
        if not clean_value:
            continue
        if clean_key in WHOIS_FIELD_MAP["registrar"] and not result.get("registrar"):
            result["registrar"] = clean_value
        elif clean_key in WHOIS_FIELD_MAP["expires_at"] and not result.get("expires_at"):
            result["expires_at"] = parse_whois_date(clean_value)
        elif clean_key in WHOIS_FIELD_MAP["status"] and not result.get("status"):
            result["status"] = clean_value
        elif clean_key in WHOIS_FIELD_MAP["nameservers"]:
            nameserver = clean_value.split()[0].lower().rstrip(".")
            if nameserver and nameserver not in result["nameservers"]:
                result["nameservers"].append(nameserver)
    return result


def lookup_whois(domain: str) -> dict:
    server = whois_server_for(domain)
    if not server:
        raise LookupError("No WHOIS server published by IANA.")
    return parse_whois_response(query_whois(server, domain))


def lookup_dns(domain: str) -> dict[str, list[str]]:
    if dns is None:
        raise RuntimeError("DNS lookup dependency is not installed.")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    records: dict[str, list[str]] = {}
    for record_type in DNS_TYPES:
        try:
            with external_call():
                answers = resolver.resolve(domain, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[record_type] = []
            continue
        except (dns.exception.DNSException, socket.timeout) as exc:
            records[record_type] = [f"Lookup failed: {exc}"]
            continue
        records[record_type] = [answer.to_text().strip('"').rstrip(".") for answer in answers]
    return records


def lookup_domain(domain: str) -> dict:
    clean_domain = normalize_domain(domain)
    errors = []
    rdap_data: dict = {}
    whois_data: dict = {}
    dns_records: dict[str, list[str]] = {}

    try:
        rdap_data = lookup_rdap(clean_domain)
    except LookupError as exc:
        registration_error = str(exc)
        try:
            whois_data = lookup_whois(clean_domain)
        except (LookupError, OSError, TimeoutError) as whois_exc:
            errors.append(f"Registration lookup unavailable: RDAP failed: {registration_error}; WHOIS failed: {whois_exc}")

    try:
        dns_records = lookup_dns(clean_domain)
    except Exception as exc:  # noqa: BLE001 - lookup failures should be stored, not raised to users
        errors.append(f"DNS lookup failed: {exc}")

    nameservers = nameservers_from_rdap(rdap_data)
    if not nameservers:
        nameservers = whois_data.get("nameservers", [])
    if not nameservers:
        nameservers = dns_records.get("NS", [])

    status_values = rdap_data.get("status") or []
    return {
        "name": clean_domain,
        "registrar": registrar_from_rdap(rdap_data) or whois_data.get("registrar"),
        "dns_provider": infer_dns_provider(nameservers),
        "status": ", ".join(status_values) if status_values else whois_data.get("status"),
        "expires_at": rdap_event_date(rdap_data, {"expiration", "expiry"}) or whois_data.get("expires_at"),
        "nameservers": nameservers,
        "dns_records": dns_records,
        "lookup_error": "\n".join(errors) or None,
        "last_lookup_at": datetime.utcnow(),
    }
