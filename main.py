import argparse
import json
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from ipaddress import ip_address
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import whois
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


VERSION = "1.1.0"
DEFAULT_TIMEOUT = 5
console = Console()


class TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data


@dataclass
class DNSInfo:
    target: str
    is_ip: bool
    resolved_ips: List[str]
    reverse_dns: List[str]
    txt_records: List[str]
    mx_records: List[str]
    ns_records: List[str]


@dataclass
class HTTPInfo:
    final_url: Optional[str]
    status_code: Optional[int]
    reason: Optional[str]
    server: Optional[str]
    content_type: Optional[str]
    content_length: Optional[str]
    title: Optional[str]
    response_time_ms: Optional[float]
    redirect_chain: List[str]
    security_headers: Dict[str, Optional[str]]
    headers: Dict[str, str]
    robots_txt_available: Optional[bool]


@dataclass
class TLSInfo:
    hostname: Optional[str]
    tls_supported: bool
    subject: Dict[str, str]
    issuer: Dict[str, str]
    san: List[str]
    not_before: Optional[str]
    not_after: Optional[str]


@dataclass
class IPGeoInfo:
    ip: str
    country: Optional[str]
    region: Optional[str]
    city: Optional[str]
    isp: Optional[str]
    org: Optional[str]
    as_name: Optional[str]


@dataclass
class WhoisInfo:
    registrar: Optional[str]
    creation_date: Optional[str]
    expiration_date: Optional[str]
    updated_date: Optional[str]
    name_servers: List[str]
    status: List[str]
    emails: List[str]


def print_banner() -> None:
    console.print(
        Panel.fit(
            f"[bold]Network Recon Toolkit[/bold]\nVersion: {VERSION}",
            border_style="cyan",
        )
    )


def normalize_target(raw: str) -> Tuple[str, Optional[str], bool]:
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty target.")

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = parsed.hostname or raw
    try:
        ip_address(host)
        return host, parsed.geturl(), True
    except ValueError:
        return host.lower(), parsed.geturl(), False


def resolve_ips(host: str) -> List[str]:
    ips = set()
    try:
        for item in socket.getaddrinfo(host, None):
            sockaddr = item[4]
            if sockaddr and len(sockaddr) > 0:
                ips.add(sockaddr[0])
    except socket.gaierror:
        return []
    return sorted(ips)


def reverse_dns_lookup(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


def query_dns_records(host: str, record_type: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(host, record_type)
        return [str(r).rstrip(".") for r in answers]
    except Exception:
        return []


def gather_dns_info(target: str, is_ip: bool) -> DNSInfo:
    if is_ip:
        rdns = reverse_dns_lookup(target)
        return DNSInfo(
            target=target,
            is_ip=True,
            resolved_ips=[target],
            reverse_dns=[rdns] if rdns else [],
            txt_records=[],
            mx_records=[],
            ns_records=[],
        )

    ips = resolve_ips(target)
    reverse_names = []
    for ip in ips:
        rdns = reverse_dns_lookup(ip)
        if rdns:
            reverse_names.append(rdns)

    txt_records = query_dns_records(target, "TXT")
    mx_records = query_dns_records(target, "MX")
    ns_records = query_dns_records(target, "NS")

    return DNSInfo(
        target=target,
        is_ip=False,
        resolved_ips=ips,
        reverse_dns=sorted(set(reverse_names)),
        txt_records=txt_records,
        mx_records=mx_records,
        ns_records=ns_records,
    )


def extract_title(html_text: str) -> Optional[str]:
    parser = TitleParser()
    try:
        parser.feed(html_text)
        title = parser.title.strip()
        return title or None
    except Exception:
        return None


def pick_url_candidates(target: str, original_url: Optional[str]) -> List[str]:
    candidates: List[str] = []

    if original_url:
        candidates.append(original_url)

    if target.startswith("http://") or target.startswith("https://"):
        candidates.append(target)
    else:
        candidates.append(f"https://{target}")
        candidates.append(f"http://{target}")

    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def fetch_http_info(target: str, original_url: Optional[str], timeout: int) -> HTTPInfo:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": f"NetworkReconToolkit/{VERSION}",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )

    last_error = None
    for candidate in pick_url_candidates(target, original_url):
        try:
            start = time.perf_counter()
            resp = session.get(candidate, timeout=timeout, allow_redirects=True)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

            title = extract_title(resp.text[:200000]) if "text/html" in resp.headers.get("Content-Type", "") else None
            redirect_chain = [r.url for r in resp.history] + [resp.url]

            security_headers = {
                "strict-transport-security": resp.headers.get("Strict-Transport-Security"),
                "content-security-policy": resp.headers.get("Content-Security-Policy"),
                "x-frame-options": resp.headers.get("X-Frame-Options"),
                "x-content-type-options": resp.headers.get("X-Content-Type-Options"),
                "referrer-policy": resp.headers.get("Referrer-Policy"),
                "permissions-policy": resp.headers.get("Permissions-Policy"),
            }

            robots_available = None
            try:
                robots = session.get(f"{resp.url.rstrip('/')}/robots.txt", timeout=timeout, allow_redirects=True)
                robots_available = robots.status_code == 200
            except requests.RequestException:
                robots_available = None

            return HTTPInfo(
                final_url=resp.url,
                status_code=resp.status_code,
                reason=resp.reason,
                server=resp.headers.get("Server"),
                content_type=resp.headers.get("Content-Type"),
                content_length=resp.headers.get("Content-Length"),
                title=title,
                response_time_ms=elapsed_ms,
                redirect_chain=redirect_chain,
                security_headers=security_headers,
                headers=dict(resp.headers),
                robots_txt_available=robots_available,
            )
        except requests.RequestException as exc:
            last_error = exc

    return HTTPInfo(
        final_url=None,
        status_code=None,
        reason=str(last_error) if last_error else None,
        server=None,
        content_type=None,
        content_length=None,
        title=None,
        response_time_ms=None,
        redirect_chain=[],
        security_headers={},
        headers={},
        robots_txt_available=None,
    )


def parse_name_items(items: Tuple[Tuple[Tuple[str, str], ...], ...]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for entry in items:
        for key, value in entry:
            result[key] = value
    return result


def fetch_tls_info(host: str, timeout: int) -> TLSInfo:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        san = [value for typ, value in cert.get("subjectAltName", []) if typ == "DNS"]
        return TLSInfo(
            hostname=host,
            tls_supported=True,
            subject=parse_name_items(cert.get("subject", ())),
            issuer=parse_name_items(cert.get("issuer", ())),
            san=san,
            not_before=cert.get("notBefore"),
            not_after=cert.get("notAfter"),
        )
    except Exception:
        return TLSInfo(
            hostname=host,
            tls_supported=False,
            subject={},
            issuer={},
            san=[],
            not_before=None,
            not_after=None,
        )


def fetch_ip_geo(ip: str, timeout: int) -> IPGeoInfo:
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=timeout)
        data = resp.json()
        return IPGeoInfo(
            ip=ip,
            country=data.get("country"),
            region=data.get("regionName"),
            city=data.get("city"),
            isp=data.get("isp"),
            org=data.get("org"),
            as_name=data.get("as"),
        )
    except Exception:
        return IPGeoInfo(
            ip=ip,
            country=None,
            region=None,
            city=None,
            isp=None,
            org=None,
            as_name=None,
        )


def to_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def first_value_as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def fetch_whois_info(host: str) -> WhoisInfo:
    try:
        data = whois.whois(host)
        return WhoisInfo(
            registrar=first_value_as_str(data.registrar),
            creation_date=first_value_as_str(data.creation_date),
            expiration_date=first_value_as_str(data.expiration_date),
            updated_date=first_value_as_str(data.updated_date),
            name_servers=to_list(data.name_servers),
            status=to_list(data.status),
            emails=to_list(data.emails),
        )
    except Exception:
        return WhoisInfo(
            registrar=None,
            creation_date=None,
            expiration_date=None,
            updated_date=None,
            name_servers=[],
            status=[],
            emails=[],
        )


def build_report(target_input: str, timeout: int) -> Dict[str, Any]:
    normalized_target, original_url, is_ip = normalize_target(target_input)

    dns_info = gather_dns_info(normalized_target, is_ip)
    geo_info = [fetch_ip_geo(ip, timeout) for ip in dns_info.resolved_ips[:3]]
    http_info = fetch_http_info(normalized_target, original_url, timeout)
    tls_info = fetch_tls_info(normalized_target, timeout) if not is_ip else TLSInfo(
        hostname=None,
        tls_supported=False,
        subject={},
        issuer={},
        san=[],
        not_before=None,
        not_after=None,
    )
    whois_info = fetch_whois_info(normalized_target) if not is_ip else WhoisInfo(
        registrar=None,
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        name_servers=[],
        status=[],
        emails=[],
    )

    return {
        "input": target_input,
        "normalized_target": normalized_target,
        "dns": asdict(dns_info),
        "ip_geolocation": [asdict(x) for x in geo_info],
        "http": asdict(http_info),
        "tls": asdict(tls_info),
        "whois": asdict(whois_info),
    }


def print_simple_table(title: str, rows: List[Tuple[str, Any]]) -> None:
    table = Table(title=title)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    for key, value in rows:
        table.add_row(key, str(value))
    console.print(table)


def print_list_table(title: str, values: List[str], col_name: str = "Value") -> None:
    table = Table(title=title)
    table.add_column(col_name, style="white")
    if values:
        for v in values:
            table.add_row(v)
    else:
        table.add_row("None")
    console.print(table)


def run_console_report(result: Dict[str, Any]) -> None:
    dns = result["dns"]
    http = result["http"]
    tls = result["tls"]
    who = result["whois"]

    print_simple_table(
        "Target",
        [
            ("Input", result["input"]),
            ("Normalized", result["normalized_target"]),
            ("Type", "IP" if dns["is_ip"] else "Domain"),
        ],
    )

    print_simple_table(
        "DNS",
        [
            ("Resolved IPs", ", ".join(dns["resolved_ips"]) if dns["resolved_ips"] else "None"),
            ("Reverse DNS", ", ".join(dns["reverse_dns"]) if dns["reverse_dns"] else "None"),
        ],
    )

    print_list_table("DNS TXT Records", dns["txt_records"])
    print_list_table("DNS MX Records", dns["mx_records"])
    print_list_table("DNS NS Records", dns["ns_records"])

    for item in result["ip_geolocation"]:
        print_simple_table(
            f"IP Geolocation - {item['ip']}",
            [
                ("Country", item.get("country") or "Unknown"),
                ("Region", item.get("region") or "Unknown"),
                ("City", item.get("city") or "Unknown"),
                ("ISP", item.get("isp") or "Unknown"),
                ("Org", item.get("org") or "Unknown"),
                ("ASN", item.get("as_name") or "Unknown"),
            ],
        )

    print_simple_table(
        "HTTP",
        [
            ("Final URL", http.get("final_url") or "Unavailable"),
            ("Status", http.get("status_code") or "Unavailable"),
            ("Reason", http.get("reason") or "Unavailable"),
            ("Title", http.get("title") or "Unavailable"),
            ("Server", http.get("server") or "Unavailable"),
            ("Content-Type", http.get("content_type") or "Unavailable"),
            ("Content-Length", http.get("content_length") or "Unavailable"),
            ("Response Time (ms)", http.get("response_time_ms") or "Unavailable"),
            ("robots.txt", http.get("robots_txt_available")),
        ],
    )

    print_list_table("Redirect Chain", http.get("redirect_chain", []), "URL")

    sec_headers = http.get("security_headers", {})
    print_simple_table(
        "Security Headers",
        [(k, v or "Missing") for k, v in sec_headers.items()],
    )

    print_simple_table(
        "TLS",
        [
            ("Supported", tls.get("tls_supported")),
            ("Issued To", tls.get("subject", {}).get("commonName", "Unknown")),
            ("Issued By", tls.get("issuer", {}).get("commonName", "Unknown")),
            ("Valid From", tls.get("not_before") or "Unavailable"),
            ("Valid To", tls.get("not_after") or "Unavailable"),
            ("SAN Count", len(tls.get("san", []))),
        ],
    )

    print_simple_table(
        "WHOIS",
        [
            ("Registrar", who.get("registrar") or "Unavailable"),
            ("Created", who.get("creation_date") or "Unavailable"),
            ("Updated", who.get("updated_date") or "Unavailable"),
            ("Expires", who.get("expiration_date") or "Unavailable"),
        ],
    )
    print_list_table("WHOIS Name Servers", who.get("name_servers", []))
    print_list_table("WHOIS Status", who.get("status", []))
    print_list_table("WHOIS Emails", who.get("emails", []))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Passive reconnaissance toolkit for owned or authorized targets."
    )
    parser.add_argument("target", help="Domain, IP, or URL")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout in seconds")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Print JSON")
    parser.add_argument("--output", help="Write JSON output to file")
    args = parser.parse_args()

    print_banner()

    try:
        report = build_report(args.target, args.timeout)
    except ValueError as exc:
        console.print(f"[red][ERROR][/red] {exc}")
        return 1

    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        run_console_report(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            console.print(f"\n[green]Saved report to:[/green] {args.output}")
        except OSError as exc:
            console.print(f"[red][ERROR][/red] Could not write output file: {exc}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
