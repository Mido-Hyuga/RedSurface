"""
Port Intelligence Plugin — Wrapper around modules/port_intel.py.

Uses Shodan API to passively enrich IPs with:
  - Open ports and services
  - Operating system detection
  - Known vulnerabilities
  - Geolocation (country, city)
  - Organization info
  - Service banners
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class PortIntelPlugin(PluginBase):
    name = "Port Intelligence"
    description = (
        "Passive port/service enumeration via Shodan API. Discovers open ports, "
        "services, OS, vulnerabilities, and geolocation for target IPs."
    )
    category = PluginCategory.DISCOVERY
    api_type = ApiType.TIERED
    requires_api_key = True
    api_key_names = ["SHODAN_KEY"]
    result_types = ["port", "service", "vulnerability"]
    website = "https://www.shodan.io/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="service")
        try:
            import socket
            from modules.port_intel import PortIntel

            port_intel = PortIntel(
                shodan_api_key=self.api_keys.get("SHODAN_KEY"),
                rate_limit_delay=(config or {}).get("rate_limit", 1.0),
                timeout=(config or {}).get("timeout", 15.0),
            )

            # Resolve target to IP first
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                result.errors.append(f"Could not resolve {target} to IP")
                result.success = False
                return result

            # Query Shodan for this IP
            host_intel = await port_intel.query_ip_async(ip)

            if host_intel is None:
                result.values = []
                result.metadata = {"ip": ip, "note": "No Shodan data available"}
                return result

            values = []
            hi = host_intel.to_dict()

            # Ports and services
            for port in hi.get("ports", []):
                values.append(f"{ip}:{port}")

            # Vulnerabilities
            for vuln in hi.get("vulns", []):
                values.append(f"VULN: {vuln}")

            result.values = values
            result.metadata = {
                "ip": ip,
                "os": hi.get("os"),
                "org": hi.get("org"),
                "isp": hi.get("isp"),
                "country": hi.get("country"),
                "city": hi.get("city"),
                "ports": hi.get("ports", []),
                "services": hi.get("services", []),
                "vulns": hi.get("vulns", []),
                "tags": hi.get("tags", []),
                "last_update": hi.get("last_update"),
                "hostnames": hi.get("hostnames", []),
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
