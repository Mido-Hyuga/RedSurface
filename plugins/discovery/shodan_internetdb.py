"""
Shodan InternetDB — Free, no-key-needed IP enrichment.
Provides ports, hostnames, CPEs, vulns, and tags for any IP.
https://internetdb.shodan.io/
"""
import socket
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class ShodanInternetDBPlugin(PluginBase):
    name = "Shodan InternetDB"
    description = (
        "Free Shodan IP lookup (no API key). Returns open ports, hostnames, "
        "CPEs, known vulnerabilities, and tags for the target IP."
    )
    category = PluginCategory.DISCOVERY
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["port", "vulnerability", "hostname"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="port")
        try:
            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                result.errors.append(f"Could not resolve {target}")
                result.success = False
                return result

            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(f"https://internetdb.shodan.io/{ip}")
                if resp.status_code != 200:
                    result.errors.append(f"InternetDB returned {resp.status_code}")
                    return result

                data = resp.json()

            values = []
            # Open ports
            for port in data.get("ports", []):
                values.append(f"{ip}:{port}")

            # Hostnames
            for hostname in data.get("hostnames", []):
                values.append(hostname)

            # Vulnerabilities
            for vuln in data.get("vulns", []):
                values.append(f"CVE: {vuln}")

            result.values = values
            result.metadata = {
                "ip": ip,
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpes", []),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", []),
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
