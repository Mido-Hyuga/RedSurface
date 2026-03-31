"""
URLScan.io Plugin — Free domain scanning and intelligence.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class URLScanPlugin(PluginBase):
    name = "URLScan.io"
    description = "Search URLScan.io cache for domain information, technologies, and links."
    category = PluginCategory.THREAT_INTEL
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain", "ip"]
    website = "https://urlscan.io/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": f"domain:{target}", "size": 100},
                )
                if resp.status_code != 200:
                    result.errors.append(f"URLScan.io returned {resp.status_code}")
                    result.success = False
                    return result

                data = resp.json()
                subdomains = set()
                ips = set()
                for entry in data.get("results", []):
                    page = entry.get("page", {})
                    domain = page.get("domain", "").strip().lower()
                    ip = page.get("ip", "")
                    if domain and (domain.endswith(f".{target}") or domain == target):
                        subdomains.add(domain)
                    if ip:
                        ips.add(ip)

                result.values = sorted(subdomains)
                result.metadata = {
                    "total_subdomains": len(subdomains),
                    "ips": sorted(ips),
                    "total_results": len(data.get("results", [])),
                }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
