"""
VirusTotal Plugin — Domain information from VirusTotal API (free tier: 4 req/min).
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class VirusTotalPlugin(PluginBase):
    name = "VirusTotal"
    description = "Obtain subdomain and reputation information from VirusTotal."
    category = PluginCategory.THREAT_INTEL
    api_type = ApiType.TIERED
    requires_api_key = True
    api_key_names = ["VIRUSTOTAL_KEY"]
    result_types = ["subdomain"]
    website = "https://www.virustotal.com/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        api_key = self.api_keys.get("VIRUSTOTAL_KEY")
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}/subdomains",
                    headers={"x-apikey": api_key},
                    params={"limit": 100},
                )
                if resp.status_code == 401:
                    result.errors.append("Invalid VirusTotal API key")
                    result.success = False
                    return result
                if resp.status_code != 200:
                    result.errors.append(f"VirusTotal returned {resp.status_code}")
                    result.success = False
                    return result

                data = resp.json()
                subdomains = set()
                for item in data.get("data", []):
                    subdomain = item.get("id", "").strip().lower()
                    if subdomain:
                        subdomains.add(subdomain)

                result.values = sorted(subdomains)
                result.metadata = {"total": len(subdomains)}
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
