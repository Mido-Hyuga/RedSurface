"""
AlienVault OTX Plugin — Free threat intelligence from Open Threat Exchange.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class AlienVaultOTXPlugin(PluginBase):
    name = "AlienVault OTX"
    description = "Obtain passive DNS and threat data from AlienVault Open Threat Exchange."
    category = PluginCategory.THREAT_INTEL
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain", "ip"]
    website = "https://otx.alienvault.com/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns",
                    headers={"Accept": "application/json"},
                )
                if resp.status_code != 200:
                    result.errors.append(f"OTX returned {resp.status_code}")
                    result.success = False
                    return result

                data = resp.json()
                subdomains = set()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip().lower()
                    if hostname and (hostname.endswith(f".{target}") or hostname == target):
                        subdomains.add(hostname)

                result.values = sorted(subdomains)
                result.metadata = {"total": len(subdomains)}
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
