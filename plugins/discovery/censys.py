"""
Censys — Subdomain discovery via Censys Search API.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class CensysPlugin(PluginBase):
    name = "Censys"
    description = "Discover subdomains and certificates using the Censys search API."
    category = PluginCategory.DISCOVERY
    api_type = ApiType.TIERED
    requires_api_key = True
    api_key_names = ["CENSYS_ID", "CENSYS_SECRET"]
    result_types = ["subdomain"]
    website = "https://search.censys.io/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            from modules.discovery import InfrastructureDiscoverer
            d = InfrastructureDiscoverer(use_crtsh=False, analyze_ssl=False)
            d.set_api_keys(
                censys_id=self.api_keys.get("CENSYS_ID"),
                censys_secret=self.api_keys.get("CENSYS_SECRET"),
            )
            subs = await d.discover_subdomains_censys(target)
            result.values = sorted(subs)
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
